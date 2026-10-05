"""Unit 4.2 attacks: transfer reversal (PLAN.md Stage 4, D4.4-D4.7, I25-I27, history D4.2).
Written from the contract before the build. Every class skips until
`POST /transfers/{id}/reverse` exists (it answers something other than the generic 404
`not_found`).

Spec in brief: POST /transfers/{id}/reverse, body exactly {}. Moves the original amount
to -> from, needs the token of the original `to`. Stored as an ordinary transfers row plus a
`reversals(transfer_id PK, reversal_id UNIQUE, created_at)` link row in the same write
transaction. 201 {"id", "from", "to", "amount", "reverses"}. Check order: 400 (body, malformed
id) -> 404 transfer_not_found -> 401 -> [lock] idempotency lookup -> 409 already_reversed ->
422 not_reversible -> 409 insufficient_funds -> 422 balance_limit -> write. Idempotency-Key in
the `debit` namespace of the original `to`, fingerprint (reverse, to, transfer_id); reuse of a
withdraw/transfer key -> 422 idempotency_key_reused. History: reversal_in / reversal_out items
carry "reverses".
"""
import concurrent.futures as cf
import contextlib
import json
import os
import random
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid

from breaker_harness import MAX_BALANCE, MAX_AMOUNT, REQUEST_TIMEOUT, AttackCase, Server

KEY = "Idempotency-Key"
REPLAYED = "idempotent-replayed"
BODY_KEYS = {"id", "from", "to", "amount", "reverses"}
ITEM_KEYS = {"id", "type", "amount", "counterparty", "created_at"}
CREDITS = {"deposit", "transfer_in", "reversal_in"}


def reverse(s, tid, token=None, body=b"{}", key=None, headers=None, timeout=REQUEST_TIMEOUT):
    h = dict(headers or {})
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    if key is not None:
        h[KEY] = key
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return s.request("POST", f"/transfers/{tid}/reverse", raw=raw, headers=h, timeout=timeout)


def kwithdraw(s, acct, amount, token, key):
    return s.request("POST", f"/accounts/{acct}/withdraw", {"amount": amount},
                     headers={**s.auth(token), KEY: key})


def ktransfer(s, src, dst, amount, token, key):
    return s.request("POST", "/transfers", {"from": src, "to": dst, "amount": amount},
                     headers={**s.auth(token), KEY: key})


def body_error(body):
    """D4.11: not a JSON object -> invalid_json; an object other than {} -> invalid_request.
    Over 16 KiB is invalid_json whatever it holds (the stage-1 body rule, unchanged by D4.7)."""
    if len(body) > 16 * 1024:
        return "invalid_json"
    try:
        v = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return "invalid_json"
    return "invalid_request" if isinstance(v, dict) else "invalid_json"


def replayed(r):
    return {k.lower(): v for k, v in r.headers.items()}.get(REPLAYED) == "true"


def fire(n, fn):
    """Run fn(i) for i in range(n) released together by a barrier; return responses in order."""
    gate = threading.Barrier(n)

    def go(i):
        gate.wait(30)
        return fn(i)

    with cf.ThreadPoolExecutor(n) as pool:
        return list(pool.map(go, range(n)))


class ReverseCase(AttackCase):

    def setUp(self):
        r = reverse(self.server, uuid.uuid4())
        if r.status == 404 and r.error == "not_found":
            self.skipTest("POST /transfers/{id}/reverse not built yet")

    def tearDown(self):
        super().tearDown()
        self.check_reversal_links()

    # -- helpers ----------------------------------------------------------------------------
    def pair(self, funded=1000, amount=300):
        """sender a (funded), recipient b, transfer a -> b of `amount`. Returns (a, b, tid)."""
        s = self.server
        a, b = self.funded(funded, "sender"), s.create_account("recipient")
        r = s.transfer(a["id"], b["id"], amount, a["token"])
        self.assertEqual(r.status, 201, r)
        return a, b, r.json["id"]

    def rows(self, sql, args=()):
        with contextlib.closing(self.server.db()) as c:
            return c.execute(sql, args).fetchall()

    def reversal_rows(self, tid):
        return self.rows("SELECT transfer_id, reversal_id FROM reversals WHERE transfer_id = ?", (tid,))

    def check_reversal_links(self):
        """I25/I27 from the DB: every link joins a non-reversal transfer to its exact mirror."""
        if "reversals" not in self.server.tables():
            return
        bad = self.rows("""
            SELECT r.transfer_id, r.reversal_id FROM reversals r
            JOIN transfers t ON t.id = r.transfer_id
            JOIN transfers v ON v.id = r.reversal_id
            WHERE v.from_id <> t.to_id OR v.to_id <> t.from_id OR v.amount <> t.amount
               OR r.transfer_id IN (SELECT reversal_id FROM reversals)
               OR r.transfer_id = r.reversal_id""")
        self.assertEqual(bad, [], "I27: a reversal link is not an exact mirror of a plain transfer")
        dangling = self.rows("""SELECT count(*) FROM reversals r
            WHERE NOT EXISTS (SELECT 1 FROM transfers WHERE id = r.transfer_id)
               OR NOT EXISTS (SELECT 1 FROM transfers WHERE id = r.reversal_id)""")[0][0]
        self.assertEqual(dangling, 0, "reversal link to a missing transfer")

    def history(self, acct):
        s, items, cursor = self.server, [], None
        for _ in range(1000):
            q = "?limit=100" + (f"&cursor={cursor}" if cursor else "")
            r = s.request("GET", f"/accounts/{acct['id']}/transactions{q}", headers=s.auth(acct["token"]))
            self.assertEqual(r.status, 200, r)
            items += r.json["items"]
            cursor = r.json["next_cursor"]
            if cursor is None:
                return items
        self.fail("history did not end")

    def assert_free(self, fn, status, error=None):
        return self.assertRejectedFree(fn, status, error)


# -- D4.4: the happy path, shape, ledger, history -----------------------------------------------

class A19Basics(ReverseCase):

    def test_reverse_moves_the_exact_amount_back(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        r = reverse(s, tid, b["token"])
        self.assertEqual(r.status, 201, r)
        self.assertEqual(set(r.json), BODY_KEYS, r)
        self.assertEqual((r.json["from"], r.json["to"], r.json["amount"], r.json["reverses"]),
                         (b["id"], a["id"], 300, tid), r)
        self.assertNotEqual(r.json["id"], tid)
        self.assertFalse(replayed(r))
        self.assertEqual((s.balance(a["id"]), s.balance(b["id"])), (1000, 0))
        rid = r.json["id"]
        self.assertEqual(self.rows("SELECT from_id, to_id, amount FROM transfers WHERE id = ?", (rid,)),
                         [(b["id"], a["id"], 300)], "D4.4: reversal is an ordinary transfers row to -> from")
        self.assertEqual(self.reversal_rows(tid), [(tid, rid)])

    def test_exact_balance_reverses_and_one_more_does_not(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        self.assertEqual(s.withdraw(b["id"], 1, b["token"]).status, 200)
        self.assert_free(lambda: reverse(s, tid, b["token"]), 409, "insufficient_funds")
        self.assertEqual(s.deposit(b["id"], 1).status, 200)  # exactly the amount again
        r = reverse(s, tid, b["token"])
        self.assertEqual(r.status, 201, r)
        self.assertEqual(s.balance(b["id"]), 0)

    def test_recipient_spent_part_is_409_no_partial(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        c = s.create_account("third")
        self.assertEqual(s.transfer(b["id"], c["id"], 120, b["token"]).status, 201)
        self.assert_free(lambda: reverse(s, tid, b["token"]), 409, "insufficient_funds")
        self.assertEqual((s.balance(a["id"]), s.balance(b["id"])), (700, 180), "D4.5: partial reversal")
        self.assertEqual(self.reversal_rows(tid), [])

    def test_second_reverse_is_409_already_reversed_also_after_restart(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        self.assertEqual(reverse(s, tid, b["token"]).status, 201)
        s.deposit(b["id"], 5000)  # funds are no excuse
        self.assert_free(lambda: reverse(s, tid, b["token"]), 409, "already_reversed")
        s.restart()
        self.assert_free(lambda: reverse(s, tid, b["token"]), 409, "already_reversed")
        self.assertEqual(len(self.reversal_rows(tid)), 1)

    def test_reversal_cannot_be_reversed(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        rid = reverse(s, tid, b["token"]).json["id"]
        # rid moved b -> a, so its `to` is a: a's token passes 401 and reaches 422
        self.assert_free(lambda: reverse(s, rid, a["token"]), 422, "not_reversible")
        self.assert_free(lambda: reverse(s, rid, b["token"]), 401)
        s.deposit(a["id"], 10**6)
        self.assert_free(lambda: reverse(s, rid, a["token"], key="rr-1"), 422, "not_reversible")

    def test_reverse_an_old_transfer_after_newer_ones(self):
        s = self.server
        a, b, t1 = self.pair(1000, 100)
        t2 = s.transfer(a["id"], b["id"], 200, a["token"]).json["id"]
        t3 = s.transfer(b["id"], a["id"], 50, b["token"]).json["id"]
        self.assertEqual(reverse(s, t1, b["token"]).status, 201)
        self.assertEqual(reverse(s, t3, a["token"]).status, 201)   # b -> a reversed by a
        self.assertEqual(reverse(s, t2, b["token"]).status, 201)
        self.assertEqual((s.balance(a["id"]), s.balance(b["id"])), (1000, 0))


# -- D4.5: tokens, ids, bodies, and the exact check order ---------------------------------------

BAD_BODIES = [b"", b"[]", b"null", b"0", b'""', b"true", b'{"amount":300}', b'{"a":1}', b'{"":0}',
              b"{}{}", b"{} x", b"{}\x00", b'{"a":1,"a":1}', b"{", b"}", b"{}]", b"\xff\xfe{}",
              b'{"reverses":"x"}', b'{"__proto__":{}}', b'{"amount":null}', b"{,}", b"[{}]",
              b"{}" + b" " * (17 * 1024)]


class A19Rejections(ReverseCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    def test_tokens_other_than_the_recipients_are_401_no_effect(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        c = s.create_account("third")
        for name, h in {"none": {}, "sender": s.auth(a["token"]), "third": s.auth(c["token"]),
                        "empty": {"Authorization": ""}, "basic": {"Authorization": f"Basic {b['token']}"},
                        "suffix": s.auth(b["token"] + "x"), "truncated": s.auth(b["token"][:-1]),
                        "lowercase scheme": {"Authorization": f"bearer {b['token']}"},
                        "id as token": s.auth(b["id"])}.items():
            r = self.assert_free(lambda: reverse(s, tid, headers=h), 401)
            self.assertEqual(set(r.json), {"error"}, (name, r))
            self.assertNotIn(b["token"].encode(), r.raw, name)
        self.assertEqual(reverse(s, tid, b["token"]).status, 201)

    def test_unknown_and_non_transfer_ids_are_404(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        dep_id = self.rows("SELECT id FROM external_moves WHERE account_id = ?", (a["id"],))[0][0]
        for x in (str(uuid.uuid4()), dep_id, a["id"], b["id"], str(uuid.UUID(int=0))):
            for tok in (None, b["token"]):
                self.assert_free(lambda: reverse(s, x, tok), 404, "transfer_not_found")

    def test_malformed_ids_are_rejected_without_effect(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        strict = ["x", "1", "0", tid + "0", tid[:-1], tid.replace("-", ""), "%27%20OR%201%3D1--",
                  "1%3BDROP%20TABLE%20reversals", "%27", "%2e%2e", "{" + tid + "}", tid + "%00",
                  "%20" + tid, "-1", "9" * 40, "NULL", "*"]
        for x in strict:
            r = self.assert_free(lambda: reverse(s, x, b["token"]), 400, "invalid_request")
        # non-canonical spellings of a real id: never a reversal, 400 (malformed) or 404
        for x in (tid.upper(), "urn:uuid:" + tid):
            before = s.snapshot()
            r = reverse(s, x, b["token"])
            self.assertIn(r.status, (400, 404), (x, r))
            self.assertEqual(s.snapshot(), before)
        self.assertEqual(self.reversal_rows(tid), [])

    def test_path_and_method_variants_are_not_reverse(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        h = s.auth(b["token"])
        for method, path in (("GET", f"/transfers/{tid}/reverse"), ("PUT", f"/transfers/{tid}/reverse"),
                             ("DELETE", f"/transfers/{tid}/reverse"),
                             ("POST", f"/transfers/{tid}/reverse/"), ("POST", f"/transfers/{tid}/Reverse"),
                             ("POST", f"/transfers//{tid}/reverse"), ("POST", f"/transfers/{tid}")):
            before = s.snapshot()
            r = s.request(method, path, raw=b"{}", headers=h)
            self.assertIn(r.status, (400, 404), (method, path, r))
            self.assertEqual(s.snapshot(), before, (method, path))
        # D4.11: POST ignores the query string -- the same request as without it
        r = s.request("POST", f"/transfers/{tid}/reverse?x=1&y=2;", raw=b"{}", headers=h)
        self.assertEqual(r.status, 201, r)
        self.assertEqual(r.json["reverses"], tid)
        for q in ("", "?", "?limit=0", "?cursor=zz&cursor=zz"):
            self.assert_free(lambda: s.request("POST", f"/transfers/{tid}/reverse{q}", raw=b"{}", headers=h),
                             409, "already_reversed")

    def test_bodies_other_than_empty_object_are_400(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        failures = []
        for body in BAD_BODIES:
            before = s.snapshot()
            r = reverse(s, tid, b["token"], body=body)
            want = body_error(body)
            if body == b'{"a":1,"a":1}':
                want = "invalid_json"  # stage-1 body rule: duplicate keys are invalid_json
            ok = r.status == 400 and r.error == want
            if not ok or s.snapshot() != before:
                failures.append((body[:40], want, r.status, r.raw[:80]))
        self.assertEqual(failures, [], "D4.4/D4.11: body must be exactly {}")
        for body in (b"{ }", b" {}", b"{}\n", b'{\t}'):
            before = s.snapshot()
            r = reverse(s, tid, b["token"], body=body)
            self.assertIn(r.status, (201, 400), (body, r))  # whitespace: either ruling, never other
            if r.status == 201:
                break
            self.assertEqual(s.snapshot(), before)
        else:
            self.assertEqual(reverse(s, tid, b["token"]).status, 201)
        self.assertEqual(len(self.reversal_rows(tid)), 1)

    def test_bad_idempotency_keys_are_400(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        for k in ("", "x" * 256, "a b", "été".encode().decode("latin-1"), "a\x7fb"):
            before = s.snapshot()
            try:
                r = reverse(s, tid, b["token"], key=k)
            except ValueError:   # http.client refuses some values outright
                continue
            self.assertEqual((r.status, r.error), (400, "invalid_request"), (k, r))
            self.assertEqual(s.snapshot(), before)
        st, raw = s.raw_http((f"POST /transfers/{tid}/reverse HTTP/1.1\r\nHost: x\r\n"
                              f"Authorization: Bearer {b['token']}\r\n{KEY}: k1\r\n{KEY}: k1\r\n"
                              "Content-Length: 2\r\n\r\n{}").encode())
        self.assertEqual(st, 400, raw)
        self.assertEqual(self.reversal_rows(tid), [])


class A19CheckOrder(ReverseCase):
    """D4.5 order, faults combined pairwise; the earlier check must win, with no effect."""

    def test_pairwise_order(self):
        s = self.server
        a, b, tid = self.pair(10_000, 300)
        c = s.create_account("third")
        unknown = str(uuid.uuid4())
        cases = [
            ("body+unknown", lambda: reverse(s, unknown, b["token"], body=b"[]"), 400, "invalid_json"),
            ("body+no token", lambda: reverse(s, tid, None, body=b'{"a":1}'), 400, "invalid_request"),
            ("malformed+no token", lambda: reverse(s, "zz", None), 400, "invalid_request"),
            ("body+malformed", lambda: reverse(s, "zz", None, body=b"null"), 400, "invalid_json"),
            ("object+malformed", lambda: reverse(s, "zz", None, body=b'{"amount":1}'), 400, "invalid_request"),
            ("broken json+unknown", lambda: reverse(s, unknown, None, body=b"{"), 400, "invalid_json"),
            ("bad key+unknown", lambda: reverse(s, unknown, None, key="a b"), 400, "invalid_request"),
            ("unknown+no token", lambda: reverse(s, unknown, None), 404, "transfer_not_found"),
            ("unknown+sender token", lambda: reverse(s, unknown, a["token"]), 404, "transfer_not_found"),
        ]
        for name, fn, st, err in cases:
            with self.subTest(name):
                self.assert_free(fn, st, err)
        # spend part of it: 401 must still come before insufficient_funds
        self.assertEqual(s.transfer(b["id"], c["id"], 1, b["token"]).status, 201)
        self.assert_free(lambda: reverse(s, tid, c["token"]), 401)
        self.assert_free(lambda: reverse(s, tid, b["token"]), 409, "insufficient_funds")
        s.deposit(b["id"], 1)
        rid = reverse(s, tid, b["token"], key="ord-1").json["id"]
        # already reversed + wrong token -> 401
        self.assert_free(lambda: reverse(s, tid, a["token"]), 401)
        # already reversed + recipient now broke -> already_reversed, not insufficient
        self.assertEqual(s.balance(b["id"]), 0)
        self.assert_free(lambda: reverse(s, tid, b["token"]), 409, "already_reversed")
        # idempotency lookup before already_reversed: same key replays
        r = reverse(s, tid, b["token"], key="ord-1")
        self.assertEqual((r.status, replayed(r), r.json["id"]), (201, True, rid), r)
        # replay still needs the right token
        self.assert_free(lambda: reverse(s, tid, a["token"], key="ord-1"), 401)
        # a withdraw key reused on an already-reversed transfer: mismatch beats already_reversed
        s.deposit(b["id"], 10)
        self.assertEqual(kwithdraw(s, b["id"], 1, b["token"], "ord-w").status, 200)
        self.assert_free(lambda: reverse(s, tid, b["token"], key="ord-w"), 422, "idempotency_key_reused")
        # not_reversible + insufficient funds: rid moved b -> a; a spends everything
        bal = s.balance(a["id"])
        self.assertEqual(s.withdraw(a["id"], bal, a["token"]).status, 200)
        self.assert_free(lambda: reverse(s, rid, a["token"]), 422, "not_reversible")
        # not_reversible + wrong token -> 401
        self.assert_free(lambda: reverse(s, rid, b["token"]), 401)
        # malformed id beats a valid key replay
        self.assert_free(lambda: reverse(s, tid + "x", b["token"], key="ord-1"), 400, "invalid_request")


class A19BalanceLimit(ReverseCase):
    """D4.5: reversing into a sender near 10^15 -> 422 balance_limit; exactly 10^15 is fine."""

    def test_sender_near_limit(self):
        s = self.server
        a, b = s.create_account("rich"), s.create_account("poorer")
        with cf.ThreadPoolExecutor(32) as pool:
            sts = list(pool.map(lambda _: s.deposit(a["id"], MAX_AMOUNT).status,
                                range(MAX_BALANCE // MAX_AMOUNT)))
        self.assertEqual(set(sts), {200})
        self.assertEqual(s.balance(a["id"]), MAX_BALANCE)
        t = s.transfer(a["id"], b["id"], 5, a["token"]).json["id"]
        self.assertEqual(s.deposit(a["id"], 1).status, 200)  # a = 10^15 - 4
        self.assert_free(lambda: reverse(s, t, b["token"]), 422, "balance_limit")
        self.assert_free(lambda: reverse(s, t, b["token"], key="lim-1"), 422, "balance_limit")
        # insufficient beats balance_limit
        c = s.create_account("sink")
        self.assertEqual(s.transfer(b["id"], c["id"], 1, b["token"]).status, 201)
        self.assert_free(lambda: reverse(s, t, b["token"]), 409, "insufficient_funds")
        self.assertEqual(s.transfer(c["id"], b["id"], 1, c["token"]).status, 201)
        self.assertEqual(s.withdraw(a["id"], 1, a["token"]).status, 200)  # a = 10^15 - 5
        r = reverse(s, t, b["token"], key="lim-1")  # same key, rejected before: evaluated fresh
        self.assertEqual(r.status, 201, r)
        self.assertEqual(s.balance(a["id"]), MAX_BALANCE)


# -- D4.6: idempotency ------------------------------------------------------------------------

class A19Idempotency(ReverseCase):

    def test_replay_byte_identical_after_balance_change_and_restart(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        first = reverse(s, tid, b["token"], key="rep-1")
        self.assertEqual(first.status, 201, first)
        self.assertFalse(replayed(first))
        s.deposit(b["id"], 77)
        s.withdraw(a["id"], 500, a["token"])
        for _ in range(2):
            before = s.snapshot()
            r = reverse(s, tid, b["token"], key="rep-1",
                        headers={"Authorization": f"Bearer {b['token']} \t"})  # other valid spelling
            self.assertEqual((r.status, r.raw), (201, first.raw), "I13: replay not byte-identical")
            self.assertTrue(replayed(r), r.headers)
            self.assertEqual(s.snapshot(), before, "I13: replay had an effect")
            s.restart()
        self.assertEqual(len(self.reversal_rows(tid)), 1)

    def test_key_reuse_across_operations_is_422(self):
        s = self.server
        a, b, t1 = self.pair(10_000, 300)
        t2 = s.transfer(a["id"], b["id"], 400, a["token"]).json["id"]
        c = s.create_account("c")
        self.assertEqual(kwithdraw(s, b["id"], 1, b["token"], "w").status, 200)
        self.assertEqual(ktransfer(s, b["id"], c["id"], 1, b["token"], "t").status, 201)
        self.assert_free(lambda: reverse(s, t1, b["token"], key="w"), 422, "idempotency_key_reused")
        self.assert_free(lambda: reverse(s, t1, b["token"], key="t"), 422, "idempotency_key_reused")
        self.assertEqual(reverse(s, t1, b["token"], key="r").status, 201)
        # the reverse key now blocks a withdraw/transfer on b, and a reverse of another transfer
        self.assert_free(lambda: kwithdraw(s, b["id"], 1, b["token"], "r"), 422,
                         "idempotency_key_reused")
        self.assert_free(lambda: ktransfer(s, b["id"], c["id"], 1, b["token"], "r"), 422,
                         "idempotency_key_reused")
        self.assert_free(lambda: reverse(s, t2, b["token"], key="r"), 422, "idempotency_key_reused")
        # independent namespaces: b's deposit key, and a's debit key, do not collide
        self.assertEqual(s.request("POST", f"/accounts/{b['id']}/deposit", {"amount": 5},
                                   headers={KEY: "d"}).status, 200)
        self.assertEqual(kwithdraw(s, a["id"], 1, a["token"], "x").status, 200)
        self.assertEqual(reverse(s, t2, b["token"], key="d").status, 201)
        _, e, t3 = self.pair(1000, 10)
        self.assertEqual(reverse(s, t3, e["token"], key="x").status, 201)
        # case-sensitive keys
        self.assertEqual(reverse(s, t1, b["token"], key="R").status, 409)

    def test_rejected_keyed_reverse_consumes_nothing(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        s.withdraw(b["id"], 100, b["token"])
        self.assert_free(lambda: reverse(s, tid, b["token"], key="i15"), 409, "insufficient_funds")
        self.assertEqual(self.rows("SELECT count(*) FROM idempotency_keys WHERE key = 'i15'")[0][0], 0)
        s.deposit(b["id"], 100)
        r1 = reverse(s, tid, b["token"], key="i15")
        self.assertEqual((r1.status, replayed(r1)), (201, False), r1)
        r2 = reverse(s, tid, b["token"], key="i15")
        self.assertEqual((r2.status, replayed(r2), r2.raw), (201, True, r1.raw))
        # an unrelated fresh key after the reversal: already_reversed, and no key row
        self.assert_free(lambda: reverse(s, tid, b["token"], key="fresh"), 409, "already_reversed")
        self.assertEqual(self.rows("SELECT count(*) FROM idempotency_keys WHERE key = 'fresh'")[0][0], 0)


# -- I25 / I26: concurrency -------------------------------------------------------------------

class A19Concurrency(ReverseCase):

    def settle(self, rs, tid, b, a_start, a_id, amount):
        """Exactly one committing 201; every other 201 is a replay of it; the rest are 409
        already_reversed or (above 100-way) 503 busy. One link row, money moved once."""
        fresh = [r for r in rs if r.status == 201 and not replayed(r)]
        self.assertEqual(len(fresh), 1, f"I25: {len(fresh)} committing reversals: "
                                        f"{sorted({(r.status, r.error) for r in rs})}")
        body = fresh[0].raw
        for r in rs:
            if r.status == 201:
                self.assertTrue(r.raw == body, "two different 201 bodies")
            else:
                self.assertIn((r.status, r.error), {(409, "already_reversed"), (503, "busy")}, r)
        self.assertEqual(len(self.reversal_rows(tid)), 1, "I25: reversals rows")
        self.assertEqual(self.server.balance(b["id"]), 0)
        self.assertEqual(self.server.balance(a_id), a_start + amount)

    def test_100_keyless(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        rs = fire(100, lambda i: reverse(s, tid, b["token"]))
        self.assertEqual(self.busy_count(rs), 0, "I19: no 503 at <= 100 writers")
        self.settle(rs, tid, b, 700, a["id"], 300)

    def test_100_same_key(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        rs = fire(100, lambda i: reverse(s, tid, b["token"], key="burst"))
        self.assertEqual(self.busy_count(rs), 0)
        self.assertTrue(all(r.status == 201 for r in rs), {(r.status, r.error) for r in rs})
        self.settle(rs, tid, b, 700, a["id"], 300)

    def test_200_mixed(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)

        def go(i):
            k = i % 4
            key = None if k == 0 else "shared" if k == 1 else f"own-{i}" if k == 2 else f"pair-{i // 8}"
            return reverse(s, tid, b["token"], key=key)

        rs = fire(200, go)
        self.settle(rs, tid, b, 700, a["id"], 300)

    def test_many_transfers_each_hammered(self):
        """20 transfers, each reversed by 8 threads at once (160 requests): one link each."""
        s = self.server
        a, b = self.funded(100_000, "a"), s.create_account("b")
        tids = [s.transfer(a["id"], b["id"], 10 + i, a["token"]).json["id"] for i in range(20)]
        rs = fire(160, lambda i: reverse(s, tids[i % 20], b["token"], key=None if i % 2 else f"k{i % 20}"))
        for i, tid in enumerate(tids):
            mine = [r for j, r in enumerate(rs) if j % 20 == i]
            fresh = [r for r in mine if r.status == 201 and not replayed(r)]
            busy = self.busy_count(mine)
            self.assertLessEqual(len(fresh), 1, f"I25: transfer {i} reversed twice")
            if busy == 0:
                self.assertEqual(len(fresh), 1, f"transfer {i}: nothing committed and no 503")
            self.assertEqual(len(self.reversal_rows(tid)), len(fresh))
        self.assertEqual(s.balance(b["id"]),
                         sum(10 + i for i, t in enumerate(tids) if not self.reversal_rows(t)))

    def test_recipient_withdraw_races_reversals(self):
        """I26: 10 transfers of 100 into b (b = 1000). 10x8 reverses race 40 withdrawals of 100.
        Total out of b never exceeds 1000; nothing goes negative; every 2xx is one row."""
        s = self.server
        a, b = self.funded(10_000, "a"), s.create_account("b")
        tids = [s.transfer(a["id"], b["id"], 100, a["token"]).json["id"] for _ in range(10)]
        w_before = self.rows("SELECT count(*) FROM external_moves WHERE account_id = ? AND kind = 'withdrawal'",
                             (b["id"],))[0][0]

        def go(i):
            if i < 80:
                return ("rev", reverse(s, tids[i % 10], b["token"]))
            return ("wd", s.withdraw(b["id"], 100, b["token"]))

        out = fire(120, go)
        revs = [r for k, r in out if k == "rev" and r.status == 201]
        wds = [r for k, r in out if k == "wd" and r.status == 200]
        for k, r in out:
            self.assertIn((r.status, r.error if r.status >= 400 else None),
                          {(201, None), (200, None), (409, "already_reversed"), (409, "insufficient_funds"),
                           (503, "busy")}, (k, r))
        links = self.rows("SELECT count(*) FROM reversals WHERE transfer_id IN (%s)" % ",".join("?" * 10), tids)[0][0]
        w_after = self.rows("SELECT count(*) FROM external_moves WHERE account_id = ? AND kind = 'withdrawal'",
                            (b["id"],))[0][0]
        self.assertEqual(len(revs), links, "a 201 without a link row or the reverse")
        self.assertEqual(len(wds), w_after - w_before)
        self.assertLessEqual(100 * (len(revs) + len(wds)), 1000, "I26: b paid out more than it had")
        self.assertEqual(s.balance(b["id"]), 1000 - 100 * (len(revs) + len(wds)))
        if self.busy_count([r for _, r in out]) == 0:
            self.assertEqual(len(revs) + len(wds), 10, "funds left behind with no 503 to explain it")


class A19CrashBurst(unittest.TestCase):
    """I25 across a crash: kill -9 mid reverse burst, restart, retry every key -> exactly one
    reversal per transfer, every retry 201, I1/I7 hold."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.server = Server(os.path.join(self._tmp.name, "wallet.db")).start()
        r = reverse(self.server, uuid.uuid4())
        if r.status == 404 and r.error == "not_found":
            self.server.kill()
            self.skipTest("POST /transfers/{id}/reverse not built yet")

    def tearDown(self):
        self.server.kill()
        self._tmp.cleanup()

    def test_kill_mid_reverse_burst_then_retry_every_key(self):
        s = self.server
        a = s.create_account("a")
        s.deposit(a["id"], 10**9)
        bs = [s.create_account(f"b{i}") for i in range(6)]
        jobs = []
        for i in range(90):
            b = bs[i % 6]
            r = s.transfer(a["id"], b["id"], 1 + i, a["token"])
            self.assertEqual(r.status, 201, r)
            jobs.append((r.json["id"], b, f"crash-{i}"))
        stop = threading.Event()

        def burst(n):
            rnd = random.Random(n)
            while not stop.is_set():
                tid, b, key = rnd.choice(jobs)
                reverse(s, tid, b["token"], key=key if rnd.random() < 0.8 else None, timeout=3)

        threads = [threading.Thread(target=burst, args=(n,), daemon=True) for n in range(32)]
        for t in threads:
            t.start()
        time.sleep(0.8)
        s.kill()
        stop.set()
        for t in threads:
            t.join(15)
        s.start()
        for tid, b, key in jobs:
            r = reverse(s, tid, b["token"], key=key)
            # keyless burst requests may have reversed it already: then the key is fresh -> 409
            self.assertIn((r.status, r.error if r.status >= 400 else None),
                          {(201, None), (409, "already_reversed")}, r)
            r2 = reverse(s, tid, b["token"], key=key)
            self.assertEqual((r2.status, r2.raw), (r.status, r.raw), "retry after crash differs")
        with contextlib.closing(s.db()) as c:
            per = dict(c.execute("SELECT transfer_id, count(*) FROM reversals GROUP BY transfer_id").fetchall())
            self.assertEqual(set(per), {tid for tid, _, _ in jobs}, "a transfer was never reversed")
            self.assertEqual(set(per.values()), {1}, "I25 across the crash")
            n_tr = c.execute("SELECT count(*) FROM transfers").fetchone()[0]
            self.assertEqual(n_tr, 180, "orphan reversal transfer rows without links")
            bad = c.execute("""SELECT a.id FROM accounts a WHERE a.balance <>
                coalesce((SELECT sum(amount) FROM external_moves WHERE account_id = a.id AND kind = 'deposit'), 0)
              - coalesce((SELECT sum(amount) FROM external_moves WHERE account_id = a.id AND kind = 'withdrawal'), 0)
              + coalesce((SELECT sum(amount) FROM transfers WHERE to_id = a.id), 0)
              - coalesce((SELECT sum(amount) FROM transfers WHERE from_id = a.id), 0)""").fetchall()
            self.assertEqual(bad, [], "I7 after crash")
        self.assertEqual(s.balance(a["id"]), 10**9)
        self.assertTrue(all(s.balance(b["id"]) == 0 for b in bs))
        audit = s.request("GET", "/audit").json
        self.assertIs(audit["conserved"], True, audit)


class A19StageThreeDatabase(unittest.TestCase):
    """A transfer written by stage 3 (sequenced by the D4.9 backfill) reverses like any other,
    at most once, across a restart, and shows up linked in both histories."""

    def setUp(self):
        from test_a18_history_4_1 import seed_stage3_db
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        path = os.path.join(self._tmp.name, "stage3.db")
        self.accts, _ = seed_stage3_db(path)
        self.server = Server(path).start()
        r = reverse(self.server, uuid.uuid4())
        if r.status == 404 and r.error == "not_found":
            self.server.kill()
            self.skipTest("POST /transfers/{id}/reverse not built yet")

    def tearDown(self):
        self.server.kill()
        self._tmp.cleanup()

    def test_reverse_a_stage3_transfer(self):
        s = self.server
        by_id = {a["id"]: a for a in self.accts}
        with contextlib.closing(s.db()) as c:
            old = c.execute("SELECT id, from_id, to_id, amount FROM transfers").fetchall()
        done = 0
        for tid, frm, to, amt in old:
            r = reverse(s, tid, by_id[to]["token"])
            if r.status == 409 and r.error == "insufficient_funds":
                s.deposit(to, amt)
                r = reverse(s, tid, by_id[to]["token"])
            if r.status == 422 and r.error == "balance_limit":
                continue
            self.assertEqual(r.status, 201, r)
            self.assertEqual((r.json["from"], r.json["to"], r.json["amount"], r.json["reverses"]),
                             (to, frm, amt, tid))
            done += 1
        self.assertEqual(done, len(old))
        s.restart()
        for tid, frm, to, amt in old:
            r = reverse(s, tid, by_id[to]["token"])
            self.assertEqual((r.status, r.error), (409, "already_reversed"), r)
        for a in self.accts:
            items, cur = [], None
            while True:
                q = "?limit=3" + (f"&cursor={cur}" if cur else "")
                r = s.request("GET", f"/accounts/{a['id']}/transactions{q}", headers=s.auth(a["token"]))
                self.assertEqual(r.status, 200, r)
                items += r.json["items"]
                cur = r.json["next_cursor"]
                if not cur:
                    break
            net = sum(i["amount"] if i["type"] in CREDITS else -i["amount"] for i in items)
            self.assertEqual(net, s.balance(a["id"]), "I22 on an upgraded DB with reversals")
            revs = [i for i in items if i["type"].startswith("reversal")]
            mine = [t for t in old if a["id"] in (t[1], t[2])]
            self.assertEqual(sorted(i["reverses"] for i in revs), sorted(t[0] for t in mine))
            n_rev = len(revs)
            self.assertEqual([i["type"].startswith("reversal") for i in items[:n_rev]], [True] * n_rev,
                             "reversals of backfilled rows must sort newer than every backfilled row")
        audit = s.request("GET", "/audit").json
        self.assertIs(audit["conserved"], True, audit)


# -- D4.2 / I22 / I27: history with reversals -------------------------------------------------

class A19History(ReverseCase):

    def test_both_sides_show_linked_reversal_items(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        rid = reverse(s, tid, b["token"]).json["id"]
        ha, hb = self.history(a), self.history(b)
        ra = [i for i in ha if i["id"] == rid]
        rb = [i for i in hb if i["id"] == rid]
        self.assertEqual(len(ra), 1)
        self.assertEqual(len(rb), 1)
        self.assertEqual(set(ra[0]), ITEM_KEYS | {"reverses"})
        self.assertEqual((ra[0]["type"], ra[0]["amount"], ra[0]["counterparty"], ra[0]["reverses"]),
                         ("reversal_in", 300, b["id"], tid))
        self.assertEqual((rb[0]["type"], rb[0]["amount"], rb[0]["counterparty"], rb[0]["reverses"]),
                         ("reversal_out", 300, a["id"], tid))
        self.assertEqual(ha[0]["id"], rid, "reversal is the newest item")
        for h in (ha, hb):
            orig = [i for i in h if i["id"] == tid]
            self.assertEqual(len(orig), 1)
            self.assertNotIn("reverses", orig[0], "the original item must not gain `reverses`")
            self.assertIn(orig[0]["type"], ("transfer_in", "transfer_out"))
            for i in h:
                if i["type"].startswith("reversal"):
                    self.assertEqual(set(i), ITEM_KEYS | {"reverses"}, i)
                else:
                    self.assertEqual(set(i), ITEM_KEYS, i)
        for acct, h in ((a, ha), (b, hb)):
            net = sum(i["amount"] if i["type"] in CREDITS else -i["amount"] for i in h)
            self.assertEqual(net, s.balance(acct["id"]), "I22 with reversal items")

    def test_cursor_taken_before_a_reversal_still_pages(self):
        s = self.server
        a, b = self.funded(100_000, "a"), s.create_account("b")
        tids = [s.transfer(a["id"], b["id"], 10 + i, a["token"]).json["id"] for i in range(30)]
        before = self.history(b)
        r = s.request("GET", f"/accounts/{b['id']}/transactions?limit=10", headers=s.auth(b["token"]))
        cursor = r.json["next_cursor"]
        # reverse an item on the page already read, one on the next page, one further down
        for t in (tids[-1], tids[-15], tids[2]):
            self.assertEqual(reverse(s, t, b["token"]).status, 201)
        rest, cur = [], cursor
        while cur:
            r = s.request("GET", f"/accounts/{b['id']}/transactions?limit=10&cursor={cur}",
                          headers=s.auth(b["token"]))
            self.assertEqual(r.status, 200, r)
            rest += r.json["items"]
            cur = r.json["next_cursor"]
        self.assertEqual(rest, before[10:], "D4.10: a reversal shifted or changed older pages")
        after = self.history(b)
        self.assertEqual(after[3:], before, "reversals must be newer than every older row")
        self.assertEqual([i["type"] for i in after[:3]], ["reversal_out"] * 3)

    def test_reversal_of_reversal_never_appears(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        rid = reverse(s, tid, b["token"]).json["id"]
        reverse(s, rid, a["token"])
        self.assertEqual(len([i for i in self.history(a) if i["type"].startswith("reversal")]), 1)


class A19Schema(ReverseCase):

    def test_reversals_table_backstops_at_most_once(self):
        s = self.server
        a, b, tid = self.pair(1000, 300)
        rid = reverse(s, tid, b["token"]).json["id"]
        with contextlib.closing(s.db()) as c:
            sql = c.execute("SELECT sql FROM sqlite_master WHERE name = 'reversals'").fetchone()
        self.assertIsNotNone(sql, "D4.4: no reversals table")
        self.assertIn("STRICT", sql[0].upper())
        c = sqlite3.connect(s.db_path, timeout=10, isolation_level=None)
        try:
            c.execute("PRAGMA foreign_keys = ON")
            c.execute("BEGIN IMMEDIATE")
            other = str(uuid.uuid4())
            for stmt, args in (("INSERT INTO reversals (transfer_id, reversal_id, created_at) VALUES (?, ?, 'x')",
                                (tid, other)),
                               ("INSERT INTO reversals (transfer_id, reversal_id, created_at) VALUES (?, ?, 'x')",
                                (other, rid))):
                with self.assertRaises(sqlite3.IntegrityError, msg=stmt):
                    c.execute(stmt, args)
        finally:
            c.execute("ROLLBACK")
            c.close()


if __name__ == "__main__":
    unittest.main()
