"""Unit 2.1 attacks: Idempotency-Key (PLAN.md Stage 2, D2.1-D2.9, I12-I17). Written from the spec
before the build; every test skips until the server honours the header (a keyed repeat answers
with `Idempotent-Replayed: true`).

Spec in brief: the key is optional; exactly one header; 1-255 chars of 0x21-0x7E after OWS trim,
case-sensitive; otherwise 400 invalid_request with the shape 400s. Scope (Q2-A ruling) = two
namespaces per account: `debit` (transfer `from`, withdraw {id}; a withdraw and a transfer with
one key is a mismatch) and `deposit` (credited account). A deposit key never blocks, replays or
mismatches a debit key. Fingerprint = (operation, account,
to, amount) of the validated request. Order: 400 -> 404 -> 401 -> BEGIN IMMEDIATE -> lookup ->
replay | 422 idempotency_key_reused -> money rules -> write key row in the same tx -> commit.
Only 2xx are recorded. A replay = original status + byte-identical body + Idempotent-Replayed:
true, zero effect, still needs the 401 check. Table: idempotency_keys(account_id, key,
scope, fingerprint, status, response, created_at, PK(account_id, scope, key)).
"""
import concurrent.futures as cf
import contextlib
import json
import random
import socket
import sqlite3
import struct
import threading
import time
import uuid

from breaker_harness import MAX_AMOUNT, MAX_BALANCE, NO_RESPONSE, REQUEST_TIMEOUT, AttackCase

CRLF = bytes([13, 10])
BUSY = (503, "busy")
KEY = "Idempotency-Key"
REPLAYED = "idempotent-replayed"


def hdr(r, name):
    for k, v in r.headers.items():
        if k.lower() == name.lower():
            return v
    return None


def is_replay(r):
    return hdr(r, REPLAYED) == "true"


class IdemCase(AttackCase):
    _supported = None

    def setUp(self):
        cls = type(self)
        if cls._supported is None:
            a = self.server.create_account("probe")
            k = "probe-" + uuid.uuid4().hex
            self.server.deposit(a["id"], 1, headers={KEY: k})
            r = self.server.deposit(a["id"], 1, headers={KEY: k})
            cls._supported = r.status == 200 and is_replay(r)
        if not cls._supported:
            self.skipTest("Idempotency-Key not honoured yet (stage 2 not built)")

    def tearDown(self):
        super().tearDown()
        self.check_key_table()

    # -- keyed calls -----------------------------------------------------------
    def t(self, src, dst, amount, token, key, **kw):
        h = {"Authorization": f"Bearer {token}"}
        if key is not None:
            h[KEY] = key
        h.update(kw.pop("headers", {}))
        return self.server.request("POST", "/transfers", {"from": src, "to": dst, "amount": amount},
                                   headers=h, **kw)

    def w(self, acct, amount, token, key, **kw):
        h = {"Authorization": f"Bearer {token}"}
        if key is not None:
            h[KEY] = key
        return self.server.request("POST", f"/accounts/{acct}/withdraw", {"amount": amount}, headers=h, **kw)

    def d(self, acct, amount, key, **kw):
        h = {KEY: key} if key is not None else {}
        return self.server.request("POST", f"/accounts/{acct}/deposit", {"amount": amount}, headers=h, **kw)

    def k(self):
        return "k-" + uuid.uuid4().hex

    # -- DB views --------------------------------------------------------------
    def key_rows(self, account=None):
        with contextlib.closing(self.server.db()) as c:
            if "idempotency_keys" not in self.server.tables():
                return []
            q = "SELECT account_id, key, status, response FROM idempotency_keys"
            return c.execute(q + (" WHERE account_id = ?" if account else ""),
                             (account,) if account else ()).fetchall()

    def transfer_rows(self, where="1=1", args=()):
        with contextlib.closing(self.server.db()) as c:
            return c.execute(f"SELECT id, from_id, to_id, amount FROM transfers WHERE {where}", args).fetchall()

    def moves(self, acct):
        with contextlib.closing(self.server.db()) as c:
            return c.execute("SELECT kind, amount FROM external_moves WHERE account_id = ?", (acct,)).fetchall()

    def check_key_table(self):
        """Every key row is a recorded 2xx whose movement exists (D2.5)."""
        if "idempotency_keys" not in self.server.tables():
            return
        with contextlib.closing(self.server.db()) as c:
            rows = c.execute("SELECT account_id, key, status, response FROM idempotency_keys").fetchall()
            tids = {r[0] for r in c.execute("SELECT id FROM transfers")}
            cols = {r[1] for r in c.execute("PRAGMA table_info(idempotency_keys)")}
            self.assertIn("scope", cols, "Q2-A: idempotency_keys has no scope column")
            dup = c.execute("SELECT account_id, scope, key, count(*) FROM idempotency_keys "
                            "GROUP BY account_id, scope, key HAVING count(*) > 1").fetchall()
            scopes = c.execute("SELECT scope, status, response FROM idempotency_keys").fetchall()
        self.assertEqual(dup, [], "I12: two key rows for one (account, scope, key)")
        for scope, status, response in scopes:
            self.assertIn(scope, ("debit", "deposit"))
            if status == 201:
                self.assertEqual(scope, "debit", "transfer recorded outside the debit namespace")
        for acct, key, status, response in rows:
            self.assertIn(status, (200, 201), f"D2.5: non-2xx recorded for {key!r}: {status}")
            body = json.loads(response)
            if status == 201:
                self.assertIn(body.get("id"), tids, f"key {key!r} replays a transfer that does not exist")
                self.assertEqual(body.get("from"), acct, "transfer key not scoped to `from`")

    def assertFresh(self, r, status):
        self.assertEqual(r.status, status, r)
        self.assertFalse(is_replay(r), f"first execution marked as replay: {r}")

    def assertReplayOf(self, r, original):
        self.assertEqual(r.status, original.status, r)
        self.assertTrue(is_replay(r), f"missing Idempotent-Replayed: true on {r} {r.headers}")
        self.assertEqual(r.raw, original.raw, "I13: replay body not byte-identical")

    def assertReplayFree(self, fn, original):
        before = self.server.snapshot()
        r = fn()
        self.assertReplayOf(r, original)
        self.assertEqual(self.server.snapshot(), before, "I13: replay changed the DB")
        return r

    def fire(self, fns, workers):
        barrier = threading.Barrier(min(workers, len(fns)))

        def run(fn):
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.wait(5)
            t0 = time.monotonic()
            r = fn()
            return r, time.monotonic() - t0

        with cf.ThreadPoolExecutor(workers) as ex:
            out = list(ex.map(run, fns))
        for r, dt in out:
            self.assertLess(dt, REQUEST_TIMEOUT, "I11: request exceeded 10s")
            self.assertTrue(r.status < 500 or (r.status, r.error) == BUSY, f"5xx / no response: {r}")
        return [r for r, _ in out]

    def raw_keyed(self, path, body, key_lines, token=None):
        data = json.dumps(body).encode()
        head = (b"POST " + path.encode() + b" HTTP/1.1" + CRLF + b"Host: x" + CRLF +
                b"Content-Type: application/json" + CRLF +
                b"Content-Length: " + str(len(data)).encode() + CRLF)
        if token:
            head += b"Authorization: Bearer " + token.encode() + CRLF
        for line in key_lines:
            head += line + CRLF
        return self.server.raw_http(head + CRLF + data)


class KeyFormat(IdemCase):
    def test_valid_keys_accepted_and_replayed(self):
        a = self.funded(1000, "fmt-ok")
        visible = "".join(chr(c) for c in range(0x21, 0x7F))
        for key in ["x", "A" * 255, visible[:255], visible[94 - 40:], "a:b/c?d=e&f#g", "\"quoted\"", "%00", "\\n"]:
            first = self.d(a["id"], 1, key)
            self.assertFresh(first, 200)
            self.assertReplayFree(lambda: self.d(a["id"], 1, key), first)

    def test_invalid_keys_are_400_and_free(self):
        a = self.funded(1000, "fmt-bad")
        b = self.funded(0, "fmt-bad-b")
        bad = ["", "   ", "\t", "A" * 256, "a b", "a\tb", "\x7f", "café"]
        for key in bad:
            for call in (lambda: self.d(a["id"], 1, key),
                         lambda: self.w(a["id"], 1, a["token"], key),
                         lambda: self.t(a["id"], b["id"], 1, a["token"], key)):
                self.assertRejectedFree(call, 400, "invalid_request")

    def test_raw_byte_keys_are_400_and_free(self):
        a = self.funded(1000, "fmt-raw")
        path = f"/accounts/{a['id']}/deposit"
        cases = [[b"Idempotency-Key: a\x01b"], [b"Idempotency-Key: \xc3\xa9t\xc3\xa9"],
                 [b"Idempotency-Key: a\x00b"], [b"Idempotency-Key: k1", b"Idempotency-Key: k1"],
                 [b"Idempotency-Key: k1", b"idempotency-key: k2"], [b"Idempotency-Key:"],
                 [b"Idempotency-Key: abc", b" def"]]  # obs-fold continuation
        for lines in cases:
            before = self.server.snapshot()
            status, data = self.raw_keyed(path, {"amount": 1}, lines)
            self.assertEqual(status, 400, (lines, data[:200]))
            self.assertIn(b'"invalid_request"', data, lines)
            self.assertEqual(self.server.snapshot(), before, f"I6: {lines}")

    def test_ows_trimmed_case_sensitive_name_insensitive(self):
        a = self.funded(1000, "fmt-ows")
        first = self.d(a["id"], 5, "ows-key")
        self.assertFresh(first, 200)
        status, data = self.raw_keyed(f"/accounts/{a['id']}/deposit", {"amount": 5},
                                      [b"Idempotency-Key: \t ows-key \t"])
        self.assertEqual(status, 200, data)
        self.assertIn(b"idempotent-replayed: true", data.lower(), "OWS-trimmed key not treated as same key")
        status, data = self.raw_keyed(f"/accounts/{a['id']}/deposit", {"amount": 5},
                                      [b"idempotency-KEY: ows-key"])
        self.assertIn(b"idempotent-replayed: true", data.lower(), "header name must be case-insensitive")
        upper = self.d(a["id"], 5, "OWS-KEY")
        self.assertFresh(upper, 200)  # value is case-sensitive: a different key
        self.assertEqual(self.server.balance(a["id"]), 1010)

    def test_bad_key_is_a_shape_400_before_404_and_401(self):
        a = self.funded(10, "fmt-order")
        ghost = str(uuid.uuid4())
        self.assertRejectedFree(lambda: self.d(ghost, 1, "a b"), 400, "invalid_request")
        self.assertRejectedFree(lambda: self.w(a["id"], 1, "wrong-token", "a b"), 400, "invalid_request")
        self.assertRejectedFree(lambda: self.t(a["id"], ghost, 1, "wrong-token", "x" * 256), 400, "invalid_request")


class AtMostOnce(IdemCase):
    def test_sequential_repeats_move_once(self):
        a, b = self.funded(1000, "seq-a"), self.funded(0, "seq-b")
        key = self.k()
        first = self.t(a["id"], b["id"], 100, a["token"], key)
        self.assertFresh(first, 201)
        for _ in range(5):
            self.assertReplayFree(lambda: self.t(a["id"], b["id"], 100, a["token"], key), first)
        self.assertEqual((self.server.balance(a["id"]), self.server.balance(b["id"])), (900, 100))
        self.assertEqual(len(self.transfer_rows("from_id = ?", (a["id"],))), 1)

    def _parallel(self, make_call, n, check_once):
        rs = self.fire([make_call] * n, workers=n)
        ok = [r for r in rs if r.status in (200, 201)]
        busy = self.busy_count(rs)
        for r in rs:
            self.assertIn((r.status, r.error) if r.status >= 400 else (r.status, None),
                          [(200, None), (201, None), BUSY], r)
        self.assertEqual(len({r.raw for r in ok}), min(1, len(ok)), "I12: 2xx bodies differ")
        fresh = [r for r in ok if not is_replay(r)]
        self.assertLessEqual(len(fresh), 1, f"I12: {len(fresh)} fresh executions for one key")
        if busy == 0:
            self.assertEqual(len(fresh), 1)
        check_once(len(fresh) if ok else 0, ok)

    def test_100_parallel_identical_keyed_transfers(self):
        for round_ in range(3):
            a, b = self.funded(10_000, f"pt-a{round_}"), self.funded(0, f"pt-b{round_}")
            key = self.k()

            def once(_, ok):
                rows = self.transfer_rows("from_id = ?", (a["id"],))
                self.assertEqual(len(rows), 1 if ok else 0, "I12: ledger rows for one key")
                moved = 300 * len(rows)
                self.assertEqual((self.server.balance(a["id"]), self.server.balance(b["id"])),
                                 (10_000 - moved, moved))
                if ok:
                    self.assertEqual(ok[0].json["id"], rows[0][0])

            self._parallel(lambda: self.t(a["id"], b["id"], 300, a["token"], key), 100, once)

    def test_100_parallel_identical_keyed_withdrawals(self):
        a = self.funded(10_000, "pw")
        key = self.k()

        def once(_, ok):
            n = len([m for m in self.moves(a["id"]) if m[0] == "withdrawal"])
            self.assertEqual(n, 1 if ok else 0)
            self.assertEqual(self.server.balance(a["id"]), 10_000 - 700 * n)

        self._parallel(lambda: self.w(a["id"], 700, a["token"], key), 100, once)

    def test_100_parallel_identical_keyed_deposits(self):
        a = self.funded(0, "pd")
        key = self.k()

        def once(_, ok):
            n = len([m for m in self.moves(a["id"]) if m[0] == "deposit"])
            self.assertEqual(n, 1 if ok else 0)
            self.assertEqual(self.server.balance(a["id"]), 900 * n)

        self._parallel(lambda: self.d(a["id"], 900, key), 100, once)

    def test_same_key_raced_with_different_amounts(self):
        a, b = self.funded(100_000, "ra-a"), self.funded(0, "ra-b")
        key = self.k()
        amounts = list(range(1, 61))
        barrier = threading.Barrier(60)

        def go(n):
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.wait(5)
            return n, self.t(a["id"], b["id"], n, a["token"], key)

        with cf.ThreadPoolExecutor(60) as ex:
            out = list(ex.map(go, amounts))
        rows = self.transfer_rows("from_id = ?", (a["id"],))
        self.assertLessEqual(len(rows), 1, "I12/I14: two amounts committed under one key")
        winner = rows[0][3] if rows else None
        for n, r in out:
            if r.status == 201:
                self.assertEqual(n, winner, f"201 for amount {n} but the committed amount is {winner}")
            else:
                self.assertIn((r.status, r.error), [(422, "idempotency_key_reused"), BUSY], (n, r))
        self.assertEqual(self.server.balance(a["id"]), 100_000 - (winner or 0))


class FaithfulReplay(IdemCase):
    def test_replay_after_balance_moved_and_after_drain(self):
        a, b = self.funded(500, "rb-a"), self.funded(0, "rb-b")
        kd, kt, kw = self.k(), self.k(), self.k()
        dep = self.d(a["id"], 100, kd)               # balance 600 in the body
        self.assertFresh(dep, 200)
        tr = self.t(a["id"], b["id"], 250, a["token"], kt)
        self.assertFresh(tr, 201)
        wd = self.w(a["id"], 50, a["token"], kw)     # balance 300
        self.assertFresh(wd, 200)
        self.assertEqual(self.w(a["id"], 300, a["token"], None).status, 200)  # drain to 0, keyless
        self.assertReplayFree(lambda: self.d(a["id"], 100, kd), dep)
        self.assertEqual(json.loads(dep.raw)["balance"], 600)
        # lookup precedes money rules: a drained `from` still replays, never 409
        self.assertReplayFree(lambda: self.t(a["id"], b["id"], 250, a["token"], kt), tr)
        self.assertReplayFree(lambda: self.w(a["id"], 50, a["token"], kw), wd)

    def test_replay_survives_restart(self):
        a, b = self.funded(500, "rr-a"), self.funded(0, "rr-b")
        key = self.k()
        tr = self.t(a["id"], b["id"], 77, a["token"], key)
        self.assertFresh(tr, 201)
        self.server.restart()
        self.assertReplayFree(lambda: self.t(a["id"], b["id"], 77, a["token"], key), tr)
        self.assertEqual(self.server.balance(a["id"]), 423)

    def test_replay_needs_the_owner_token(self):
        a, b, c = self.funded(500, "rt-a"), self.funded(0, "rt-b"), self.funded(0, "rt-c")
        key = self.k()
        tr = self.t(a["id"], b["id"], 10, a["token"], key)
        self.assertFresh(tr, 201)
        for tok in ("wrong", b["token"], c["token"]):
            r = self.assertRejectedFree(lambda: self.t(a["id"], b["id"], 10, tok, key), 401, "unauthorized")
            self.assertNotIn(tr.json["id"].encode(), r.raw, "401 leaked the replay body")
            self.assertFalse(is_replay(r))
        no_auth = self.server.request("POST", "/transfers", {"from": a["id"], "to": b["id"], "amount": 10},
                                      headers={KEY: key})
        self.assertEqual(no_auth.status, 401, no_auth)

    def test_replay_ignores_json_spelling_and_auth_ows(self):
        a, b = self.funded(500, "rs-a"), self.funded(0, "rs-b")
        key = self.k()
        tr = self.t(a["id"], b["id"], 42, a["token"], key)
        self.assertFresh(tr, 201)
        raw = ('{ "amount" : 42 ,\n "to":"%s",   "from" : "%s" }' % (b["id"], a["id"])).encode()
        self.assertReplayFree(lambda: self.server.request(
            "POST", "/transfers", raw=raw,
            headers={"Authorization": f"  Bearer {a['token']}\t", KEY: key}), tr)

    def test_first_response_has_no_replay_header(self):
        a = self.funded(0, "nh")
        r = self.d(a["id"], 3, self.k())
        self.assertFresh(r, 200)
        keyless = self.d(a["id"], 3, None)
        self.assertFresh(keyless, 200)


class Mismatch(IdemCase):
    def test_matrix(self):
        a, b, c = self.funded(10_000, "mm-a"), self.funded(0, "mm-b"), self.funded(0, "mm-c")
        key = self.k()
        base = self.t(a["id"], b["id"], 10, a["token"], key)
        self.assertFresh(base, 201)
        for label, call in [
            ("other to", lambda: self.t(a["id"], c["id"], 10, a["token"], key)),
            ("other amount", lambda: self.t(a["id"], b["id"], 11, a["token"], key)),
            ("withdraw same account", lambda: self.w(a["id"], 10, a["token"], key)),
        ]:
            with self.subTest(label):
                self.assertRejectedFree(call, 422, "idempotency_key_reused")
        # the base still replays after the mismatches
        self.assertReplayFree(lambda: self.t(a["id"], b["id"], 10, a["token"], key), base)

    def test_scope_is_per_account(self):
        a, b = self.funded(1000, "sc-a"), self.funded(1000, "sc-b")
        key = "shared-key"
        r1 = self.t(a["id"], b["id"], 10, a["token"], key)
        r2 = self.t(b["id"], a["id"], 10, b["token"], key)   # scope = b now: independent
        self.assertFresh(r1, 201)
        self.assertFresh(r2, 201)
        r3 = self.d(b["id"], 5, "dep-shared")
        r4 = self.d(a["id"], 5, "dep-shared")
        self.assertFresh(r3, 200)
        self.assertFresh(r4, 200)

    def test_transfer_key_does_not_scope_the_recipient(self):
        a, b = self.funded(1000, "tr-a"), self.funded(0, "tr-b")
        key = self.k()
        self.assertFresh(self.t(a["id"], b["id"], 10, a["token"], key), 201)
        self.assertFresh(self.d(b["id"], 10, key), 200)       # b's own namespace
        self.assertFresh(self.w(b["id"], 5, b["token"], key), 200)  # b's debit namespace
        self.assertEqual(self.server.balance(b["id"]), 15)

    def test_deposit_and_withdraw_mismatch_matrix(self):
        a = self.funded(1000, "dw-mm")
        kd, kw = self.k(), self.k()
        dep = self.d(a["id"], 10, kd)
        self.assertFresh(dep, 200)
        self.assertRejectedFree(lambda: self.d(a["id"], 11, kd), 422, "idempotency_key_reused")
        wd = self.w(a["id"], 10, a["token"], kw)
        self.assertFresh(wd, 200)
        self.assertRejectedFree(lambda: self.w(a["id"], 11, a["token"], kw), 422, "idempotency_key_reused")
        b = self.funded(0, "dw-mm-b")
        self.assertRejectedFree(lambda: self.t(a["id"], b["id"], 10, a["token"], kw), 422,
                                "idempotency_key_reused")  # withdraw key reused for a transfer


class Namespaces(IdemCase):
    """Q2-A ruling: a deposit key (anyone can send one) never blocks, replays or mismatches a debit key."""

    def test_deposit_squat_cannot_block_a_debit_key(self):
        v, b = self.funded(1000, "sq-v"), self.funded(0, "sq-b")
        key = "order-42"
        squat = self.d(v["id"], 1, key)                  # attacker, no token
        self.assertFresh(squat, 200)
        tr = self.t(v["id"], b["id"], 100, v["token"], key)
        self.assertFresh(tr, 201)                        # evaluated normally: never 422, never a replay
        self.assertReplayFree(lambda: self.t(v["id"], b["id"], 100, v["token"], key), tr)
        k2 = "order-43"
        self.assertFresh(self.d(v["id"], 1, k2), 200)
        self.assertFresh(self.w(v["id"], 5, v["token"], k2), 200)
        self.assertEqual(self.server.balance(v["id"]), 1000 + 1 - 100 + 1 - 5)

    def test_debit_key_does_not_touch_deposits(self):
        v, b = self.funded(1000, "sq2-v"), self.funded(0, "sq2-b")
        key = self.k()
        self.assertFresh(self.t(v["id"], b["id"], 100, v["token"], key), 201)
        dep = self.d(v["id"], 7, key)
        self.assertFresh(dep, 200)
        self.assertReplayFree(lambda: self.d(v["id"], 7, key), dep)
        self.assertRejectedFree(lambda: self.d(v["id"], 8, key), 422, "idempotency_key_reused")
        with contextlib.closing(self.server.db()) as c:
            got = sorted(r[0] for r in c.execute(
                "SELECT scope FROM idempotency_keys WHERE account_id = ? AND key = ?", (v["id"], key)))
        self.assertEqual(got, ["debit", "deposit"])


class RejectionsConsumeNothing(IdemCase):
    def test_409_then_fund_then_retry(self):
        a, b = self.funded(50, "rf-a"), self.funded(0, "rf-b")
        key = self.k()
        self.assertRejectedFree(lambda: self.t(a["id"], b["id"], 80, a["token"], key), 409, "insufficient_funds")
        self.assertEqual(self.key_rows(a["id"]), [], "D2.5: 409 recorded a key row")
        self.assertEqual(self.d(a["id"], 30, None).status, 200)
        ok = self.t(a["id"], b["id"], 80, a["token"], key)
        self.assertFresh(ok, 201)
        self.assertReplayFree(lambda: self.t(a["id"], b["id"], 80, a["token"], key), ok)
        self.assertEqual(self.server.balance(b["id"]), 80)

    def test_every_rejection_leaves_no_key_row(self):
        a, b = self.funded(10, "rj-a"), self.funded(0, "rj-b")
        cap = self.funded(0, "rj-cap")
        for _ in range(MAX_BALANCE // MAX_AMOUNT):
            self.assertEqual(self.server.deposit(cap["id"], MAX_AMOUNT).status, 200)
        ghost = str(uuid.uuid4())
        key = self.k()
        cases = [
            (lambda: self.t(a["id"], b["id"], 0, a["token"], key), 400),
            (lambda: self.t(a["id"], a["id"], 1, a["token"], key), 400),
            (lambda: self.t(a["id"], ghost, 1, a["token"], key), 404),
            (lambda: self.t(a["id"], b["id"], 1, "nope", key), 401),
            (lambda: self.t(a["id"], b["id"], 11, a["token"], key), 409),
            (lambda: self.t(a["id"], cap["id"], 1, a["token"], key), 422),
            (lambda: self.w(a["id"], 11, a["token"], key), 409),
            (lambda: self.w(a["id"], 1, b["token"], key), 401),
            (lambda: self.d(cap["id"], 1, key), 422),
            (lambda: self.d(ghost, 1, key), 404),
        ]
        for call, status in cases:
            self.assertRejectedFree(call, status)
        self.assertEqual(self.key_rows(a["id"]) + self.key_rows(cap["id"]), [])
        # the same key is still fresh for a fitting request on each scope
        self.assertFresh(self.t(a["id"], b["id"], 10, a["token"], key), 201)
        self.assertFresh(self.w(cap["id"], 1, cap["token"], key), 200)

    def test_503_records_nothing_then_retry_commits(self):
        a, b = self.funded(500, "lk-a"), self.funded(0, "lk-b")
        key = self.k()
        got, done = threading.Event(), threading.Event()

        def holder():
            c = sqlite3.connect(self.server.db_path, timeout=0, isolation_level=None)
            try:
                c.execute("BEGIN IMMEDIATE")
                got.set()
                done.wait(15)
                c.execute("ROLLBACK")
            finally:
                c.close()

        th = threading.Thread(target=holder)
        th.start()
        try:
            self.assertTrue(got.wait(5))
            before = self.server.snapshot()
            r = self.t(a["id"], b["id"], 5, a["token"], key)
            self.assertEqual((r.status, r.error), BUSY, r)
        finally:
            done.set()
            th.join()
        self.assertEqual(self.server.snapshot(), before, "I6: keyed 503 left an effect")
        self.assertFresh(self.t(a["id"], b["id"], 5, a["token"], key), 201)


class TimeoutAndRetry(IdemCase):
    def send_and_drop(self, path, body, headers):
        data = json.dumps(body).encode()
        head = b"POST " + path.encode() + b" HTTP/1.1" + CRLF + b"Host: x" + CRLF
        for k_, v in headers.items():
            head += f"{k_}: {v}".encode() + CRLF
        head += b"Content-Length: " + str(len(data)).encode() + CRLF + CRLF
        s = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
        try:
            s.sendall(head + data)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        finally:
            s.close()

    def test_disconnect_then_retry_moves_once(self):
        a, b = self.funded(100_000, "dr-a"), self.funded(0, "dr-b")
        keys = [self.k() for _ in range(40)]
        with cf.ThreadPoolExecutor(20) as ex:
            list(ex.map(lambda kk: self.send_and_drop(
                "/transfers", {"from": a["id"], "to": b["id"], "amount": 10},
                {"Authorization": f"Bearer {a['token']}", KEY: kk}), keys))
        ids = []
        for kk in keys:
            for _ in range(10):
                r = self.t(a["id"], b["id"], 10, a["token"], kk)
                if r.status != 503:
                    break
            self.assertEqual(r.status, 201, r)
            ids.append(r.json["id"])
        rows = self.transfer_rows("from_id = ?", (a["id"],))
        self.assertEqual(len(rows), len(keys), "I16: movements != keys after disconnect + retry")
        self.assertEqual(sorted(ids), sorted(r[0] for r in rows))
        self.assertEqual(self.server.balance(b["id"]), 10 * len(keys))

    def test_sigkill_mid_keyed_burst_then_retry_every_key(self):
        accts = [self.funded(MAX_AMOUNT, f"kk-{n}") for n in range(6)]
        lock = threading.Lock()
        sent = {}          # key -> (src, dst, amount, token)
        stop = threading.Event()

        def worker(seed):
            rnd = random.Random(seed)
            while not stop.is_set():
                s, d = rnd.sample(accts, 2)
                kk = self.k()
                amt = rnd.randint(1, 1000)
                with lock:
                    sent[kk] = (s["id"], d["id"], amt, s["token"])
                r = self.t(s["id"], d["id"], amt, s["token"], kk, timeout=5)
                if r.status == NO_RESPONSE:
                    return

        with cf.ThreadPoolExecutor(16) as ex:
            for n in range(16):
                ex.submit(worker, n)
            time.sleep(1.5)
            self.server.kill()
            stop.set()
        self.server.start()
        self.assertGreater(len(sent), 20)
        ids = {}
        for kk, (s, d, amt, tok) in sent.items():
            for _ in range(10):
                r = self.t(s, d, amt, tok, kk)
                if r.status != 503:
                    break
            self.assertEqual(r.status, 201, (kk, r))
            ids[kk] = r.json["id"]
            r2 = self.t(s, d, amt, tok, kk)
            self.assertTrue(is_replay(r2) and r2.raw == r.raw, f"I13 after restart: {kk} {r2}")
        mine = [x["id"] for x in accts]
        rows = {r[0]: r[1:] for r in self.transfer_rows(
            f"from_id IN ({','.join('?' * len(mine))})", tuple(mine))}
        self.assertEqual(len(set(ids.values())), len(sent), "I12: two keys share one movement id")
        self.assertEqual(set(ids.values()), set(rows), "I12/I16: movements != one per key")
        for kk, tid in ids.items():
            s, d, amt, _ = sent[kk]
            self.assertEqual(rows[tid], (s, d, amt))
        self.assertEqual(sum(self.server.balance(x["id"]) for x in accts), 6 * MAX_AMOUNT)


class KeylessUnchanged(IdemCase):
    def test_keyless_repeats_still_move_each_time(self):
        a, b = self.funded(100, "kl-a"), self.funded(0, "kl-b")
        for _ in range(3):
            r = self.t(a["id"], b["id"], 10, a["token"], None)
            self.assertFresh(r, 201)
        self.assertEqual(self.server.balance(b["id"]), 30)
        self.assertEqual(self.key_rows(a["id"]), [], "keyless request wrote a key row")


class DebitNamespaceRace(IdemCase):
    def test_withdraw_and_transfer_race_on_one_debit_key(self):
        for round_ in range(10):
            a, b = self.funded(1000, f"wt-a{round_}"), self.funded(0, f"wt-b{round_}")
            key = self.k()
            calls = ([lambda: ("w", self.w(a["id"], 10, a["token"], key))] * 20 +
                     [lambda: ("t", self.t(a["id"], b["id"], 10, a["token"], key))] * 20)
            random.shuffle(calls)
            barrier = threading.Barrier(40)

            def go(fn):
                with contextlib.suppress(threading.BrokenBarrierError):
                    barrier.wait(5)
                return fn()

            with cf.ThreadPoolExecutor(40) as ex:
                out = list(ex.map(go, calls))
            wins = {k_ for k_, r in out if r.status in (200, 201)}
            self.assertLessEqual(len(wins), 1, f"I12: both endpoints committed under one debit key: {wins}")
            moved = len(self.transfer_rows("from_id = ?", (a["id"],))) + \
                len([m for m in self.moves(a["id"]) if m[0] == "withdrawal"])
            self.assertLessEqual(moved, 1)
            self.assertEqual(self.server.balance(a["id"]), 1000 - 10 * moved)
            for k_, r in out:
                if k_ not in wins:
                    self.assertIn((r.status, r.error), [(422, "idempotency_key_reused"), BUSY], (k_, r))


class UpgradeFromStage1Db(IdemCase):
    def test_stage2_on_a_stage1_database(self):
        import os
        import breaker_harness as bh
        s1_dir = os.path.join(bh.STAGE_DIR, "..", "stage-1")
        if not os.path.isdir(os.path.join(s1_dir, "app")):
            self.skipTest("stage-1 folder not present")
        path = os.path.join(self._tmp.name, "from_stage1.db")
        old = bh.STAGE_DIR
        bh.STAGE_DIR = os.path.abspath(s1_dir)
        try:
            s1 = bh.Server(path).start()
            a, b = s1.create_account("up-a"), s1.create_account("up-b")
            self.assertEqual(s1.deposit(a["id"], 500).status, 200)
            self.assertEqual(s1.transfer(a["id"], b["id"], 100, a["token"]).status, 201)
            s1.kill()
        finally:
            bh.STAGE_DIR = old
        s2 = bh.Server(path).start()
        try:
            key = self.k()
            h = {"Authorization": f"Bearer {a['token']}", KEY: key}
            body = {"from": a["id"], "to": b["id"], "amount": 50}
            first = s2.request("POST", "/transfers", body, headers=h)
            self.assertFresh(first, 201)
            again = s2.request("POST", "/transfers", body, headers=h)
            self.assertReplayOf(again, first)
            self.assertEqual((s2.balance(a["id"]), s2.balance(b["id"])), (350, 150))
            audit = s2.request("GET", "/audit")
            self.assertIs(audit.json["conserved"], True, audit)
        finally:
            s2.kill()
