"""Unit 1.3 attacks: POST /transfers. Skips until the route exists.

Rules (Architect, 1.3): 400 (shape, from == to, amount, duplicate Authorization) -> 404 if EITHER
account is missing (before auth) -> 401 (token of `from` only) -> 409 insufficient_funds ->
422 balance_limit if the credit would push `to` past 10^15 (whole tx rolls back). One BEGIN
IMMEDIATE: conditional debit + capped credit + INSERT transfers; 201 {id, from, to, amount} with
id == transfers.id. /audit does not count transfers. Q5: Authorization is OWS-trimmed (SP/HTAB)
then matched exactly, on withdraw AND transfer.

a04/a05/a07 already cover: amount table, token matrix, 404-before-401, from == to, full-balance x100,
fractional drain x200, withdraw vs transfer race, A<->B random, deposit while draining, audit
under transfer load, kill mid-burst (acked ids survive), 30 s load. This file adds the rest.
CRLF is built from bytes so no editor can turn an escape into a real line break.
"""
import concurrent.futures as cf
import contextlib
import itertools
import random
import sqlite3
import threading
import time
import uuid

from breaker_harness import MAX_AMOUNT, MAX_BALANCE, NO_RESPONSE, REQUEST_TIMEOUT, AttackCase

CRLF = bytes([13, 10]).decode()
TAB = chr(9)
BUSY = (503, "busy")


class TransferCase(AttackCase):
    def setUp(self):
        self.need_route("POST", "/transfers", {})

    def rows(self, where="1=1", args=()):
        with contextlib.closing(self.server.db()) as c:
            return c.execute(f"SELECT id, from_id, to_id, amount FROM transfers WHERE {where}", args).fetchall()

    def fire(self, fns, workers=100):
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

    def raw_transfer(self, body, auth_lines):
        """auth_lines: list of raw Authorization values (lets us send 0, 1 or many)."""
        data = body if isinstance(body, bytes) else body.encode()
        head = "POST /transfers HTTP/1.1" + CRLF + "Host: x" + CRLF + f"Content-Length: {len(data)}" + CRLF
        for v in auth_lines:
            head += "Authorization: " + v + CRLF
        return self.server.raw_http((head + CRLF).encode() + data)


class TransferCheckOrder(TransferCase):
    def body(self, f, t, amount):
        return f'{{"from": "{f}", "to": "{t}", "amount": {amount}}}'

    def test_order_matrix(self):
        a = self.funded(10, "ord-a")
        b = self.funded(0, "ord-b")
        full = self.funded(0, "ord-full")
        for _ in range(MAX_BALANCE // MAX_AMOUNT):
            self.assertEqual(self.server.deposit(full["id"], MAX_AMOUNT).status, 200)
        ghost, ghost2 = str(uuid.uuid4()), str(uuid.uuid4())
        A, B, F = a["id"], b["id"], full["id"]
        ok, bad = "Bearer " + a["token"], "Bearer " + b["token"]
        cases = [
            # (body, auth headers, status, error)
            (self.body(ghost, ghost, 1), [], 400, "invalid_request"),          # from == to before 404
            (self.body(A, A, 1.5), [ok], 400, None),                           # two 400s; order not ruled
            (self.body(ghost, B, 0), [], 400, "invalid_amount"),               # amount before 404
            (self.body(A, B, 1), [ok, ok], 400, "invalid_request"),            # dup auth
            (self.body(ghost, B, 1), [ok, bad], 400, "invalid_request"),       # dup auth before 404
            ('{"from": "%s", "to": "%s"}' % (A, B), [ok], 400, "invalid_amount"),
            ('{"from": "%s", "to": "%s", "amount": 1, "x": 1}' % (A, B), [ok], 400, "invalid_request"),
            (self.body(ghost, B, 1), [], 404, "account_not_found"),
            (self.body(A, ghost, 1), [], 404, "account_not_found"),           # missing TO before 401
            (self.body(A, ghost, 1), [bad], 404, "account_not_found"),
            (self.body(ghost, ghost2, 1), [ok], 404, "account_not_found"),
            (self.body(A.upper(), B, 1), [ok], 404, "account_not_found"),     # non-canonical id
            (self.body(A, B, 11), [], 401, "unauthorized"),                    # 401 before 409
            (self.body(A, B, 11), [bad], 401, "unauthorized"),                 # token of `to` is not `from`
            (self.body(A, F, 11), [bad], 401, "unauthorized"),                 # 401 before 422
            (self.body(A, F, 11), [ok], 409, "insufficient_funds"),            # 409 before 422
            (self.body(A, F, 1), [ok], 422, "balance_limit"),                  # credit leg refused
            (self.body(A, B, 11), [ok], 409, "insufficient_funds"),
        ]
        for body, auth, status, error in cases:
            with self.subTest(body=body[-60:], auth=len(auth), want=status):
                before = self.server.snapshot()
                st, data = self.raw_transfer(body, auth)
                self.assertEqual(st, status, data[:250])
                if error:
                    self.assertIn(f'"{error}"'.encode(), data, data[:250])
                self.assertEqual(self.server.snapshot(), before, "I6/I2: rejected transfer changed the DB")
        self.assertEqual((self.server.balance(A), self.server.balance(B), self.server.balance(F)),
                         (10, 0, MAX_BALANCE))

    def test_ows_trimmed_then_exact(self):
        """Q5 ruling: leading/trailing SP/HTAB trimmed, then exact; interior stays exact."""
        a = self.funded(100, "ows-a")
        b = self.funded(0, "ows-b")
        t = a["token"]
        good = {"lead-sp": " Bearer " + t, "trail-sp": "Bearer " + t + " ", "both": "  Bearer " + t + "  ",
                "trail-tab": "Bearer " + t + TAB, "lead-tab": TAB + "Bearer " + t}
        bad = {"two-inner": "Bearer  " + t, "inner-tab": "Bearer" + TAB + t, "lower": "bearer " + t}
        n = 0
        for name, v in good.items():
            with self.subTest(v=name, op="transfer"):
                st, data = self.raw_transfer(
                    '{"from": "%s", "to": "%s", "amount": 1}' % (a["id"], b["id"]), [v])
                self.assertEqual(st, 201, data[:200])
                n += 1
            with self.subTest(v=name, op="withdraw"):
                r = self.server.request("POST", f"/accounts/{a['id']}/withdraw", {"amount": 1},
                                        headers={"Authorization": v.strip(" " + TAB)})  # http.client strips
                body = b'{"amount": 1}'
                st, data = self.server.raw_http(
                    (f"POST /accounts/{a['id']}/withdraw HTTP/1.1" + CRLF + "Host: x" + CRLF +
                     f"Content-Length: {len(body)}" + CRLF + "Authorization: " + v + CRLF + CRLF).encode() + body)
                self.assertEqual(r.status, 200, r)
                self.assertEqual(st, 200, data[:200])
                n += 2
        for name, v in bad.items():
            with self.subTest(v=name):
                before = self.server.snapshot()
                st, data = self.raw_transfer('{"from": "%s", "to": "%s", "amount": 1}' % (a["id"], b["id"]), [v])
                self.assertEqual(st, 401, data[:200])
                self.assertEqual(self.server.snapshot(), before)
        self.assertEqual(self.server.balance(a["id"]), 100 - n)


class TransferShapeAndLedger(TransferCase):
    def test_201_shape_and_row(self):
        a, b = self.funded(500, "shape-a"), self.funded(0, "shape-b")
        r = self.server.transfer(a["id"], b["id"], 123, a["token"])
        self.assertEqual(r.status, 201, r)
        self.assertEqual(set(r.json), {"id", "from", "to", "amount"})
        self.assertEqual((r.json["from"], r.json["to"], r.json["amount"]), (a["id"], b["id"], 123))
        self.assertNotIn(a["token"].encode(), r.raw)
        self.assertEqual(self.rows("id = ?", (r.json["id"],)), [(r.json["id"], a["id"], b["id"], 123)])
        self.assertEqual((self.server.balance(a["id"]), self.server.balance(b["id"])), (377, 123))

    def test_audit_ignores_transfers(self):
        self.need_route("GET", "/audit")
        before = self.server.request("GET", "/audit").json
        a, b = self.funded(1000, "aud-a"), self.funded(0, "aud-b")
        mid = self.server.request("GET", "/audit").json
        for _ in range(5):
            self.assertEqual(self.server.transfer(a["id"], b["id"], 100, a["token"]).status, 201)
        after = self.server.request("GET", "/audit").json
        self.assertEqual(mid["total_deposits"], before["total_deposits"] + 1000)
        self.assertEqual(after, mid, "transfers moved the audit totals")

    def test_exact_balance_and_full_cap_boundaries(self):
        a, b = self.funded(300, "bnd-a"), self.funded(0, "bnd-b")
        self.assertRejectedFree(lambda: self.server.transfer(a["id"], b["id"], 301, a["token"]),
                                409, "insufficient_funds")
        self.assertEqual(self.server.transfer(a["id"], b["id"], 300, a["token"]).status, 201)
        self.assertRejectedFree(lambda: self.server.transfer(a["id"], b["id"], 1, a["token"]),
                                409, "insufficient_funds")
        # credit exactly to the cap succeeds; one more is 422 with the source untouched
        cap = self.funded(0, "cap")
        for _ in range(MAX_BALANCE // MAX_AMOUNT - 1):
            self.assertEqual(self.server.deposit(cap["id"], MAX_AMOUNT).status, 200)
        src = self.funded(MAX_AMOUNT, "cap-src")
        other = self.funded(5, "cap-other")
        self.assertEqual(self.server.transfer(src["id"], cap["id"], MAX_AMOUNT - 1, src["token"]).status, 201)
        self.assertEqual(self.server.balance(cap["id"]), MAX_BALANCE - 1)
        self.assertRejectedFree(lambda: self.server.transfer(other["id"], cap["id"], 2, other["token"]),
                                422, "balance_limit")
        self.assertEqual(self.server.transfer(src["id"], cap["id"], 1, src["token"]).status, 201)
        self.assertEqual(self.server.balance(cap["id"]), MAX_BALANCE)
        self.assertRejectedFree(lambda: self.server.transfer(other["id"], cap["id"], 1, other["token"]),
                                422, "balance_limit")
        self.assertEqual((self.server.balance(src["id"]), self.server.balance(other["id"])), (0, 5))


class TransferConcurrency(TransferCase):
    def test_identical_pair_in_parallel(self):
        for round_ in range(30):
            a, b = self.funded(100, f"pair-a{round_}"), self.funded(0, f"pair-b{round_}")
            rs = self.fire([lambda: self.server.transfer(a["id"], b["id"], 100, a["token"])] * 2, workers=2)
            ok = sum(r.status == 201 for r in rs)
            self.assertCommitCount(ok, self.busy_count(rs), 1, f"I4 round {round_}: {rs}")
            self.assertEqual((self.server.balance(a["id"]), self.server.balance(b["id"])), (100 - 100 * ok, 100 * ok))
            self.assertEqual(len(self.rows("from_id = ?", (a["id"],))), ok)

    def test_swap_full_balances_at_once(self):
        # A->B(all of A) and B->A(all of B) at the same instant: both have the funds, both must commit
        for round_ in range(20):
            a, b = self.funded(70, f"sw-a{round_}"), self.funded(30, f"sw-b{round_}")
            rs = self.fire([lambda: self.server.transfer(a["id"], b["id"], 70, a["token"]),
                            lambda: self.server.transfer(b["id"], a["id"], 30, b["token"])], workers=2)
            # both have the funds: each must commit, unless it got 503 busy (no effect)
            for r in rs:
                self.assertIn((r.status, r.error), [(201, None), BUSY], r)
            ab, ba = (70 if rs[0].status == 201 else 0), (30 if rs[1].status == 201 else 0)
            self.assertEqual((self.server.balance(a["id"]), self.server.balance(b["id"])),
                             (70 - ab + ba, 30 - ba + ab))

    def test_cycle_a_b_c(self):
        accts = [self.funded(1000, f"cyc-{k}") for k in range(3)]
        fns = []
        for i in range(300):
            s, d = accts[i % 3], accts[(i + 1) % 3]
            fns.append(lambda s=s, d=d: self.server.transfer(s["id"], d["id"], random.randint(1, 40), s["token"]))
        self.fire(fns, workers=60)
        self.assertEqual(sum(self.server.balance(x["id"]) for x in accts), 3000, "I1/I2 across a cycle")

    def test_many_to_many_rows_match_201s(self):
        accts = [self.funded(20_000, f"mm-{k}") for k in range(8)]
        counter = itertools.count(1)
        fns, meta = [], []
        for _ in range(400):
            s, d = random.sample(accts, 2)
            n = next(counter)
            fns.append(lambda s=s, d=d, n=n: self.server.transfer(s["id"], d["id"], n, s["token"]))
            meta.append((s["id"], d["id"], n))
        rs = self.fire(fns, workers=100)
        acked = {r.json["id"]: m for r, m in zip(rs, meta) if r.status == 201}
        refused = {m for r, m in zip(rs, meta) if r.status in (409, 503)}
        have = {row[0]: tuple(row[1:]) for row in self.rows()}
        for tid, m in acked.items():
            self.assertEqual(have.get(tid), m, "I4: 201 without its exact ledger row")
        self.assertFalse(refused & set(have.values()), "I6: a refused transfer left a row")
        self.assertEqual(sum(self.server.balance(x["id"]) for x in accts), 8 * 20_000)

    def test_many_sources_into_nearly_full_account(self):
        """I2 under contention: credits refused at the cap must roll their debits back."""
        cap = self.funded(0, "nf-cap")
        for _ in range(MAX_BALANCE // MAX_AMOUNT - 3):
            self.assertEqual(self.server.deposit(cap["id"], MAX_AMOUNT).status, 200)
        srcs = [self.funded(MAX_AMOUNT, f"nf-{k}") for k in range(40)]
        rs = self.fire([(lambda s=s: self.server.transfer(s["id"], cap["id"], MAX_AMOUNT, s["token"]))
                        for s in srcs], workers=40)
        ok = [s for s, r in zip(srcs, rs) if r.status == 201]
        self.assertCommitCount(len(ok), self.busy_count(rs), 3, f"statuses {sorted({r.status for r in rs})}")
        for s, r in zip(srcs, rs):
            want = 0 if r.status == 201 else MAX_AMOUNT
            self.assertEqual(self.server.balance(s["id"]), want, f"I2: source after {r.status}")
            if r.status != 201:
                self.assertIn((r.status, r.error), [(422, "balance_limit"), BUSY], r)
        self.assertEqual(self.server.balance(cap["id"]), MAX_BALANCE - (3 - len(ok)) * MAX_AMOUNT)

    def test_transfer_racing_deposit_into_destination(self):
        src, dst = self.funded(5000, "rd-src"), self.funded(0, "rd-dst")
        fns = []
        for i in range(200):
            if i % 2:
                fns.append(lambda: ("t", self.server.transfer(src["id"], dst["id"], 50, src["token"])))
            else:
                fns.append(lambda: ("d", self.server.deposit(dst["id"], 7)))
        with cf.ThreadPoolExecutor(100) as ex:
            out = list(ex.map(lambda f: f(), fns))
        moved = sum(50 for k, r in out if k == "t" and r.status == 201)
        dep = sum(7 for k, r in out if k == "d" and r.status == 200)
        self.assertEqual((self.server.balance(src["id"]), self.server.balance(dst["id"])),
                         (5000 - moved, moved + dep))


class TransferLockTimeout(TransferCase):
    def test_503_no_effect(self):
        a, b = self.funded(500, "lk-a"), self.funded(0, "lk-b")
        before = self.server.snapshot()
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
            t0 = time.monotonic()
            r = self.server.transfer(a["id"], b["id"], 5, a["token"])
            self.assertEqual((r.status, r.error), BUSY, r)
            self.assertLess(time.monotonic() - t0, REQUEST_TIMEOUT)
        finally:
            done.set()
            th.join()
        self.assertEqual(self.server.snapshot(), before, "I6: 503 transfer left an effect")


class KillMidTransferBurst(TransferCase):
    def test_kill_refused_absent_acked_present(self):
        """Complements a07: also checks that no refused transfer exists after restart, and that
        the 201 body's from/to/amount match the surviving row."""
        accts = [self.funded(50_000, f"kt-{k}") for k in range(6)]
        counter = itertools.count(1)
        acked, refused, stop = {}, [], threading.Event()

        def worker():
            while not stop.is_set():
                s, d = random.sample(accts, 2)
                n = next(counter)
                r = self.server.transfer(s["id"], d["id"], n, s["token"], timeout=5)
                if r.status == 201:
                    acked[r.json["id"]] = (s["id"], d["id"], n)
                elif 400 <= r.status < 500:
                    refused.append((s["id"], d["id"], n))
                elif r.status == NO_RESPONSE:
                    return

        with cf.ThreadPoolExecutor(16) as ex:
            for _ in range(16):
                ex.submit(worker)
            time.sleep(1.5)
            self.server.kill()
            stop.set()
        self.server.start()
        self.assertGreater(len(acked), 0)
        have = {row[0]: tuple(row[1:]) for row in self.rows()}
        self.assertEqual([t for t, m in acked.items() if have.get(t) != m][:5], [], "I10: acked transfer lost")
        self.assertEqual([m for m in refused if m in set(have.values())][:5], [], "I6: refused transfer present")
        self.assertEqual(sum(self.server.balance(x["id"]) for x in accts), 6 * 50_000, "I1/I2 across kill")
