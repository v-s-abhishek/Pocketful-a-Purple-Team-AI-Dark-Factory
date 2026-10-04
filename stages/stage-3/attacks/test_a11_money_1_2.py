"""Unit 1.2 attacks: deposit / withdraw / audit, without transfers.

a07's double-spend, audit-under-load, kill and sustained-load attacks need POST /transfers and
therefore skip until 1.3. These are their deposit/withdraw-only counterparts, plus 1.2 rules:
check order on withdraw (400 body -> 404 -> 401 -> 409), lock timeout -> 503 busy with no
effect, GET /audit from one snapshot, and "every 2xx == exactly one ledger row".

Where it matters, amounts are unique per request so each response can be matched to its
ledger row: every 2xx amount must be in external_moves, every 4xx amount must not (I6).
"""
import concurrent.futures as cf
import contextlib
import itertools
import os
import random
import sqlite3
import threading
import time
import unittest
import uuid

from breaker_harness import MAX_AMOUNT, NO_RESPONSE, REQUEST_TIMEOUT, SLOW, AttackCase

BUSY = (503, "busy")


class MoneyCase(AttackCase):
    def setUp(self):
        self.need_route("POST", f"/accounts/{uuid.uuid4()}/deposit", {"amount": 1})
        self.need_route("POST", f"/accounts/{uuid.uuid4()}/withdraw", {"amount": 1})

    # -- helpers -------------------------------------------------------------
    def moves(self, acct_id, kind):
        """Amounts of external_moves rows for one account and kind, as a sorted list."""
        with contextlib.closing(self.server.db()) as c:
            return sorted(r[0] for r in c.execute(
                "SELECT amount FROM external_moves WHERE account_id = ? AND kind = ?", (acct_id, kind)))

    def fire(self, fns, workers=100):
        """Run all fns as close to simultaneously as possible. Returns responses in order.
        Fails on any hang (I11) or any 5xx other than 503 busy."""
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


class WithdrawCheckOrder(MoneyCase):
    """PLAN 1.2: 400 body -> 404 -> 401 -> 409. 409 before 401 would let anyone probe balances."""

    def test_withdraw_order_matrix(self):
        a = self.funded(10, "order-a")
        b = self.funded(10, "order-b")
        ghost = str(uuid.uuid4())
        bad = b'{"amount": 1.5}'
        good = b'{"amount": 1}'
        over = b'{"amount": 11}'
        tok_a, tok_b = self.server.auth(a["token"]), self.server.auth(b["token"])
        cases = [
            # (account, body, headers, status, error)
            (ghost, bad, {}, 400, "invalid_amount"),
            (ghost, b"{", {}, 400, "invalid_json"),
            ("not-a-uuid", bad, {}, 400, "invalid_amount"),
            (ghost, good, {}, 404, "account_not_found"),
            (ghost, good, tok_a, 404, "account_not_found"),
            ("not-a-uuid", good, tok_a, 404, "account_not_found"),
            (a["id"], bad, {}, 400, "invalid_amount"),
            (a["id"], b"[]", tok_b, 400, "invalid_json"),
            (a["id"], b'{"amount": 1, "x": 1}', {}, 400, "invalid_request"),
            (a["id"], over, {}, 401, "unauthorized"),
            (a["id"], over, tok_b, 401, "unauthorized"),
            (a["id"], good, tok_b, 401, "unauthorized"),
            (a["id"], over, tok_a, 409, "insufficient_funds"),
        ]
        for acct, body, hdr, status, error in cases:
            with self.subTest(acct=acct[:8], body=body, auth=bool(hdr), want=status):
                self.assertRejectedFree(
                    lambda: self.server.request("POST", f"/accounts/{acct}/withdraw", raw=body, headers=hdr),
                    status, error)

    def test_deposit_order(self):
        ghost = str(uuid.uuid4())
        a = self.funded(0, "dep-order")
        for acct, body, status, error in [(ghost, b'{"amount": 0}', 400, "invalid_amount"),
                                          (ghost, b"nope", 400, "invalid_json"),
                                          (ghost, b'{"amount": 1}', 404, "account_not_found"),
                                          (a["id"], b'{"amount": 1, "token": "x"}', 400, "invalid_request")]:
            with self.subTest(acct=acct[:8], body=body):
                self.assertRejectedFree(
                    lambda: self.server.request("POST", f"/accounts/{acct}/deposit", raw=body), status, error)

    def test_deposit_ignores_any_authorization(self):
        a = self.funded(0, "dep-anyauth")
        for h in [{"Authorization": "Bearer garbage"}, {"Authorization": "Basic Zm9vOmJhcg=="},
                  {"Authorization": "Bearer " + "A" * 60_000}]:
            with self.subTest(h=str(h)[:30]):
                r = self.server.request("POST", f"/accounts/{a['id']}/deposit", {"amount": 1}, headers=h)
                self.assertEqual(r.status, 200, r)
        self.assertEqual(self.server.balance(a["id"]), 3)


class ResponseShapeAndLedger(MoneyCase):
    def test_shapes_and_one_row_per_2xx(self):
        a = self.funded(0, "shape")
        r = self.server.deposit(a["id"], 700)
        self.assertEqual((r.status, r.json), (200, {"id": a["id"], "balance": 700}))
        r = self.server.withdraw(a["id"], 300, a["token"])
        self.assertEqual((r.status, r.json), (200, {"id": a["id"], "balance": 400}))
        self.assertNotIn(a["token"].encode(), r.raw, "token echoed in response")
        self.assertEqual(self.moves(a["id"], "deposit"), [700])
        self.assertEqual(self.moves(a["id"], "withdrawal"), [300])

    def test_withdraw_boundaries(self):
        a = self.funded(250, "bounds")
        self.assertRejectedFree(lambda: self.server.withdraw(a["id"], 251, a["token"]), 409, "insufficient_funds")
        r = self.server.withdraw(a["id"], 250, a["token"])
        self.assertEqual((r.status, r.json["balance"]), (200, 0))
        self.assertRejectedFree(lambda: self.server.withdraw(a["id"], 1, a["token"]), 409, "insufficient_funds")
        self.assertRejectedFree(lambda: self.server.withdraw(a["id"], MAX_AMOUNT, a["token"]),
                                409, "insufficient_funds")
        z = self.funded(0, "zero")
        self.assertRejectedFree(lambda: self.server.withdraw(z["id"], 1, z["token"]), 409, "insufficient_funds")

    def test_path_and_id_tricks(self):
        a = self.funded(0, "paths")
        i = a["id"]
        nohyphen = i.replace("-", "")
        tricks = [f"/accounts/{i.upper()}/deposit", f"/accounts/{{{i}}}/deposit", f"/accounts/urn:uuid:{i}/deposit",
                  f"/accounts/{nohyphen}/deposit", f"/accounts/{i}/deposit/", f"/accounts/{i}//deposit",
                  f"/accounts//{i}/deposit", f"/accounts/{i}%2Fdeposit", f"/accounts/{i}/%64eposit",
                  f"/accounts/{i}/DEPOSIT", f"/accounts/{i}/deposit;x", f"/accounts/../accounts/{i}/deposit",
                  f"/accounts/{i}%27%20OR%20%271%27=%271/deposit", f"/accounts/{i}%00/deposit", f"/accounts/{i}%20/deposit",
                  f"/accounts/{i}/deposit%20"]
        ok = 0
        for p in tricks:
            with self.subTest(p=p):
                before = self.server.snapshot()
                r = self.server.request("POST", p, {"amount": 1})
                self.assertIn(r.status, (200, 400, 404), r)
                if r.status == 200:
                    ok += 1
                else:
                    self.assertEqual(self.server.snapshot(), before, f"I6: {r}")
        self.assertEqual(self.server.balance(i), ok, "deposits applied != 200s returned")
        for m in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(m=m):
                r = self.server.request(m, f"/accounts/{i}/deposit", {"amount": 1} if m != "GET" else None)
                self.assertEqual((r.status, r.error), (404, "not_found"), r)
        r = self.server.request("POST", "/audit", {})
        self.assertEqual((r.status, r.error), (404, "not_found"), r)

    def test_auth_header_exact_form(self):
        """Q4 ruling: the value must be exactly 'Bearer <token>' (case-sensitive scheme, one space);
        any other form -> 401 with no effect."""
        a = self.funded(1000, "authvar")
        t = a["token"]
        variants = {"lower-scheme": f"bearer {t}", "upper-scheme": f"BEARER {t}", "two-spaces": f"Bearer  {t}",
                    "tab": f"Bearer\t{t}", "extra-param": f"Bearer {t}, x", "no-space": f"Bearer{t}",
                    "token-only": t, "scheme-only": "Bearer"}
        for name, value in variants.items():
            with self.subTest(v=name):
                self.assertRejectedFree(
                    lambda: self.server.request("POST", f"/accounts/{a['id']}/withdraw", {"amount": 1},
                                                headers={"Authorization": value}),
                    401, "unauthorized")
        r = self.server.withdraw(a["id"], 1, t)
        self.assertEqual(r.status, 200, r)
        # Q5 (open): leading/trailing whitespace around a header value is OWS per RFC 9110, not part of the
        # value. Python's parser drops the leading space but keeps the trailing one. Not ruled: 200 or 401,
        # and a 401 must be free.
        ok = 0
        for name, value in {"leading-OWS": f" Bearer {t}", "trailing-OWS": f"Bearer {t} "}.items():
            with self.subTest(v=name):
                before = self.server.snapshot()
                r = self.server.request("POST", f"/accounts/{a['id']}/withdraw", {"amount": 1},
                                        headers={"Authorization": value})
                self.assertIn(r.status, (200, 401), r)
                if r.status == 200:
                    ok += 1
                else:
                    self.assertEqual(self.server.snapshot(), before)
        self.assertEqual(self.server.balance(a["id"]), 999 - ok)

    def dup_auth(self, acct_id, first, second, body=b'{"amount": 1}', extra=b""):
        req = (f"POST /accounts/{acct_id}/withdraw HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n"
               f"Authorization: {first}\r\n").encode() + extra + f"Authorization: {second}\r\n\r\n".encode() + body
        return self.server.raw_http(req)

    def test_duplicate_authorization_is_400(self):
        """Q4 ruling: 2+ Authorization headers -> 400 invalid_request, a request-shape check that runs
        before 404/401 (so before the account lookup and the token compare)."""
        a = self.funded(1000, "dupauth")
        t = a["token"]
        ghost = str(uuid.uuid4())
        right, wrong = f"Bearer {t}", "Bearer wrong"
        cases = [("right+wrong", a["id"], right, wrong, b""), ("wrong+right", a["id"], wrong, right, b""),
                 ("right+right", a["id"], right, right, b""), ("right+empty", a["id"], right, "", b""),
                 ("case-variant name", a["id"], right, right, b""),
                 ("three headers", a["id"], right, right, f"Authorization: {right}\r\n".encode()),
                 ("ghost account", ghost, right, wrong, b""), ("malformed id", "not-a-uuid", right, right, b"")]
        for name, acct, first, second, extra in cases:
            with self.subTest(case=name):
                before = self.server.snapshot()
                if name == "case-variant name":
                    body = b'{"amount": 1}'
                    st, data = self.server.raw_http(
                        (f"POST /accounts/{acct}/withdraw HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n"
                         f"Authorization: {first}\r\nauthorization: {second}\r\n\r\n").encode() + body)
                else:
                    st, data = self.dup_auth(acct, first, second, extra=extra)
                self.assertEqual(st, 400, data[:200])
                self.assertIn(b'"invalid_request"', data, data[:200])
                self.assertEqual(self.server.snapshot(), before, "I6: duplicate-auth request had an effect")
        # a bad body together with duplicate auth is still a 400 (which 400 code comes first is not ruled)
        st, data = self.dup_auth(a["id"], right, wrong, body=b'{"amount": 1.5}')
        self.assertEqual(st, 400, data[:200])
        self.assertEqual(self.server.balance(a["id"]), 1000)


class Concurrency(MoneyCase):
    def test_same_full_withdrawal_100x(self):
        for round_ in range(5):
            B = 1000
            a = self.funded(B, f"dup-{round_}")
            rs = self.fire([lambda: self.server.withdraw(a["id"], B, a["token"])] * 100)
            ok = [r for r in rs if r.status == 200]
            self.assertCommitCount(len(ok), self.busy_count(rs), 1, f"I4 round {round_}: full-balance withdrawals")
            self.assertEqual(self.server.balance(a["id"]), B - B * len(ok))
            self.assertEqual(self.moves(a["id"], "withdrawal"), [B] * len(ok), "I4: 2xx count != ledger rows")
            for r in rs:
                if r.status != 200:
                    self.assertIn((r.status, r.error), [(409, "insufficient_funds"), BUSY], r)

    def test_same_withdrawal_twice_in_parallel(self):
        # the narrowest race: exactly two identical requests, 30 rounds
        for round_ in range(30):
            a = self.funded(100, f"pair-{round_}")
            rs = self.fire([lambda: self.server.withdraw(a["id"], 100, a["token"])] * 2, workers=2)
            ok = sum(r.status == 200 for r in rs)
            self.assertCommitCount(ok, self.busy_count(rs), 1, f"I4 round {round_}: {rs}")
            self.assertEqual(self.server.balance(a["id"]), 100 - 100 * ok)

    def test_drain_by_ones_200x_and_response_balances(self):
        B = 50
        a = self.funded(B, "drain")
        rs = self.fire([lambda: self.server.withdraw(a["id"], 1, a["token"])] * 200, workers=200)
        ok = [r for r in rs if r.status == 200]
        self.assertCommitCount(len(ok), self.busy_count(rs), B, "I4: one-unit withdrawals")
        self.assertEqual(self.server.balance(a["id"]), B - len(ok))
        self.assertEqual(len(self.moves(a["id"], "withdrawal")), len(ok), "I4: 2xx count != ledger rows")
        # each committed withdrawal must report the balance from its own transaction
        self.assertEqual(sorted(r.json["balance"] for r in ok), list(range(B - len(ok), B)),
                         "response balances are not one-per-commit (read outside the transaction?)")

    def test_unique_amount_drain_rows_match_responses(self):
        a = self.funded(5000, "uniq")
        amounts = list(range(1, 151))  # sum 11325 > 5000: some must fail
        random.shuffle(amounts)
        rs = self.fire([(lambda n=n: self.server.withdraw(a["id"], n, a["token"])) for n in amounts], workers=150)
        acked = sorted(n for n, r in zip(amounts, rs) if r.status == 200)
        refused = {n for n, r in zip(amounts, rs) if r.status in (409, 503)}
        rows = self.moves(a["id"], "withdrawal")
        self.assertEqual(rows, acked, "I4/I6: ledger rows != acknowledged withdrawals")
        self.assertFalse(refused & set(rows), "I6: a refused withdrawal left a row")
        self.assertLessEqual(sum(acked), 5000)
        self.assertEqual(self.server.balance(a["id"]), 5000 - sum(acked))

    def test_deposit_racing_drain(self):
        a = self.funded(100, "dep-race")
        counter = itertools.count(1)
        fns, meta = [], []
        for i in range(240):
            n = next(counter)
            if i % 3 == 0:
                fns.append(lambda n=n: self.server.deposit(a["id"], 1000 + n))
                meta.append(("deposit", 1000 + n))
            else:
                fns.append(lambda n=n: self.server.withdraw(a["id"], 30 + n, a["token"]))
                meta.append(("withdrawal", 30 + n))
        rs = self.fire(fns, workers=120)
        for kind in ("deposit", "withdrawal"):
            acked = sorted(amt for (k, amt), r in zip(meta, rs) if k == kind and r.status == 200)
            if kind == "deposit":
                acked = sorted(acked + [100])  # the funding deposit
            self.assertEqual(self.moves(a["id"], kind), acked, f"I4/I6: {kind} rows != 200 responses")
        dep = sum(amt for (k, amt), r in zip(meta, rs) if k == "deposit" and r.status == 200)
        wd = sum(amt for (k, amt), r in zip(meta, rs) if k == "withdrawal" and r.status == 200)
        self.assertEqual(self.server.balance(a["id"]), 100 + dep - wd)

    def test_audit_one_snapshot_under_load(self):
        """GET /audit must read all three totals from ONE snapshot. Three autocommit SELECTs under
        WAL see different commits; a writer landing between them shows conserved=false or bad sums."""
        self.need_route("GET", "/audit")
        accts = [self.funded(10_000, f"aud-{k}") for k in range(6)]
        stop, bad, regress = threading.Event(), [], []
        samples = [0]

        def sampler():
            last = (0, 0)
            while not stop.is_set():
                r = self.server.request("GET", "/audit")
                samples[0] += 1
                if r.status != 200:
                    bad.append(repr(r))
                    continue
                j = r.json
                if j["conserved"] is not True or j["total_balances"] != j["total_deposits"] - j["total_withdrawals"]:
                    bad.append(j)
                cur = (j["total_deposits"], j["total_withdrawals"])
                if cur[0] < last[0] or cur[1] < last[1]:
                    regress.append((last, cur))
                last = cur

        samplers = [threading.Thread(target=sampler) for _ in range(4)]
        for th in samplers:
            th.start()
        try:
            fns = []
            for _ in range(600):
                x = random.choice(accts)
                if random.random() < 0.5:
                    fns.append(lambda x=x: self.server.deposit(x["id"], random.randint(1, 500)))
                else:
                    fns.append(lambda x=x: self.server.withdraw(x["id"], random.randint(1, 500), x["token"]))
            with cf.ThreadPoolExecutor(48) as ex:
                list(ex.map(lambda f: f(), fns))
        finally:
            stop.set()
            for th in samplers:
                th.join()
        self.assertGreater(samples[0], 20, "sampler barely ran; attack proves nothing")
        self.assertEqual(bad[:5], [], f"I1: audit not from one snapshot ({len(bad)} bad of {samples[0]})")
        self.assertEqual(regress[:5], [], "audit totals went backwards for a single sequential reader")

    def test_audit_matches_independent_db_query(self):
        self.need_route("GET", "/audit")
        self.funded(123, "aud-ind")
        a = self.server.request("GET", "/audit").json
        with contextlib.closing(self.server.db()) as c:
            bal = c.execute("SELECT coalesce(sum(balance),0) FROM accounts").fetchone()[0]
            dep = c.execute("SELECT coalesce(sum(amount),0) FROM external_moves WHERE kind='deposit'").fetchone()[0]
            wd = c.execute("SELECT coalesce(sum(amount),0) FROM external_moves WHERE kind='withdrawal'").fetchone()[0]
        self.assertEqual(a, {"total_balances": bal, "total_deposits": dep, "total_withdrawals": wd,
                             "conserved": True})
        for k in ("total_balances", "total_deposits", "total_withdrawals"):
            self.assertIs(type(a[k]), int, k)


class LockTimeout(MoneyCase):
    """PLAN: lock timeout -> 503 busy, no effect; never a hang (I11). Hold SQLite's write lock from
    outside the service, exactly as a long writer would."""

    def hold_lock(self, seconds):
        got, done = threading.Event(), threading.Event()

        def holder():
            c = sqlite3.connect(self.server.db_path, timeout=0, isolation_level=None)
            try:
                c.execute("BEGIN IMMEDIATE")
                got.set()
                done.wait(seconds)
                c.execute("ROLLBACK")
            finally:
                c.close()

        th = threading.Thread(target=holder)
        th.start()
        self.assertTrue(got.wait(5), "could not take the write lock")
        return th, done

    def test_writes_get_503_and_no_effect_while_locked(self):
        a = self.funded(500, "locked")
        before = self.server.snapshot()
        th, done = self.hold_lock(15)
        try:
            for name, fn in [("deposit", lambda: self.server.deposit(a["id"], 7)),
                             ("withdraw", lambda: self.server.withdraw(a["id"], 7, a["token"]))]:
                with self.subTest(op=name):
                    t0 = time.monotonic()
                    r = fn()
                    dt = time.monotonic() - t0
                    self.assertEqual((r.status, r.error), BUSY, r)
                    self.assertLess(dt, REQUEST_TIMEOUT, "I11: lock wait exceeded 10s")
            # readers must not be blocked by a writer under WAL
            self.assertEqual(self.server.request("GET", f"/accounts/{a['id']}").status, 200)
            if self.server.has_route("GET", "/audit"):
                self.assertEqual(self.server.request("GET", "/audit").status, 200)
        finally:
            done.set()
            th.join()
        self.assertEqual(self.server.snapshot(), before, "I6: a 503 left an effect")

    def test_short_lock_is_waited_out_not_refused(self):
        # busy_timeout >= 5 s: a lock held ~2 s must be waited out, not turned into 503
        a = self.funded(500, "brief-lock")
        th, done = self.hold_lock(2)
        try:
            r = self.server.deposit(a["id"], 9)
        finally:
            done.set()
            th.join()
        self.assertEqual(r.status, 200, f"gave up before busy_timeout: {r}")
        self.assertEqual(self.server.balance(a["id"]), 509)

    def test_503_burst_then_recovery(self):
        a = self.funded(1000, "lock-burst")
        before = self.server.snapshot()
        th, done = self.hold_lock(12)
        try:
            rs = self.fire([lambda: self.server.withdraw(a["id"], 1, a["token"])] * 40, workers=40)
        finally:
            done.set()
            th.join()
        self.assertTrue(all((r.status, r.error) == BUSY for r in rs), {(r.status, r.error) for r in rs})
        self.assertEqual(self.server.snapshot(), before, "I6: 503 burst left an effect")
        r = self.server.withdraw(a["id"], 1, a["token"])
        self.assertEqual(r.status, 200, f"service did not recover after the lock: {r}")


class KillMidMoneyBurst(MoneyCase):
    def test_kill_during_deposit_withdraw_burst(self):
        """I10: SIGKILL mid-burst. After restart every 200 is in the ledger, every 4xx is not,
        and the tearDown sweep re-checks I1/I3/I7."""
        accts = [self.funded(10**9, f"kill-{k}") for k in range(4)]
        counter = itertools.count(1)
        acked, refused, stop = [], [], threading.Event()

        def worker():
            while not stop.is_set():
                n = next(counter)
                x = random.choice(accts)
                if n % 2:
                    kind, amt = "deposit", 10**6 + n
                    r = self.server.deposit(x["id"], amt, timeout=5)
                else:
                    kind, amt = "withdrawal", n
                    r = self.server.withdraw(x["id"], amt, x["token"], timeout=5)
                if r.status == 200:
                    acked.append((x["id"], kind, amt))
                elif 400 <= r.status < 500:
                    refused.append((x["id"], kind, amt))
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
        with contextlib.closing(self.server.db()) as c:
            have = set(c.execute("SELECT account_id, kind, amount FROM external_moves"))
        self.assertEqual([m for m in acked if m not in have][:5], [], "I10: acknowledged moves lost after kill")
        self.assertEqual([m for m in refused if m in have][:5], [], "I6/I10: refused move present after kill")


@unittest.skipUnless(SLOW, "set ATTACK_SLOW=1")
class SustainedMoneyLoad(MoneyCase):
    def test_30s_mixed_deposit_withdraw_with_audit(self):
        accts = [self.funded(10**8, f"load-{k}") for k in range(5)] + [self.funded(0, "load-poor")]
        counter = itertools.count(1)
        stop = threading.Event()
        worst, errors, acked, refused, bad_audit = [0.0], [], [], [], []

        def worker():
            while not stop.is_set():
                n = next(counter)
                x = random.choice(accts)
                t0 = time.monotonic()
                if n % 3 == 0:
                    kind, amt = "deposit", 10**7 + n
                    r = self.server.deposit(x["id"], amt)
                else:
                    kind, amt = "withdrawal", n
                    r = self.server.withdraw(x["id"], amt, x["token"])
                worst[0] = max(worst[0], time.monotonic() - t0)
                if r.status == 200:
                    acked.append((x["id"], kind, amt))
                elif r.status in (409, 503):
                    refused.append((x["id"], kind, amt))
                else:
                    errors.append(r)

        def sampler():
            while not stop.is_set():
                r = self.server.request("GET", "/audit")
                j = r.json if r.status == 200 else None
                if j is None or j["conserved"] is not True or \
                        j["total_balances"] != j["total_deposits"] - j["total_withdrawals"]:
                    bad_audit.append(r)
                time.sleep(0.05)

        with cf.ThreadPoolExecutor(66) as ex:
            for _ in range(64):
                ex.submit(worker)
            for _ in range(2):
                ex.submit(sampler)
            time.sleep(30)
            stop.set()
        self.assertEqual(errors[:5], [], "I11: error or no response under load")
        self.assertLess(worst[0], REQUEST_TIMEOUT, "I11: a request hung")
        self.assertEqual(bad_audit[:5], [], "I1: audit not conserved under load")
        with contextlib.closing(self.server.db()) as c:
            have = set(c.execute("SELECT account_id, kind, amount FROM external_moves"))
        self.assertEqual([m for m in acked if m not in have][:5], [], "acknowledged move missing")
        self.assertEqual([m for m in refused if m in have][:5], [], "I6: refused move present under load")


class ConnectionFlood(MoneyCase):
    """I11: one thread per connection. Park many half-sent requests (each pins a handler thread
    until its 10 s deadline) and check that real money requests are still answered in time."""

    def test_idle_flood_does_not_wedge_money_path(self):
        import socket
        a = self.funded(1000, "flood")
        parked = []
        try:
            for _ in range(800):
                try:
                    s = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
                    s.sendall(f"POST /accounts/{a['id']}/withdraw HTTP/1.1".encode())
                    parked.append(s)
                except OSError:
                    break
            self.assertGreater(len(parked), 500, "could not park enough connections to mean anything")
            rs = self.fire([lambda: self.server.deposit(a["id"], 1)] * 40, workers=40)
            ok = sum(r.status == 200 for r in rs)
            # 503 busy (no effect) is within contract under contention; anything else is a refusal
            self.assertEqual(ok + self.busy_count(rs), 40, f"money path refused under idle flood: {rs}")
            self.assertGreater(ok, 0, "every money request refused under idle flood")
            r = self.server.withdraw(a["id"], ok, a["token"])
            self.assertEqual(r.status, 200, r)
        finally:
            for s in parked:
                with contextlib.suppress(OSError):
                    s.close()
        self.assertEqual(self.server.balance(a["id"]), 1000)
        self.assertEqual(self.moves(a["id"], "deposit"), [1] * ok + [1000])
