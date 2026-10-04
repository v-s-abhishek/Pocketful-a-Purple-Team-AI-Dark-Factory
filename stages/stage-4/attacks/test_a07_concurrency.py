"""I4 no double-spend, I1 during load, I10 kill mid-burst, I11 no wedge."""
import concurrent.futures as cf
import contextlib
import random
import threading
import time
import unittest
import uuid

from breaker_harness import REQUEST_TIMEOUT, SLOW, AttackCase

OK_BUSY = 503  # I11: lock timeout may answer 503 `busy`, with no effect


class DoubleSpend(AttackCase):
    def setUp(self):
        self.need_route("POST", "/transfers", {})

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
            self.assertTrue(r.status < 500 or (r.status == OK_BUSY and r.error == "busy"), f"5xx: {r}")
        return [r for r, _ in out]

    def transfer_rows(self):
        with contextlib.closing(self.server.db()) as c:
            if "transfers" in self.server.tables():
                return c.execute("SELECT count(*) FROM transfers").fetchone()[0]
        return None

    def test_same_full_balance_100x(self):
        B = 1000
        src, dst = self.funded(B), self.funded(0)
        rows0 = self.transfer_rows()
        rs = self.fire([lambda: self.server.transfer(src["id"], dst["id"], B, src["token"])] * 100)
        ok = [r for r in rs if r.status == 201]
        self.assertCommitCount(len(ok), self.busy_count(rs), 1, "I4: transfers of the full balance")
        moved = B * len(ok)
        self.assertEqual((self.server.balance(src["id"]), self.server.balance(dst["id"])), (B - moved, moved))
        if rows0 is not None:
            self.assertEqual(self.transfer_rows() - rows0, len(ok), "I4: 2xx count != ledger rows")

    def test_fractional_drain_200x(self):
        B, k = 1000, 10
        src = self.funded(B)
        dsts = [self.funded(0) for _ in range(20)]
        rs = self.fire([(lambda d=dsts[i % 20]: self.server.transfer(src["id"], d["id"], B // k, src["token"]))
                        for i in range(200)], workers=200)
        ok = sum(r.status == 201 for r in rs)
        self.assertCommitCount(ok, self.busy_count(rs), k, "I4: fractional drain")
        self.assertEqual(self.server.balance(src["id"]), B - ok * (B // k))
        self.assertEqual(sum(self.server.balance(d["id"]) for d in dsts), ok * (B // k))
        for r in rs:
            if r.status != 201:
                self.assertIn((r.status, r.error), [(409, "insufficient_funds"), (503, "busy")], r)

    def test_withdraw_and_transfer_race(self):
        self.need_route("POST", f"/accounts/{uuid.uuid4()}/withdraw", {"amount": 1})
        B = 600
        src, dst = self.funded(B), self.funded(0)
        fns = []
        for i in range(120):
            if i % 2:
                fns.append(lambda: self.server.withdraw(src["id"], 100, src["token"]))
            else:
                fns.append(lambda: self.server.transfer(src["id"], dst["id"], 100, src["token"]))
        rs = self.fire(fns)
        ok = sum(r.status in (200, 201) for r in rs)
        self.assertCommitCount(ok, self.busy_count(rs), 6, "I4: debits of 100 from 600")
        self.assertEqual(self.server.balance(src["id"]), B - 100 * ok)

    def test_cross_transfers_ab_ba(self):
        a, b = self.funded(500), self.funded(500)
        fns = []
        for i in range(200):
            if i % 2:
                fns.append(lambda: self.server.transfer(a["id"], b["id"], random.randint(1, 50), a["token"]))
            else:
                fns.append(lambda: self.server.transfer(b["id"], a["id"], random.randint(1, 50), b["token"]))
        self.fire(fns)
        self.assertEqual(self.server.balance(a["id"]) + self.server.balance(b["id"]), 1000, "I1/I2")

    def test_deposit_while_draining(self):
        src, dst = self.funded(100), self.funded(0)
        deposits, transfers = [], []
        fns = []
        for i in range(150):
            if i % 3 == 0:
                fns.append(lambda: ("d", self.server.deposit(src["id"], 10)))
            else:
                fns.append(lambda: ("t", self.server.transfer(src["id"], dst["id"], 10, src["token"])))
        with cf.ThreadPoolExecutor(100) as ex:
            out = list(ex.map(lambda f: f(), fns))
        dep = sum(10 for k, r in out if k == "d" and r.status == 200)
        moved = sum(10 for k, r in out if k == "t" and r.status == 201)
        self.assertEqual(self.server.balance(dst["id"]), moved)
        self.assertEqual(self.server.balance(src["id"]), 100 + dep - moved)

    def test_audit_conserved_during_load(self):
        self.need_route("GET", "/audit")
        accts = [self.funded(1000) for _ in range(5)]
        stop, bad = threading.Event(), []

        def sampler():
            while not stop.is_set():
                a = self.server.request("GET", "/audit")
                if a.status == 200 and (a.json["conserved"] is not True or
                                        a.json["total_balances"] != a.json["total_deposits"] - a.json["total_withdrawals"]):
                    bad.append(a.json)

        th = threading.Thread(target=sampler)
        th.start()
        try:
            fns = []
            for _ in range(300):
                s, d = random.sample(accts, 2)
                fns.append(lambda s=s, d=d: self.server.transfer(s["id"], d["id"], random.randint(1, 300), s["token"]))
            with cf.ThreadPoolExecutor(50) as ex:
                list(ex.map(lambda f: f(), fns))
        finally:
            stop.set()
            th.join()
        self.assertEqual(bad, [], "I1: audit observed non-conserved state mid-flight")
        self.assertEqual(sum(self.server.balance(a["id"]) for a in accts), 5000)


class KillMidBurst(AttackCase):
    def test_kill_during_transfer_burst(self):
        self.need_route("POST", "/transfers", {})
        accts = [self.funded(10_000) for _ in range(6)]
        acked, stop = [], threading.Event()

        def worker():
            while not stop.is_set():
                s, d = random.sample(accts, 2)
                try:
                    r = self.server.transfer(s["id"], d["id"], random.randint(1, 500), s["token"], timeout=5)
                except OSError:
                    return
                if r.status == 201:
                    acked.append(r.json["id"])

        with cf.ThreadPoolExecutor(16) as ex:
            for _ in range(16):
                ex.submit(worker)
            time.sleep(1.5)
            self.server.kill()
            stop.set()
        self.server.start()
        self.assertGreater(len(acked), 0)
        total = sum(self.server.balance(a["id"]) for a in accts)
        self.assertEqual(total, 60_000, "I1/I2: money created or destroyed across a crash")
        if "transfers" in self.server.tables():
            with contextlib.closing(self.server.db()) as c:
                have = {r[0] for r in c.execute("SELECT id FROM transfers")}
            missing = [i for i in acked if i not in have]
            self.assertEqual(missing, [], "I10: acknowledged transfers lost after kill")


@unittest.skipUnless(SLOW, "set ATTACK_SLOW=1")
class SustainedLoad(AttackCase):
    def test_30s_mixed_load(self):
        self.need_route("POST", "/transfers", {})
        accts = [self.funded(100_000) for _ in range(8)]
        stop = threading.Event()
        worst, errors = [0.0], []

        def worker():
            while not stop.is_set():
                s, d = random.sample(accts, 2)
                t0 = time.monotonic()
                try:
                    r = self.server.transfer(s["id"], d["id"], random.randint(1, 5000), s["token"])
                    if r.status >= 500 and r.status != OK_BUSY:
                        errors.append(r)
                except OSError as e:
                    errors.append(e)
                worst[0] = max(worst[0], time.monotonic() - t0)

        with cf.ThreadPoolExecutor(64) as ex:
            for _ in range(64):
                ex.submit(worker)
            time.sleep(30)
            stop.set()
        self.assertEqual(errors[:5], [], "I11")
        self.assertLess(worst[0], REQUEST_TIMEOUT, "I11: a request hung")
        self.assertEqual(sum(self.server.balance(a["id"]) for a in accts), 800_000)
