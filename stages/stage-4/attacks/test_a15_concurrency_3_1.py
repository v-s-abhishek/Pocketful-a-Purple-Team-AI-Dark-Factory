"""Unit 3.1 attacks: concurrency hardening (PLAN.md Stage 3, D3.1-D3.4, Q3-A..Q3-D, measurement
notes 1-5, I18-I21). Written from the spec before the build. Every class skips until the stage-3
build is present (`stress/run_stress.py` exists, D3.4), unless ATTACK_FORCE_3=1.

Spec in brief: every write goes through db.write_transaction (D3.1), which takes a process-wide
FIFO lock (4 s acquire timeout -> 503 busy, no effect; released on every path) and then BEGIN
IMMEDIATE (D3.2, busy_timeout 2 s per Q3-B). The lock covers BEGIN..COMMIT only; a waiter whose
client disconnected still commits (Q3-D). At most 256 requests handled at once, backlog 1024
(D3.3). I19: no request >= 10 s; zero 503 at <= 100 concurrent writers, so drains at <= 100-way
assert committed == limit exactly; arrival order = order of the lock acquire (note 1). I20: after
load, /health and two fresh keyed writes each answer within 1 s. I21: SIGKILL mid-stress, restart,
retry every key: at most one movement per key in total.

The Breaker's own stress driver is breaker_stress.py (note 5).
"""
import concurrent.futures as cf
import contextlib
import json
import os
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import unittest
import uuid

from breaker_harness import DOCKER, NO_RESPONSE, REQUEST_TIMEOUT, SLOW, STAGE_DIR, AttackCase, Server
from breaker_stress import Driver, build_request, parse_response, send, send_and_drop, Op

CRLF = b"\r\n"
KEY = "Idempotency-Key"
LINGER0 = struct.pack("ii", 1, 0)
BUILT = (os.path.exists(os.path.join(STAGE_DIR, "stress", "run_stress.py"))
         or os.environ.get("ATTACK_FORCE_3") == "1")
built = unittest.skipUnless(BUILT, "stage 3 not built yet (no stress/run_stress.py)")
slow = unittest.skipUnless(SLOW, "set ATTACK_SLOW=1")


class ExternalLock:
    """Another process's writer: holds the SQLite write lock (BEGIN IMMEDIATE) for `seconds`.
    Readers are unaffected (WAL); the server's writers queue behind it."""

    def __init__(self, db_path, seconds):
        self.db_path, self.seconds = db_path, seconds
        self.acquired = threading.Event()
        self.t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        c = sqlite3.connect(self.db_path, isolation_level=None, timeout=10)
        try:
            c.execute("BEGIN IMMEDIATE")
            self.acquired.set()
            time.sleep(self.seconds)
            c.execute("ROLLBACK")
        finally:
            c.close()

    def start(self):
        self.t.start()
        assert self.acquired.wait(10), "could not take the SQLite write lock"
        self.t0 = time.monotonic()
        return self

    def join(self):
        self.t.join(self.seconds + 10)


class C3Case(AttackCase):
    """Shared helpers. The server is started per class; an I20 probe runs after every test."""

    def setUp(self):
        self.need_route("POST", "/transfers", {})

    def tearDown(self):
        super().tearDown()
        self.assertNoWedge()

    # -- helpers --
    def timed(self, fn):
        t0 = time.monotonic()
        r = fn()
        return r, time.monotonic() - t0

    def fire(self, fns):
        """Run every fn at once (one thread each, behind a barrier). Returns [(response, secs)]."""
        barrier = threading.Barrier(len(fns))

        def run(fn):
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.wait(10)
            return self.timed(fn)

        with cf.ThreadPoolExecutor(len(fns)) as ex:
            out = list(ex.map(run, fns))
        slowest = max(dt for _, dt in out)
        self.assertLess(slowest, REQUEST_TIMEOUT, f"I19: a request took {slowest:.2f}s")
        bad = [r for r, _ in out if r.status >= 500 and r.status != 503 or r.status == NO_RESPONSE]
        self.assertEqual(bad, [], "5xx / no response under contention")
        return out

    def assertZeroBusy(self, out, what):
        busy = [r for r, _ in out if r.status == 503]
        self.assertEqual(busy, [], f"I19: {len(busy)} x 503 at <= 100 writers ({what})")

    def assertNoWedge(self):
        """I20, note 3: /health, then a fresh keyed write and a second one right behind it,
        each answered within 1 s."""
        s = self.server
        r, dt = self.timed(lambda: s.request("GET", "/health"))
        self.assertEqual(r.status, 200, r)
        self.assertLess(dt, 1.0, f"I20: /health took {dt:.2f}s after the attack")
        a = s.create_account("probe")
        for i in range(2):
            r, dt = self.timed(lambda: s.deposit(a["id"], 1, headers={KEY: f"probe-{uuid.uuid4()}"}))
            self.assertEqual(r.status, 200, f"I20: fresh write #{i + 1} after the attack: {r}")
            self.assertLess(dt, 1.0, f"I20: fresh write #{i + 1} took {dt:.2f}s (lock still held?)")

    def settle(self, quiet=1.0, limit=30.0):
        """Wait until no row changes for `quiet` seconds (dropped requests may still commit)."""
        end = time.monotonic() + limit
        last, since = None, time.monotonic()
        while time.monotonic() < end:
            with contextlib.closing(self.server.db()) as c:
                n = c.execute("SELECT (SELECT count(*) FROM transfers) + (SELECT count(*) FROM external_moves)"
                              " + (SELECT count(*) FROM accounts)").fetchone()[0]
            if n != last:
                last, since = n, time.monotonic()
            elif time.monotonic() - since >= quiet:
                return
            time.sleep(0.1)

    def rows_by_amount(self, src_id):
        with contextlib.closing(self.server.db()) as c:
            rows = c.execute("SELECT amount FROM transfers WHERE from_id = ?", (src_id,)).fetchall()
        out = {}
        for (a,) in rows:
            out[a] = out.get(a, 0) + 1
        return out

    def run_driver(self, **kw):
        d = Driver(self.server, **kw).run().resolve()
        summary = d.check()
        print(f"\n[a15 driver] {json.dumps({k: v for k, v in summary.items() if k != 'violations'})}",
              file=sys.stderr)
        self.assertEqual(summary["violations"], [], summary)
        if summary["zero_503_rule"]:
            self.assertEqual(summary["busy"], 0, summary)
        return summary


# --------------------------------------------------------------------------------------------
@built
class ExactDrains(C3Case):
    """I19: at <= 100 concurrent writers there are zero 503s, so exact counts hold."""

    def test_drain_100way_transfers_exact(self):
        src, dst = self.funded(50, "d-src"), self.funded(0, "d-dst")
        out = self.fire([lambda: self.server.transfer(src["id"], dst["id"], 1, src["token"])] * 100)
        self.assertZeroBusy(out, "100 transfers of 1 against balance 50")
        st = sorted(r.status for r, _ in out)
        self.assertEqual((st.count(201), st.count(409)), (50, 50), st)
        self.assertEqual((self.server.balance(src["id"]), self.server.balance(dst["id"])), (0, 50))
        self.assertEqual(sum(self.rows_by_amount(src["id"]).values()), 50)

    def test_drain_100way_withdraw_and_transfer_exact(self):
        src, dst = self.funded(60, "dm-src"), self.funded(0, "dm-dst")
        fns = ([lambda: self.server.withdraw(src["id"], 1, src["token"])] * 50
               + [lambda: self.server.transfer(src["id"], dst["id"], 1, src["token"])] * 50)
        out = self.fire(fns)
        self.assertZeroBusy(out, "50 withdraw + 50 transfer against 60")
        ok = sum(r.status in (200, 201) for r, _ in out)
        self.assertEqual(ok, 60)
        self.assertEqual(sum(r.status == 409 for r, _ in out), 40)
        self.assertEqual(self.server.balance(src["id"]), 0)

    def test_drain_100way_all_fit(self):
        src = self.funded(100, "af-src")
        dsts = [self.funded(0, f"af-dst{i}") for i in range(10)]
        out = self.fire([lambda i=i: self.server.transfer(src["id"], dsts[i % 10]["id"], 1, src["token"])
                         for i in range(100)])
        self.assertZeroBusy(out, "100 transfers that all fit")
        self.assertEqual([r.status for r, _ in out], [201] * 100)
        self.assertEqual([self.server.balance(d["id"]) for d in dsts], [10] * 10)

    def test_100_copies_of_one_keyed_transfer(self):
        src, dst = self.funded(1000, "k-src"), self.funded(0, "k-dst")
        k = {KEY: "k100-" + uuid.uuid4().hex}
        out = self.fire([lambda: self.server.request(
            "POST", "/transfers", {"from": src["id"], "to": dst["id"], "amount": 7},
            headers=dict(self.server.auth(src["token"]), **k))] * 100)
        self.assertZeroBusy(out, "100 copies of one keyed transfer")
        self.assertEqual({r.status for r, _ in out}, {201})
        self.assertEqual(len({r.raw for r, _ in out}), 1, "copies answered with different bodies")
        self.assertEqual(self.rows_by_amount(src["id"]), {7: 1}, "I12: one key moved money twice")

    def test_100way_account_creation(self):
        out = self.fire([lambda i=i: self.server.request("POST", "/accounts", {"owner": f"c{i}"})
                         for i in range(100)])
        self.assertZeroBusy(out, "100 POST /accounts")
        self.assertEqual({r.status for r, _ in out}, {201})
        self.assertEqual(len({r.json["id"] for r, _ in out}), 100)

    def test_100way_deposits_into_one_account(self):
        a = self.funded(0, "dep-hot")
        out = self.fire([lambda i=i: self.server.deposit(a["id"], i + 1) for i in range(100)])
        self.assertZeroBusy(out, "100 deposits into one account")
        self.assertEqual(self.server.balance(a["id"]), sum(range(1, 101)))

    def test_pure_cycles_99way_exact(self):
        """A->B, B->C, C->A all at once. Each account starts with exactly what it sends, so every
        transfer fits whatever the order: all 99 commit and the balances end where they started."""
        a, b, c = (self.funded(330, f"cy-{n}") for n in "abc")
        ring = [(a, b), (b, c), (c, a)]
        out = self.fire([lambda s=s, d=d: self.server.transfer(s["id"], d["id"], 10, s["token"])
                         for s, d in ring for _ in range(33)])
        self.assertZeroBusy(out, "99-way cycle")
        self.assertEqual([r.status for r, _ in out], [201] * 99)
        self.assertEqual([self.server.balance(x["id"]) for x in (a, b, c)], [330] * 3)

    def test_hot_account_100way_exact(self):
        """One account debited and credited by everyone at once."""
        hot = self.funded(500, "hot")
        others = [self.funded(500, f"cold{i}") for i in range(10)]
        fns = []
        for i in range(50):
            o = others[i % 10]
            fns.append(lambda o=o: self.server.transfer(hot["id"], o["id"], 10, hot["token"]))
            fns.append(lambda o=o: self.server.transfer(o["id"], hot["id"], 10, o["token"]))
        out = self.fire(fns)
        self.assertZeroBusy(out, "hot account 100-way")
        self.assertEqual([r.status for r, _ in out], [201] * 100)
        self.assertEqual(self.server.balance(hot["id"]), 500)


# --------------------------------------------------------------------------------------------
@built
class ArrivalOrder(C3Case):
    """Note 1: an external writer holds the SQLite lock ~1.5 s (< 2 s busy_timeout); 20 keyless
    transfers from different sources are sent 50 ms apart; after the release the ledger order
    (transfers rowid) equals the send order, with zero 503."""

    def one_round(self, tag):
        srcs = [self.funded(100, f"{tag}-s{i}") for i in range(20)]
        dst = self.funded(0, f"{tag}-dst")
        res = [None] * 20
        lk = ExternalLock(self.server.db_path, 1.5).start()
        threads = []
        for i, s in enumerate(srcs):
            th = threading.Thread(target=lambda i=i, s=s: res.__setitem__(
                i, self.timed(lambda: self.server.transfer(s["id"], dst["id"], i + 1, s["token"]))))
            th.start()
            threads.append(th)
            time.sleep(max(0.0, lk.t0 + 0.05 * (i + 1) - time.monotonic()))
        for th in threads:
            th.join(REQUEST_TIMEOUT + 2)
        lk.join()
        self.assertEqual([r.status for r, _ in res], [201] * 20, [r for r, _ in res])
        self.assertLess(max(dt for _, dt in res), REQUEST_TIMEOUT)
        with contextlib.closing(self.server.db()) as c:
            order = [r[0] for r in c.execute(
                "SELECT from_id FROM transfers WHERE to_id = ? ORDER BY rowid", (dst["id"],))]
            by_time = [r[0] for r in c.execute(
                "SELECT from_id FROM transfers WHERE to_id = ? ORDER BY created_at, rowid", (dst["id"],))]
        want = [s["id"] for s in srcs]
        self.assertEqual([want.index(x) for x in order], list(range(20)), "I19: not served in arrival order")
        self.assertEqual(by_time, order, "created_at order disagrees with rowid order")

    def test_ledger_order_equals_send_order(self):
        for n in range(3):
            self.one_round(f"ao{n}")

    def test_readers_do_not_queue_behind_writers(self):
        """D3.2: GETs and /audit never take the writer lock."""
        a = self.funded(100, "rd")
        lk = ExternalLock(self.server.db_path, 3.0).start()
        with cf.ThreadPoolExecutor(20) as ex:
            writers = [ex.submit(self.server.deposit, a["id"], 1) for _ in range(20)]
            time.sleep(0.3)  # writers are now queued on the lock
            for path in ("/audit", f"/accounts/{a['id']}", "/health"):
                r, dt = self.timed(lambda: self.server.request("GET", path))
                self.assertEqual(r.status, 200, r)
                self.assertLess(dt, 0.5, f"{path} took {dt:.2f}s while writers were queued")
            done = [w.result() for w in writers]
        lk.join()
        self.assertEqual({r.status for r in done}, {200})


# --------------------------------------------------------------------------------------------
@built
class LockQueuePoisoning(C3Case):
    def test_mass_disconnects_while_queued(self):
        """Clients that queue on the lock and then RST (after the full body, or mid-body) must not
        leave the queue stuck. Each dropped keyed request moves money at most once, and a retry of
        its key settles it to exactly once."""
        src, dst = self.funded(10**9, "mq-src"), self.funded(0, "mq-dst")
        tokens = {src["id"]: src["token"]}
        ops = [Op("transfer", src["id"], dst["id"], a, f"mq-{uuid.uuid4().hex}", a) for a in range(1, 61)]
        lk = ExternalLock(self.server.db_path, 1.5).start()
        with cf.ThreadPoolExecutor(60) as ex:
            list(ex.map(lambda op: send_and_drop(self.server.port, build_request(op, tokens), op.amount > 40), ops))
        behind = Op("transfer", src["id"], dst["id"], 1000, f"mq-{uuid.uuid4().hex}", 0)
        st, _, body, dt = send(self.server.port, build_request(behind, tokens))
        lk.join()
        self.assertEqual(st, 201, body)
        self.assertLess(dt, REQUEST_TIMEOUT, "I19: the writer behind the dropped queue waited too long")
        self.settle()
        pre = self.rows_by_amount(src["id"])
        self.assertTrue(all(n == 1 for n in pre.values()), f"I12: a dropped request applied twice {pre}")
        self.assertFalse(set(pre) & set(range(41, 61)), "a truncated body moved money")
        print(f"\n[a15] dropped after full body that committed anyway: "
              f"{len(set(pre) & set(range(1, 41)))}/40", file=sys.stderr)
        for op in ops:
            st, hdrs, body, _ = send(self.server.port, build_request(op, tokens))
            self.assertEqual(st, 201, (op, body))
        rows = self.rows_by_amount(src["id"])
        self.assertEqual(rows, {a: 1 for a in list(range(1, 61)) + [1000]}, "I12/I16 after retry")

    def waiters_around_4s(self, hold, n=70, gap=0.1):
        """An external writer holds the lock for `hold` s. Writers arrive every `gap` s from t=0.
        The FIFO head 503s after the 2 s busy_timeout; queued waiters 503 at arrival + 4 s; the
        lock changes hands while waiters are timing out. Anyone arriving > 3 s before the
        release + its 4 s window must be served: an orphaned ticket would stall them."""
        src, dst = self.funded(10**9, f"t4-{hold}-src"), self.funded(0, f"t4-{hold}-dst")
        tokens = {src["id"]: src["token"]}
        ops = [Op("transfer", src["id"], dst["id"], i + 1, f"t4-{uuid.uuid4().hex}", i) for i in range(n)]
        res = [None] * n
        lk = ExternalLock(self.server.db_path, hold).start()
        threads = []
        for i, op in enumerate(ops):
            th = threading.Thread(target=lambda i=i, op=op: res.__setitem__(
                i, send(self.server.port, build_request(op, tokens))))
            th.start()
            threads.append(th)
            time.sleep(max(0.0, lk.t0 + gap * (i + 1) - time.monotonic()))
        for th in threads:
            th.join(REQUEST_TIMEOUT + 5)
        lk.join()
        self.settle()
        statuses = [r[0] for r in res]
        for i, (st, _, body, dt) in enumerate(res):
            self.assertIn(st, (201, 503), f"writer {i}: {st} {body[:200]!r}")
            if st == 503:
                self.assertEqual(json.loads(body).get("error"), "busy")
            self.assertLess(dt, REQUEST_TIMEOUT, f"I19: writer {i} took {dt:.2f}s")
        ok = {op.amount for op, r in zip(ops, res) if r[0] == 201}
        self.assertEqual(set(self.rows_by_amount(src["id"])), ok, "a 503 had an effect, or a 201 is missing")
        late = [i for i in range(n) if gap * (i + 1) > hold - 4 + 1.0]
        stuck = [(i, statuses[i]) for i in late if statuses[i] != 201]
        self.assertEqual(stuck, [], f"waiters that should have been served after the release (hold {hold}s)")
        for op, r in zip(ops, res):
            if r[0] == 503:
                st, hdrs, body, _ = send(self.server.port, build_request(op, tokens))
                self.assertEqual(st, 201, body)
                self.assertNotEqual(hdrs.get("idempotent-replayed"), "true", "a 503 recorded its key")
        self.assertEqual(self.rows_by_amount(src["id"]), {i + 1: 1 for i in range(n)})
        print(f"\n[a15] hold {hold}s: {statuses.count(503)} x 503, {statuses.count(201)} x 201", file=sys.stderr)

    def test_waiters_timing_out_at_4s_do_not_orphan_the_queue(self):
        self.waiters_around_4s(6.0)

    @slow
    def test_timeout_handover_sweep(self):
        for hold in (4.0, 4.05, 5.95, 6.05, 7.5):
            self.waiters_around_4s(hold, gap=0.05, n=140)


# --------------------------------------------------------------------------------------------
@built
class SlowClients(C3Case):
    def slowloris(self, n, stop):
        """n connections that dribble header bytes until the server closes them (408 at 10 s)."""
        outcomes = []

        def one():
            s = socket.create_connection(("127.0.0.1", self.server.port), timeout=15)
            got = b""
            try:
                s.sendall(b"POST /transfers HTTP/1.1" + CRLF + b"Host: x" + CRLF)
                while not stop.is_set():
                    s.sendall(b"X")
                    time.sleep(0.3)
            except OSError:
                pass
            with contextlib.suppress(OSError):
                s.settimeout(15)
                while True:
                    c = s.recv(65536)
                    if not c:
                        break
                    got += c
            s.close()
            outcomes.append(got)

        threads = [threading.Thread(target=one, daemon=True) for _ in range(n)]
        for t in threads:
            t.start()
        return threads, outcomes

    def test_64_slowloris_during_100way_drain(self):
        """Q3-A: with 64 slow connections holding handler slots, I19 still binds at 100 writers."""
        stop = threading.Event()
        threads, outcomes = self.slowloris(64, stop)
        time.sleep(1.0)
        src, dst = self.funded(50, "sl-src"), self.funded(0, "sl-dst")
        out = self.fire([lambda: self.server.transfer(src["id"], dst["id"], 1, src["token"])] * 100)
        self.assertZeroBusy(out, "100-way drain with 64 slowloris")
        self.assertEqual(sum(r.status == 201 for r, _ in out), 50)
        for t in threads:
            t.join(30)
        stop.set()
        self.assertEqual(len(outcomes), 64)
        for got in outcomes:
            if got:  # a response, if any, is a full JSON 408 (or 400/431), never a 5xx or HTML
                p = parse_response(got)
                self.assertIsNotNone(p, got[:200])
                self.assertIn(p[0], (400, 408, 431), got[:200])
                json.loads(p[2])

    def test_1000_connections_at_once(self):
        """D3.3 + note 4: refused/reset before any byte is fine; every full request gets a full JSON
        response; every 2xx is in the ledger; nothing commits while its client saw a reset."""
        a = self.funded(0, "k1000")
        n = 1000
        keys = [f"c1k-{uuid.uuid4().hex}" for _ in range(n)]
        res = [None] * n
        barrier = threading.Barrier(n)

        def one(i):
            op = Op("deposit", None, a["id"], 1, keys[i], i)
            payload = build_request(op, {})
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.wait(30)
            t0 = time.monotonic()
            try:
                s = socket.create_connection(("127.0.0.1", self.server.port), timeout=20)
            except OSError as e:
                res[i] = ("refused", repr(e), 0)
                return
            try:
                try:
                    s.sendall(payload)
                except OSError as e:
                    res[i] = ("send_failed", repr(e), 0)
                    return
                chunks = []
                try:
                    while True:
                        c = s.recv(65536)
                        if not c:
                            break
                        chunks.append(c)
                except OSError as e:
                    res[i] = ("reset_after_send", repr(e) + repr(b"".join(chunks)[:100]), time.monotonic() - t0)
                    return
                res[i] = ("response", b"".join(chunks), time.monotonic() - t0)
            finally:
                with contextlib.suppress(OSError):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
                s.close()

        old = threading.stack_size(256 * 1024)
        try:
            threads = [threading.Thread(target=one, args=(i,), daemon=True) for i in range(n)]
        finally:
            threading.stack_size(old)
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        self.settle()
        with contextlib.closing(self.server.db()) as c:
            committed = {r[0] for r in c.execute(
                "SELECT key FROM idempotency_keys WHERE account_id = ? AND scope = 'deposit'", (a["id"],))}
        counts, failures, slowest = {}, [], 0.0
        for i, (kind, data, dt) in enumerate(res):
            counts[kind] = counts.get(kind, 0) + 1
            if kind == "response":
                p = parse_response(data)
                if p is None:
                    failures.append(f"#{i} partial/non-HTTP response {data[:120]!r}")
                    continue
                st, _, body, = p
                slowest = max(slowest, dt)
                counts[st] = counts.get(st, 0) + 1
                try:
                    json.loads(body)
                except ValueError:
                    failures.append(f"#{i} non-JSON body {body[:120]!r}")
                if st == 200 and keys[i] not in committed:
                    failures.append(f"#{i} 2xx not in the ledger")
                if st != 200 and keys[i] in committed:
                    failures.append(f"#{i} {st} but committed")
                if st not in (200, 503):
                    failures.append(f"#{i} unexpected {st} {body[:120]!r}")
            elif kind == "reset_after_send" and keys[i] in committed:
                failures.append(f"#{i} LOST 2xx: committed while the client saw a reset ({data})")
            elif kind == "send_failed" and keys[i] in committed:
                failures.append(f"#{i} committed although the send failed ({data})")
        print(f"\n[a15] 1000 connections: {counts}, slowest response {slowest:.2f}s", file=sys.stderr)
        self.assertEqual(failures[:20], [], f"{len(failures)} failures; counts {counts}")
        self.assertEqual(self.server.balance(a["id"]), len(committed))
        self.assertLess(slowest, REQUEST_TIMEOUT, "I19: a response took >= 10 s")


# --------------------------------------------------------------------------------------------
@built
class Storms(C3Case):
    """200-500 writers on 2-3 accounts (short runs; the 60 s I18 runs are in SlowStorms)."""

    def test_300_writers_3_accounts_mix(self):
        self.run_driver(workers=300, n_accounts=3, seconds=8, seed=31, mode="mix")

    def test_300_writers_pure_cycles(self):
        self.run_driver(workers=300, n_accounts=3, seconds=6, seed=32, mode="cycle", initial=2000)

    def test_300_writers_one_hot_account(self):
        self.run_driver(workers=300, n_accounts=3, seconds=6, seed=33, mode="hot")

    def test_50_writers_with_racing_retries_zero_503(self):
        """50 workers, each keyed request racing its own retry: <= 100 in flight, so zero 503."""
        self.run_driver(workers=50, n_accounts=3, seconds=6, seed=34, mode="mix",
                        race_rate=1.0, keyless_rate=0.0, drop_rate=0.0, retry_rate=0.2)

    def test_100_writers_no_drops_zero_503(self):
        self.run_driver(workers=100, n_accounts=2, seconds=6, seed=35, mode="hot",
                        race_rate=0.0, drop_rate=0.0)

    def test_keyed_retries_racing_originals_200way(self):
        """100 keyed transfers each sent twice at once (200 writers): one row per key; any 503 has
        no effect and its retry settles it."""
        src, dst = self.funded(10**9, "rr-src"), self.funded(0, "rr-dst")
        tokens = {src["id"]: src["token"]}
        ops = [Op("transfer", src["id"], dst["id"], i + 1, f"rr-{uuid.uuid4().hex}", i) for i in range(100)]
        barrier = threading.Barrier(200)

        def run(op):
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.wait(10)
            return send(self.server.port, build_request(op, tokens))

        with cf.ThreadPoolExecutor(200) as ex:
            out = list(ex.map(run, [op for op in ops for _ in (0, 1)]))
        for (st, _, body, dt) in out:
            self.assertIn(st, (201, 503), body)
            self.assertLess(dt, REQUEST_TIMEOUT)
        for i, op in enumerate(ops):
            a, b = out[2 * i], out[2 * i + 1]
            if a[0] == b[0] == 201:
                self.assertEqual(a[2], b[2], "I13: original and racing retry differ")
        for op in ops:
            st, _, body, _ = send(self.server.port, build_request(op, tokens))
            self.assertEqual(st, 201, body)
        self.assertEqual(self.rows_by_amount(src["id"]), {i + 1: 1 for i in range(100)})


# --------------------------------------------------------------------------------------------
@built
class WriteChokepoint(C3Case):
    """D3.1: no write outside db.write_transaction. Runtime trace in a server process whose
    sqlite3.connect and write_transaction are wrapped: every INSERT/UPDATE/DELETE/REPLACE
    statement executed while no write_transaction is open on that thread is a violation."""

    RUNNER = r'''
import contextlib, re, runpy, sqlite3, sys, threading
sys.path.insert(0, sys.argv[1])
tl = threading.local()
WRITE = re.compile(r"^\s*(INSERT|UPDATE|DELETE|REPLACE|UPSERT)\b", re.I)
_real = sqlite3.connect
def trace(sql):
    if WRITE.match(sql or "") and not getattr(tl, "w", 0) and not getattr(tl, "init", 0):
        print("D31-VIOLATION", threading.current_thread().name, " ".join(sql.split())[:200], flush=True)
def connect(*a, **k):
    c = _real(*a, **k)
    c.set_trace_callback(trace)
    return c
sqlite3.connect = connect
import app.db as db
_wt = db.write_transaction
class Flag:
    def __init__(self, cm): self.cm = cm
    def __enter__(self):
        tl.w = getattr(tl, "w", 0) + 1
        try: return self.cm.__enter__()
        except BaseException: tl.w -= 1; raise
    def __exit__(self, *e):
        try: return self.cm.__exit__(*e)
        finally: tl.w -= 1
def wt(*a, **k):
    tl.w = getattr(tl, "w", 0) + 1
    try: res = _wt(*a, **k)
    finally: tl.w -= 1
    return Flag(res) if hasattr(res, "__enter__") else res
db.write_transaction = wt
_init = db.init_db
def init(*a, **k):
    tl.init = 1
    try: return _init(*a, **k)
    finally: tl.init = 0
db.init_db = init
print("TRACER-ARMED", flush=True)
runpy.run_module("app", run_name="__main__")
'''

    @classmethod
    def setUpClass(cls):
        import tempfile
        cls._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        runner = os.path.join(cls._tmp.name, "trace_runner.py")
        with open(runner, "w") as f:
            f.write(cls.RUNNER)

        class Traced(Server):
            def start(self):
                from breaker_harness import free_port
                self.port = free_port()
                env = dict(os.environ, PORT=str(self.port), DB_PATH=self.db_path, PYTHONUNBUFFERED="1")
                self.log = open(self.db_path + f".{self.port}.log", "wb")
                self.proc = subprocess.Popen([sys.executable, runner, STAGE_DIR], cwd=STAGE_DIR, env=env,
                                             stdout=self.log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if self.proc.poll() is not None:
                        raise RuntimeError(self.read_log())
                    with contextlib.suppress(OSError):
                        if self.request("GET", "/health", timeout=1).status == 200:
                            return self
                    time.sleep(0.05)
                raise RuntimeError(self.read_log())

        cls.server = Traced(os.path.join(cls._tmp.name, "wallet.db")).start()

    def full_log(self):
        with open(self.server.log.name, "rb") as f:
            return f.read().decode("utf-8", "replace")

    def test_every_write_path_goes_through_write_transaction(self):
        s = self.server
        a, b = s.create_account("w-a"), s.create_account("w-b")
        k = lambda: {KEY: uuid.uuid4().hex}
        s.deposit(a["id"], 100)
        s.deposit(a["id"], 100, headers=k())
        s.withdraw(a["id"], 1, a["token"])
        s.transfer(a["id"], b["id"], 1, a["token"])
        h = dict(s.auth(a["token"]), **k())
        s.request("POST", "/transfers", {"from": a["id"], "to": b["id"], "amount": 2}, headers=h)
        s.request("POST", "/transfers", {"from": a["id"], "to": b["id"], "amount": 2}, headers=h)  # replay
        s.request("POST", "/transfers", {"from": a["id"], "to": b["id"], "amount": 3}, headers=h)  # 422
        s.withdraw(a["id"], 10**9, a["token"])  # 409
        s.deposit(b["id"], 10**12)
        s.transfer(a["id"], b["id"], 1, "wrong")  # 401
        self.fire([lambda: s.transfer(a["id"], b["id"], 1, a["token"])] * 30)
        self.settle()
        log = self.full_log()
        self.assertIn("TRACER-ARMED", log)
        bad = [ln for ln in log.splitlines() if ln.startswith("D31-VIOLATION")]
        self.assertEqual(bad, [], "D3.1: write statement outside write_transaction")
        self.assertNotIn("internal error", log)

    def test_static_no_second_write_path(self):
        """No module but db.py opens connections or runs BEGIN/COMMIT/executescript."""
        app_dir = os.path.join(STAGE_DIR, "app")
        hits = []
        pat = re.compile(r"sqlite3\.connect\(|\bBEGIN\b|\bCOMMIT\b|executescript|\.commit\(\)|isolation_level\s*=")
        for name in sorted(os.listdir(app_dir)):
            if not name.endswith(".py") or name == "db.py":
                continue
            with open(os.path.join(app_dir, name), encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    code = line.split("#", 1)[0]
                    if pat.search(code) and not code.strip().startswith(('"', "'")):
                        hits.append(f"{name}:{n}: {line.strip()}")
        self.assertEqual(hits, [], "D3.1: transaction control outside app/db.py")


# --------------------------------------------------------------------------------------------
@built
@slow
class SlowStorms(C3Case):
    def test_i18_60s_250_writers_8_accounts(self):
        self.run_driver(workers=250, n_accounts=8, seconds=60, seed=41, mode="mix")

    def test_500_writers_2_accounts_30s(self):
        self.run_driver(workers=500, n_accounts=2, seconds=30, seed=42, mode="mix")

    def test_400_writers_cycles_and_hot_20s(self):
        self.run_driver(workers=400, n_accounts=3, seconds=20, seed=43, mode="cycle", initial=1000)
        self.run_driver(workers=400, n_accounts=3, seconds=20, seed=44, mode="hot")

    def test_100_writers_60s_zero_503(self):
        self.run_driver(workers=100, n_accounts=4, seconds=60, seed=45, mode="mix",
                        race_rate=0.0, drop_rate=0.0)


@built
@slow
class CrashUnderStress(C3Case):
    def test_kill9_mid_stress_then_retry_every_key(self):
        """I21: SIGKILL during a 300-writer keyed storm; restart on the same DB; I1/I3/I7 hold;
        retrying every key ever sent (twice) moves money at most once per key in total."""
        d = Driver(self.server, workers=300, n_accounts=4, seconds=0, seed=51, mode="mix",
                   keyless_rate=0.0, crash_tolerant=True, tag="crash")
        d.run(kill_at=4.0)
        d.resolve(retry_all=True)
        n_first = len(d.results)
        d.resolve(retry_all=True)
        second = [r for r in d.results[n_first:]]
        summary = d.check()
        print(f"\n[a15 crash] {json.dumps({k: v for k, v in summary.items() if k != 'violations'})}",
              file=sys.stderr)
        self.assertEqual(summary["violations"], [], summary)
        # the second full retry pass: every key that has a 2xx anywhere now replays
        ok_keys = {r[0].key for r in d.results[:n_first] if r[1] in (200, 201)}
        not_replayed = [r[0] for r in second if r[0].key in ok_keys and not r[4]]
        self.assertEqual(not_replayed[:5], [], "I12/I21: a committed key was not replayed on retry")


@built
@slow
class BuilderHarnessHostile(unittest.TestCase):
    """Note 5: the Builder's stress/run_stress.py with hostile parameters must exit 0 on a correct
    build (non-zero only on a real violation) and its summary must agree."""

    def run_it(self, *args):
        p = subprocess.run([sys.executable, os.path.join("stress", "run_stress.py"), *args],
                           cwd=STAGE_DIR, capture_output=True, text=True, timeout=600)
        print(f"\n[a15 run_stress {' '.join(args)}] rc={p.returncode}\n{p.stdout[-3000:]}\n{p.stderr[-2000:]}",
              file=sys.stderr)
        return p

    def test_500_workers_2_accounts(self):
        p = self.run_it("--workers", "500", "--accounts", "2", "--seconds", "30", "--seed", "7")
        self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr[-2000:])

    def test_1_account(self):
        p = self.run_it("--workers", "200", "--accounts", "1", "--seconds", "10", "--seed", "8")
        self.assertIn(p.returncode, (0, 2), "a degenerate account set must be refused or survived, not crash")
        self.assertNotIn("Traceback", p.stderr)


@built
@unittest.skipUnless(DOCKER, "set ATTACK_DOCKER=1")
class DockerZeroBusy(unittest.TestCase):
    """Q3-C: zero 503 at <= 100 writers also in the container, DB on the container filesystem."""

    def test_exact_drains_in_container(self):
        tag = "pocketful:stage-3-a15"
        b = subprocess.run(["docker", "build", "--network=none", "-t", tag, STAGE_DIR],
                           capture_output=True, text=True, timeout=900)
        self.assertEqual(b.returncode, 0, b.stderr[-3000:])
        r = subprocess.run(["docker", "run", "--rm", "--network=none", "-e", "ATTACK_FORCE_3=1",
                            "-w", "/srv/attacks", tag, "python", "-m", "unittest", "-v",
                            "test_a15_concurrency_3_1.ExactDrains", "test_a15_concurrency_3_1.ArrivalOrder"],
                           capture_output=True, text=True, timeout=900)
        self.assertEqual(r.returncode, 0, r.stderr[-4000:])


if __name__ == "__main__":
    unittest.main()
