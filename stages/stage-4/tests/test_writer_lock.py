"""Unit 3.1, D3.1 + D3.2: the write chokepoint and the FIFO writer lock,
checked by importing app.db directly (Q3-D), plus the lock state seen from
an in-process server after rejected writes."""

import ast
import glob
import http.client
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

from harness import STAGE_DIR

if STAGE_DIR not in sys.path:
    sys.path.insert(0, STAGE_DIR)

from app import db  # noqa: E402
from app.server import WalletServer  # noqa: E402

WAIT_S = 5


def wait_until(predicate, timeout=WAIT_S, what="condition"):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.002)


class TempDbCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="pocketful-lock-")
        self.db_path = os.path.join(self.tmpdir, "wallet.db")
        db.init_db(self.db_path)
        self.assertFalse(db.WRITER_LOCK.locked(), "writer lock leaked into this test")
        self.assertEqual(db.WRITER_LOCK.waiting(), 0)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def connect(self):
        conn = db.connect(self.db_path)
        self.addCleanup(conn.close)
        return conn

    def accounts(self):
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute("SELECT owner FROM accounts ORDER BY rowid").fetchall()
        finally:
            conn.close()

    @staticmethod
    def insert(conn, owner):
        conn.execute(
            "INSERT INTO accounts (id, owner, token_hash) VALUES (lower(hex(randomblob(18))), ?, ?)",
            (owner, "0" * 64))


# --- D3.1 one write chokepoint -------------------------------------------

class WriteChokepointTest(TempDbCase):
    WRITES = {
        "insert": "INSERT INTO accounts (id, owner, token_hash) VALUES ('{}', 'x', '{}')".format(
            "a" * 36, "0" * 64),
        "update": "UPDATE accounts SET balance = balance + 1",
        "delete": "DELETE FROM idempotency_keys",
        "create": "CREATE TABLE sneaky (x INTEGER)",
        "drop": "DROP INDEX transfers_from",
        "temp table": "CREATE TEMP TABLE sneaky (x INTEGER)",
    }

    def test_every_write_outside_write_transaction_is_refused(self):
        conn = self.connect()
        for name, sql in self.WRITES.items():
            with self.subTest(write=name):
                with self.assertRaises(sqlite3.DatabaseError) as ctx:
                    conn.execute(sql)
                self.assertIn("not authorized", str(ctx.exception))
        self.assertEqual(self.accounts(), [])

    def test_explicit_transaction_outside_the_chokepoint_cannot_write(self):
        conn = self.connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                self.insert(conn, "bypass")
        finally:
            conn.execute("ROLLBACK")
        self.assertEqual(self.accounts(), [])

    def test_writes_inside_are_allowed_and_refused_again_after(self):
        conn = self.connect()
        with db.write_transaction(conn):
            self.insert(conn, "inside")
        self.assertEqual(self.accounts(), [("inside",)])
        # The same SQL text again, after the block: not served from a cache
        # that was prepared while writing was allowed.
        with self.assertRaises(sqlite3.DatabaseError):
            self.insert(conn, "after")
        with self.assertRaises(ValueError):
            with db.write_transaction(conn):
                self.insert(conn, "rolled back")
                raise ValueError("rejection")
        with self.assertRaises(sqlite3.DatabaseError):
            self.insert(conn, "after failure")
        self.assertEqual(self.accounts(), [("inside",)])

    def test_reads_are_allowed_everywhere(self):
        conn = self.connect()
        self.assertEqual(conn.execute("SELECT count(*) FROM accounts").fetchone(), (0,))

    def test_no_app_module_opens_sqlite_or_bypasses_the_authorizer(self):
        """Static guard: every connection comes from db.connect (which
        installs the authorizer), and only db.py may touch the authorizer,
        the writable flag, or executescript."""
        offenders = []
        for path in sorted(glob.glob(os.path.join(STAGE_DIR, "app", "*.py"))):
            if os.path.basename(path) == "db.py":
                continue
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), path)
            for node in ast.walk(tree):
                name = None
                if isinstance(node, ast.Attribute):
                    name = node.attr
                elif isinstance(node, ast.Name):
                    name = node.id
                if name in ("set_authorizer", "writable", "executescript", "Connection",
                            "WRITER_LOCK", "_Connection"):
                    offenders.append(f"{os.path.basename(path)}:{node.lineno} {name}")
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "connect"
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "sqlite3"):
                    offenders.append(f"{os.path.basename(path)}:{node.lineno} sqlite3.connect")
        self.assertEqual(offenders, [])


# --- D3.2 FIFO writer lock -----------------------------------------------

class FifoLockTest(unittest.TestCase):
    def queue_threads(self, lock, count, timeout=WAIT_S, record=None):
        """Start `count` threads that acquire `lock`, one at a time, each
        only after the previous one is visibly queued."""
        order, threads = record if record is not None else [], []

        def worker(n):
            if lock.acquire(timeout):
                order.append(n)
                lock.release()

        for n in range(count):
            thread = threading.Thread(target=worker, args=(n,))
            thread.start()
            threads.append(thread)
            wait_until(lambda: lock.waiting() == n + 1, what=f"waiter {n} queued")
        return order, threads

    def test_waiters_acquire_in_arrival_order(self):
        lock = db.FifoLock()
        self.assertTrue(lock.acquire(1))
        order, threads = self.queue_threads(lock, 30)
        lock.release()
        for thread in threads:
            thread.join(WAIT_S)
        self.assertEqual(order, list(range(30)))
        self.assertFalse(lock.locked())
        self.assertEqual(lock.waiting(), 0)

    def test_timed_out_waiter_leaves_no_ticket(self):
        lock = db.FifoLock()
        self.assertTrue(lock.acquire(1))
        start = time.monotonic()
        self.assertFalse(lock.acquire(0.2))
        self.assertGreaterEqual(time.monotonic() - start, 0.2)
        self.assertEqual(lock.waiting(), 0)
        lock.release()
        self.assertFalse(lock.locked())
        # No ghost ticket ahead of the next caller: immediate acquire.
        self.assertTrue(lock.acquire(0.05))
        lock.release()

    def test_timed_out_head_does_not_wedge_the_waiter_behind_it(self):
        lock = db.FifoLock()
        self.assertTrue(lock.acquire(1))
        head_result = []
        head = threading.Thread(target=lambda: head_result.append(lock.acquire(0.3)))
        head.start()
        wait_until(lambda: lock.waiting() == 1, what="head queued")
        got = threading.Event()

        def second():
            if lock.acquire(WAIT_S):
                got.set()
                lock.release()

        behind = threading.Thread(target=second)
        behind.start()
        wait_until(lambda: lock.waiting() == 2, what="second queued")
        head.join(WAIT_S)
        self.assertEqual(head_result, [False])
        self.assertEqual(lock.waiting(), 1, "the timed-out head left its ticket behind")
        lock.release()
        self.assertTrue(got.wait(1), "a timed-out waiter wedged the queue")
        behind.join(WAIT_S)
        self.assertFalse(lock.locked())
        self.assertEqual(lock.waiting(), 0)

    def test_head_timing_out_after_release_hands_over(self):
        """The holder releases while the head is giving up: the waiter
        behind must still get the lock promptly."""
        lock = db.FifoLock()
        for _ in range(20):
            self.assertTrue(lock.acquire(1))
            head = threading.Thread(target=lambda: lock.acquire(0.05) and lock.release())
            head.start()
            wait_until(lambda: lock.waiting() == 1, what="head queued")
            got = threading.Event()
            behind = threading.Thread(
                target=lambda: lock.acquire(WAIT_S) and (got.set(), lock.release()))
            behind.start()
            wait_until(lambda: lock.waiting() == 2, what="second queued")
            time.sleep(0.05)  # release right around the head's deadline
            lock.release()
            self.assertTrue(got.wait(1), "the waiter behind a timed-out head was wedged")
            head.join(WAIT_S)
            behind.join(WAIT_S)
            self.assertFalse(lock.locked())
            self.assertEqual(lock.waiting(), 0)


class WriteTransactionLockTest(TempDbCase):
    def hold_writer_lock(self):
        """Enter write_transaction on another thread and stay inside until
        the returned event is set."""
        inside, leave = threading.Event(), threading.Event()

        def holder():
            conn = db.connect(self.db_path)
            try:
                with db.write_transaction(conn):
                    inside.set()
                    leave.wait(WAIT_S * 2)
            finally:
                conn.close()

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(inside.wait(WAIT_S))
        self.addCleanup(thread.join, WAIT_S)
        self.addCleanup(leave.set)
        return leave, thread

    def test_writers_commit_in_the_order_they_reached_the_lock(self):
        """The writer lock is taken before BEGIN IMMEDIATE: with SQLite's
        busy handler in front instead, the waiters would never be queued on
        WRITER_LOCK and the order would be arbitrary."""
        leave, holder = self.hold_writer_lock()
        threads = []
        for n in range(20):
            def writer(n=n):
                conn = db.connect(self.db_path)
                try:
                    with db.write_transaction(conn):
                        self.insert(conn, f"w{n:02d}")
                finally:
                    conn.close()
            thread = threading.Thread(target=writer)
            thread.start()
            threads.append(thread)
            wait_until(lambda: db.WRITER_LOCK.waiting() == n + 1, what=f"writer {n} queued")
        leave.set()
        holder.join(WAIT_S)
        for thread in threads:
            thread.join(WAIT_S)
        self.assertEqual(self.accounts(), [(f"w{n:02d}",) for n in range(20)])
        self.assertFalse(db.WRITER_LOCK.locked())

    def test_lock_timeout_is_busy_with_no_effect_and_no_ticket(self):
        leave, holder = self.hold_writer_lock()
        conn = self.connect()
        original = db.WRITER_LOCK_TIMEOUT_S
        db.WRITER_LOCK_TIMEOUT_S = 0.3
        try:
            start = time.monotonic()
            with self.assertRaises(db.Busy):
                with db.write_transaction(conn):
                    self.insert(conn, "must not happen")
            self.assertLess(time.monotonic() - start, 2)
        finally:
            db.WRITER_LOCK_TIMEOUT_S = original
        self.assertFalse(conn.in_transaction)
        self.assertEqual(db.WRITER_LOCK.waiting(), 0, "timed-out waiter left a ticket")
        leave.set()
        holder.join(WAIT_S)
        self.assertEqual(self.accounts(), [])
        # The next writer is not wedged by the one that timed out.
        start = time.monotonic()
        with db.write_transaction(conn):
            self.insert(conn, "next")
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(self.accounts(), [("next",)])

    def test_default_lock_timeout_is_four_seconds(self):
        self.assertEqual(db.WRITER_LOCK_TIMEOUT_S, 4.0)
        self.assertEqual(db.BUSY_TIMEOUT_MS, 3000)  # Q3.1-A
        conn = self.connect()
        self.assertEqual(conn.execute("PRAGMA busy_timeout").fetchone(), (3000,))

    def test_exception_inside_releases_the_lock_and_rolls_back(self):
        conn = self.connect()
        for exc in (ValueError("rejected"), KeyboardInterrupt(), sqlite3.IntegrityError("x")):
            with self.subTest(exc=type(exc).__name__):
                with self.assertRaises(type(exc)):
                    with db.write_transaction(conn):
                        self.insert(conn, "rolled back")
                        raise exc
                self.assertFalse(db.WRITER_LOCK.locked())
                self.assertFalse(conn.in_transaction)
        self.assertEqual(self.accounts(), [])

    def test_sqlite_busy_at_begin_releases_the_lock(self):
        """Another process holds the SQLite write lock past busy_timeout:
        BEGIN IMMEDIATE fails, and the writer lock must not stay held."""
        other = sqlite3.connect(self.db_path, isolation_level=None)
        other.execute("BEGIN IMMEDIATE")
        try:
            conn = self.connect()
            conn.execute("PRAGMA busy_timeout = 100")
            with self.assertRaises(sqlite3.OperationalError):
                with db.write_transaction(conn):
                    self.insert(conn, "never")
            self.assertFalse(db.WRITER_LOCK.locked())
            self.assertEqual(db.WRITER_LOCK.waiting(), 0)
        finally:
            other.execute("ROLLBACK")
            other.close()
        with db.write_transaction(conn):
            self.insert(conn, "after")
        self.assertEqual(self.accounts(), [("after",)])


# --- the lock seen from a live (in-process) server ------------------------

class InProcessServer:
    def __init__(self, db_path, **kwargs):
        self.server = WalletServer(("127.0.0.1", 0), db_path, **kwargs)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=None if body is None else json.dumps(body),
                         headers=headers or {})
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read())
        finally:
            conn.close()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(WAIT_S)


class RejectedWriteReleasesLockTest(TempDbCase):
    def setUp(self):
        super().setUp()
        self.live = InProcessServer(self.db_path)
        self.addCleanup(self.live.stop)

    def assertLockFree(self, what):
        self.assertFalse(db.WRITER_LOCK.locked(), f"writer lock held after {what}")
        self.assertEqual(db.WRITER_LOCK.waiting(), 0, f"ticket left after {what}")

    def test_lock_not_held_after_409_and_422(self):
        r = self.live.request
        status, a = r("POST", "/accounts", {"owner": "a"})
        self.assertEqual(status, 201)
        status, b = r("POST", "/accounts", {"owner": "b"})
        self.assertEqual(status, 201)
        self.assertLockFree("account creation")
        auth_a = {"Authorization": f"Bearer {a['token']}"}
        self.assertEqual(r("POST", f"/accounts/{a['id']}/deposit", {"amount": 10}),
                         (200, {"id": a["id"], "balance": 10}))
        cases = [
            ("withdraw 409", ("POST", f"/accounts/{a['id']}/withdraw", {"amount": 11}, auth_a),
             (409, {"error": "insufficient_funds"})),
            ("transfer 409", ("POST", "/transfers", {"from": a["id"], "to": b["id"], "amount": 11},
                              auth_a), (409, {"error": "insufficient_funds"})),
            ("deposit 422 balance_limit",
             ("POST", f"/accounts/{b['id']}/deposit", {"amount": 10**12}, None), None),
            ("deposit 404 inside the transaction",
             ("POST", "/accounts/00000000-0000-4000-8000-000000000000/deposit", {"amount": 1},
              None), (404, {"error": "account_not_found"})),
            ("idempotency 422",
             ("POST", f"/accounts/{a['id']}/withdraw", {"amount": 2},
              dict(auth_a, **{"Idempotency-Key": "k1"})), (422, {"error": "idempotency_key_reused"})),
        ]
        # Make the 422 cases reachable: b at the balance limit, k1 used. The
        # schema caps one move at MAX_AMOUNT, so b's MAX_BALANCE is backed by
        # MAX_BALANCE / MAX_AMOUNT deposit rows, which keeps I1 conserved.
        conn = self.connect()
        with db.write_transaction(conn):
            conn.execute("UPDATE accounts SET balance = ? WHERE id = ?", (db.MAX_BALANCE, b["id"]))
            conn.executemany("INSERT INTO external_moves (id, account_id, kind, amount) "
                             "VALUES (lower(hex(randomblob(18))), ?, 'deposit', ?)",
                             [(b["id"], db.MAX_AMOUNT)] * (db.MAX_BALANCE // db.MAX_AMOUNT))
        self.assertEqual(r("GET", "/audit")[1]["conserved"], True)
        self.assertEqual(r("POST", f"/accounts/{a['id']}/withdraw", {"amount": 1},
                           dict(auth_a, **{"Idempotency-Key": "k1"}))[0], 200)
        for name, args, expected in cases:
            with self.subTest(case=name):
                status, body = r(*args)
                if expected is None:
                    self.assertEqual((status, body), (422, {"error": "balance_limit"}))
                else:
                    self.assertEqual((status, body), expected)
                self.assertLockFree(name)
        # And a write right behind them is served at once.
        start = time.monotonic()
        self.assertEqual(r("POST", f"/accounts/{a['id']}/deposit", {"amount": 1})[0], 200)
        self.assertLess(time.monotonic() - start, 1)
        self.assertLockFree("the final deposit")

    def test_writer_lock_timeout_is_503_busy_with_no_effect(self):
        r = self.live.request
        status, a = r("POST", "/accounts", {"owner": "a"})
        self.assertEqual(status, 201)
        before = self.accounts()
        original = db.WRITER_LOCK_TIMEOUT_S
        db.WRITER_LOCK_TIMEOUT_S = 0.3
        self.assertTrue(db.WRITER_LOCK.acquire(1))
        try:
            self.assertEqual(r("POST", "/accounts", {"owner": "late"}), (503, {"error": "busy"}))
            self.assertEqual(r("POST", f"/accounts/{a['id']}/deposit", {"amount": 5},
                               {"Idempotency-Key": "k"}), (503, {"error": "busy"}))
            # Readers never take the writer lock.
            self.assertEqual(r("GET", f"/accounts/{a['id']}")[0], 200)
            self.assertEqual(r("GET", "/audit")[0], 200)
        finally:
            db.WRITER_LOCK.release()
            db.WRITER_LOCK_TIMEOUT_S = original
        self.assertEqual(self.accounts(), before)
        self.assertLockFree("503s")
        # The key was not consumed by the 503 (I15).
        self.assertEqual(r("POST", f"/accounts/{a['id']}/deposit", {"amount": 5},
                           {"Idempotency-Key": "k"}), (200, {"id": a["id"], "balance": 5}))


if __name__ == "__main__":
    unittest.main()
