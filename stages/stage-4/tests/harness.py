"""Test harness: runs `python -m app` as a real subprocess on a free port
against a temporary database, and talks to it over HTTP."""

import http.client
import json
import os
import queue
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

STAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
START_TIMEOUT_S = 10
CLIENT_TIMEOUT_S = 10


class ServerProcess:
    def __init__(self, db_path):
        self.db_path = db_path
        self.proc = None
        self.port = None
        self._stderr = None

    def start(self):
        env = dict(os.environ, PORT="0", DB_PATH=self.db_path)
        env.pop("LOG_REQUESTS", None)
        self._stderr = tempfile.TemporaryFile()
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "app"],
            cwd=STAGE_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            text=True,
        )
        lines = queue.Queue()
        threading.Thread(
            target=lambda: lines.put(self.proc.stdout.readline()), daemon=True
        ).start()
        try:
            line = lines.get(timeout=START_TIMEOUT_S)
        except queue.Empty:
            line = ""
        if not line.startswith("LISTENING "):
            self.stop_process_only()
            err = self.stderr()
            self.stop()
            raise RuntimeError(f"server did not start: {line!r} {err!r}")
        self.port = int(line.split()[2])
        return self

    def stderr(self):
        if self._stderr is None:
            return ""
        self._stderr.seek(0)
        return self._stderr.read().decode("utf-8", "replace")

    def stop(self):
        self.stop_process_only()
        if self.proc and self.proc.stdout:
            self.proc.stdout.close()
        if self._stderr is not None:
            self._stderr.close()
            self._stderr = None

    def kill(self):
        """Hard kill (SIGKILL / TerminateProcess): no graceful shutdown."""
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.stop()

    def stop_process_only(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def request(self, method, path, body=None, headers=None, raw=None):
        """Send a request. `body` is JSON-encoded; `raw` is sent as-is.
        Returns (status, parsed JSON or None)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=CLIENT_TIMEOUT_S)
        try:
            data = raw if raw is not None else (
                None if body is None else json.dumps(body).encode("utf-8")
            )
            hdrs = {"Content-Type": "application/json"}
            hdrs.update(headers or {})
            conn.request(method, path, body=data, headers=hdrs)
            resp = conn.getresponse()
            payload = resp.read()
            try:
                parsed = json.loads(payload) if payload else None
            except ValueError:
                parsed = payload
            return resp.status, parsed
        finally:
            conn.close()


class ServerTestCase(unittest.TestCase):
    """One fresh database and server per test class."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="pocketful-test-")
        cls.db_path = os.path.join(cls.tmpdir, "wallet.db")
        cls.server = ServerProcess(cls.db_path).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def request(self, *args, **kwargs):
        return self.server.request(*args, **kwargs)

    def query(self, sql, params=()):
        """Independent read of the SQLite file, bypassing the service."""
        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=5)
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def account_count(self):
        return self.query("SELECT count(*) FROM accounts")[0][0]

    def create_account(self, owner="alice"):
        status, body = self.request("POST", "/accounts", {"owner": owner})
        self.assertEqual(status, 201, body)
        return body

    # --- money helpers (unit 1.2) --------------------------------------

    def deposit(self, account_id, amount):
        return self.request("POST", f"/accounts/{account_id}/deposit", {"amount": amount})

    def withdraw(self, account_id, amount, token):
        return self.request("POST", f"/accounts/{account_id}/withdraw", {"amount": amount},
                            headers={"Authorization": f"Bearer {token}"})

    def transfer(self, from_id, to_id, amount, token):
        return self.request("POST", "/transfers", {"from": from_id, "to": to_id, "amount": amount},
                            headers={"Authorization": f"Bearer {token}"})

    def fill_to(self, account_id, chunk, count, workers=16):
        """Setup only: `count` concurrent deposits of `chunk`. A 503 busy has
        no effect by contract, so it is retried; anything else must be 200."""
        def one(_):
            while True:
                result = self.deposit(account_id, chunk)
                if result != (503, {"error": "busy"}):
                    return result

        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(one, range(count)))
        self.assertEqual([r for r in results if r[0] != 200], [])

    def funded_account(self, amount, owner="funded"):
        account = self.create_account(owner)
        if amount:
            status, body = self.deposit(account["id"], amount)
            self.assertEqual(status, 200, body)
        return account

    def balance(self, account_id):
        return self.query("SELECT balance FROM accounts WHERE id = ?", (account_id,))[0][0]

    def snapshot(self):
        """Every row of every table, order-independent (I6)."""
        tables = [name for (name,) in self.query(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
        return {t: sorted(map(repr, self.query(f'SELECT * FROM "{t}"'))) for t in tables}

    def assertRejectedFree(self, call, status, error):
        """I6: the call is rejected with status/error and changes no row."""
        before = self.snapshot()
        result = call()
        self.assertEqual(result, (status, {"error": error}))
        self.assertEqual(self.snapshot(), before, f"I6: rejection changed the DB: {result}")

    def assertMoneyInvariants(self):
        """I1 (via /audit and an independent query), I3, I5 and I7."""
        status, audit = self.request("GET", "/audit")
        self.assertEqual(status, 200, audit)
        balances, deposits, withdrawals = self.query(
            "SELECT (SELECT coalesce(sum(balance), 0) FROM accounts),"
            " (SELECT coalesce(sum(amount), 0) FROM external_moves WHERE kind = 'deposit'),"
            " (SELECT coalesce(sum(amount), 0) FROM external_moves WHERE kind = 'withdrawal')")[0]
        self.assertEqual(balances, deposits - withdrawals, "I1: DB not conserved")
        self.assertIs(audit["conserved"], True, f"I1: {audit}")
        self.assertEqual(audit["total_balances"],
                         audit["total_deposits"] - audit["total_withdrawals"], f"I1: {audit}")
        for key in ("total_balances", "total_deposits", "total_withdrawals"):
            self.assertIs(type(audit[key]), int, key)
        self.assertEqual(self.query("SELECT count(*) FROM accounts WHERE balance < 0"), [(0,)],
                         "I3: negative balance")
        for table, column in (("accounts", "balance"), ("external_moves", "amount"),
                              ("transfers", "amount")):
            self.assertEqual(
                self.query(f"SELECT count(*) FROM {table} WHERE typeof({column}) != 'integer'"),
                [(0,)], f"I5: non-integer {table}.{column}")
        mismatched = self.query("""
            SELECT a.id, a.balance, replay FROM (
              SELECT a.id, a.balance,
                coalesce((SELECT sum(amount) FROM external_moves
                          WHERE account_id = a.id AND kind = 'deposit'), 0)
              - coalesce((SELECT sum(amount) FROM external_moves
                          WHERE account_id = a.id AND kind = 'withdrawal'), 0)
              + coalesce((SELECT sum(amount) FROM transfers WHERE to_id = a.id), 0)
              - coalesce((SELECT sum(amount) FROM transfers WHERE from_id = a.id), 0) AS replay
              FROM accounts a) AS a
            WHERE a.balance != replay""")
        self.assertEqual(mismatched, [], "I7: balance != ledger replay")
