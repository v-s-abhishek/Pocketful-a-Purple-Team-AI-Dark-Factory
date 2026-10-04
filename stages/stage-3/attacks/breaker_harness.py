"""Breaker attack harness (owned by the Breaker seat; grows only).

Self-contained on purpose: it does not import the Builder's test helpers or the
app package, so a bug in either cannot mask an attack. It starts the service as
a real subprocess (`python -m app`) on a free port against a throwaway DB, talks
to it over raw HTTP, and checks invariants by reading the SQLite file directly.

Env knobs:
  ATTACK_STAGE_DIR   stage folder to attack (default: parent of this file)
  ATTACK_SLOW=1      enable the long-running attacks (sustained load, kill bursts)
  ATTACK_DOCKER=1    enable the no-network docker build/run attack (I9)
"""
import contextlib
import http.client
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

STAGE_DIR = os.path.abspath(
    os.environ.get("ATTACK_STAGE_DIR") or os.path.join(os.path.dirname(__file__), "..")
)
SLOW = os.environ.get("ATTACK_SLOW") == "1"
DOCKER = os.environ.get("ATTACK_DOCKER") == "1"

REQUEST_TIMEOUT = 10.0  # I11: nothing may take longer than this
MAX_AMOUNT = 10**12
MAX_BALANCE = 10**15
MAX_BODY = 16 * 1024
NO_RESPONSE = 599  # harness sentinel: connection dropped/reset/timed out before a response


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Response:
    def __init__(self, status, headers, raw):
        self.status = status
        self.headers = headers
        self.raw = raw
        try:
            self.json = json.loads(raw) if raw else None
        except ValueError:
            self.json = None

    @property
    def error(self):
        return self.json.get("error") if isinstance(self.json, dict) else None

    def __repr__(self):
        return f"<{self.status} {self.raw[:300]!r}>"


class Server:
    """One service process bound to one DB file. Restartable on the same DB."""

    def __init__(self, db_path):
        self.db_path = db_path
        self.proc = None
        self.port = None

    def start(self):
        self.port = free_port()
        env = dict(os.environ, PORT=str(self.port), DB_PATH=self.db_path,
                   PYTHONUNBUFFERED="1")
        self.log = open(self.db_path + f".{self.port}.log", "wb")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "app"], cwd=STAGE_DIR, env=env,
            stdout=self.log, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 10  # I9: healthy within 10 s
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"server exited early rc={self.proc.returncode}: {self.read_log()}")
            try:
                if self.request("GET", "/health", timeout=1).status == 200:
                    return self
            except OSError:
                pass
            time.sleep(0.05)
        self.kill()
        raise RuntimeError(f"server not healthy within 10s: {self.read_log()}")

    def kill(self):
        """Hard kill (SIGKILL / TerminateProcess): no graceful shutdown."""
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(10)
        if getattr(self, "log", None):
            self.log.close()

    def restart(self):
        self.kill()
        return self.start()

    def read_log(self):
        try:
            with open(self.log.name, "rb") as f:
                return f.read()[-4000:].decode("utf-8", "replace")
        except OSError:
            return ""

    # -- HTTP ---------------------------------------------------------------
    def request(self, method, path, body=None, headers=None, raw=None, timeout=REQUEST_TIMEOUT):
        """`body` is JSON-encoded; `raw` (bytes) is sent verbatim instead."""
        hdrs = {"Content-Type": "application/json"}
        hdrs.update(headers or {})
        data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request(method, path, body=data, headers=hdrs)
            r = conn.getresponse()
            return Response(r.status, dict(r.getheaders()), r.read())
        except (OSError, http.client.HTTPException) as exc:
            # a dropped/reset connection is a result to assert on, not a harness crash
            # 599 (not 0) so every `status < 500` assertion counts it as a failure
            return Response(NO_RESPONSE, {}, f"<no response: {exc!r}>".encode())
        finally:
            conn.close()

    def raw_http(self, payload, timeout=REQUEST_TIMEOUT):
        """Send a hand-built HTTP request; return (status or None, raw bytes)."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as s:
            s.sendall(payload)
            chunks = []
            with contextlib.suppress(socket.timeout, ConnectionError):
                while True:
                    c = s.recv(65536)
                    if not c:
                        break
                    chunks.append(c)
        data = b"".join(chunks)
        status = None
        if data.startswith(b"HTTP/"):
            with contextlib.suppress(ValueError, IndexError):
                status = int(data.split(b" ", 2)[1])
        return status, data

    # -- API shortcuts ------------------------------------------------------
    def create_account(self, owner="attacker"):
        r = self.request("POST", "/accounts", {"owner": owner})
        assert r.status == 201, r
        return r.json

    def auth(self, token):
        return {"Authorization": f"Bearer {token}"}

    def deposit(self, acct_id, amount, **kw):
        return self.request("POST", f"/accounts/{acct_id}/deposit", {"amount": amount}, **kw)

    def withdraw(self, acct_id, amount, token, **kw):
        return self.request("POST", f"/accounts/{acct_id}/withdraw", {"amount": amount},
                            headers=self.auth(token), **kw)

    def transfer(self, src, dst, amount, token, **kw):
        return self.request("POST", "/transfers", {"from": src, "to": dst, "amount": amount},
                            headers=self.auth(token), **kw)

    def balance(self, acct_id):
        r = self.request("GET", f"/accounts/{acct_id}")
        assert r.status == 200, r
        return r.json["balance"]

    def has_route(self, method, path, body=None, headers=None):
        """A route exists if it does not answer the generic 404 `not_found`."""
        r = self.request(method, path, body, headers=headers)
        return not (r.status == 404 and r.error == "not_found")

    # -- direct DB inspection ------------------------------------------------
    def db(self):
        uri = "file:" + self.db_path.replace("\\", "/") + "?mode=ro"
        c = sqlite3.connect(uri, uri=True, timeout=10)
        return c

    def tables(self):
        with contextlib.closing(self.db()) as c:
            return [r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]

    def snapshot(self):
        """Every row of every table, order-independent. Used for I6."""
        snap = {}
        with contextlib.closing(self.db()) as c:
            for t in self.tables():
                rows = c.execute(f'SELECT * FROM "{t}"').fetchall()
                snap[t] = sorted(map(repr, rows))
        return snap


class AttackCase(unittest.TestCase):
    """One fresh server + DB per test class. Invariant sweep after every test."""

    server = None

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.server = Server(os.path.join(cls._tmp.name, "wallet.db")).start()

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.kill()
        cls._tmp.cleanup()

    def tearDown(self):
        # the process must still be up and answering after every attack (I11)
        s = self.server
        if s.proc.poll() is not None:
            self.fail(f"server died during attack: {s.read_log()}")
        self.assertEqual(s.request("GET", "/health").status, 200, "server stopped answering")
        self.check_invariants()

    # -- invariant sweep ------------------------------------------------------
    def check_invariants(self):
        s = self.server
        with contextlib.closing(s.db()) as c:
            cols = {r[1] for r in c.execute("PRAGMA table_info(accounts)")}
            if "balance" in cols:
                neg = c.execute("SELECT count(*) FROM accounts WHERE balance < 0").fetchone()[0]
                self.assertEqual(neg, 0, "I3: negative balance in DB")
                bad = c.execute(
                    "SELECT count(*) FROM accounts WHERE typeof(balance) != 'integer'").fetchone()[0]
                self.assertEqual(bad, 0, "I5: non-integer balance stored")
                over = c.execute("SELECT count(*) FROM accounts WHERE balance > ?", (MAX_BALANCE,)).fetchone()[0]
                self.assertEqual(over, 0, "balance above 10^15 limit")
            for t in s.tables():
                for col in [r[1] for r in c.execute(f'PRAGMA table_info("{t}")')]:
                    if col in ("amount", "balance"):
                        n = c.execute(f'SELECT count(*) FROM "{t}" WHERE typeof("{col}") NOT IN (\'integer\')').fetchone()[0]
                        self.assertEqual(n, 0, f"I5: non-integer {t}.{col}")
        self.check_ledger_replay()
        if s.has_route("GET", "/audit"):
            a = s.request("GET", "/audit")
            self.assertEqual(a.status, 200, a)
            self.assertIs(a.json.get("conserved"), True, f"I1: audit not conserved: {a.json}")
            self.assertEqual(a.json["total_balances"],
                             a.json["total_deposits"] - a.json["total_withdrawals"],
                             f"I1: audit arithmetic: {a.json}")

    def check_ledger_replay(self):
        """I7: every balance == deposits - withdrawals + transfers in - transfers out, replayed
        from the ledger tables (names fixed by the Architect: transfers, external_moves)."""
        tables = set(self.server.tables())
        if not {"transfers", "external_moves"} <= tables:
            return
        with contextlib.closing(self.server.db()) as c:
            bad = c.execute("""
                SELECT a.id, a.balance,
                  coalesce((SELECT sum(amount) FROM external_moves WHERE account_id = a.id AND kind = 'deposit'), 0)
                - coalesce((SELECT sum(amount) FROM external_moves WHERE account_id = a.id AND kind = 'withdrawal'), 0)
                + coalesce((SELECT sum(amount) FROM transfers WHERE to_id = a.id), 0)
                - coalesce((SELECT sum(amount) FROM transfers WHERE from_id = a.id), 0) AS replay
                FROM accounts a
            """).fetchall()
            kinds = {r[0] for r in c.execute("SELECT DISTINCT kind FROM external_moves")}
            self_tx = c.execute("SELECT count(*) FROM transfers WHERE from_id = to_id").fetchone()[0]
        mismatched = [r for r in bad if r[1] != r[2]]
        self.assertEqual(mismatched, [], "I7: balance != ledger replay (id, balance, replay)")
        self.assertLessEqual(kinds, {"deposit", "withdrawal"}, f"unexpected external_moves.kind: {kinds}")
        self.assertEqual(self_tx, 0, "self-transfer row in ledger")

    # -- helpers ----------------------------------------------------------------
    def assertRejectedFree(self, fn, status, error=None):
        """I6: a rejection returns `status` (+ error code) and changes no row anywhere."""
        before = self.server.snapshot()
        r = fn()
        self.assertEqual(r.status, status, r)
        if error:
            self.assertEqual(r.error, error, r)
        self.assertEqual(self.server.snapshot(), before, f"I6: rejected request changed the DB: {r}")
        return r

    def assertCommitCount(self, committed, busy, limit, msg=""):
        """Exact-count rule under contention (Architect ruling, 1.3): a 503 busy is a request that
        did not commit, so `committed == limit` is too strict. Require committed <= limit (never
        more: that is the double-spend) and committed + busy >= limit (nothing else refused a
        request that should have fit). Whether each 503 had no effect is checked by the caller."""
        self.assertLessEqual(committed, limit, f"over-commit: {committed} > {limit}. {msg}")
        self.assertGreaterEqual(committed + busy, limit,
                                f"under-commit not explained by 503s: {committed} + {busy} busy < {limit}. {msg}")

    @staticmethod
    def busy_count(responses):
        return sum(r.status == 503 and r.error == "busy" for r in responses)

    def need_route(self, method, path, body=None, headers=None):
        if not self.server.has_route(method, path, body, headers):
            self.skipTest(f"{method} {path} not built yet")

    def funded(self, amount, owner="victim"):
        self.need_route("POST", f"/accounts/{uuid.uuid4()}/deposit", {"amount": 1})
        a = self.server.create_account(owner)
        if amount:
            # setup only: a 503 busy has no effect by contract, so retrying it is safe
            for _ in range(5):
                r = self.server.deposit(a["id"], amount)
                if r.status != 503:
                    break
            self.assertEqual(r.status, 200, r)
        return a
