"""Stage 3 stress harness (D3.4). Standard library only.

    python stress/run_stress.py --seconds 60 --workers 200 --accounts 8 --seed 1

Starts `python -m app` from this stage on a free port against a fresh
temporary database (or --db), creates and funds --accounts accounts, then runs
--workers client threads for --seconds. Each worker loops over a random mix:

  transfer, A<->B pair, A->B->C->A cycle, withdraw, deposit, read,
  keyed retry of an earlier keyed request, disconnect after sending a full
  keyed request, disconnect in the middle of the body.

About half of the money requests carry an Idempotency-Key. The harness keeps a
client-side model: every 2xx moves the model once (a key is applied once, on
the first 2xx seen for it, replay or not). Requests whose answer was never
read (disconnects) are always keyed, and are retried after the run until one
definitive answer settles them. A sampler reads I1, I3 and I7 straight from
the SQLite file at least once a second. After the load, an I20 probe checks
that /health and two fresh writes answer within 1 s each.

Prints one JSON summary on stdout and exits 1 on any violation:
  I1/I3/I7 in any sample; I18 model != database; I19 a request took >= 10 s,
  or any 503 with --workers <= 100; I13 a replay differing from the original;
  any 5xx other than 503 busy, an unexpected status, or a complete request
  without a full JSON answer; I20 probe failure. A connect refused before
  any request byte is sent is not a violation; it is reported as
  `refused_at_connect` (R3.1-B, measurement note 4).
"""

import argparse
import http.client
import json
import os
import queue
import random
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid

STAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_TIMEOUT_S = 15
I19_LIMIT_S = 10
ZERO_503_MAX_WRITERS = 100
INITIAL_BALANCE = 1_000_000
SAMPLE_INTERVAL_S = 0.5
MAX_VIOLATIONS_SHOWN = 25

OPS = [  # (name, weight)
    ("transfer", 30), ("pair", 8), ("cycle", 8), ("withdraw", 12), ("deposit", 14),
    ("read", 8), ("retry", 10), ("disconnect_after_send", 5), ("disconnect_mid_body", 5),
]

I1_SQL = """SELECT (SELECT coalesce(sum(balance), 0) FROM accounts)
                 = (SELECT coalesce(sum(amount), 0) FROM external_moves WHERE kind = 'deposit')
                 - (SELECT coalesce(sum(amount), 0) FROM external_moves WHERE kind = 'withdrawal')"""
I3_SQL = "SELECT count(*) FROM accounts WHERE balance < 0"
I7_SQL = """SELECT count(*) FROM accounts a WHERE a.balance !=
      coalesce((SELECT sum(amount) FROM external_moves WHERE account_id = a.id AND kind = 'deposit'), 0)
    - coalesce((SELECT sum(amount) FROM external_moves WHERE account_id = a.id AND kind = 'withdrawal'), 0)
    + coalesce((SELECT sum(amount) FROM transfers WHERE to_id = a.id), 0)
    - coalesce((SELECT sum(amount) FROM transfers WHERE from_id = a.id), 0)"""


def percentiles_ms(samples):
    if not samples:
        return {"p50": None, "p99": None, "max": None}
    samples = sorted(samples)

    def at(q):
        return round(samples[min(len(samples) - 1, int(q * len(samples)))] * 1000, 3)

    return {"p50": at(0.50), "p99": at(0.99), "max": round(samples[-1] * 1000, 3)}


# --- server ---------------------------------------------------------------

class Server:
    def __init__(self, db_path, stats_path):
        self.db_path = db_path
        self.stats_path = stats_path
        self.proc = None
        self.port = None

    def start(self):
        env = dict(os.environ, PORT="0", DB_PATH=self.db_path, LOCK_STATS_PATH=self.stats_path)
        env.pop("LOG_REQUESTS", None)
        self.stderr = tempfile.TemporaryFile()
        self.proc = subprocess.Popen([sys.executable, "-m", "app"], cwd=STAGE_DIR, env=env,
                                     stdout=subprocess.PIPE, stderr=self.stderr, text=True)
        lines = queue.Queue()
        threading.Thread(target=lambda: lines.put(self.proc.stdout.readline()),
                         daemon=True).start()
        try:
            line = lines.get(timeout=15)
        except queue.Empty:
            line = ""
        if not line.startswith("LISTENING "):
            self.stop()
            raise RuntimeError(f"server did not start: {line!r} {self.stderr_text()!r}")
        self.port = int(line.split()[2])

    def stderr_text(self):
        self.stderr.seek(0)
        return self.stderr.read().decode("utf-8", "replace")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.proc and self.proc.stdout:
            self.proc.stdout.close()

    def lock_stats(self):
        try:
            with open(self.stats_path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None


class Refused(OSError):
    """The connect itself failed: no request byte was sent (R3.1-B, note 4).
    Reported as a count, not a violation."""


# --- results --------------------------------------------------------------

class Results:
    def __init__(self, workers):
        self.lock = threading.Lock()
        self.workers = workers
        self.ops = {}
        self.statuses = {}
        self.latencies = []
        self.busy = 0
        self.disconnects = 0
        self.refused = 0
        self.violations = []
        self.violation_kinds = {}

    def op(self, name):
        with self.lock:
            self.ops[name] = self.ops.get(name, 0) + 1

    def response(self, status, elapsed):
        with self.lock:
            self.statuses[str(status)] = self.statuses.get(str(status), 0) + 1
            self.latencies.append(elapsed)
            if status == 503:
                self.busy += 1
        if elapsed >= I19_LIMIT_S:
            self.violation("I19", f"request took {elapsed:.3f} s")

    def violation(self, kind, detail):
        with self.lock:
            self.violation_kinds[kind] = self.violation_kinds.get(kind, 0) + 1
            if len(self.violations) < MAX_VIOLATIONS_SHOWN:
                self.violations.append(f"{kind}: {detail}")


# --- client model -----------------------------------------------------------

class Model:
    """Expected balances from the 2xx answers the clients observed."""

    def __init__(self, accounts):
        self.lock = threading.Lock()
        self.balance = {a["id"]: 0 for a in accounts}
        self.applied = {}       # (scope, account, key) -> original 2xx body bytes
        self.history = []       # keyed requests eligible for a retry
        self.unresolved = {}    # (scope, account, key) -> request whose answer was not read

    def apply(self, req, status, body, results):
        """Move the model for a 2xx answer to `req`, once per key."""
        with self.lock:
            if req.key is not None:
                ident = req.ident()
                original = self.applied.get(ident)
                if original is not None:
                    if body != original:
                        results.violation("I13", f"key {req.key}: {body!r} != {original!r}")
                    return
                self.applied[ident] = body
                self.unresolved.pop(ident, None)
            for account, delta in req.effects():
                self.balance[account] += delta

    def remember(self, req):
        with self.lock:
            self.history.append(req)

    def pick_earlier(self, rnd):
        with self.lock:
            return rnd.choice(self.history) if self.history else None

    def lost(self, req):
        with self.lock:
            if req.ident() not in self.applied:
                self.unresolved[req.ident()] = req


class Request:
    def __init__(self, kind, accounts, amount, key, src=None, dst=None):
        self.kind, self.amount, self.key = kind, amount, key
        self.src, self.dst = src, dst
        self.accounts = accounts

    def ident(self):
        scope = "deposit" if self.kind == "deposit" else "debit"
        return scope, self.src["id"], self.key

    def effects(self):
        if self.kind == "deposit":
            return [(self.src["id"], self.amount)]
        if self.kind == "withdraw":
            return [(self.src["id"], -self.amount)]
        return [(self.src["id"], -self.amount), (self.dst["id"], self.amount)]

    def http(self):
        headers = {"Content-Type": "application/json"}
        if self.key is not None:
            headers["Idempotency-Key"] = self.key
        if self.kind == "deposit":
            return "POST", f"/accounts/{self.src['id']}/deposit", {"amount": self.amount}, headers
        headers["Authorization"] = f"Bearer {self.src['token']}"
        if self.kind == "withdraw":
            return "POST", f"/accounts/{self.src['id']}/withdraw", {"amount": self.amount}, headers
        body = {"from": self.src["id"], "to": self.dst["id"], "amount": self.amount}
        return "POST", "/transfers", body, headers

    def raw(self):
        method, path, body, headers = self.http()
        data = json.dumps(body).encode()
        head = f"{method} {path} HTTP/1.1\r\nHost: stress\r\nContent-Length: {len(data)}\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
        return head.encode(), data


# --- the driver ---------------------------------------------------------------

class Stress:
    def __init__(self, args, server):
        self.args = args
        self.server = server
        self.results = Results(args.workers)
        self.accounts = []
        self.model = None
        self.stop = threading.Event()
        self.samples = 0
        self.sample_failures = {"I1": 0, "I3": 0, "I7": 0}

    # transport

    def call(self, method, path, body=None, headers=None):
        """One complete request. Returns (status, raw body, replayed) or
        raises Refused if the connect failed (nothing sent), or
        OSError/HTTPException when no full answer arrived."""
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=CLIENT_TIMEOUT_S)
        try:
            data = None if body is None else json.dumps(body).encode()
            start = time.monotonic()
            try:
                conn.connect()
            except OSError as exc:
                raise Refused(*exc.args) from None
            conn.request(method, path, body=data, headers=headers or {})
            resp = conn.getresponse()
            payload = resp.read()
            elapsed = time.monotonic() - start
            replayed = resp.getheader("Idempotent-Replayed") == "true"
            return resp.status, payload, replayed, elapsed
        finally:
            conn.close()

    def send(self, req, op):
        """Send a money request and account for its answer."""
        method, path, body, headers = req.http()
        try:
            status, payload, replayed, elapsed = self.call(method, path, body, headers)
        except Refused:
            with self.results.lock:
                self.results.refused += 1
            return None  # never sent, so it cannot have committed
        except (OSError, http.client.HTTPException) as exc:
            self.results.violation("no_answer", f"{op} {path}: {exc!r}")
            if req.key is not None:
                self.model.lost(req)
            return None
        self.results.response(status, elapsed)
        self.check_status(op, status, payload)
        if 200 <= status < 300:
            self.model.apply(req, status, payload, self.results)
        elif replayed:
            self.results.violation("I13", f"non-2xx replay {status} {payload!r}")
        if req.key is not None:
            self.model.remember(req)
        return status

    def check_status(self, op, status, payload):
        try:
            parsed = json.loads(payload)
        except ValueError:
            self.results.violation("no_json", f"{op} {status} {payload[:80]!r}")
            return
        if 200 <= status < 300:
            return
        allowed = {409: {"insufficient_funds"}, 422: {"balance_limit"}, 503: {"busy"}}
        if parsed.get("error") not in allowed.get(status, ()):
            self.results.violation("unexpected_status", f"{op} {status} {parsed}")

    # operations

    def new_key(self, rnd):
        return str(uuid.UUID(int=rnd.getrandbits(128), version=4)) if rnd.random() < 0.5 else None

    def amount(self, rnd):
        return rnd.randint(1, 5000)

    def op_transfer(self, rnd):
        src, dst = rnd.sample(self.accounts, 2)
        self.send(Request("transfer", self.accounts, self.amount(rnd), self.new_key(rnd), src, dst),
                  "transfer")

    def op_pair(self, rnd):
        a, b = rnd.sample(self.accounts, 2)
        amount = self.amount(rnd)
        self.send(Request("transfer", self.accounts, amount, self.new_key(rnd), a, b), "pair")
        self.send(Request("transfer", self.accounts, amount, self.new_key(rnd), b, a), "pair")

    def op_cycle(self, rnd):
        ring = rnd.sample(self.accounts, min(3, len(self.accounts)))
        amount = self.amount(rnd)
        for i, src in enumerate(ring):
            dst = ring[(i + 1) % len(ring)]
            self.send(Request("transfer", self.accounts, amount, self.new_key(rnd), src, dst),
                      "cycle")

    def op_withdraw(self, rnd):
        self.send(Request("withdraw", self.accounts, self.amount(rnd) // 2 + 1, self.new_key(rnd),
                          rnd.choice(self.accounts)), "withdraw")

    def op_deposit(self, rnd):
        self.send(Request("deposit", self.accounts, self.amount(rnd), self.new_key(rnd),
                          rnd.choice(self.accounts)), "deposit")

    def op_read(self, rnd):
        path = "/audit" if rnd.random() < 0.3 else f"/accounts/{rnd.choice(self.accounts)['id']}"
        try:
            status, payload, _, elapsed = self.call("GET", path)
        except Refused:
            with self.results.lock:
                self.results.refused += 1
            return
        except (OSError, http.client.HTTPException) as exc:
            self.results.violation("no_answer", f"GET {path}: {exc!r}")
            return
        self.results.response(status, elapsed)
        if status != 200:
            self.results.violation("unexpected_status", f"GET {path} {status} {payload[:80]!r}")
        elif path == "/audit" and json.loads(payload).get("conserved") is not True:
            self.results.violation("I1", f"/audit {payload!r}")

    def op_retry(self, rnd):
        earlier = self.model.pick_earlier(rnd)
        if earlier is None:
            return self.op_transfer(rnd)
        self.send(earlier, "retry")

    def random_money_request(self, rnd, keyed):
        kind = rnd.choice(["transfer", "transfer", "withdraw", "deposit"])
        src, dst = rnd.sample(self.accounts, 2)
        key = str(uuid.UUID(int=rnd.getrandbits(128), version=4)) if keyed else None
        return Request(kind, self.accounts, self.amount(rnd), key, src, dst)

    def op_disconnect_after_send(self, rnd):
        """Send a full keyed request and close without reading the answer.
        It may or may not commit; the key settles it later."""
        req = self.random_money_request(rnd, keyed=True)
        head, data = req.raw()
        self.model.lost(req)
        try:
            with socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as sock:
                sock.sendall(head + data)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        except OSError:
            pass
        with self.results.lock:
            self.results.disconnects += 1

    def op_disconnect_mid_body(self, rnd):
        """Headers and part of the body, then close: nothing may happen."""
        req = self.random_money_request(rnd, keyed=rnd.random() < 0.5)
        head, data = req.raw()
        try:
            with socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as sock:
                sock.sendall(head + data[: len(data) // 2])
        except OSError:
            pass
        with self.results.lock:
            self.results.disconnects += 1

    # setup, sampler, workers

    def setup(self):
        for n in range(self.args.accounts):
            status, payload, _, _ = self.call("POST", "/accounts", {"owner": f"stress-{n}"},
                                              {"Content-Type": "application/json"})
            if status != 201:
                raise RuntimeError(f"account setup failed: {status} {payload!r}")
            self.accounts.append(json.loads(payload))
        self.model = Model(self.accounts)
        for account in self.accounts:
            req = Request("deposit", self.accounts, INITIAL_BALANCE, None, account)
            if self.send(req, "setup") != 200:
                raise RuntimeError("initial deposit failed")

    def sample(self):
        conn = sqlite3.connect(f"file:{self.server.db_path}?mode=ro", uri=True, timeout=5,
                               isolation_level=None)
        try:
            conn.execute("BEGIN")  # one read snapshot for all three checks
            i1 = conn.execute(I1_SQL).fetchone()[0] == 1
            i3 = conn.execute(I3_SQL).fetchone()[0] == 0
            i7 = conn.execute(I7_SQL).fetchone()[0] == 0
            conn.execute("COMMIT")
        finally:
            conn.close()
        self.samples += 1
        for name, ok in (("I1", i1), ("I3", i3), ("I7", i7)):
            if not ok:
                self.sample_failures[name] += 1
                self.results.violation(name, f"sample {self.samples}")

    def sampler(self):
        while not self.stop.wait(SAMPLE_INTERVAL_S):
            try:
                self.sample()
            except sqlite3.Error as exc:
                self.results.violation("sampler", repr(exc))

    def worker(self, n):
        rnd = random.Random(f"{self.args.seed}-{n}")
        names = [name for name, _ in OPS]
        weights = [weight for _, weight in OPS]
        while not self.stop.is_set():
            name = rnd.choices(names, weights)[0]
            self.results.op(name)
            getattr(self, f"op_{name}")(rnd)

    def tamper(self):
        """Self-test only: change a balance behind the service's back, which
        the sampler and the model must both catch."""
        time.sleep(self.args.seconds / 2)
        conn = sqlite3.connect(self.server.db_path, timeout=10, isolation_level=None)
        try:
            conn.execute("UPDATE accounts SET balance = balance + 1 WHERE id = ?",
                         (self.accounts[0]["id"],))
        finally:
            conn.close()

    def resolve(self):
        """Settle every request whose answer was never read: retry its key
        until a definitive answer. 2xx moves the model once; a rejection
        means the original did not commit (only 2xx outcomes are stored)."""
        pending = list(self.model.unresolved.values())
        for req in pending:
            for _ in range(20):
                status = self.send(req, "resolve")
                if status not in (None, 503):
                    break
            else:
                self.results.violation("unresolved", f"key {req.key} never settled")
        return len(pending)

    def probe(self):
        """I20: /health and two fresh keyed writes, each within 1 s."""
        ok = True
        try:
            status, _, _, elapsed = self.call("GET", "/health")
            ok &= status == 200 and elapsed < 1
        except (OSError, http.client.HTTPException):
            ok = False
        for _ in range(2):
            req = Request("deposit", self.accounts, 1, str(uuid.uuid4()), self.accounts[0])
            start = time.monotonic()
            status = self.send(req, "probe")
            ok &= status == 200 and time.monotonic() - start < 1
        if not ok:
            self.results.violation("I20", "health or a fresh write took >= 1 s or failed")
        return ok

    def compare_model(self):
        conn = sqlite3.connect(f"file:{self.server.db_path}?mode=ro", uri=True, timeout=5)
        try:
            actual = dict(conn.execute("SELECT id, balance FROM accounts").fetchall())
        finally:
            conn.close()
        mismatches = {a: (self.model.balance[a], actual.get(a)) for a in self.model.balance
                      if self.model.balance[a] != actual.get(a)}
        for account, (expected, got) in mismatches.items():
            self.results.violation("I18", f"{account}: model {expected} != db {got}")
        return not mismatches

    def run(self):
        self.setup()
        sampler = threading.Thread(target=self.sampler, daemon=True)
        sampler.start()
        workers = [threading.Thread(target=self.worker, args=(n,), daemon=True)
                   for n in range(self.args.workers)]
        if self.args.self_test_tamper:
            threading.Thread(target=self.tamper, daemon=True).start()
        started = time.monotonic()
        for thread in workers:
            thread.start()
        time.sleep(self.args.seconds)
        self.stop.set()
        for thread in workers:
            thread.join(CLIENT_TIMEOUT_S * 2)
        load_s = time.monotonic() - started
        sampler.join(5)
        stuck = sum(thread.is_alive() for thread in workers)
        if stuck:
            self.results.violation("I19", f"{stuck} workers still blocked after the run")
        time.sleep(0.5)  # disconnected requests already sent finish server-side
        probe_ok = self.probe()
        resolved = self.resolve()
        self.sample()
        model_ok = self.compare_model()
        time.sleep(1.5)  # let the server write its lock statistics once more
        return self.summary(load_s, probe_ok, model_ok, resolved)

    def summary(self, load_s, probe_ok, model_ok, resolved):
        r = self.results
        if r.busy and self.args.workers <= ZERO_503_MAX_WRITERS:
            r.violation("I19", f"{r.busy} x 503 busy with only {self.args.workers} writers")
        latency = percentiles_ms(r.latencies)
        invariants = {
            "I1": self.sample_failures["I1"] == 0 and "I1" not in r.violation_kinds,
            "I3": self.sample_failures["I3"] == 0,
            "I7": self.sample_failures["I7"] == 0,
            "I13": "I13" not in r.violation_kinds,
            "I18": model_ok,
            "I19": "I19" not in r.violation_kinds,
            "I20": probe_ok,
            "answers": not any(k in r.violation_kinds for k in
                               ("no_answer", "no_json", "unexpected_status", "unresolved")),
        }
        return {
            "config": {"seconds": self.args.seconds, "workers": self.args.workers,
                       "accounts": self.args.accounts, "seed": self.args.seed},
            "load_seconds": round(load_s, 3),
            "ops": sum(r.ops.values()),
            "ops_by_kind": dict(sorted(r.ops.items())),
            "requests": len(r.latencies),
            "statuses": dict(sorted(r.statuses.items())),
            "latency_ms": latency,
            "busy_503": r.busy,
            "disconnects": r.disconnects,
            "refused_at_connect": r.refused,
            "resolved_after_run": resolved,
            "lock": self.server.lock_stats(),
            "samples": self.samples,
            "sample_failures": self.sample_failures,
            "invariants": invariants,
            "violation_counts": dict(sorted(r.violation_kinds.items())),
            "violations": r.violations,
            "ok": all(invariants.values()) and not r.violation_kinds,
        }


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--workers", type=int, default=200)
    parser.add_argument("--accounts", type=int, default=8)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--db", help="SQLite file to use (default: a fresh temporary file)")
    parser.add_argument("--self-test-tamper", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.accounts < 2:
        parser.error("--accounts must be at least 2")
    if args.workers < 1 or not (0 < args.seconds < float("inf")):
        parser.error("--workers and --seconds must be positive (and --seconds finite)")
    return args


def main(argv=None):
    args = parse_args(argv)
    tmpdir = tempfile.mkdtemp(prefix="pocketful-stress-")
    db_path = args.db or os.path.join(tmpdir, "wallet.db")
    server = Server(db_path, os.path.join(tmpdir, "lock-stats.json"))
    try:
        server.start()
        summary = Stress(args, server).run()
    finally:
        server.stop()
    stderr = server.stderr_text()
    if "internal error" in stderr:
        summary["ok"] = False
        summary["violations"].append("server logged an internal error (500)")
    server.stderr.close()
    shutil.rmtree(tmpdir, ignore_errors=True)
    print(json.dumps(summary, indent=2), flush=True)
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
