"""Breaker's own stress driver (PLAN Stage 3, measurement note 5). Independent of the Builder's
`stress/run_stress.py`: it imports nothing from the app or the Builder's harness.

It runs `workers` client threads for `seconds` against a small account set and keeps a client-side
model of every 2xx it saw. Modes:
  mix    random transfers (any pair), deposits and withdrawals
  cycle  transfers only along the ring a0->a1->...->a0 (pure cycles)
  hot    every op debits or credits a0 (one hot account, hit by everyone)
Per op, with configurable rates: keyless or keyed; keyed requests can be sent twice at once (a
retry racing its original), re-sent later (a retry of an earlier request), or sent and then dropped
with an RST after the full body or mid-body (outcome unknown until resolved).

After the run: wait for the DB to settle, resolve every unknown outcome by retrying its key, then
check I18 (final balances == initial + effects of the observed 2xx, each key once), the ledger row
count, identical bodies for every 2xx of one key, and the I1/I3/I7 samples taken from SQLite during
the run (one read snapshot each, every `sample_every` seconds).

Standalone: python breaker_stress.py --workers 500 --accounts 2 --seconds 30 [--mode mix]
(starts its own server against a temp DB, prints one JSON summary, exits 1 on any violation).
"""
import argparse
import collections
import contextlib
import json
import os
import random
import socket
import struct
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from breaker_harness import NO_RESPONSE, REQUEST_TIMEOUT, Server  # noqa: E402

CRLF = b"\r\n"
OK = (200, 201)
LINGER0 = struct.pack("ii", 1, 0)
# Measurement note 4: a connect refused before any request byte was sent is not a lost response.
# Bare Windows caps the listen backlog near 200 whatever listen() asks for, so 256 slots + ~200
# queued connections is the most it accepts; such refusals are counted and reported, never
# mistaken for a dropped answer. Anything after a successful connect is still NO_RESPONSE.
REFUSED = 598

Op = collections.namedtuple("Op", "kind src dst amount key uid")

REPLAY_SQL = """
    SELECT a.id, a.balance,
      coalesce((SELECT sum(amount) FROM external_moves WHERE account_id = a.id AND kind = 'deposit'), 0)
    - coalesce((SELECT sum(amount) FROM external_moves WHERE account_id = a.id AND kind = 'withdrawal'), 0)
    + coalesce((SELECT sum(amount) FROM transfers WHERE to_id = a.id), 0)
    - coalesce((SELECT sum(amount) FROM transfers WHERE from_id = a.id), 0)
    FROM accounts a
"""


# -- wire -------------------------------------------------------------------------------------
def build_request(op, tokens):
    if op.kind == "transfer":
        path, body = "/transfers", {"from": op.src, "to": op.dst, "amount": op.amount}
        auth = tokens[op.src]
    elif op.kind == "deposit":
        path, body, auth = f"/accounts/{op.dst}/deposit", {"amount": op.amount}, None
    else:
        path, body, auth = f"/accounts/{op.src}/withdraw", {"amount": op.amount}, tokens[op.src]
    data = json.dumps(body).encode()
    head = [f"POST {path} HTTP/1.1", "Host: x", "Content-Type: application/json",
            f"Content-Length: {len(data)}", "Connection: close"]
    if auth:
        head.append(f"Authorization: Bearer {auth}")
    if op.key:
        head.append(f"Idempotency-Key: {op.key}")
    return "\r\n".join(head).encode() + CRLF + CRLF + data


def parse_response(data):
    """(status, headers{lower: value}, body) or None when the response is not complete."""
    head, sep, body = data.partition(CRLF + CRLF)
    if not sep or not head.startswith(b"HTTP/"):
        return None
    lines = head.split(CRLF)
    try:
        status = int(lines[0].split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None
    hdrs = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        hdrs[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    n = hdrs.get("content-length")
    if n is None or not n.isascii() or not n.isdigit() or len(body) != int(n):
        return None
    return status, hdrs, body


def send(port, payload, timeout=REQUEST_TIMEOUT + 2):
    """Send one full request; read to EOF. Returns (status, headers, body, latency). status is
    NO_RESPONSE when the connection failed or the response is incomplete. The socket is closed
    with an RST after the read, so a long run does not exhaust client ports in TIME_WAIT."""
    t0 = time.monotonic()
    s = None
    chunks = []
    try:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        except ConnectionRefusedError:
            return REFUSED, {}, b"", time.monotonic() - t0
        s.sendall(payload)
        while True:
            c = s.recv(65536)
            if not c:
                break
            chunks.append(c)
    except OSError:
        pass
    finally:
        if s is not None:
            with contextlib.suppress(OSError):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
            s.close()
    dt = time.monotonic() - t0
    parsed = parse_response(b"".join(chunks))
    if parsed is None:
        return NO_RESPONSE, {}, b"".join(chunks), dt
    return parsed + (dt,)


def send_and_drop(port, payload, midbody):
    """Send the full request (or half of it) and reset the connection without reading."""
    with contextlib.suppress(OSError):
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            s.sendall(payload[: len(payload) - 20] if midbody else payload)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
        finally:
            s.close()


# -- model --------------------------------------------------------------------------------------
def effects(op):
    if op.kind == "transfer":
        return {op.src: -op.amount, op.dst: op.amount}
    if op.kind == "deposit":
        return {op.dst: op.amount}
    return {op.src: -op.amount}


def error_of(body):
    with contextlib.suppress(ValueError, AttributeError):
        return json.loads(body).get("error")
    return None


def db_sample(server):
    """One read transaction = one WAL snapshot: list of violation strings (empty if fine)."""
    out = []
    with contextlib.closing(server.db()) as c:
        c.isolation_level = None
        c.execute("BEGIN")
        neg = c.execute("SELECT count(*) FROM accounts WHERE balance < 0").fetchone()[0]
        bad = [r for r in c.execute(REPLAY_SQL).fetchall() if r[1] != r[2]]
        bal, dep, wd = c.execute(
            "SELECT (SELECT coalesce(sum(balance),0) FROM accounts),"
            " (SELECT coalesce(sum(amount),0) FROM external_moves WHERE kind='deposit'),"
            " (SELECT coalesce(sum(amount),0) FROM external_moves WHERE kind='withdrawal')").fetchone()
        c.execute("COMMIT")
    if neg:
        out.append(f"I3: {neg} negative balances")
    if bad:
        out.append(f"I7: balance != ledger replay {bad[:3]}")
    if bal != dep - wd:
        out.append(f"I1: balances {bal} != deposits {dep} - withdrawals {wd}")
    return out


def ledger_rows(server, ids):
    q = ",".join("?" * len(ids))
    with contextlib.closing(server.db()) as c:
        t = c.execute(f"SELECT count(*) FROM transfers WHERE from_id IN ({q}) OR to_id IN ({q})",
                      ids + ids).fetchone()[0]
        e = c.execute(f"SELECT count(*) FROM external_moves WHERE account_id IN ({q})", ids).fetchone()[0]
    return t + e


def settle(server, ids, quiet=1.0, limit=30.0):
    """Wait until the driver's ledger stops changing for `quiet` seconds (dropped requests may
    still be committing after their clients went away)."""
    end = time.monotonic() + limit
    last, since = None, time.monotonic()
    while time.monotonic() < end:
        n = ledger_rows(server, ids)
        if n != last:
            last, since = n, time.monotonic()
        elif time.monotonic() - since >= quiet:
            return
        time.sleep(0.1)


def setup_accounts(server, n, initial, tag):
    accts = []
    for i in range(n):
        for _ in range(20):  # setup only: 503 has no effect by contract
            r = server.request("POST", "/accounts", {"owner": f"{tag}{i}"})
            if r.status == 201:
                break
        assert r.status == 201, r
        a = r.json
        for _ in range(20):
            d = server.deposit(a["id"], initial)
            if d.status == 200:
                break
        assert d.status == 200, d
        accts.append(a)
    return accts


class Driver:
    def __init__(self, server, *, workers, n_accounts, seconds, seed=1, mode="mix", initial=10_000,
                 max_amount=50, keyless_rate=0.25, race_rate=0.1, retry_rate=0.05,
                 drop_rate=0.05, sample_every=0.5, crash_tolerant=False, tag="bst"):
        self.server, self.workers, self.seconds, self.seed = server, workers, seconds, seed
        self.mode, self.initial, self.max_amount = mode, initial, max_amount
        self.keyless_rate, self.race_rate, self.retry_rate = keyless_rate, race_rate, retry_rate
        self.drop_rate, self.sample_every = drop_rate, sample_every
        # crash_tolerant: a missing response is an unknown outcome (the server was killed on
        # purpose), resolved later by retrying the key; otherwise it is a violation.
        self.crash_tolerant = crash_tolerant
        accts = setup_accounts(server, n_accounts, initial, tag)
        self.ids = [a["id"] for a in accts]
        self.tokens = {a["id"]: a["token"] for a in accts}
        self.lock = threading.Lock()
        self.results = []      # (op, status, error, body, replayed, latency, phase)
        self.unknown = []      # keyed ops whose outcome the client did not see
        self.violations = []
        self.samples = 0
        self.stop = threading.Event()
        self.uid = 0
        # I19 zero-503 rule binds at <= 100 concurrent writers. A racing retry adds a second
        # in-flight writer per worker; a dropped client's request keeps running server-side after
        # its worker moved on, so with drops the writer count is unbounded and the rule is off.
        self.max_inflight = workers * (2 if race_rate else 1)
        self.exact_rule = self.max_inflight <= 100 and not drop_rate and not crash_tolerant

    # -- op generation --
    def next_op(self, rnd):
        ids, a = self.ids, rnd.randint(1, self.max_amount)
        key = None if rnd.random() < self.keyless_rate else "bst-" + uuid.uuid4().hex
        with self.lock:
            self.uid += 1
            uid = self.uid
        if self.mode == "cycle":
            i = rnd.randrange(len(ids))
            return Op("transfer", ids[i], ids[(i + 1) % len(ids)], a, key, uid)
        if self.mode == "hot":
            x = rnd.choice(ids[1:])
            src, dst = (ids[0], x) if rnd.random() < 0.5 else (x, ids[0])
            return Op("transfer", src, dst, a, key, uid)
        r = rnd.random()
        if r < 0.6 and len(ids) > 1:
            s, d = rnd.sample(ids, 2)
            return Op("transfer", s, d, a, key, uid)
        if r < 0.8:
            return Op("deposit", None, rnd.choice(ids), a, key, uid)
        return Op("withdraw", rnd.choice(ids), None, a, key, uid)

    def execute(self, op, phase="run"):
        status, hdrs, body, dt = send(self.server.port, build_request(op, self.tokens))
        rec = (op, status, error_of(body), body, hdrs.get("idempotent-replayed") == "true", dt, phase)
        with self.lock:
            self.results.append(rec)
            if status == NO_RESPONSE:
                if self.crash_tolerant and op.key:
                    self.unknown.append(op)
                else:
                    self.violations.append(f"no/partial response ({phase}): {op} {body[:200]!r}")
        return rec

    def worker(self, wid):
        rnd = random.Random(self.seed * 100_003 + wid)
        history = []
        while not self.stop.is_set():
            op = self.next_op(rnd)
            if op.key and rnd.random() < self.drop_rate:
                send_and_drop(self.server.port, build_request(op, self.tokens), rnd.random() < 0.3)
                with self.lock:
                    self.unknown.append(op)
                continue
            if op.key and rnd.random() < self.race_rate:
                t = threading.Thread(target=self.execute, args=(op, "race"))
                t.start()
                self.execute(op, "race")
                t.join()
            else:
                self.execute(op)
            if op.key:
                history.append(op)
            if history and rnd.random() < self.retry_rate:
                self.execute(rnd.choice(history), "retry")

    def sampler(self):
        while not self.stop.wait(self.sample_every):
            with contextlib.suppress(Exception):
                v = db_sample(self.server)
                with self.lock:
                    self.samples += 1
                    self.violations.extend(v)

    # -- run --
    def run(self, kill_at=None):
        threads = [threading.Thread(target=self.worker, args=(i,), daemon=True)
                   for i in range(self.workers)]
        smp = threading.Thread(target=self.sampler, daemon=True)
        smp.start()
        t0 = time.monotonic()
        for t in threads:
            t.start()
        if kill_at is not None:
            time.sleep(kill_at)
            self.server.kill()
            time.sleep(0.5)
            self.stop.set()
            for t in threads:
                t.join(REQUEST_TIMEOUT + 5)
            smp.join(5)
            self.server.start()
        else:
            time.sleep(self.seconds)
            self.stop.set()
            for t in threads:
                t.join(REQUEST_TIMEOUT + 5)
            smp.join(5)
        self.elapsed = time.monotonic() - t0
        return self

    def resolve(self, retry_all=False):
        """Retry every unknown keyed op (and with retry_all, every keyed op ever sent) once,
        sequentially. The outcome tells whether it had committed (replay) or commits now."""
        settle(self.server, self.ids)
        ops = list(self.unknown)
        if retry_all:
            seen = {}
            for r in self.results:
                if r[0].key:
                    seen.setdefault(r[0].key, r[0])
            for op in ops:
                seen.setdefault(op.key, op)
            ops = list(seen.values())
        done = set()
        for op in ops:
            if op.key in done:
                continue
            done.add(op.key)
            self.execute(op, "resolve")
        return self

    def check(self):
        """Model vs DB. Returns the summary dict; violations are in summary['violations']."""
        v = self.violations
        by_key = collections.defaultdict(list)
        committed = []
        for op, status, err, body, replayed, dt, phase in self.results:
            if dt >= REQUEST_TIMEOUT and status not in (NO_RESPONSE, REFUSED):
                v.append(f"I19: {dt:.2f}s for {op.kind} ({phase}) -> {status}")
            if status in OK:
                if op.key:
                    by_key[op.key].append((body, replayed, op))
                else:
                    committed.append(op)
            elif status == 503:
                if err != "busy":
                    v.append(f"503 without busy: {body[:200]!r}")
                elif self.exact_rule and phase != "resolve":
                    v.append(f"I19: 503 busy at <= {self.max_inflight} writers ({op.kind})")
            elif status == 409 and err == "insufficient_funds":
                pass
            elif status == 422 and err == "balance_limit":
                pass
            elif status not in (NO_RESPONSE, REFUSED):
                v.append(f"unexpected {status} {body[:200]!r} for {op} ({phase})")
        for key, hits in by_key.items():
            bodies = {b for b, _, _ in hits}
            if len(bodies) != 1:
                v.append(f"I13: key {key} answered with different 2xx bodies {sorted(bodies)[:2]}")
            committed.append(hits[0][2])
        expected = {i: self.initial for i in self.ids}
        for op in committed:
            for acct, d in effects(op).items():
                expected[acct] += d
        actual = {i: self.server.balance(i) for i in self.ids}
        if actual != expected:
            diff = {i[:8]: (expected[i], actual[i]) for i in self.ids if expected[i] != actual[i]}
            v.append(f"I18: lost/extra update (expected, actual): {diff}")
        rows = ledger_rows(self.server, self.ids)
        if rows != len(self.ids) + len(committed):
            v.append(f"ledger rows {rows} != setup {len(self.ids)} + observed commits {len(committed)}")
        v.extend(db_sample(self.server))
        lat = sorted(r[5] for r in self.results if r[6] != "resolve" and r[1] not in (NO_RESPONSE, REFUSED))

        def pct(p):
            return round(lat[min(len(lat) - 1, int(p * len(lat)))], 4) if lat else None

        statuses = collections.Counter(str(r[1]) for r in self.results)
        return {
            "mode": self.mode, "workers": self.workers, "accounts": len(self.ids),
            "seconds": round(getattr(self, "elapsed", 0), 1), "ops": len(self.results),
            "dropped": len(self.unknown), "statuses": dict(statuses),
            "max_inflight": self.max_inflight, "zero_503_rule": self.exact_rule,
            "refused": sum(r[1] == REFUSED for r in self.results),
            "busy": sum(r[1] == 503 for r in self.results if r[6] != "resolve"),
            "commits": len(committed), "samples": self.samples,
            "p50": pct(0.5), "p99": pct(0.99), "max": lat[-1] if lat else None,
            "violations": v[:50], "violation_count": len(v),
        }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--workers", type=int, default=200)
    p.add_argument("--accounts", type=int, default=3)
    p.add_argument("--seconds", type=float, default=20)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--mode", choices=("mix", "cycle", "hot"), default="mix")
    a = p.parse_args(argv)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        srv = Server(os.path.join(tmp, "wallet.db")).start()
        try:
            d = Driver(srv, workers=a.workers, n_accounts=a.accounts, seconds=a.seconds,
                       seed=a.seed, mode=a.mode).run().resolve()
            summary = d.check()
        finally:
            srv.kill()
    print(json.dumps(summary))
    return 1 if summary["violation_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
