"""SQLite access. One connection per request; the database, not Python,
enforces the money rules (STRICT types, CHECK constraints, foreign keys).

Stage 3 (D3.1, D3.2): `write_transaction` is the only way to write. Every
connection carries an SQLite authorizer that refuses any write statement
outside it, and it serializes in-process writers through one FIFO lock."""

import collections
import contextlib
import os
import sqlite3
import threading
import time

# Q3-B as amended by Q3.1-A: the cross-process backstop. In-process writers
# queue on WRITER_LOCK first. Worst case 4 s + 3 s + commit stays under 10 s.
BUSY_TIMEOUT_MS = 3000
WRITER_LOCK_TIMEOUT_S = 4.0
MAX_BALANCE = 10**15
MAX_AMOUNT = 10**12

_NOW = "(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))"

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS accounts (
    id          TEXT    PRIMARY KEY CHECK (length(id) = 36),
    owner       TEXT    NOT NULL CHECK (length(owner) BETWEEN 1 AND 64
                                        AND instr(owner, char(0)) = 0),
    balance     INTEGER NOT NULL DEFAULT 0
                        CHECK (balance >= 0 AND balance <= {MAX_BALANCE}),
    token_hash  TEXT    NOT NULL CHECK (length(token_hash) = 64),
    created_at  TEXT    NOT NULL DEFAULT {_NOW}
) STRICT;

-- External money in (deposit) and out (withdrawal). One row per 2xx.
CREATE TABLE IF NOT EXISTS external_moves (
    id          TEXT    PRIMARY KEY CHECK (length(id) = 36),
    account_id  TEXT    NOT NULL REFERENCES accounts(id),
    kind        TEXT    NOT NULL CHECK (kind IN ('deposit', 'withdrawal')),
    amount      INTEGER NOT NULL CHECK (amount BETWEEN 1 AND {MAX_AMOUNT}),
    created_at  TEXT    NOT NULL DEFAULT {_NOW}
) STRICT;
CREATE INDEX IF NOT EXISTS external_moves_account ON external_moves (account_id);

-- Internal transfers. Created now so the schema is stable; filled from 1.3.
CREATE TABLE IF NOT EXISTS transfers (
    id          TEXT    PRIMARY KEY CHECK (length(id) = 36),
    from_id     TEXT    NOT NULL REFERENCES accounts(id),
    to_id       TEXT    NOT NULL REFERENCES accounts(id),
    amount      INTEGER NOT NULL CHECK (amount > 0 AND amount <= {MAX_AMOUNT}),
    created_at  TEXT    NOT NULL DEFAULT {_NOW},
    CHECK (from_id <> to_id)
) STRICT;
CREATE INDEX IF NOT EXISTS transfers_from ON transfers (from_id);
CREATE INDEX IF NOT EXISTS transfers_to ON transfers (to_id);

-- Stage 2: one row per (account, scope, Idempotency-Key), written in the same
-- transaction as the 2xx money movement it answers. Kept forever (D2.9).
-- Q2-A: 'debit' keys (withdraw, transfer) and 'deposit' keys never interact.
CREATE TABLE IF NOT EXISTS idempotency_keys (
    account_id  TEXT    NOT NULL REFERENCES accounts(id),
    scope       TEXT    NOT NULL CHECK (scope IN ('debit', 'deposit')),
    key         TEXT    NOT NULL CHECK (length(key) BETWEEN 1 AND 255),
    fingerprint TEXT    NOT NULL,
    status      INTEGER NOT NULL CHECK (status BETWEEN 200 AND 299),
    response    TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT {_NOW},
    PRIMARY KEY (account_id, scope, key)
) STRICT;
"""


class Busy(Exception):
    """The writer lock was not obtained in time: 503 busy, nothing written."""


class FifoLock:
    """A lock granted strictly in the order acquire() was called (D3.2).
    threading.Lock makes no ordering promise. Each waiter has its own
    condition, so a release wakes exactly the head of the queue, and a
    waiter that times out removes itself and wakes the next one, so it
    never leaves a ticket behind that could wedge the queue."""

    def __init__(self):
        self._mutex = threading.Lock()
        self._queue = collections.deque()  # one Condition per waiter
        self._held = False

    def acquire(self, timeout):
        """True once the lock is held, False after `timeout` seconds."""
        with self._mutex:
            if not self._held and not self._queue:
                self._held = True
                return True
            me = threading.Condition(self._mutex)
            self._queue.append(me)
            deadline = time.monotonic() + timeout
            while self._held or self._queue[0] is not me:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._queue.remove(me)
                    self._wake_head()
                    return False
                me.wait(remaining)
            self._queue.popleft()
            self._held = True
            return True

    def release(self):
        with self._mutex:
            if not self._held:
                raise RuntimeError("release of an unheld FifoLock")
            self._held = False
            self._wake_head()

    def _wake_head(self):
        if not self._held and self._queue:
            self._queue[0].notify()

    def locked(self):
        with self._mutex:
            return self._held

    def waiting(self):
        with self._mutex:
            return len(self._queue)


WRITER_LOCK = FifoLock()


class LockStats:
    """Writer-lock wait and hold times, collected only when enabled (the
    stress harness turns it on through LOCK_STATS_PATH). Bounded."""

    MAX_SAMPLES = 200_000

    def __init__(self):
        self.enabled = False
        self.wait_s = collections.deque(maxlen=self.MAX_SAMPLES)
        self.hold_s = collections.deque(maxlen=self.MAX_SAMPLES)
        self.timeouts = 0

    def summary(self):
        return {
            "acquired": len(self.hold_s),
            "timeouts": self.timeouts,
            "wait_ms": percentiles_ms(list(self.wait_s)),
            "hold_ms": percentiles_ms(list(self.hold_s)),
        }


def percentiles_ms(samples):
    """p50/p99/max of durations in seconds, reported in milliseconds."""
    if not samples:
        return {"p50": None, "p99": None, "max": None}
    samples = sorted(samples)

    def at(q):
        return round(samples[min(len(samples) - 1, int(q * len(samples)))] * 1000, 3)

    return {"p50": at(0.50), "p99": at(0.99), "max": round(samples[-1] * 1000, 3)}


LOCK_STATS = LockStats()

# Authorizer action codes that change the database or its schema.
WRITE_ACTIONS = frozenset(
    getattr(sqlite3, name) for name in dir(sqlite3)
    if name in ("SQLITE_INSERT", "SQLITE_UPDATE", "SQLITE_DELETE", "SQLITE_ALTER_TABLE",
                "SQLITE_ANALYZE", "SQLITE_ATTACH", "SQLITE_DETACH", "SQLITE_REINDEX")
    or name.startswith(("SQLITE_CREATE_", "SQLITE_DROP_"))
)


class _Connection(sqlite3.Connection):
    # True only inside write_transaction, from BEGIN IMMEDIATE to
    # COMMIT/ROLLBACK; the authorizer refuses writes otherwise (D3.1).
    writable = False


def _authorizer(conn):
    def check(action, *_):
        if action in WRITE_ACTIONS and not conn.writable:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    return check


def connect(path):
    """Open a connection configured per PLAN. Autocommit mode
    (isolation_level=None): transactions are explicit BEGIN IMMEDIATE.
    The authorizer runs when a statement is prepared, so the statement cache
    is off: a write prepared inside write_transaction is never reused
    outside it unchecked."""
    conn = sqlite3.connect(
        path,
        timeout=BUSY_TIMEOUT_MS / 1000,
        isolation_level=None,
        check_same_thread=True,
        factory=_Connection,
        cached_statements=0,
    )
    conn.set_authorizer(_authorizer(conn))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


@contextlib.contextmanager
def write_transaction(conn):
    """The only write path (D3.1). Takes the process-wide FIFO writer lock
    (Busy after WRITER_LOCK_TIMEOUT_S, nothing written), then BEGIN
    IMMEDIATE ... COMMIT. The lock covers only that span (Q3-D) and is
    released on every path. Any exception, including an expected rejection
    raised inside the block, rolls the whole transaction back."""
    started = time.monotonic()
    if not WRITER_LOCK.acquire(WRITER_LOCK_TIMEOUT_S):
        if LOCK_STATS.enabled:
            LOCK_STATS.timeouts += 1
        raise Busy()
    acquired = time.monotonic()
    try:
        conn.writable = True
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
    finally:
        conn.writable = False
        WRITER_LOCK.release()
        if LOCK_STATS.enabled:
            LOCK_STATS.wait_s.append(acquired - started)
            LOCK_STATS.hold_s.append(time.monotonic() - acquired)


def init_db(path):
    """Create the database file and schema if missing. Fails loudly if the
    SQLite library is too old for STRICT tables or WAL cannot be enabled."""
    if sqlite3.sqlite_version_info < (3, 37, 0):
        raise RuntimeError(
            f"SQLite {sqlite3.sqlite_version} is too old; STRICT tables need 3.37+"
        )
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    conn = connect(path)
    try:
        mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if mode.lower() != "wal":
            raise RuntimeError(f"could not enable WAL journal mode (got {mode!r})")
        # executescript() would commit on its own, outside the chokepoint.
        with write_transaction(conn):
            for statement in _statements(SCHEMA):
                conn.execute(statement)
    finally:
        conn.close()


def _statements(script):
    """Split an SQL script into complete statements (comments may contain
    semicolons, so a plain split is not enough)."""
    statements, pending = [], ""
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statements.append(pending.strip())
            pending = ""
    if pending.strip():
        raise ValueError(f"incomplete SQL statement: {pending!r}")
    return statements
