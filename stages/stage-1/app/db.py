"""SQLite access. One connection per request; the database, not Python,
enforces the money rules (STRICT types, CHECK constraints, foreign keys)."""

import contextlib
import os
import sqlite3

BUSY_TIMEOUT_MS = 5000
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
"""


def connect(path):
    """Open a connection configured per PLAN. Autocommit mode
    (isolation_level=None): transactions are explicit BEGIN IMMEDIATE."""
    conn = sqlite3.connect(
        path,
        timeout=BUSY_TIMEOUT_MS / 1000,
        isolation_level=None,
        check_same_thread=True,
    )
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


@contextlib.contextmanager
def write_transaction(conn):
    """BEGIN IMMEDIATE ... COMMIT. Takes the write lock up front (a lock
    timeout surfaces here as OperationalError, before anything is written).
    Any exception, including an expected rejection raised inside the block,
    rolls the whole transaction back."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


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
        conn.executescript(SCHEMA)
    finally:
        conn.close()
