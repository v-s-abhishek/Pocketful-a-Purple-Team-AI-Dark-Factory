"""Idempotency keys (stage 2, D2.1-D2.9). A key belongs to one account and
one scope: 'debit' (withdraw and transfer, authorized by the owner's token)
or 'deposit' (Q2-A). Only 2xx outcomes are stored, in the same write
transaction as the money movement, so a rejection leaves nothing behind."""

import json
import re
import sqlite3

from .validation import RequestError

HEADER = "Idempotency-Key"
DEBIT = "debit"
DEPOSIT = "deposit"
# D2.2: 1-255 visible ASCII characters, matched exactly.
_KEY = re.compile(r"[\x21-\x7e]{1,255}")


def parse_key(headers):
    """The Idempotency-Key value, or None if the header is absent. A repeated
    header, or a value that is not 1-255 visible ASCII characters after
    trimming leading/trailing OWS (interior whitespace and obs-fold
    included), is 400 invalid_request."""
    values = headers.get_all(HEADER) or []
    if not values:
        return None
    if len(values) > 1:
        raise RequestError(400, "invalid_request")
    key = values[0].strip(" \t")
    if not _KEY.fullmatch(key):
        raise RequestError(400, "invalid_request")
    return key


def fingerprint(operation, account_id, to_id, amount):
    """D2.4: the validated request, not its raw bytes."""
    return json.dumps([operation, account_id, to_id, amount], separators=(",", ":"))


def stored_outcome(conn, account_id, scope, key, fp):
    """The stored (status, body bytes) for this key, None if there is none,
    or 422 idempotency_key_reused if it was stored for a different request."""
    row = conn.execute(
        "SELECT fingerprint, status, response FROM idempotency_keys"
        " WHERE account_id = ? AND scope = ? AND key = ?",
        (account_id, scope, key),
    ).fetchone()
    if row is None:
        return None
    if row[0] != fp:
        raise RequestError(422, "idempotency_key_reused")
    return row[1], row[2].encode("utf-8")


class KeyRace(Exception):
    """The PRIMARY KEY backstop fired: another request stored this key first.
    The caller rolls back and answers from the stored row (D2.6)."""


def record(conn, account_id, scope, key, fp, status, body):
    try:
        conn.execute(
            "INSERT INTO idempotency_keys"
            " (account_id, scope, key, fingerprint, status, response)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (account_id, scope, key, fp, status, body.decode("utf-8")),
        )
    except sqlite3.IntegrityError as exc:
        if "UNIQUE" not in str(exc):
            raise
        raise KeyRace() from None
