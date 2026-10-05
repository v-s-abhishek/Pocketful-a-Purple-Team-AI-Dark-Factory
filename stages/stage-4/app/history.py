"""Unit 4.1: account history (D4.1-D4.3, D4.10); reversal items from 4.2.

`GET /accounts/{id}/transactions?limit=&cursor=` pages one account's ledger
rows newest first, by the ledger sequence (keyset, never OFFSET). The
cursor is opaque to clients: the sequence of the last item served, bound to
the account and protected by an HMAC with a per-database key."""

import base64
import hashlib
import hmac
import re
from urllib.parse import parse_qsl

from .validation import RequestError

DEFAULT_LIMIT = 20
MAX_LIMIT = 100
MAX_CURSOR_CHARS = 256
# ASCII digits, no sign, no leading zero (D4.10). [0-9], not \d, which
# would also match other scripts' digits.
_LIMIT = re.compile(r"[1-9][0-9]{0,2}")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")
_CURSOR_VERSION = 1
_SEQ_BYTES = 8
_MAC_BYTES = 32
_CURSOR_BYTES = 1 + _SEQ_BYTES + _MAC_BYTES
_MAC_CONTEXT = b"pocketful history cursor v1\0"

# Every row of one page comes from this one statement: one read snapshot.
# A reversal is a transfers row with a reversals link (D4.4); the original
# transfer it reverses stays an ordinary transfer item.
PAGE_SQL = (
    "SELECT la.seq, l.source,"
    " e.id, e.kind, e.amount, e.created_at,"
    " t.id, t.from_id, t.to_id, t.amount, t.created_at, r.transfer_id"
    " FROM ledger_accounts la"
    " JOIN ledger l ON l.seq = la.seq"
    " LEFT JOIN external_moves e ON l.source = 'external_moves' AND e.id = l.row_id"
    " LEFT JOIN transfers t ON l.source = 'transfers' AND t.id = l.row_id"
    " LEFT JOIN reversals r ON r.reversal_id = t.id"
    " WHERE la.account_id = ? AND la.seq < ?"
    " ORDER BY la.seq DESC LIMIT ?"
)
# No cursor: start from the newest row. SQLite rowids are at most
# 2**63 - 1, so `seq < 2**63 - 1` misses only a row SQLite cannot reach
# by max + 1 (it would have to have been inserted with that rowid).
_NO_CURSOR = 2**63 - 1


def invalid():
    return RequestError(400, "invalid_request")


def parse_query(query):
    """(limit, cursor or None) from the raw query string, decoded once.
    Only `limit` and `cursor`, each at most once and never empty."""
    try:
        pairs = parse_qsl(query, strict_parsing=True, keep_blank_values=True)
    except ValueError:
        raise invalid() from None
    params = {}
    for name, value in pairs:
        if name not in ("limit", "cursor") or name in params or value == "":
            raise invalid()
        params[name] = value
    limit = DEFAULT_LIMIT
    if "limit" in params:
        if not _LIMIT.fullmatch(params["limit"]) or int(params["limit"]) > MAX_LIMIT:
            raise invalid()
        limit = int(params["limit"])
    return limit, params.get("cursor")


def _mac(key, account_id, seq_bytes):
    return hmac.new(key, _MAC_CONTEXT + account_id.encode("utf-8") + b"\0" + seq_bytes,
                    hashlib.sha256).digest()


def make_cursor(key, account_id, seq):
    seq_bytes = seq.to_bytes(_SEQ_BYTES, "big")
    raw = bytes([_CURSOR_VERSION]) + seq_bytes + _mac(key, account_id, seq_bytes)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def open_cursor(key, account_id, cursor):
    """The sequence a cursor continues after, or 400 if it is not one this
    server issued for `account_id` (forged, truncated, re-encoded, or from
    another account)."""
    if len(cursor) > MAX_CURSOR_CHARS or not _BASE64URL.fullmatch(cursor):
        raise invalid()
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
    except ValueError:
        raise invalid() from None
    # Only the canonical spelling: no padding, no stray trailing bits.
    if len(raw) != _CURSOR_BYTES or base64.urlsafe_b64encode(raw).rstrip(b"=") != cursor.encode():
        raise invalid()
    version, seq_bytes, mac = raw[0], raw[1:1 + _SEQ_BYTES], raw[1 + _SEQ_BYTES:]
    if version != _CURSOR_VERSION or not hmac.compare_digest(mac, _mac(key, account_id, seq_bytes)):
        raise invalid()
    return int.from_bytes(seq_bytes, "big")


def _item(account_id, row):
    (_seq, source, e_id, kind, e_amount, e_created,
     t_id, from_id, to_id, t_amount, t_created, reverses) = row
    if source == "external_moves":
        return {"id": e_id, "type": kind, "amount": e_amount,
                "counterparty": None, "created_at": e_created}
    outgoing = from_id == account_id
    item = {"id": t_id, "type": None, "amount": t_amount,
            "counterparty": to_id if outgoing else from_id, "created_at": t_created}
    if reverses is None:
        item["type"] = "transfer_out" if outgoing else "transfer_in"
    else:
        item["type"] = "reversal_out" if outgoing else "reversal_in"
        item["reverses"] = reverses
    return item


def read_page(conn, account_id, before, limit):
    """(items, last sequence or None if this is the last page)."""
    rows = conn.execute(PAGE_SQL, (account_id, _NO_CURSOR if before is None else before, limit + 1)).fetchall()
    more = len(rows) > limit
    rows = rows[:limit]
    return [_item(account_id, row) for row in rows], rows[-1][0] if more else None
