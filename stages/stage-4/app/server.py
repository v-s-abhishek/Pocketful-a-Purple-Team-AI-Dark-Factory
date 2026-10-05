"""HTTP layer: routing, body reading, JSON responses."""

import http.client
import io
import json
import queue
import re
import socketserver
import sqlite3
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import db, history, idempotency, parking
from .tokens import hash_token, new_token, token_matches
from .validation import (
    MAX_BODY_BYTES,
    RequestError,
    invalid_json,
    parse_header_int,
    parse_json_object,
    require_fields,
    validate_amount,
    validate_owner,
)

# An oversized body whose Content-Length is at most this is read and
# discarded so the client reliably receives the 400 instead of a reset.
# Anything larger is refused without reading and the connection is closed.
DRAIN_LIMIT_BYTES = 1024 * 1024
SOCKET_TIMEOUT_S = 10
# I11: from connection start to the end of the request body.
REQUEST_DEADLINE_S = 10
# Only these explicit versions are served; anything else is 400.
SERVED_VERSIONS = frozenset({"HTTP/1.0", "HTTP/1.1"})
# D3.3: requests handled at once. D3.3a: a connection takes a slot only once
# its request head is complete; until then it is parked (app/parking.py).
MAX_HANDLERS = 256

ACCOUNT_PATH = re.compile(r"^/accounts/([^/]+)$")
ACCOUNT_ACTION_PATH = re.compile(r"^/accounts/([^/]+)/(deposit|withdraw)$")
ACCOUNT_HISTORY_PATH = re.compile(r"^/accounts/([^/]+)/transactions$")


def _json_bytes(payload):
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _canonical_uuid(text):
    """Return text if it is a canonical lowercase UUID string, else None."""
    try:
        return text if str(uuid.UUID(text)) == text else None
    except ValueError:
        return None


class _DeadlineReader(io.RawIOBase):
    """Socket reader with one absolute deadline for the whole request.
    A plain socket timeout restarts on every recv, so a client trickling one
    byte every few seconds could hold a handler forever (slowloris).
    `prefix` is what the parked phase already received (the head and any
    bytes after it); it is served first, then the socket."""

    def __init__(self, sock, deadline, prefix=b""):
        super().__init__()
        self._sock = sock
        self._deadline = deadline
        self._prefix = memoryview(prefix)

    def readable(self):
        return True

    def readinto(self, buffer):
        if self._prefix:
            count = min(len(buffer), len(self._prefix))
            buffer[:count] = self._prefix[:count]
            self._prefix = self._prefix[count:]
            return count
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request deadline exceeded")
        self._sock.settimeout(remaining)
        return self._sock.recv_into(buffer)


# Status codes the stdlib raises for protocol errors, mapped onto the
# contract's JSON errors. Anything else from the stdlib is a malformed request.
_PROTOCOL_ERRORS = {
    408: (408, "request_timeout"),
    431: (431, "invalid_request"),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "pocketful/1"
    sys_version = ""
    timeout = SOCKET_TIMEOUT_S
    # Never fall back to HTTP/0.9, which answers without a status line.
    default_request_version = "HTTP/1.0"

    # --- plumbing -------------------------------------------------------

    def setup(self):
        super().setup()
        # One deadline from connection start to the end of the request body,
        # across the parked phase too. With HTTP/1.0 there is exactly one
        # request per connection.
        deadline, prefix = self.server.take_handoff(self.connection)
        self.rfile.close()
        self.rfile = io.BufferedReader(_DeadlineReader(self.connection, deadline, prefix))

    def handle_one_request(self):
        """Replaces the stdlib version so that every response, including
        protocol errors, timeouts and unknown methods, is JSON."""
        self.command = None
        self.requestline = ""
        self.request_version = self.default_request_version
        # True once the declared body is read, drained or refused. Before the
        # headers are parsed there is no body to drain.
        self._body_settled = True
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if not self.raw_requestline:
                self.close_connection = True
                return
            if len(self.raw_requestline) > 65536 or not self.raw_requestline.strip():
                # Over-long or blank request line (the stdlib would answer a
                # blank one with nothing at all).
                self.send_error(400)
                return
            if not self.parse_request():
                return  # parse_request already sent the error
            self._body_settled = False
            if self.request_version not in SERVED_VERSIONS:
                # R1.1-G: parse_request accepts an explicit "HTTP/0.9" (and
                # 1.2+), and the stdlib then answers 0.9 with no status line.
                self.request_version = "HTTP/1.0"
                self.send_error(400)
                return
            self._dispatch(self.command)
            self.wfile.flush()
        except TimeoutError:
            self._body_settled = True
            self.send_error(408)
        except ConnectionError:
            self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        """Every stdlib-level error becomes {"error": code} JSON."""
        status, error = _PROTOCOL_ERRORS.get(code, (400, "invalid_request"))
        self.close_connection = True
        if code == 505:
            # parse_request refuses HTTP/2+ before reading the headers. Read
            # them here so the declared body is drained like any other (R1.3-A).
            self._read_headers_for_drain()
        try:
            self._error(status, error)
        except OSError:
            pass  # the client is gone; nothing more to do

    def _read_headers_for_drain(self):
        try:
            self.headers = http.client.parse_headers(self.rfile, _class=self.MessageClass)
        except (http.client.HTTPException, TimeoutError):
            return  # unusable or too slow: answer and close without draining
        self._body_settled = False

    def log_message(self, fmt, *args):
        if self.server.log_requests:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status, payload):
        self._send_raw(status, _json_bytes(payload))

    def _send_raw(self, status, body, replayed=False):
        """Every response goes out here. `body` is the exact JSON bytes, so an
        idempotent replay is byte-identical to the original (I13)."""
        if not self._body_settled and not self._drain_body():
            status, body, replayed = 408, _json_bytes({"error": "request_timeout"}), False
        # Writing is outside the request deadline; give it a fresh timeout.
        self.connection.settimeout(SOCKET_TIMEOUT_S)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if replayed:
            self.send_header("Idempotent-Replayed", "true")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, code):
        self._send(status, {"error": code})

    def _read_body(self):
        """Read the raw request body, enforcing the 16 KiB cap before
        reading. Any Transfer-Encoding, or a missing, repeated or
        non-ASCII-digit Content-Length is invalid_json. Running past the
        request deadline is 408 request_timeout."""
        self._body_settled = True
        try:
            return self._read_body_framed()
        except TimeoutError:
            self.close_connection = True
            raise RequestError(408, "request_timeout") from None

    def _read_body_framed(self):
        if self.headers.get("Transfer-Encoding") is not None:
            self.close_connection = True
            raise invalid_json()
        lengths = self.headers.get_all("Content-Length") or []
        if not lengths:
            return b""
        length = parse_header_int(lengths[0]) if len(lengths) == 1 else None
        if length is None:
            self.close_connection = True
            raise invalid_json()
        if length > MAX_BODY_BYTES:
            if length <= DRAIN_LIMIT_BYTES:
                self._discard(length)
            else:
                self.close_connection = True
            raise invalid_json()
        body = self.rfile.read(length)
        if len(body) != length:
            self.close_connection = True
            raise invalid_json()
        return body

    def _drain_body(self):
        """Called before any response while the declared body is still unread.
        Reads and discards it, so the client reliably receives the response
        instead of a reset when the body arrives after the headers (R1.3-A).
        Bodies that cannot be framed or exceed DRAIN_LIMIT_BYTES are not read;
        the connection is closed. Returns False if the request deadline ran
        out while draining (the response becomes 408)."""
        self._body_settled = True
        if self.headers.get("Transfer-Encoding") is not None:
            self.close_connection = True
            return True
        lengths = self.headers.get_all("Content-Length") or []
        if not lengths:
            return True
        length = parse_header_int(lengths[0]) if len(lengths) == 1 else None
        if length is None or length > DRAIN_LIMIT_BYTES:
            self.close_connection = True
            return True
        try:
            self._discard(length)
        except TimeoutError:
            self.close_connection = True
            return False
        return True

    def _discard(self, length):
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 64 * 1024))
            if not chunk:
                break
            remaining -= len(chunk)

    def _json_body(self):
        return parse_json_object(self._read_body())

    def _dispatch(self, method):
        parts = urlsplit(self.path)
        path = parts.path
        route = None
        args = ()
        if path == "/health":
            route = {"GET": self.get_health}.get(method)
        elif path == "/accounts":
            route = {"POST": self.post_accounts}.get(method)
        elif path == "/audit":
            route = {"GET": self.get_audit}.get(method)
        elif path == "/transfers":
            route = {"POST": self.post_transfers}.get(method)
        else:
            match = ACCOUNT_PATH.match(path)
            action = ACCOUNT_ACTION_PATH.match(path)
            listing = ACCOUNT_HISTORY_PATH.match(path)
            if match:
                route = {"GET": self.get_account}.get(method)
                args = (match.group(1),)
            elif listing:
                route = {"GET": self.get_transactions}.get(method)
                args = (listing.group(1), parts.query)
            elif action:
                handler = {"deposit": self.post_deposit,
                           "withdraw": self.post_withdraw}[action.group(2)]
                route = {"POST": handler}.get(method)
                args = (action.group(1),)
        try:
            if route is None:
                # Unknown path or known path with the wrong method: both 404.
                raise RequestError(404, "not_found")
            route(*args)
        except RequestError as exc:
            self._error(exc.status, exc.code)
        except ConnectionError:
            raise  # client went away; handle_one_request closes quietly
        except db.Busy:
            self._error(503, "busy")
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc) or "busy" in str(exc):
                self._error(503, "busy")
            else:
                self._internal_error(exc)
        except Exception as exc:  # never leak a traceback to the client
            self._internal_error(exc)

    def _internal_error(self, exc):
        sys.stderr.write(f"internal error on {self.command} {self.path}: {exc!r}\n")
        self.close_connection = True
        self._error(500, "internal")

    # --- endpoints ------------------------------------------------------

    def get_health(self):
        self._send(200, {"ok": True})

    def post_accounts(self):
        body = self._json_body()
        require_fields(body, {"owner"})
        if "owner" not in body:
            raise RequestError(400, "invalid_request")
        owner = validate_owner(body["owner"])
        account_id = str(uuid.uuid4())
        token = new_token()
        conn = db.connect(self.server.db_path)
        try:
            with db.write_transaction(conn):
                conn.execute(
                    "INSERT INTO accounts (id, owner, balance, token_hash) VALUES (?, ?, 0, ?)",
                    (account_id, owner, hash_token(token)),
                )
        finally:
            conn.close()
        self._send(201, {"id": account_id, "owner": owner, "balance": 0, "token": token})

    def get_account(self, raw_id):
        account_id = _canonical_uuid(raw_id)
        if account_id is None:
            raise RequestError(404, "account_not_found")
        conn = db.connect(self.server.db_path)
        try:
            row = conn.execute(
                "SELECT id, owner, balance FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise RequestError(404, "account_not_found")
        self._send(200, {"id": row[0], "owner": row[1], "balance": row[2]})

    def get_transactions(self, raw_id, query):
        # D4.1 check order: query and repeated Authorization 400 (a cursor is
        # checked against the account in the path, so one from another
        # account is a 400 too) -> 404 -> 401. Then one read snapshot for
        # the page; no writer lock (D3.2).
        limit, cursor = history.parse_query(query)
        self._require_single_authorization()
        before = None
        if cursor is not None:
            before = history.open_cursor(self.server.cursor_key(), raw_id, cursor)
        account_id = _canonical_uuid(raw_id)
        if account_id is None:
            raise RequestError(404, "account_not_found")
        conn = db.connect(self.server.db_path)
        try:
            with db.read_transaction(conn):
                row = conn.execute(
                    "SELECT token_hash FROM accounts WHERE id = ?", (account_id,)
                ).fetchone()
                if row is None:
                    raise RequestError(404, "account_not_found")
                if not token_matches(row[0], self._bearer_token()):
                    raise RequestError(401, "unauthorized")
                items, last_seq = history.read_page(conn, account_id, before, limit)
        finally:
            conn.close()
        next_cursor = None
        if last_seq is not None:
            next_cursor = history.make_cursor(self.server.cursor_key(), account_id, last_seq)
        self._send(200, {"items": items, "next_cursor": next_cursor})

    def _amount_body(self):
        """The body of deposit/withdraw: exactly {"amount": <valid amount>}.
        A missing or bad amount is invalid_amount; with a valid amount, any
        other field is invalid_request."""
        body = self._json_body()
        amount = validate_amount(body.get("amount"))
        require_fields(body, {"amount"})
        return amount

    def _require_single_authorization(self):
        """Two or more Authorization headers are a malformed request (400),
        checked with the other request-shape 400s, before 404/401."""
        if len(self.headers.get_all("Authorization") or []) > 1:
            raise RequestError(400, "invalid_request")

    def _bearer_token(self):
        """The token from an Authorization value of exactly `Bearer <token>`
        (case-sensitive scheme, one space), or None. Any other form is
        simply not a credential, so the caller answers 401."""
        value = self.headers.get("Authorization")
        if value is None:
            return None
        # Q5: leading/trailing OWS (SP/HTAB) is not part of the value.
        value = value.strip(" \t")
        if not value.startswith("Bearer "):
            return None
        return value[len("Bearer "):] or None

    def post_deposit(self, raw_id):
        # Check order: body/amount and Idempotency-Key 400 -> 404 -> key
        # replay or 422 idempotency_key_reused -> 422 balance_limit.
        amount = self._amount_body()
        key = idempotency.parse_key(self.headers)
        account_id = _canonical_uuid(raw_id)
        if account_id is None:
            raise RequestError(404, "account_not_found")

        def move(conn):
            rows = conn.execute(
                "UPDATE accounts SET balance = balance + ? "
                "WHERE id = ? AND balance + ? <= ? RETURNING balance",
                (amount, account_id, amount, db.MAX_BALANCE),
            ).fetchall()
            if not rows:
                exists = conn.execute(
                    "SELECT 1 FROM accounts WHERE id = ?", (account_id,)
                ).fetchone()
                if exists is None:
                    raise RequestError(404, "account_not_found")
                raise RequestError(422, "balance_limit")
            self._record_move(conn, account_id, "deposit", amount)
            return 200, {"id": account_id, "balance": rows[0][0]}

        conn = db.connect(self.server.db_path)
        try:
            outcome = self._money_transaction(
                conn, account_id, idempotency.DEPOSIT, key,
                idempotency.fingerprint("deposit", account_id, None, amount), move,
            )
        finally:
            conn.close()
        self._send_raw(*outcome)

    def post_withdraw(self, raw_id):
        # Check order: body/amount and repeated Authorization 400 -> 404 ->
        # 401 -> 409. Existence and the token are checked before taking the
        # write lock, so requests without a valid token never contend for it.
        # Accounts are never deleted and tokens never change, so this read
        # cannot go stale; the money check is the conditional UPDATE inside
        # the transaction.
        amount = self._amount_body()
        self._require_single_authorization()
        key = idempotency.parse_key(self.headers)
        account_id = _canonical_uuid(raw_id)
        if account_id is None:
            raise RequestError(404, "account_not_found")

        def move(conn):
            rows = conn.execute(
                "UPDATE accounts SET balance = balance - ? "
                "WHERE id = ? AND balance >= ? RETURNING balance",
                (amount, account_id, amount),
            ).fetchall()
            if len(rows) != 1:
                raise RequestError(409, "insufficient_funds")
            self._record_move(conn, account_id, "withdrawal", amount)
            return 200, {"id": account_id, "balance": rows[0][0]}

        conn = db.connect(self.server.db_path)
        try:
            row = conn.execute(
                "SELECT token_hash FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
            if row is None:
                raise RequestError(404, "account_not_found")
            if not token_matches(row[0], self._bearer_token()):
                raise RequestError(401, "unauthorized")
            outcome = self._money_transaction(
                conn, account_id, idempotency.DEBIT, key,
                idempotency.fingerprint("withdraw", account_id, None, amount), move,
            )
        finally:
            conn.close()
        self._send_raw(*outcome)

    def post_transfers(self):
        # Check order: body/shape 400 (amount code first; then fields, id
        # types, from == to, repeated Authorization) -> 404 if either account
        # is missing -> 401 -> 409 -> 422. As in withdraw, existence and the
        # token are read before taking the write lock.
        body = self._json_body()
        amount = validate_amount(body.get("amount"))
        require_fields(body, {"from", "to", "amount"})
        from_raw, to_raw = body.get("from"), body.get("to")
        if type(from_raw) is not str or type(to_raw) is not str or from_raw == to_raw:
            raise RequestError(400, "invalid_request")
        self._require_single_authorization()
        key = idempotency.parse_key(self.headers)
        from_id, to_id = _canonical_uuid(from_raw), _canonical_uuid(to_raw)
        if from_id is None or to_id is None:
            raise RequestError(404, "account_not_found")

        def move(conn):
            debited = conn.execute(
                "UPDATE accounts SET balance = balance - ? "
                "WHERE id = ? AND balance >= ? RETURNING balance",
                (amount, from_id, amount),
            ).fetchall()
            if len(debited) != 1:
                raise RequestError(409, "insufficient_funds")
            credited = conn.execute(
                "UPDATE accounts SET balance = balance + ? "
                "WHERE id = ? AND balance + ? <= ? RETURNING balance",
                (amount, to_id, amount, db.MAX_BALANCE),
            ).fetchall()
            if len(credited) != 1:
                # Rolls back the debit too.
                raise RequestError(422, "balance_limit")
            transfer_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO transfers (id, from_id, to_id, amount) VALUES (?, ?, ?, ?)",
                (transfer_id, from_id, to_id, amount),
            )
            return 201, {"id": transfer_id, "from": from_id, "to": to_id, "amount": amount}

        conn = db.connect(self.server.db_path)
        try:
            rows = dict(conn.execute(
                "SELECT id, token_hash FROM accounts WHERE id IN (?, ?)", (from_id, to_id)
            ).fetchall())
            if from_id not in rows or to_id not in rows:
                raise RequestError(404, "account_not_found")
            if not token_matches(rows[from_id], self._bearer_token()):
                raise RequestError(401, "unauthorized")
            outcome = self._money_transaction(
                conn, from_id, idempotency.DEBIT, key,
                idempotency.fingerprint("transfer", from_id, to_id, amount), move,
            )
        finally:
            conn.close()
        self._send_raw(*outcome)

    @staticmethod
    def _money_transaction(conn, account_id, scope, key, fingerprint, move):
        """Run move(conn) -> (status, payload) in one BEGIN IMMEDIATE
        transaction and return (status, body bytes, replayed). With a key, the
        stored outcome is looked up inside that transaction first (D2.6): the
        same request is replayed with no effect, a different one is 422;
        otherwise the 2xx outcome is stored with the movement (D2.5). A
        rejection raised by move() rolls everything back, key row included."""
        for _ in range(2):
            try:
                with db.write_transaction(conn):
                    if key is not None:
                        stored = idempotency.stored_outcome(
                            conn, account_id, scope, key, fingerprint)
                        if stored is not None:
                            return stored[0], stored[1], True
                    status, payload = move(conn)
                    body = _json_bytes(payload)
                    if key is not None:
                        idempotency.record(
                            conn, account_id, scope, key, fingerprint, status, body)
                return status, body, False
            except idempotency.KeyRace:
                continue  # rolled back; the next pass finds the stored row
        raise RuntimeError("idempotency key row neither found nor stored")

    @staticmethod
    def _record_move(conn, account_id, kind, amount):
        conn.execute(
            "INSERT INTO external_moves (id, account_id, kind, amount) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), account_id, kind, amount),
        )

    def get_audit(self):
        # One statement is one read snapshot: a concurrent commit cannot land
        # between the three sums.
        conn = db.connect(self.server.db_path)
        try:
            balances, deposits, withdrawals = conn.execute(
                "SELECT"
                " (SELECT coalesce(sum(balance), 0) FROM accounts),"
                " (SELECT coalesce(sum(amount), 0) FROM external_moves WHERE kind = 'deposit'),"
                " (SELECT coalesce(sum(amount), 0) FROM external_moves WHERE kind = 'withdrawal')"
            ).fetchone()
        finally:
            conn.close()
        self._send(200, {
            "total_balances": balances,
            "total_deposits": deposits,
            "total_withdrawals": withdrawals,
            "conserved": balances == deposits - withdrawals,
        })


# --- D3.3a: the parked phase ------------------------------------------------

class _NeedMore(Exception):
    """The head probe ran out of received bytes before it could decide."""


class _HeadComplete(Exception):
    """The head probe reached dispatch: the request needs a handler."""


class _ProbeFile:
    """The bytes a parked connection has received, read the way the
    handler's BufferedReader over _DeadlineReader would read them: running
    out means EOF if the peer closed, TimeoutError past the deadline, and
    otherwise "not yet" (_NeedMore)."""

    def __init__(self, data, eof, expired):
        self._data, self._pos = data, 0
        self._eof, self._expired = eof, expired

    def readline(self, limit=-1):
        data, pos = self._data, self._pos
        end = len(data) if limit is None or limit < 0 else min(len(data), pos + limit)
        newline = data.find(b"\n", pos, end)
        if newline >= 0:
            end = newline + 1
        elif (limit is None or limit < 0 or end - pos < limit) and not self._eof:
            if self._expired:
                raise TimeoutError("request deadline exceeded")
            raise _NeedMore()
        self._pos = end
        return bytes(data[pos:end])

    def take(self, count):
        """Consume up to `count` received bytes; return how many are missing."""
        taken = min(count, len(self._data) - self._pos)
        self._pos += taken
        return count - taken


class _NoSocket:
    def settimeout(self, value):
        pass


class _HeadProbe(Handler):
    """Runs the handler's own head handling (request line, headers, version,
    and every error reply they produce) on a parked connection's bytes,
    writing into memory. Reaching dispatch means the head is complete; a
    reply that has to drain a body first reports how much is still due."""

    def __init__(self, server, client_address, data, eof, expired):
        # No BaseRequestHandler.__init__: nothing here touches the socket.
        self.server, self.client_address = server, client_address
        self.request = self.connection = _NoSocket()
        self.rfile = _ProbeFile(data, eof, expired)
        self.wfile = io.BytesIO()
        self.close_connection = True
        self.drain_left = 0

    def _dispatch(self, method):
        raise _HeadComplete()

    def _discard(self, length):
        self.drain_left = self.rfile.take(length)

    def timeout_reply(self):
        """The reply instead, when the body does not arrive in time."""
        self.wfile = io.BytesIO()
        self._body_settled = True
        self._send_raw(408, _json_bytes({"error": "request_timeout"}))
        return self.wfile.getvalue()


class WalletServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # socketserver's default listen backlog is 5; bursts of concurrent
    # clients then get connection resets on Linux.
    request_queue_size = 1024

    def __init__(self, address, db_path, log_requests=False, max_handlers=MAX_HANDLERS):
        self.db_path = db_path
        self.log_requests = log_requests
        # D3.3: one slot per handler thread, taken once the head is complete
        # (D3.3a) and before the thread exists; given back when it ends.
        self._handler_slots = threading.BoundedSemaphore(max_handlers)
        # D3.3a: connections accepted and not yet in a handler (parked, or
        # head complete and waiting for a slot). With none free, the accept
        # loop stops and the excess waits in the listen backlog.
        self._parked_slots = threading.BoundedSemaphore(parking.PARKED_MAX)
        self._ready = queue.Queue()
        self._handoffs = {}
        self._cursor_key = None
        self._lot = None
        self._dispatcher = None
        # Set by shutdown(): waits for a free slot give up, so serve_forever
        # can stop even while every slot is held.
        self._stopping = threading.Event()
        super().__init__(address, Handler)

    def cursor_key(self):
        """D4.10: the per-database HMAC key for history cursors (read once)."""
        if self._cursor_key is None:
            conn = db.connect(self.db_path)
            try:
                self._cursor_key = db.cursor_key(conn)
            finally:
                conn.close()
        return self._cursor_key

    def serve_forever(self, poll_interval=0.5):
        self._stopping.clear()
        self._lot = parking.ParkingLot(self._probe, self._ready.put, self._parked_slots.release)
        self._lot.start()
        self._dispatcher = threading.Thread(target=self._dispatch_ready,
                                            name="pocketful-dispatch", daemon=True)
        self._dispatcher.start()
        try:
            super().serve_forever(poll_interval)
        finally:
            self._stop_pool()

    def shutdown(self):
        self._stopping.set()
        super().shutdown()

    def server_close(self):
        self._stop_pool()
        super().server_close()

    def _stop_pool(self):
        self._stopping.set()
        if self._lot is not None:
            self._lot.stop()
        if self._dispatcher is not None:
            self._dispatcher.join(5)

    def get_request(self):
        # A timed wait, so the serving thread still handles signals and sees
        # a shutdown request. OSError is what _handle_request_noblock treats
        # as "no request this time"; the connection stays in the backlog.
        while not self._parked_slots.acquire(timeout=0.1):
            if self._stopping.is_set():
                raise OSError("server is shutting down")
        try:
            return super().get_request()
        except BaseException:
            self._parked_slots.release()
            raise

    def process_request(self, request, client_address):
        """Park the connection until its head is complete (no thread yet)."""
        self._lot.park(request, client_address, time.monotonic() + REQUEST_DEADLINE_S)

    def shutdown_request(self, request):
        # Only for connections socketserver gives up on before parking.
        try:
            super().shutdown_request(request)
        finally:
            self._parked_slots.release()

    def _probe(self, client_address, data, eof, expired):
        probe = _HeadProbe(self, client_address, data, eof, expired)
        try:
            probe.handle_one_request()
        except _NeedMore:
            return None
        except _HeadComplete:
            return parking.HEAD_COMPLETE
        reply = probe.wfile.getvalue()
        timeout_reply = probe.timeout_reply() if probe.drain_left else None
        return reply, probe.drain_left, timeout_reply

    def _dispatch_ready(self):
        """Give each complete head, in arrival order, a slot and a thread."""
        while True:
            try:
                conn = self._ready.get(timeout=0.1)
            except queue.Empty:
                if self._stopping.is_set():
                    return
                continue
            while not self._handler_slots.acquire(timeout=0.1):
                if self._stopping.is_set():
                    break
            else:
                if not self._stopping.is_set():
                    self._start_handler(conn)
                    continue
                self._handler_slots.release()
            # Stopping: what has not reached a handler is closed unanswered,
            # as connections still in the listen backlog are.
            self._close_unhandled(conn)
            while True:
                try:
                    self._close_unhandled(self._ready.get_nowait())
                except queue.Empty:
                    return

    def _start_handler(self, conn):
        self._parked_slots.release()
        # A3.1-3: the handler keeps the head (raw and parsed) until it ends,
        # so its bytes stay charged to the Q3.1-B budget until then.
        head = self._lot.release_head(conn, keep_charge=True)
        self._handoffs[conn.sock] = (conn.deadline, head)
        conn.sock.setblocking(True)
        thread = threading.Thread(target=self.process_request_thread,
                                  args=(conn.sock, conn.addr, len(head)), daemon=True)
        try:
            thread.start()
        except RuntimeError:
            self._handoffs.pop(conn.sock, None)
            self._lot.uncharge(len(head))
            self._handler_slots.release()
            socketserver.TCPServer.shutdown_request(self, conn.sock)

    def _close_unhandled(self, conn):
        self._lot.release_head(conn)
        socketserver.TCPServer.shutdown_request(self, conn.sock)
        self._parked_slots.release()

    def take_handoff(self, sock):
        """(deadline, bytes already received) for a connection's handler."""
        handoff = self._handoffs.pop(sock, None)
        if handoff is None:
            return time.monotonic() + REQUEST_DEADLINE_S, b""
        return handoff

    def process_request_thread(self, request, client_address, charged=0):
        """A handler thread: one request, then the slot is given back and
        its `charged` head bytes stop counting against the budget."""
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self._handoffs.pop(request, None)
            try:
                socketserver.TCPServer.shutdown_request(self, request)
            finally:
                self._lot.uncharge(charged)
                self._handler_slots.release()
