"""HTTP-level checks for unit 1.1 against a real server process."""

import http.client
import json
import os
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from harness import CLIENT_TIMEOUT_S, ServerProcess, ServerTestCase


def raw_exchange(port, data):
    """Send raw bytes and read the whole response until the server closes."""
    with socket.create_connection(("127.0.0.1", port), timeout=CLIENT_TIMEOUT_S) as sock:
        sock.sendall(data)
        chunks = []
        while True:
            try:
                chunk = sock.recv(65536)
            except ConnectionResetError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


class HealthAndRoutingTest(ServerTestCase):
    def test_health(self):
        self.assertEqual(self.request("GET", "/health"), (200, {"ok": True}))

    def test_unknown_routes_and_wrong_methods_are_404(self):
        cases = [
            ("GET", "/"),
            ("GET", "/nope"),
            ("GET", "/accounts"),
            ("GET", "/accounts/"),
            ("POST", "/health"),
            ("DELETE", "/accounts"),
            ("PUT", "/accounts/" + str(uuid.uuid4())),
            ("POST", "/accounts/" + str(uuid.uuid4())),
            ("GET", "/accounts/a/b"),
            ("GET", "/transfers"),
            ("PUT", "/transfers"),
            ("POST", "/transfers/"),
            ("GET", "/accounts/" + str(uuid.uuid4()) + "/deposit"),
            ("PUT", "/accounts/" + str(uuid.uuid4()) + "/withdraw"),
            ("POST", "/accounts/" + str(uuid.uuid4()) + "/deposit/"),
            ("POST", "/accounts/" + str(uuid.uuid4()) + "/DEPOSIT"),
            ("POST", "/accounts/" + str(uuid.uuid4()) + "/transfer"),
            ("POST", "/audit"),
        ]
        for method, path in cases:
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(method, path), (404, {"error": "not_found"}))

    def test_query_string_ignored_for_routing(self):
        self.assertEqual(self.request("GET", "/health?x=1"), (200, {"ok": True}))

    def test_body_after_headers_still_gets_response(self):
        # R1.3-A: a declared body still unread when the response goes out is
        # drained first, or a body arriving after the close resets the response.
        body = b'{"amount": 1}'
        cases = [
            ("POST", "/nope", "HTTP/1.1", 404, {"error": "not_found"}),
            ("PUT", "/transfers", "HTTP/1.1", 404, {"error": "not_found"}),
            ("GET", "/health", "HTTP/1.1", 200, {"ok": True}),
            ("GET", "/accounts/" + str(uuid.uuid4()), "HTTP/1.1", 404,
             {"error": "account_not_found"}),
            # Unserved versions: HTTP/2+ is refused before the headers are read.
            ("POST", "/accounts", "HTTP/2.0", 400, {"error": "invalid_request"}),
            ("POST", "/accounts", "HTTP/1.2", 400, {"error": "invalid_request"}),
        ]
        for method, path, version, status, payload in cases:
            with self.subTest(method=method, path=path, version=version):
                with socket.create_connection(
                    ("127.0.0.1", self.server.port), timeout=CLIENT_TIMEOUT_S
                ) as sock:
                    sock.sendall(
                        f"{method} {path} {version}\r\nHost: x\r\n"
                        f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                    )
                    time.sleep(0.2)
                    sock.sendall(body)
                    chunks = []
                    while chunk := sock.recv(65536):
                        chunks.append(chunk)
                head, _, raw = b"".join(chunks).partition(b"\r\n\r\n")
                self.assertTrue(head.startswith(f"HTTP/1.0 {status} ".encode()), head)
                self.assertEqual(json.loads(raw), payload)


class AccountsTest(ServerTestCase):
    def test_create_then_get(self):
        status, created = self.request("POST", "/accounts", {"owner": "alice"})
        self.assertEqual(status, 201)
        self.assertEqual(set(created), {"id", "owner", "balance", "token"})
        self.assertEqual(created["owner"], "alice")
        self.assertIs(type(created["balance"]), int)
        self.assertEqual(created["balance"], 0)
        self.assertEqual(str(uuid.UUID(created["id"])), created["id"])
        self.assertEqual(uuid.UUID(created["id"]).version, 4)
        self.assertIsInstance(created["token"], str)

        status, fetched = self.request("GET", "/accounts/" + created["id"])
        self.assertEqual(status, 200)
        self.assertEqual(fetched, {"id": created["id"], "owner": "alice", "balance": 0})

    def test_unknown_account_is_404(self):
        for account_id in (str(uuid.uuid4()), "not-a-uuid", "1%20OR%201=1",
                           "..%2F..%2Fetc%2Fpasswd", "'", str(uuid.uuid4()).upper()):
            with self.subTest(id=account_id):
                self.assertEqual(self.request("GET", "/accounts/" + account_id),
                                 (404, {"error": "account_not_found"}))

    def test_owner_validation(self):
        before = self.account_count()
        for body in ({}, {"owner": ""}, {"owner": "x" * 65}, {"owner": None},
                     {"owner": 5}, {"owner": ["a"]}, {"owner": "a", "extra": 1},
                     {"owner": "a", "id": str(uuid.uuid4())},
                     {"owner": "a", "balance": 100}):
            with self.subTest(body=body):
                self.assertEqual(self.request("POST", "/accounts", body),
                                 (400, {"error": "invalid_request"}))
        lone = self.request("POST", "/accounts", raw=b'{"owner": "\\ud800"}')
        self.assertEqual(lone, (400, {"error": "invalid_request"}))
        self.assertEqual(self.account_count(), before)

    def test_owner_control_characters_rejected(self):
        # R1.1-A: NUL used to reach SQLite and come back as a 500.
        before = self.account_count()
        for owner in ("\x00", "\x00abc", "a\x00b", "\x00" * 64, "a\nb", "\n", "\t",
                      "a\rb", "\x1f", "\x7f", "a\x7f"):
            with self.subTest(owner=owner):
                self.assertEqual(self.request("POST", "/accounts", {"owner": owner}),
                                 (400, {"error": "invalid_request"}))
        self.assertEqual(self.account_count(), before)

    def test_owner_invisible_and_whitespace_only_rejected(self):
        # 1.1c owner ruling (Breaker Q1/Q2).
        before = self.account_count()
        rejected = [" ", " " * 64, " ", "　"]
        for ch in ("​", "‮", " ", " ", "﻿", "\U000e0001"):
            rejected += [ch, ch + "bob", "b" + ch + "ob", "bob" + ch]
        for owner in rejected:
            with self.subTest(owner=owner):
                self.assertEqual(self.request("POST", "/accounts", {"owner": owner}),
                                 (400, {"error": "invalid_request"}))
        self.assertEqual(self.account_count(), before)
        for owner in ("a b", "Zoë"):
            with self.subTest(owner=owner):
                self.assertEqual(self.create_account(owner)["owner"], owner)

    def test_owner_boundaries(self):
        self.assertEqual(self.create_account("x")["owner"], "x")
        self.assertEqual(self.create_account("y" * 64)["owner"], "y" * 64)

    def test_client_cannot_choose_id_or_balance(self):
        # Same as the extra-field rejection above, asserted from the DB side.
        chosen = str(uuid.uuid4())
        self.request("POST", "/accounts", {"owner": "a", "id": chosen, "balance": 10})
        self.assertEqual(self.query("SELECT count(*) FROM accounts WHERE id = ?", (chosen,)),
                         [(0,)])
        self.assertEqual(self.query("SELECT count(*) FROM accounts WHERE balance != 0"),
                         [(0,)])

    def test_concurrent_creates(self):
        before = self.account_count()
        with ThreadPoolExecutor(max_workers=50) as pool:
            results = list(pool.map(
                lambda i: self.request("POST", "/accounts", {"owner": f"user{i}"}),
                range(100)))
        self.assertTrue(all(status == 201 for status, _ in results), results)
        ids = {body["id"] for _, body in results}
        tokens = {body["token"] for _, body in results}
        self.assertEqual(len(ids), 100)
        self.assertEqual(len(tokens), 100)
        self.assertEqual(self.account_count(), before + 100)


class BodyParserOverHttpTest(ServerTestCase):
    """Every malformed body is 400 invalid_json and creates no row."""

    def test_malformed_bodies(self):
        cases = {
            "non-json": b"owner=alice",
            "empty": b"",
            "array": b'[{"owner": "alice"}]',
            "scalar": b"42",
            "string": b'"alice"',
            "duplicate keys": b'{"owner": "a", "owner": "b"}',
            "NaN": b'{"owner": "a", "n": NaN}',
            "Infinity": b'{"owner": "a", "n": Infinity}',
            "over 16 KiB": b'{"owner": "a"}'.ljust(16 * 1024 + 1, b" "),
            "bad utf-8": b'{"owner": "\xff"}',
        }
        for name, raw in cases.items():
            with self.subTest(case=name):
                before = self.account_count()
                self.assertEqual(self.request("POST", "/accounts", raw=raw),
                                 (400, {"error": "invalid_json"}))
                self.assertEqual(self.account_count(), before)

    def test_no_body_at_all(self):
        before = self.account_count()
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=CLIENT_TIMEOUT_S)
        try:
            conn.putrequest("POST", "/accounts")
            conn.endheaders()
            resp = conn.getresponse()
            self.assertEqual(resp.status, 400)
            self.assertEqual(resp.read(), b'{"error":"invalid_json"}')
        finally:
            conn.close()
        self.assertEqual(self.account_count(), before)

    def test_exactly_16_kib_is_accepted(self):
        raw = b'{"owner": "edge"}'.ljust(16 * 1024, b" ")
        status, body = self.request("POST", "/accounts", raw=raw)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["owner"], "edge")

    def test_huge_declared_length_refused_without_reading(self):
        # Declares 1 GiB, sends almost nothing: must answer 400, not hang.
        reply = raw_exchange(self.server.port, b"POST /accounts HTTP/1.1\r\nHost: x\r\n"
                                               b"Content-Length: 1073741824\r\n\r\n{")
        self.assertIn(b" 400 ", reply.split(b"\r\n")[0])
        self.assertIn(b"invalid_json", reply)

    def test_chunked_body_rejected(self):
        before = self.account_count()
        reply = raw_exchange(self.server.port, b"POST /accounts HTTP/1.1\r\nHost: x\r\n"
                                               b"Transfer-Encoding: chunked\r\n\r\n"
                                               b"e\r\n{\"owner\": \"a\"}\r\n0\r\n\r\n")
        self.assertEqual(self.account_count(), before)
        self.assertIn(b" 400 ", reply.split(b"\r\n")[0])
        self.assertIn(b"invalid_json", reply)

    def test_bad_content_length(self):
        before = self.account_count()
        for value in (b"-1", b"abc", b"1e3"):
            with self.subTest(value=value):
                reply = raw_exchange(self.server.port,
                                     b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Length: "
                                     + value + b"\r\n\r\n{}")
                self.assertIn(b"invalid_json", reply)
        self.assertEqual(self.account_count(), before)


def split_response(data):
    head, _, body = data.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    return status_line, head, body


class ProtocolErrorsAreJsonTest(ServerTestCase):
    """R1.1-B/C/D: every response, including protocol errors, is JSON with a
    proper HTTP/1.x status line, and client input never produces a 500."""

    def assertJsonError(self, data, status, error):
        status_line, head, body = split_response(data)
        self.assertRegex(status_line, rb"^HTTP/1\.[01] %d " % status, data[:200])
        self.assertIn(b"Content-Type: application/json", head, data[:200])
        self.assertEqual(json.loads(body), {"error": error})

    def test_unicode_digit_content_length(self):
        before = self.account_count()
        for value in (b"\xb2", b"\xb9", b"\xb3", b"1\xb2", b"+14", b"-1", b"14, 14"):
            with self.subTest(value=value):
                data = raw_exchange(self.server.port,
                                    b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Length: "
                                    + value + b"\r\n\r\n" + b'{"owner": "a"}')
                self.assertJsonError(data, 400, "invalid_json")
        self.assertEqual(self.account_count(), before)

    def test_duplicate_content_length_rejected(self):
        before = self.account_count()
        data = raw_exchange(self.server.port,
                            b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Length: 14\r\n"
                            b"Content-Length: 14\r\n\r\n" + b'{"owner": "a"}')
        self.assertJsonError(data, 400, "invalid_json")
        self.assertEqual(self.account_count(), before)

    def test_leading_zero_content_length_is_fine(self):
        body = b'{"owner": "z"}'
        data = raw_exchange(self.server.port,
                            b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Length: 0"
                            + str(len(body)).encode() + b"\r\n\r\n" + body)
        self.assertRegex(split_response(data)[0], rb"^HTTP/1\.0 201 ")

    def test_unrouted_methods_are_404_json(self):
        for method in (b"HEAD", b"OPTIONS", b"TRACE", b"CONNECT", b"FOO", b"PATCH", b"PUT",
                       b"DELETE"):
            for path in (b"/health", b"/accounts", b"/nope"):
                with self.subTest(method=method, path=path):
                    data = raw_exchange(self.server.port,
                                        method + b" " + path + b" HTTP/1.1\r\nHost: x\r\n\r\n")
                    self.assertJsonError(data, 404, "not_found")

    def test_malformed_request_lines(self):
        for request in (b"GARBAGE\r\n\r\n", b"GET /health HTTP/9.9\r\n\r\n",
                        b"GET /health HTTP/1.1 extra\r\n\r\n", b"GET /health FOO/1.1\r\n\r\n",
                        b"\r\n\r\n", b"GET /" + b"a" * 70_000 + b" HTTP/1.1\r\n\r\n"):
            with self.subTest(request=request[:30]):
                self.assertJsonError(raw_exchange(self.server.port, request),
                                     400, "invalid_request")

    def test_only_http_1_0_and_1_1_are_served(self):
        # R1.1-G: an explicit HTTP/0.9 used to get a bare body with no status line.
        for version in (b"HTTP/0.9", b"HTTP/2.0", b"HTTP/1.2", b"HTTP/9.9"):
            for request in (b"GET /health " + version + b"\r\n\r\n",
                            b"GET /health " + version + b"\r\nHost: x\r\n\r\n"):
                with self.subTest(request=request):
                    data = raw_exchange(self.server.port, request)
                    self.assertTrue(data.startswith(b"HTTP/1.0 400 "), data[:200])
                    self.assertJsonError(data, 400, "invalid_request")
        for version in (b"HTTP/1.0", b"HTTP/1.1"):
            with self.subTest(version=version):
                data = raw_exchange(self.server.port,
                                    b"GET /health " + version + b"\r\nHost: x\r\n\r\n")
                self.assertRegex(split_response(data)[0], rb"^HTTP/1\.0 200 ")

    def test_oversized_headers_are_431_json(self):
        for request in (b"GET /health HTTP/1.1\r\nX-Pad: " + b"a" * 70_000 + b"\r\n\r\n",
                        b"GET /health HTTP/1.1\r\n"
                        + b"".join(b"H%d: v\r\n" % i for i in range(150)) + b"\r\n"):
            with self.subTest(request=request[:40]):
                self.assertJsonError(raw_exchange(self.server.port, request),
                                     431, "invalid_request")


class RequestDeadlineTest(ServerTestCase):
    """R1.1-E / I11: one 10 s deadline per request, however slowly the client
    trickles bytes; other clients keep being served meanwhile."""

    def slow_client(self, preamble, trickle, results, key):
        sock = socket.create_connection(("127.0.0.1", self.server.port), timeout=20)
        start = time.monotonic()
        sock.sendall(preamble)
        stop = threading.Event()

        def sender():
            for byte in trickle:
                if stop.wait(1.0):
                    return
                try:
                    sock.sendall(bytes([byte]))
                except OSError:
                    return

        thread = threading.Thread(target=sender, daemon=True)
        thread.start()
        chunks = []
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except OSError:
            pass
        results[key] = (time.monotonic() - start, b"".join(chunks))
        stop.set()
        thread.join()
        sock.close()

    def test_trickling_clients_are_cut_off_and_health_stays_up(self):
        body = b'{"owner": "slowloris-slowloris"}'
        clients = {
            # headers complete, body at 1 byte/s (would take ~32 s)
            "body": (b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n"
                     % len(body), body),
            # headers at 1 byte/s, never finishing
            "headers": (b"GET /health HTTP/1.1\r\n", b"X-Slow: " + b"a" * 40),
            # opens a connection and sends nothing
            "idle": (b"", b""),
        }
        before = self.account_count()
        results = {}
        threads = [threading.Thread(target=self.slow_client, args=(pre, tr, results, key))
                   for key, (pre, tr) in clients.items()]
        for thread in threads:
            thread.start()
        # While they are held, the service keeps answering quickly.
        for _ in range(5):
            t0 = time.monotonic()
            self.assertEqual(self.request("GET", "/health"), (200, {"ok": True}))
            self.assertLess(time.monotonic() - t0, 1.0)
            time.sleep(1)
        for thread in threads:
            thread.join(25)
        for key in clients:
            with self.subTest(client=key):
                elapsed, data = results[key]
                self.assertLess(elapsed, 12.0, f"{key} held for {elapsed:.1f}s")
                self.assertGreater(elapsed, 9.0, f"{key} cut too early ({elapsed:.1f}s)")
                # The idle and header-trickle clients must always receive
                # the 408. The body client may be reset while still sending.
                if key != "body" or data:
                    status_line, head, payload = split_response(data)
                    self.assertRegex(status_line, rb"^HTTP/1\.0 408 ")
                    self.assertEqual(json.loads(payload), {"error": "request_timeout"})
        self.assertEqual(self.account_count(), before)
        self.assertFalse(self.query("SELECT count(*) FROM accounts WHERE owner LIKE 'slow%'")[0][0])


class StorageInvariantsTest(ServerTestCase):
    def test_i5_balance_is_stored_as_integer(self):
        for i in range(5):
            self.create_account(f"o{i}")
        types = self.query("SELECT DISTINCT typeof(balance) FROM accounts")
        self.assertEqual(types, [("integer",)])

    def test_i3_schema_rejects_negative_and_non_integer_balance(self):
        # Defense in depth: the database itself refuses bad balances.
        import sqlite3
        account = self.create_account("schema")
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            for value in (-1, 1.5, "ten", 10**15 + 1):
                with self.subTest(value=value):
                    with self.assertRaises(sqlite3.IntegrityError):
                        conn.execute("UPDATE accounts SET balance = ? WHERE id = ?",
                                     (value, account["id"]))
            # STRICT converts integer-looking text losslessly; it is still
            # stored as an integer, never as text or real.
            conn.execute("UPDATE accounts SET balance = '10' WHERE id = ?", (account["id"],))
            self.assertEqual(
                conn.execute("SELECT typeof(balance) FROM accounts WHERE id = ?",
                             (account["id"],)).fetchone(), ("integer",))
            conn.execute("UPDATE accounts SET balance = 0 WHERE id = ?", (account["id"],))
            # R1.1-A: the owner CHECK is NUL-safe even if validation is bypassed.
            for owner in ("\x00", "a\x00b", "a\x00"):
                with self.subTest(owner=owner):
                    with self.assertRaises(sqlite3.IntegrityError):
                        conn.execute("UPDATE accounts SET owner = ? WHERE id = ?",
                                     (owner, account["id"]))
        finally:
            conn.close()

    def test_i8_token_hashed_never_stored_or_returned(self):
        created = self.create_account("secret")
        token = created["token"]
        (stored,) = self.query("SELECT token_hash FROM accounts WHERE id = ?", (created["id"],))[0]
        self.assertRegex(stored, r"^[0-9a-f]{64}$")
        self.assertNotEqual(stored, token)

        status, fetched = self.request("GET", "/accounts/" + created["id"])
        self.assertEqual(status, 200)
        self.assertNotIn("token", fetched)
        self.assertNotIn("token_hash", fetched)
        self.assertNotIn(token, repr(fetched))

        needle = token.encode()
        for suffix in ("", "-wal", "-shm"):
            path = self.db_path + suffix
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    self.assertNotIn(needle, fh.read(), path)

    def test_database_pragmas(self):
        self.assertEqual(self.query("PRAGMA journal_mode"), [("wal",)])
        sql = self.query("SELECT sql FROM sqlite_master WHERE name = 'accounts'")[0][0]
        self.assertIn("STRICT", sql)
        tables = self.query("SELECT name, sql FROM sqlite_master WHERE type = 'table'")
        # Stage 4 (D4.3, D4.10): the ledger sequence and the cursor key.
        self.assertEqual(sorted(name for name, _ in tables),
                         ["accounts", "external_moves", "idempotency_keys", "ledger",
                          "ledger_accounts", "settings", "transfers"])
        for name, sql in tables:
            with self.subTest(table=name):
                self.assertIn("STRICT", sql)


class RestartDurabilityTest(ServerTestCase):
    def test_i10_account_survives_restart(self):
        created = self.create_account("durable")
        self.server.stop()
        self.server = ServerProcess(self.db_path).start()
        type(self).server = self.server
        self.assertEqual(self.request("GET", "/accounts/" + created["id"]),
                         (200, {"id": created["id"], "owner": "durable", "balance": 0}))
