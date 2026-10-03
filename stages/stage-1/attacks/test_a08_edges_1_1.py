"""Edge attacks found by reading the 1.1 code (server.py/validation.py/db.py)."""
import contextlib
import json
import socket
import time

from breaker_harness import AttackCase


def rows(server):
    with contextlib.closing(server.db()) as c:
        return c.execute("SELECT count(*) FROM accounts").fetchone()[0]


class FramingEdges(AttackCase):
    def test_unicode_digit_content_length(self):
        """str.isdigit() is True for '²' (U+00B2, latin-1 0xB2) but int('²') raises ValueError."""
        for cl in [b"\xb2", b"\xb9", b"\xb3", b"1\xb2"]:
            with self.subTest(cl=cl):
                st, data = self.server.raw_http(
                    b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Length: " + cl +
                    b"\r\nConnection: close\r\n\r\n" + b'{"owner": "a"}')
                self.assertEqual(st, 400, data[:300])
                self.assertIn(b"invalid_json", data)

    def test_non_ascii_digit_content_length_ok_path(self):
        # full-width / arabic-indic digits cannot arrive (header is latin-1), but '+17' and '017' can
        for cl, body in [(b"+15", b'{"owner": "a"}x'), (b"015", b'{"owner": "abc"}'[:15] + b"}")]:
            with self.subTest(cl=cl):
                st, data = self.server.raw_http(b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Length: " + cl +
                                                b"\r\nConnection: close\r\n\r\n" + body)
                self.assertIsNotNone(st, data)
                self.assertLess(st, 500, data[:300])


class OwnerStorageEdges(AttackCase):
    def test_nul_owner(self):
        """Python len('\\x00') == 1 passes validate_owner, but SQLite length() stops at NUL -> CHECK fails."""
        for owner in ["\x00", "\x00abc", "a" * 64 + "", "\x00" * 64]:
            with self.subTest(owner=repr(owner)[:20]):
                n = rows(self.server)
                r = self.server.request("POST", "/accounts", {"owner": owner})
                self.assertIn(r.status, (201, 400), r)
                if r.status == 400:
                    self.assertEqual(r.error, "invalid_request", r)
                    self.assertEqual(rows(self.server), n)
                else:
                    self.assertEqual(self.server.request("GET", f"/accounts/{r.json['id']}").json["owner"], owner)


class ErrorShape(AttackCase):
    """PLAN: errors are {"error": code}; unknown routes/methods -> 404 not_found."""

    def assert_json_error(self, st, data, status=None):
        head, _, body = data.partition(b"\r\n\r\n")
        if status:
            self.assertEqual(st, status, data[:300])
        self.assertIn(b"application/json", head, f"non-JSON error body for {st}: {data[:300]!r}")
        self.assertIn("error", json.loads(body), body)

    def test_methods_without_handlers(self):
        for m in [b"HEAD", b"OPTIONS", b"TRACE", b"CONNECT", b"FOO"]:
            with self.subTest(m=m):
                st, data = self.server.raw_http(m + b" /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                if m == b"HEAD":
                    self.assertIn(st, (200, 404), data[:300])
                else:
                    self.assert_json_error(st, data, 404)

    def test_malformed_request_line_and_headers(self):
        for req in [b"GARBAGE\r\n\r\n", b"GET /health HTTP/9.9\r\n\r\n",
                    b"GET /health HTTP/1.1\r\nX-Pad: " + b"a" * 70_000 + b"\r\n\r\n",
                    b"GET /health HTTP/1.1\r\n" + b"".join(b"H%d: v\r\n" % i for i in range(150)) + b"\r\n"]:
            with self.subTest(req=req[:30]):
                st, data = self.server.raw_http(req)
                self.assertIsNotNone(st, data[:200])
                self.assertLess(st, 500, data[:200])
                self.assert_json_error(st, data)


class ConnectionLimits(AttackCase):
    def hold(self, n, payload=b""):
        socks = []
        for _ in range(n):
            s = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
            if payload:
                s.sendall(payload)
            socks.append(s)
        return socks

    def health_latency(self):
        t0 = time.monotonic()
        r = self.server.request("GET", "/health", timeout=10)
        return r.status, time.monotonic() - t0

    def test_idle_connections_do_not_starve(self):
        for n in (500, 1500):
            with self.subTest(n=n):
                socks = self.hold(n)
                try:
                    st, dt = self.health_latency()
                    self.assertEqual(st, 200, f"/health failed with {n} idle connections open")
                    self.assertLess(dt, 2.0, f"/health took {dt:.2f}s with {n} idle connections")
                finally:
                    for s in socks:
                        s.close()

    def test_idle_connection_is_reaped(self):
        """A connection that never finishes its request must be closed by the server (timeout 10s)."""
        s = socket.create_connection(("127.0.0.1", self.server.port), timeout=20)
        try:
            s.sendall(b"GET /health HTTP/1.1\r\n")
            t0 = time.monotonic()
            with contextlib.suppress(ConnectionError):
                while s.recv(4096):
                    pass
            self.assertLess(time.monotonic() - t0, 15, "server kept a stalled connection open")
        finally:
            s.close()

    def test_trickle_body_holds_thread_indefinitely(self):
        """Slowloris: one byte every 3 s resets the 10 s socket timeout, so a request can be held open
        well past the 10 s I11 budget. Measured, and reported if the server never cuts it off."""
        s = socket.create_connection(("127.0.0.1", self.server.port), timeout=30)
        body = b'{"owner": "slow"}'
        try:
            s.sendall(b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body))
            t0 = time.monotonic()
            cut = False
            for b in body[:8]:
                time.sleep(3)
                try:
                    s.sendall(bytes([b]))
                except OSError:
                    cut = True
                    break
            held = time.monotonic() - t0
            if not cut:
                s.settimeout(0.5)
                with contextlib.suppress(socket.timeout):
                    cut = s.recv(1) == b""
            self.assertTrue(cut or held < 15, f"server held a trickling request open for {held:.0f}s (I11 budget 10s)")
        finally:
            s.close()

    def test_burst_of_new_connections(self):
        """Next limit after the backlog fix: 1000 connects at once, each a real request."""
        import concurrent.futures as cf
        with cf.ThreadPoolExecutor(300) as ex:
            rs = list(ex.map(lambda i: self.server.request("POST", "/accounts", {"owner": f"b{i}"}), range(1000)))
        codes = {}
        for r in rs:
            codes[r.status] = codes.get(r.status, 0) + 1
        self.assertEqual(set(codes) - {201, 503}, set(), f"burst outcomes: {codes}; e.g. {[r for r in rs if r.status not in (201, 503)][:2]}")
        self.assertEqual(rows(self.server), codes.get(201, 0), "rows != 201 responses")
