"""Attacks on the 1.1 fix build's new surface: header framing, the custom
handle_one_request/send_error paths, and owner character classes."""
import contextlib
import json

from breaker_harness import AttackCase

BODY = b'{"owner": "frame"}'  # 18 bytes


def rows(server):
    with contextlib.closing(server.db()) as c:
        return c.execute("SELECT count(*) FROM accounts").fetchone()[0]


class HeaderFraming(AttackCase):
    def send(self, headers, body=BODY, line=b"POST /accounts HTTP/1.1"):
        return self.server.raw_http(line + b"\r\nHost: x\r\n" + headers + b"Connection: close\r\n\r\n" + body)

    def assert_json(self, st, data, status):
        head, _, body = data.partition(b"\r\n\r\n")
        self.assertEqual(st, status, data[:300])
        self.assertIn(b"application/json", head.lower(), data[:300])
        self.assertIn("error", json.loads(body))

    def rejected(self, headers, body=BODY):
        n = rows(self.server)
        st, data = self.send(headers, body)
        self.assert_json(st, data, 400)
        self.assertIn(b"invalid_json", data)
        self.assertEqual(rows(self.server), n, "rejected request created a row")

    def test_duplicate_content_length_variants(self):
        for h in [b"Content-Length: 18\r\nContent-Length: 18\r\n",
                  b"Content-Length: 18\r\ncontent-length: 18\r\n",
                  b"Content-Length: 18\r\nCONTENT-LENGTH: 5\r\n",
                  b"Content-Length: 5\r\nContent-Length: 18\r\n",
                  b"Content-Length: 18, 18\r\n",
                  b"Content-Length: 18,18\r\n"]:
            with self.subTest(h=h):
                self.rejected(h)

    def test_content_length_whitespace_forms(self):
        # trimmed space/tab is documented as valid; other whitespace/garbage is not
        for h, ok in [(b"Content-Length:18\r\n", True), (b"Content-Length:  18  \r\n", True),
                      (b"Content-Length: \t18\t\r\n", True), (b"Content-Length: 1 8\r\n", False),
                      (b"Content-Length: 18\x0b\r\n", False), (b"Content-Length: 18\x0c\r\n", False),
                      (b"Content-Length: \xa018\r\n", False), (b"Content-Length: 0000018\r\n", True),
                      (b"Content-Length: 00000018\r\n", False)]:
            with self.subTest(h=h):
                if ok:
                    st, data = self.send(h)
                    self.assertEqual(st, 201, data[:300])
                else:
                    self.rejected(h)

    def test_transfer_encoding_variants(self):
        for h in [b"Transfer-Encoding: identity\r\nContent-Length: 18\r\n",
                  b"Transfer-Encoding: chunked\r\nContent-Length: 18\r\n",
                  b"Content-Length: 18\r\nTransfer-Encoding: gzip\r\n",
                  b"Transfer-Encoding:\r\nContent-Length: 18\r\n",
                  b"transfer-encoding: CHUNKED\r\nContent-Length: 18\r\n",
                  b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nContent-Length: 18\r\n"]:
            with self.subTest(h=h):
                self.rejected(h)

    def test_header_name_tricks(self):
        # a space before the colon is not the Content-Length header; body is then unread -> empty body
        for h in [b"Content-Length : 18\r\n", b"Content_Length: 18\r\n", b" Content-Length: 18\r\n"]:
            with self.subTest(h=h):
                n = rows(self.server)
                st, data = self.send(h)
                self.assertIsNotNone(st, data)
                self.assertLess(st, 500, data[:300])
                self.assertIn(b"application/json", data.partition(b"\r\n\r\n")[0].lower())
                self.assertNotEqual(st, 201, "created an account without a valid Content-Length")
                self.assertEqual(rows(self.server), n)

    def test_pipelined_second_request_not_executed(self):
        """HTTP/1.0 close-after-one: bytes after the body must never run as a second request."""
        second = b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Length: 18\r\n\r\n" + BODY
        n = rows(self.server)
        st, data = self.send(b"Content-Length: 18\r\n", BODY + second)
        self.assertEqual(st, 201, data[:300])
        self.assertEqual(data.count(b"HTTP/1."), 1, "server answered a pipelined request")
        self.assertEqual(rows(self.server), n + 1)

    def test_body_longer_than_declared_is_ignored(self):
        n = rows(self.server)
        st, data = self.send(b"Content-Length: 18\r\n", BODY + b'{"owner": "second"}')
        self.assertEqual(st, 201, data[:300])
        self.assertEqual(rows(self.server), n + 1)


class ErrorPaths(AttackCase):
    def raw_json_status(self, req):
        st, data = self.server.raw_http(req)
        head, _, body = data.partition(b"\r\n\r\n")
        self.assertIsNotNone(st, data[:300])
        self.assertTrue(head.startswith(b"HTTP/1."), data[:300])
        self.assertIn(b"application/json", head.lower(), data[:300])
        parsed = json.loads(body)
        self.assertTrue("error" in parsed or (st == 200 and parsed == {"ok": True}), data[:300])
        return st

    def test_request_line_variants(self):
        cases = [b"\r\n\r\n", b"GET\r\n\r\n", b"GET /health\r\n\r\n", b"GET /health HTTP/1.1 extra\r\n\r\n",
                 b"GET /health HTTP/1.1\r\r\n\r\n", b"GET  /health  HTTP/1.1\r\n\r\n", b"get /health HTTP/1.1\r\n\r\n",
                 b"GET health HTTP/1.1\r\n\r\n", b"GET /health HTTP/2.0\r\n\r\n", b"GET /health HTTP/0.9\r\n\r\n",
                 b"GET /health HTTP/1\r\n\r\n", b"GET /health http/1.1\r\n\r\n", b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" * 4 + b"\r\n\r\n",
                 b"GET /\xff\xfe HTTP/1.1\r\n\r\n", b"GET /health HTTP/1.1\r\nBad Header Line\r\n\r\n",
                 b"GET /health HTTP/1.1\r\n: novalue\r\n\r\n", b"GET /health HTTP/1.1\r\nX: \x00\r\n\r\n",
                 b"GET /" + b"a" * 70_000 + b" HTTP/1.1\r\n\r\n"]
        for req in cases:
            with self.subTest(req=req[:30]):
                st = self.raw_json_status(req)
                self.assertTrue(400 <= st < 500 or (st == 200 and b"/health" in req), st)

    def test_every_method_json_404(self):
        for m in [b"HEAD", b"OPTIONS", b"TRACE", b"CONNECT", b"PUT", b"PATCH", b"DELETE", b"PROPFIND",
                  b"M" * 200, b"G\xffT", b"POST\x00"]:
            for path in [b"/health", b"/accounts", b"/nope"]:
                with self.subTest(m=m[:12], path=path):
                    req = m + b" " + path + b" HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
                    st = self.raw_json_status(req)
                    self.assertIn(st, (400, 404), st)

    def test_error_bodies_do_not_echo_input(self):
        marker = b"<script>MARKER</script>"
        for req in [b"GET /" + marker + b" HTTP/1.1\r\n\r\n", marker + b" / HTTP/1.1\r\n\r\n",
                    b"GET / HTTP/" + marker + b"\r\n\r\n"]:
            with self.subTest(req=req[:40]):
                _, data = self.server.raw_http(req)
                self.assertNotIn(b"MARKER", data, "error echoes attacker input")


class OwnerClasses(AttackCase):
    """Owner rule as ruled for 1.1c: reject Cc/Cf/Zl/Zp anywhere and whitespace-only owners."""

    def create(self, owner):
        return self.server.request("POST", "/accounts", {"owner": owner})

    def test_c1_controls_rejected(self):
        # U+0080-U+009F are category Cc -> 400 since 1.1c (flipped from 201)
        for c in range(0x80, 0xA0):
            owner = "a" + chr(c) + "b"
            with self.subTest(c=hex(c)):
                self.assertRejectedFree(lambda: self.create(owner), 400, "invalid_request")

    def test_whitespace_only_and_invisible_owners(self):
        """Q1/Q2 ruling (1.1c): all of these -> 400 invalid_request, no effect (flipped from 201|400)."""
        for owner in [" ", " " * 64, "\xa0", "\u3000", "\u200b", "\u202e" + "evil",
                      "\u2028", "\u2029", "\ufeff", "\U000e0001"]:
            with self.subTest(owner=ascii(owner)[:20]):
                self.assertRejectedFree(lambda: self.create(owner), 400, "invalid_request")

    def test_interior_space_and_letters_accepted(self):
        for owner in ["a b", "a" * 64, "a\u0301" * 32]:
            with self.subTest(owner=ascii(owner)[:20]):
                r = self.create(owner)
                self.assertEqual(r.status, 201, r)
                self.assertEqual(self.server.request("GET", f"/accounts/{r.json['id']}").json["owner"], owner)

    def test_length_counted_same_in_python_and_sqlite(self):
        # 64 combining sequences / astral chars: Python len and SQLite length() must agree at the limit
        for owner in ["\U0001F4B0" * 64, "a\u0301" * 32, "\U00010000" * 64]:
            with self.subTest(owner=ascii(owner)[:16]):
                r = self.create(owner)
                self.assertEqual(r.status, 201, r)
        for owner in ["\U0001F4B0" * 65, "a\u0301" * 33]:
            with self.subTest(owner=ascii(owner)[:16]):
                self.assertRejectedFree(lambda: self.create(owner), 400, "invalid_request")

    def test_escaped_controls_in_json(self):
        # controls arriving as JSON escapes, not raw bytes
        for raw in [b'{"owner": "a\\u0000b"}', b'{"owner": "\\u001f"}', b'{"owner": "\\u007f"}',
                    b'{"owner": "a\\nb"}', b'{"owner": "\\t"}', b'{"owner": "a\\u0085b"}',
                    b'{"owner": "\\u2028"}', b'{"owner": "a\\ufeff"}']:
            with self.subTest(raw=raw):
                self.assertRejectedFree(lambda: self.server.request("POST", "/accounts", raw=raw),
                                        400, "invalid_request")
        # raw control bytes inside a JSON string are invalid JSON per the RFC
        self.assertRejectedFree(lambda: self.server.request("POST", "/accounts", raw=b'{"owner": "a\x01b"}'),
                                400)
