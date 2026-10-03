"""Malformed bodies against the shared JSON parser (PLAN: invalid_json rules, I6, I11).

Every attack must: return 400 `invalid_json`, create nothing, and leave the
server answering. POST /accounts is the body endpoint that exists from 1.1.
"""
import socket
import time

from breaker_harness import MAX_BODY, NO_RESPONSE, AttackCase


class ParserAttacks(AttackCase):
    def post_raw(self, raw, headers=None):
        return self.server.request("POST", "/accounts", raw=raw, headers=headers)

    def reject(self, raw, headers=None):
        return self.assertRejectedFree(lambda: self.post_raw(raw, headers), 400, "invalid_json")

    def test_not_json(self):
        for raw in [b"owner=bob", b"{owner: 'bob'}", b"{'owner': 'bob'}", b'{"owner": "bob",}',
                    b'{"owner": "bob"', b'{"owner": "bob"}}', b'{"owner": "bob"} {}', b"\x00",
                    b'{"owner": "bob"} x']:
            with self.subTest(raw=raw):
                self.reject(raw)

    def test_empty_and_whitespace(self):
        for raw in [b"", b" ", b"\n\n", b"\t"]:
            with self.subTest(raw=raw):
                self.reject(raw)

    def test_non_object_top_level(self):
        for raw in [b"[]", b'[{"owner": "bob"}]', b'"bob"', b"1", b"null", b"true", b"false",
                    b"1.5", b'"{\\"owner\\": \\"bob\\"}"']:
            with self.subTest(raw=raw):
                self.reject(raw)

    def test_duplicate_keys(self):
        for raw in [b'{"owner": "a", "owner": "b"}', b'{"owner": "a", "owner": "a"}',
                    b'{"owner": "a", "x": {"k": 1, "k": 2}}']:
            with self.subTest(raw=raw):
                self.reject(raw)

    def test_non_standard_constants(self):
        # Python's json accepts these by default; the plan says reject.
        for raw in [b'{"owner": "a", "x": NaN}', b'{"owner": "a", "x": Infinity}',
                    b'{"owner": "a", "x": -Infinity}']:
            with self.subTest(raw=raw):
                self.reject(raw)

    def test_oversized_body(self):
        pad = MAX_BODY + 1 - len(b'{"owner": "a", "pad": ""}')
        self.reject(b'{"owner": "a", "pad": "' + b"x" * pad + b'"}')
        self.reject(b" " * (MAX_BODY + 1) + b'{"owner": "a"}')
        # far past the limit the server may refuse to read and drop the connection; still no effect
        before = self.server.snapshot()
        r = self.post_raw(b'{"owner": "a", "pad": "' + b"x" * (5 * 1024 * 1024) + b'"}')
        self.assertIn(r.status, (400, NO_RESPONSE), r)
        self.assertEqual(self.server.snapshot(), before, "I6")

    def test_body_at_limit_is_not_rejected_as_too_big(self):
        # exactly 16 KiB of valid JSON: must not be `invalid_json` (boundary off-by-one)
        body = b'{"owner": "edge"}'
        body = body + b" " * (MAX_BODY - len(body))
        self.assertEqual(len(body), MAX_BODY)
        r = self.post_raw(body)
        self.assertEqual(r.status, 201, r)

    def test_invalid_utf8_and_bom(self):
        for raw in [b'{"owner": "\xff\xfe"}', b'{"owner": "\xc3"}', b"\xef\xbb\xbf" + b'{"owner": "a"}',
                    '{"owner": "a"}'.encode("utf-16")]:
            with self.subTest(raw=raw):
                r = self.post_raw(raw)
                self.assertLess(r.status, 500, r)
                if r.status != 201:
                    self.assertEqual(r.status, 400, r)

    def test_deep_nesting(self):
        # RecursionError inside json.loads must not become a 500 or kill the thread silently
        for depth in (1000, 3000, MAX_BODY // 2 - 16):  # all under the size limit
            with self.subTest(depth=depth):
                self.reject(b'{"owner": "a", "x": ' + b"[" * depth + b"]" * depth + b"}")
        self.reject(b"[" * (MAX_BODY // 2) + b"]" * (MAX_BODY // 2))

    def test_huge_integer_literal(self):
        # int('9'*5000) raises ValueError in 3.11 (int max str digits) -> must be 400 not 500
        self.reject(b'{"owner": "a", "x": ' + b"9" * 5000 + b"}")

    def test_content_length_lies(self):
        s = self.server
        # declared shorter than sent: parser sees truncated JSON
        st, _ = s.raw_http(b'POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n'
                           b'Content-Length: 5\r\nConnection: close\r\n\r\n{"owner": "bob"}')
        self.assertEqual(st, 400)
        # non-numeric / negative / enormous Content-Length
        for cl in [b"abc", b"-1", b"99999999999999999999", b"1e3", b"0x10"]:
            with self.subTest(cl=cl):
                t0 = time.monotonic()
                st, data = s.raw_http(b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Length: " + cl +
                                      b"\r\nConnection: close\r\n\r\n" + b'{"owner": "bob"}', timeout=12)
                self.assertLess(time.monotonic() - t0, 11, "I11: server hung on bad Content-Length")
                self.assertIsNotNone(st, f"no HTTP response for Content-Length {cl!r}: {data!r}")
                self.assertGreaterEqual(st, 400, data)
                self.assertLess(st, 500, data)

    def test_no_content_length(self):
        st, data = self.server.raw_http(b'POST /accounts HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'
                                        b'{"owner": "bob"}', timeout=12)
        self.assertIsNotNone(st, data)
        self.assertLess(st, 500, data)
        self.assertNotEqual(st, 201, "created an account from a body it never read")

    def test_chunked_body(self):
        st, data = self.server.raw_http(
            b"POST /accounts HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            b'10\r\n{"owner": "bob"}\r\n0\r\n\r\n', timeout=12)
        self.assertIsNotNone(st, data)
        self.assertLess(st, 500, data)

    def test_short_body_does_not_wedge_others(self):
        """Clients that promise a body and stall must not stop others being served (I11)."""
        socks = []
        try:
            for _ in range(50):
                sk = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
                sk.sendall(b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n{")
                socks.append(sk)
            t0 = time.monotonic()
            self.assertEqual(self.server.request("GET", "/health", timeout=5).status, 200)
            self.assertLess(time.monotonic() - t0, 2, "stalled uploads delayed other requests")
        finally:
            for sk in socks:
                sk.close()

    def test_huge_header(self):
        st, data = self.server.raw_http(b"POST /accounts HTTP/1.1\r\nHost: x\r\nX-Pad: " + b"a" * 100_000 +
                                        b"\r\nContent-Length: 15\r\nConnection: close\r\n\r\n" + b'{"owner": "a"}',
                                        timeout=12)
        if st is not None:
            self.assertLess(st, 500, data[:200])
        self.assertNotEqual(st, 201)

    def test_wrong_content_type_still_validated(self):
        # whatever the content-type policy is, a garbage body must never create an account
        for ct in ["text/plain", "application/x-www-form-urlencoded", "", "application/json; charset=latin-1"]:
            with self.subTest(ct=ct):
                before = self.server.snapshot()
                r = self.post_raw(b"owner=bob", {"Content-Type": ct})
                self.assertIn(r.status, (400, 415), r)
                self.assertEqual(self.server.snapshot(), before, "I6")
