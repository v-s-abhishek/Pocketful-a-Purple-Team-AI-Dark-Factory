"""Attacks on the 1.1c closeout: strict HTTP version (R1.1-G) and the widened owner rule
(Cc/Cf/Zl/Zp anywhere, whitespace-only). Code points are built with chr() on purpose so the
source stays ASCII and no editor or tool can silently turn an escape into a line break."""
import json

from breaker_harness import AttackCase

C = chr


class StrictHttpVersion(AttackCase):
    def raw(self, version):
        return self.server.raw_http(b"GET /health " + version + b"\r\nHost: x\r\n\r\n")

    def assert_400_json(self, version):
        st, data = self.raw(version)
        head, _, body = data.partition(b"\r\n\r\n")
        self.assertTrue(head.startswith(b"HTTP/1.0 400"), data[:200])
        self.assertIn(b"application/json", head.lower(), data[:200])
        self.assertEqual(json.loads(body), {"error": "invalid_request"}, data[:200])

    def test_served_versions_answer(self):
        for v in (b"HTTP/1.0", b"HTTP/1.1"):
            with self.subTest(v=v):
                st, data = self.raw(v)
                self.assertEqual(st, 200, data[:200])

    def test_other_versions_rejected_with_status_line(self):
        # R1.1-G: any explicit version other than 1.0/1.1 -> 400 invalid_request, HTTP/1.0 line + JSON
        for v in (b"HTTP/0.9", b"HTTP/2.0", b"HTTP/1.2", b"HTTP/3.0", b"HTTP/1.10", b"HTTP/01.1",
                  b"HTTP/1.01", b"HTTP/0.0", b"HTTP/9.9", b"HTTP/1." + bytes([0xB2]), b"HTTP/1.1.1", b"HTTP/1.1 ", b"HTTP/1.1\t"):
            with self.subTest(v=v):
                if v.endswith((b" ", b"\t")):
                    # trailing whitespace is stripped by the request-line split; must still be a clean answer
                    st, data = self.raw(v)
                    self.assertIn(st, (200, 400), data[:200])
                    self.assertIn(b"application/json", data.partition(b"\r\n\r\n")[0].lower())
                else:
                    self.assert_400_json(v)

    def test_rejected_version_has_no_effect_on_post(self):
        before = self.server.snapshot()
        st, data = self.server.raw_http(
            b'POST /accounts HTTP/0.9\r\nContent-Length: 15\r\n\r\n{"owner": "v9"}')
        self.assertEqual(st, 400, data[:200])
        self.assertEqual(self.server.snapshot(), before, "I6: rejected version created a row")


class OwnerCategoriesWide(AttackCase):
    def create(self, owner):
        return self.server.request("POST", "/accounts", {"owner": owner})

    def test_every_cf_zl_zp_cc_rejected_alone_and_interior(self):
        # a broad sample of every rejected category, alone and embedded between letters
        cps = [0x00AD, 0x0600, 0x061C, 0x06DD, 0x070F, 0x180E, 0x200C, 0x200D, 0x200E, 0x200F,
               0x202A, 0x202D, 0x2060, 0x2064, 0x2066, 0x2069, 0xFFF9, 0xFFFB, 0x110BD,
               0x1D173, 0xE0020, 0xE007F, 0x2028, 0x2029, 0x0085, 0x009F, 0x007F, 0x001B]
        for cp in cps:
            for owner in (C(cp), "a" + C(cp) + "b", "ab" + C(cp), C(cp) + "ab"):
                with self.subTest(cp=hex(cp), form=ascii(owner)):
                    self.assertRejectedFree(lambda: self.create(owner), 400, "invalid_request")

    def test_every_whitespace_only_form_rejected(self):
        ws = [0x20, 0xA0, 0x1680, 0x2000, 0x2005, 0x200A, 0x202F, 0x205F, 0x3000]
        for cp in ws:
            for n in (1, 2, 64):
                owner = C(cp) * n
                with self.subTest(cp=hex(cp), n=n):
                    self.assertRejectedFree(lambda: self.create(owner), 400, "invalid_request")
        mixed = "".join(C(cp) for cp in ws)
        self.assertRejectedFree(lambda: self.create(mixed), 400, "invalid_request")

    def test_interior_and_edge_whitespace_kept_verbatim(self):
        # interior spaces allowed; leading/trailing whitespace around letters is not stripped on store
        for owner in [" a", "a ", " a ", "a" + C(0xA0) + "b", "a" + C(0x3000) + "b", "a" + C(0x2003) + "b"]:
            with self.subTest(owner=ascii(owner)):
                r = self.create(owner)
                self.assertEqual(r.status, 201, r)
                got = self.server.request("GET", f"/accounts/{r.json['id']}").json["owner"]
                self.assertEqual(got, owner, "owner not stored verbatim")

    def test_lone_and_paired_surrogates(self):
        # \ud800 alone (Cs) cannot be UTF-8; a valid pair is an ordinary astral char
        self.assertRejectedFree(lambda: self.server.request(
            "POST", "/accounts", raw=b'{"owner": "a\\ud800b"}'), 400, "invalid_request")
        self.assertRejectedFree(lambda: self.server.request(
            "POST", "/accounts", raw=b'{"owner": "\\udcb0"}'), 400, "invalid_request")
        r = self.server.request("POST", "/accounts", raw=b'{"owner": "\\ud83d\\udcb0"}')
        self.assertEqual(r.status, 201, r)
        self.assertEqual(r.json["owner"], C(0x1F4B0))

    def test_blank_looking_letters_not_covered_by_rule(self):
        """Coverage probe, not a ruling: these render blank but are Lo/So/Mn, so the 1.1c rule admits
        them. Asserts only no 5xx + verbatim round-trip; reported to the Architect as Q3."""
        for owner in [C(0x3164), C(0x115F), C(0xFFA0), C(0x2800), C(0x0301), C(0x034F), C(0xE000)]:
            with self.subTest(owner=ascii(owner)):
                r = self.create(owner)
                self.assertIn(r.status, (201, 400), r)
                if r.status == 201:
                    got = self.server.request("GET", f"/accounts/{r.json['id']}").json["owner"]
                    self.assertEqual(got, owner)
