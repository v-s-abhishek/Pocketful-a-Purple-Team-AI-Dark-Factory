"""Account creation/lookup: owner validation, id handling, token exposure (I8), concurrency (I11)."""
import concurrent.futures as cf
import contextlib
import urllib.parse
import uuid

from breaker_harness import AttackCase


class OwnerValidation(AttackCase):
    def reject(self, body):
        return self.assertRejectedFree(lambda: self.server.request("POST", "/accounts", body),
                                       400, "invalid_request")

    def test_bad_owner_values(self):
        for owner in ["", "x" * 65, None, 123, 1.5, True, [], ["a"], {}, {"a": "b"}]:
            with self.subTest(owner=owner):
                self.reject({"owner": owner})

    def test_missing_owner(self):
        self.reject({})
        self.reject({"name": "bob"})

    def test_owner_length_boundaries(self):
        for owner in ["a", "x" * 64]:
            with self.subTest(n=len(owner)):
                r = self.server.request("POST", "/accounts", {"owner": owner})
                self.assertEqual(r.status, 201, r)
                self.assertEqual(r.json["owner"], owner)

    def test_owner_multibyte_counted_as_chars(self):
        # 64 characters, 256 bytes in UTF-8: in range by the "1-64 chars" contract
        owner = "\U0001F4B0" * 64
        r = self.server.request("POST", "/accounts", {"owner": owner})
        self.assertEqual(r.status, 201, r)
        self.assertEqual(self.server.request("GET", f"/accounts/{r.json['id']}").json["owner"], owner)
        self.reject({"owner": "\U0001F4B0" * 65})

    def test_owner_lone_surrogate(self):
        # json.loads accepts "\ud800"; sqlite3 cannot encode it -> must be 400, not 500
        r = self.assertRejectedFree(
            lambda: self.server.request("POST", "/accounts", raw=b'{"owner": "\\ud800"}'), 400)
        self.assertIn(r.error, ("invalid_request", "invalid_json"), r)

    def test_owner_control_and_nul(self):
        # Architect ruling (R1.1-A): every C0 control and DEL is rejected, anywhere in the owner
        for ch in [chr(c) for c in range(0x20)] + ["\x7f"]:
            for owner in [ch, "a" + ch + "b", "a" * 63 + ch]:
                with self.subTest(owner=repr(owner)[-12:]):
                    self.reject({"owner": owner})

    def test_owner_non_c0_controls_not_rejected_by_mistake(self):
        # C1 controls / unicode line separators are outside the ruling: must not 500, stored exactly if accepted
        for owner in ["a\x85b", "a b", "a​b", " "]:
            with self.subTest(owner=repr(owner)):
                r = self.server.request("POST", "/accounts", {"owner": owner})
                self.assertIn(r.status, (201, 400), r)
                if r.status == 201:
                    got = self.server.request("GET", f"/accounts/{r.json['id']}").json["owner"]
                    self.assertEqual(got, owner, "owner stored differently from what was accepted")

    def test_client_cannot_choose_id_or_balance(self):
        for body in [{"owner": "a", "balance": 10**9}, {"owner": "a", "id": "chosen-id"},
                     {"owner": "a", "token": "chosen-token"}]:
            with self.subTest(body=body):
                r = self.server.request("POST", "/accounts", body)
                self.assertLess(r.status, 500, r)
                if r.status == 201:
                    self.assertEqual(r.json["balance"], 0, "client set its own balance")
                    self.assertNotEqual(r.json["id"], "chosen-id", "client chose its own id")
                    self.assertNotEqual(r.json["token"], "chosen-token", "client chose its own token")


class TokenExposure(AttackCase):
    def test_token_shape_and_uniqueness(self):
        accts = [self.server.create_account(f"u{i}") for i in range(50)]
        tokens = [a["token"] for a in accts]
        self.assertEqual(len(set(tokens)), len(tokens), "duplicate tokens")
        for t in tokens:
            self.assertIsInstance(t, str)
            self.assertGreaterEqual(len(t), 22, f"token too short to hold 128 bits: {t!r}")
        ids = [a["id"] for a in accts]
        self.assertEqual(len(set(ids)), len(ids))
        for i in ids:
            self.assertEqual(str(uuid.UUID(i)), i.lower(), f"id is not a UUID string: {i!r}")
            self.assertEqual(uuid.UUID(i).version, 4)
        for a in accts:
            self.assertNotIn(a["id"], a["token"])

    def test_get_never_returns_token(self):
        a = self.server.create_account("secret")
        r = self.server.request("GET", f"/accounts/{a['id']}")
        self.assertEqual(r.status, 200, r)
        self.assertNotIn("token", r.json)
        self.assertNotIn(a["token"].encode(), r.raw)
        for k, v in r.headers.items():
            self.assertNotIn(a["token"], v, f"token leaked in header {k}")
        self.assertEqual(set(r.json), {"id", "owner", "balance"}, r.json)

    def test_token_not_stored_in_plaintext(self):
        a = self.server.create_account("hashme")
        with contextlib.closing(self.server.db()) as c:
            for t in self.server.tables():
                for row in c.execute(f'SELECT * FROM "{t}"'):
                    for cell in row:
                        if isinstance(cell, (str, bytes)):
                            needle = a["token"] if isinstance(cell, str) else a["token"].encode()
                            self.assertNotIn(needle, cell, f"plaintext token stored in table {t}")

    def test_token_not_in_error_or_listing(self):
        a = self.server.create_account("x")
        for path in ["/accounts", f"/accounts/{a['id']}/", f"/accounts/{a['id']}?token=1", "/audit"]:
            r = self.server.request("GET", path)
            self.assertNotIn(a["token"].encode(), r.raw, path)


class IdHandling(AttackCase):
    def test_unknown_and_hostile_ids(self):
        ids = [str(uuid.uuid4()), "0", "-1", "' OR '1'='1", "1; DROP TABLE accounts;--",
               "%27%20OR%201%3D1--", "..%2F..%2Fetc%2Fpasswd", "a" * 5000, "%00", "%ff%fe",
               urllib.parse.quote("\U0001F4B0"), "null", "%2e%2e"]
        a = self.server.create_account("real")
        for i in ids:
            with self.subTest(id=i[:40]):
                r = self.server.request("GET", "/accounts/" + urllib.parse.quote(i, safe="%"))
                self.assertIn(r.status, (400, 404), r)
                self.assertNotIn(b"real", r.raw, "hostile id resolved to a real account")
        self.assertEqual(self.server.request("GET", f"/accounts/{a['id']}").status, 200)

    def test_id_case_and_padding_variants(self):
        a = self.server.create_account("case")
        for variant in [a["id"].upper(), " " + a["id"], a["id"] + "%20", a["id"] + "%00",
                        "{" + a["id"] + "}", a["id"].replace("-", "")]:
            with self.subTest(variant=variant):
                r = self.server.request("GET", "/accounts/" + urllib.parse.quote(variant, safe="%{}"))
                self.assertIn(r.status, (200, 400, 404), r)
                if r.status == 200:
                    self.assertEqual(r.json["id"], a["id"], "variant id returned a different canonical id")

    def test_path_traversal_and_extra_segments(self):
        a = self.server.create_account("p")
        for path in [f"/accounts/{a['id']}/../../health", f"//accounts/{a['id']}",
                     f"/accounts/{a['id']}/extra", "/accounts/", "/accounts", "/ACCOUNTS/" + a["id"],
                     "/health/../accounts", "*", "/../../etc/passwd"]:
            with self.subTest(path=path):
                r = self.server.request("GET", path)
                self.assertLess(r.status, 500, r)

    def test_unknown_methods(self):
        a = self.server.create_account("m")
        for m in ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "FOO"]:
            with self.subTest(m=m):
                r = self.server.request(m, f"/accounts/{a['id']}", raw=b"")
                self.assertTrue(r.status < 500 or r.status == 501, r)  # 501 = stdlib "unsupported method"
        self.assertEqual(self.server.request("GET", f"/accounts/{a['id']}").status, 200)

    def test_unknown_route_is_404_not_found(self):
        r = self.server.request("GET", "/nope")
        self.assertEqual((r.status, r.error), (404, "not_found"), r)


class ConcurrentCreation(AttackCase):
    def test_parallel_account_creation(self):
        n = 200
        with cf.ThreadPoolExecutor(64) as ex:
            rs = list(ex.map(lambda i: self.server.request("POST", "/accounts", {"owner": f"c{i}"}), range(n)))
        codes = [r.status for r in rs]
        self.assertFalse([c for c in codes if c >= 500 and c != 503], f"5xx under load: {set(codes)}")
        ok = [r.json for r in rs if r.status == 201]
        self.assertEqual(len({a["id"] for a in ok}), len(ok))
        self.assertEqual(len({a["token"] for a in ok}), len(ok))
        with contextlib.closing(self.server.db()) as c:
            count = c.execute("SELECT count(*) FROM accounts").fetchone()[0]
        self.assertEqual(count, len(ok), "rows in DB != 201 responses (phantom or lost accounts)")
        for a in ok[:20]:
            self.assertEqual(self.server.balance(a["id"]), 0)
