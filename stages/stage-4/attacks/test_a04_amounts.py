"""I5 integer money + limits, on every amount-taking endpoint. Rejections must be free (I6)."""
import uuid

from breaker_harness import MAX_AMOUNT, MAX_BALANCE, AttackCase

# raw JSON literal -> reason. Sent verbatim so the parser (not our encoder) sees it.
BAD_AMOUNTS = [
    b"1.5", b"1.0", b"0.30000000000000004", b"1e3", b"1E3", b"1e0", b"100e-2", b"-1", b"0", b"-0",
    b"-0.0", b"0.0", str(MAX_AMOUNT + 1).encode(), str(2**63).encode(), str(2**63 - 1).encode(),
    str(2**64).encode(), b"9" * 400, b"1e400", b"-1e400", b'"100"', b'"1"', b"true", b"false",
    b"null", b"NaN", b"Infinity", b"-Infinity", b"[]", b"[100]", b"{}", b'{"v": 100}',
]


class AmountValidation(AttackCase):
    def setUp(self):
        self.need_route("POST", f"/accounts/{uuid.uuid4()}/deposit", {"amount": 1})
        self.a = self.server.create_account("amt-a")
        self.b = self.server.create_account("amt-b")
        self.assertEqual(self.server.deposit(self.a["id"], 1000).status, 200)

    def raw(self, path, template, lit, token=None):
        hdr = self.server.auth(token) if token else {}
        body = template.replace(b"@", lit)
        return self.server.request("POST", path, raw=body, headers=hdr)

    def check_table(self, path, template, token=None):
        for lit in BAD_AMOUNTS:
            with self.subTest(path=path, amount=lit[:30]):
                r = self.assertRejectedFree(lambda: self.raw(path, template, lit, token), 400)
                self.assertIn(r.error, ("invalid_amount", "invalid_json"), r)
        with self.subTest(path=path, amount="missing"):
            self.assertRejectedFree(
                lambda: self.server.request("POST", path, raw=template.replace(b'"amount": @', b'"x": 1'),
                                            headers=self.server.auth(token) if token else {}),
                400, "invalid_amount")

    def test_deposit_amounts(self):
        self.check_table(f"/accounts/{self.a['id']}/deposit", b'{"amount": @}')

    def test_withdraw_amounts(self):
        self.need_route("POST", f"/accounts/{self.a['id']}/withdraw", {"amount": 1})
        self.check_table(f"/accounts/{self.a['id']}/withdraw", b'{"amount": @}', self.a["token"])

    def test_transfer_amounts(self):
        self.need_route("POST", "/transfers", {})
        tmpl = ('{"from": "%s", "to": "%s", "amount": @}' % (self.a["id"], self.b["id"])).encode()
        self.check_table("/transfers", tmpl, self.a["token"])

    def test_max_amount_boundary(self):
        r = self.server.deposit(self.b["id"], MAX_AMOUNT)
        self.assertEqual(r.status, 200, r)
        self.assertEqual(r.json["balance"], MAX_AMOUNT)
        self.assertIsInstance(r.json["balance"], int)

    def test_bool_is_not_one(self):
        # bool is an int subclass in Python: `true` must not deposit 1
        before = self.server.balance(self.a["id"])
        self.raw(f"/accounts/{self.a['id']}/deposit", b'{"amount": @}', b"true")
        self.assertEqual(self.server.balance(self.a["id"]), before)

    def test_float_equal_to_int_not_coerced(self):
        before = self.server.balance(self.a["id"])
        for lit in (b"5.0", b"5e0", b"500e-2"):
            self.raw(f"/accounts/{self.a['id']}/deposit", b'{"amount": @}', lit)
        self.assertEqual(self.server.balance(self.a["id"]), before)

    def test_duplicate_amount_key(self):
        r = self.assertRejectedFree(lambda: self.server.request(
            "POST", f"/accounts/{self.a['id']}/deposit", raw=b'{"amount": 1, "amount": 100}'),
            400, "invalid_json")


class BalanceLimit(AttackCase):
    def setUp(self):
        self.need_route("POST", f"/accounts/{uuid.uuid4()}/deposit", {"amount": 1})

    def fill_to_limit(self, acct_id):
        for _ in range(MAX_BALANCE // MAX_AMOUNT):
            r = self.server.deposit(acct_id, MAX_AMOUNT)
            self.assertEqual(r.status, 200, r)
        self.assertEqual(self.server.balance(acct_id), MAX_BALANCE)

    def test_deposit_past_limit(self):
        a = self.server.create_account("rich")
        self.fill_to_limit(a["id"])
        self.assertRejectedFree(lambda: self.server.deposit(a["id"], 1), 422, "balance_limit")
        self.assertRejectedFree(lambda: self.server.deposit(a["id"], MAX_AMOUNT), 422, "balance_limit")

    def test_transfer_into_full_account_is_free(self):
        self.need_route("POST", "/transfers", {})
        full = self.server.create_account("full")
        self.fill_to_limit(full["id"])
        src = self.server.create_account("src")
        self.assertEqual(self.server.deposit(src["id"], 10).status, 200)
        # a 422 on the credit leg must also roll back the debit leg (I2, I6)
        self.assertRejectedFree(lambda: self.server.transfer(src["id"], full["id"], 1, src["token"]),
                                422, "balance_limit")
        self.assertEqual(self.server.balance(src["id"]), 10)

    def test_many_large_deposits_concurrently_cannot_exceed_limit(self):
        import concurrent.futures as cf
        a = self.server.create_account("race-limit")
        for _ in range(MAX_BALANCE // MAX_AMOUNT - 5):
            self.assertEqual(self.server.deposit(a["id"], MAX_AMOUNT).status, 200)
        with cf.ThreadPoolExecutor(50) as ex:
            rs = list(ex.map(lambda _: self.server.deposit(a["id"], MAX_AMOUNT), range(50)))
        ok = sum(r.status == 200 for r in rs)
        for r in rs:
            self.assertIn((r.status, r.error), [(200, None), (422, "balance_limit"), (503, "busy")], r)
        self.assertCommitCount(ok, self.busy_count(rs), 5, f"statuses {set(r.status for r in rs)}")
        self.assertEqual(self.server.balance(a["id"]), MAX_BALANCE - (5 - ok) * MAX_AMOUNT)
