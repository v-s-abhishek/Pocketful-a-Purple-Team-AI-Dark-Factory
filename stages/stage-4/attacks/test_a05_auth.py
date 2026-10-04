"""I8 only the owner debits; 404-before-401 ordering; credits need no token."""
import uuid

from breaker_harness import AttackCase


class DebitAuth(AttackCase):
    def setUp(self):
        self.need_route("POST", f"/accounts/{uuid.uuid4()}/deposit", {"amount": 1})
        self.victim = self.funded(1000, "victim")
        self.thief = self.funded(1000, "thief")
        self.bad_headers = [
            {},
            {"Authorization": ""},
            {"Authorization": "Bearer"},
            {"Authorization": "Bearer "},
            {"Authorization": f"Bearer {self.thief['token']}"},
            {"Authorization": f"Basic {self.victim['token']}"},
            {"Authorization": self.victim["token"]},
            {"Authorization": f"Bearer {self.victim['token'][:-1]}"},
            {"Authorization": f"Bearer {self.victim['token']}x"},
            {"Authorization": f"Bearer {self.victim['token'].swapcase()}"},
            {"Authorization": f"Bearer {self.victim['id']}"},
            {"Authorization": "Bearer " + "A" * 60_000},
            {"Authorization": "Bearer ' OR '1'='1"},
            {"Authorization": "Bearer %s" % ("é" * 10)},
            {"X-Token": self.victim["token"]},
        ]

    def test_withdraw_needs_owner_token(self):
        self.need_route("POST", f"/accounts/{self.victim['id']}/withdraw", {"amount": 1})
        path = f"/accounts/{self.victim['id']}/withdraw"
        for h in self.bad_headers:
            with self.subTest(h=str(h)[:60]):
                self.assertRejectedFree(lambda: self.server.request("POST", path, {"amount": 1}, headers=h),
                                        401, "unauthorized")
        # token in query string / body is not a credential either
        for p, body in [(path + f"?token={self.victim['token']}", {"amount": 1}),
                        (path, {"amount": 1, "token": self.victim["token"]})]:
            with self.subTest(p=p[-20:], body=list(body)):
                r = self.server.request("POST", p, body)
                self.assertIn(r.status, (400, 401, 404), r)
        self.assertEqual(self.server.balance(self.victim["id"]), 1000)

    def test_transfer_needs_from_token(self):
        self.need_route("POST", "/transfers", {})
        body = {"from": self.victim["id"], "to": self.thief["id"], "amount": 1000}
        for h in self.bad_headers:
            with self.subTest(h=str(h)[:60]):
                self.assertRejectedFree(lambda: self.server.request("POST", "/transfers", body, headers=h),
                                        401, "unauthorized")
        self.assertEqual(self.server.balance(self.victim["id"]), 1000)

    def test_destination_token_cannot_pull(self):
        self.need_route("POST", "/transfers", {})
        self.assertRejectedFree(
            lambda: self.server.transfer(self.victim["id"], self.thief["id"], 1, self.thief["token"]),
            401, "unauthorized")

    def test_nonexistent_account_is_404_before_auth(self):
        self.need_route("POST", "/transfers", {})
        ghost = str(uuid.uuid4())
        cases = [
            lambda: self.server.transfer(ghost, self.thief["id"], 1, self.thief["token"]),
            lambda: self.server.transfer(self.victim["id"], ghost, 1, self.thief["token"]),
            lambda: self.server.request("POST", "/transfers", {"from": ghost, "to": ghost + "x", "amount": 1}),
            lambda: self.server.withdraw(ghost, 1, self.thief["token"]),
            lambda: self.server.request("POST", f"/accounts/{ghost}/withdraw", {"amount": 1}),
            lambda: self.server.deposit(ghost, 1),
        ]
        for i, fn in enumerate(cases):
            with self.subTest(case=i):
                self.assertRejectedFree(fn, 404, "account_not_found")

    def test_from_equals_to(self):
        self.need_route("POST", "/transfers", {})
        v = self.victim
        self.assertRejectedFree(lambda: self.server.transfer(v["id"], v["id"], 1, v["token"]),
                                400, "invalid_request")
        # case/format variants of the same id must not dodge the check and self-credit
        r = self.server.transfer(v["id"], v["id"].upper(), 1, v["token"])
        self.assertLess(r.status, 500, r)
        self.assertEqual(self.server.balance(v["id"]), 1000)

    def test_deposit_needs_no_token(self):
        r = self.server.deposit(self.victim["id"], 5)
        self.assertEqual(r.status, 200, r)
        self.assertEqual(r.json, {"id": self.victim["id"], "balance": 1005})

    def test_transfer_field_type_confusion(self):
        self.need_route("POST", "/transfers", {})
        v, t = self.victim, self.thief
        bodies = [
            {"from": [v["id"]], "to": t["id"], "amount": 1},
            {"from": {"id": v["id"]}, "to": t["id"], "amount": 1},
            {"from": v["id"], "to": [t["id"], t["id"]], "amount": 1},
            {"from": v["id"], "to": None, "amount": 1},
            {"from": v["id"], "amount": 1},
            {"to": t["id"], "amount": 1},
            {"from": 1, "to": 2, "amount": 1},
        ]
        for b in bodies:
            with self.subTest(b=str(b)[:60]):
                self.assertRejectedFree(
                    lambda: self.server.request("POST", "/transfers", b, headers=self.server.auth(v["token"])),
                    400, "invalid_request")
