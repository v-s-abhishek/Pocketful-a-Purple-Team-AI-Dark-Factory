"""I2 zero-sum, I3 boundaries, I1 audit, I10 durability of money."""
import uuid

from breaker_harness import AttackCase


class Boundaries(AttackCase):
    def setUp(self):
        self.need_route("POST", f"/accounts/{uuid.uuid4()}/deposit", {"amount": 1})

    def test_withdraw_exact_and_plus_one(self):
        a = self.funded(100)
        self.need_route("POST", f"/accounts/{a['id']}/withdraw", {"amount": 1})
        self.assertRejectedFree(lambda: self.server.withdraw(a["id"], 101, a["token"]), 409, "insufficient_funds")
        r = self.server.withdraw(a["id"], 100, a["token"])
        self.assertEqual((r.status, r.json), (200, {"id": a["id"], "balance": 0}), r)
        self.assertRejectedFree(lambda: self.server.withdraw(a["id"], 1, a["token"]), 409, "insufficient_funds")

    def test_transfer_exact_and_plus_one(self):
        self.need_route("POST", "/transfers", {})
        a, b = self.funded(100), self.funded(0)
        self.assertRejectedFree(lambda: self.server.transfer(a["id"], b["id"], 101, a["token"]),
                                409, "insufficient_funds")
        r = self.server.transfer(a["id"], b["id"], 100, a["token"])
        self.assertEqual(r.status, 201, r)
        self.assertEqual(r.json["amount"], 100)
        self.assertEqual((r.json["from"], r.json["to"]), (a["id"], b["id"]))
        self.assertEqual((self.server.balance(a["id"]), self.server.balance(b["id"])), (0, 100))
        self.assertRejectedFree(lambda: self.server.transfer(a["id"], b["id"], 1, a["token"]),
                                409, "insufficient_funds")

    def test_empty_account_amount_one(self):
        self.need_route("POST", "/transfers", {})
        a, b = self.funded(0), self.funded(0)
        self.assertRejectedFree(lambda: self.server.transfer(a["id"], b["id"], 1, a["token"]),
                                409, "insufficient_funds")

    def test_transfer_ids_unique_and_zero_sum(self):
        self.need_route("POST", "/transfers", {})
        a, b = self.funded(1000), self.funded(0)
        ids = set()
        for _ in range(10):
            r = self.server.transfer(a["id"], b["id"], 7, a["token"])
            self.assertEqual(r.status, 201, r)
            ids.add(r.json["id"])
        self.assertEqual(len(ids), 10)
        self.assertEqual(self.server.balance(a["id"]) + self.server.balance(b["id"]), 1000)
        self.assertEqual(self.server.balance(b["id"]), 70)


class Audit(AttackCase):
    def setUp(self):
        self.need_route("GET", "/audit")

    def test_audit_tracks_external_flows(self):
        base = self.server.request("GET", "/audit").json
        a = self.funded(500)
        self.server.withdraw(a["id"], 200, a["token"])
        now = self.server.request("GET", "/audit").json
        self.assertEqual(now["total_deposits"] - base["total_deposits"], 500)
        self.assertEqual(now["total_withdrawals"] - base["total_withdrawals"], 200)
        self.assertEqual(now["total_balances"] - base["total_balances"], 300)

    def test_audit_independent_of_service(self):
        """Recompute Σ balances straight from the DB file; the service must agree."""
        self.funded(123)
        with __import__("contextlib").closing(self.server.db()) as c:
            db_sum = c.execute("SELECT coalesce(sum(balance), 0) FROM accounts").fetchone()[0]
        self.assertEqual(self.server.request("GET", "/audit").json["total_balances"], db_sum)

    def test_audit_after_hard_kill(self):
        a = self.funded(1000)
        self.server.withdraw(a["id"], 1, a["token"])
        before = self.server.request("GET", "/audit").json
        self.server.restart()
        self.assertEqual(self.server.request("GET", "/audit").json, before, "I10")
        self.assertEqual(self.server.balance(a["id"]), 999)
