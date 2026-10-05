"""Unit 4.2: reversal. D4.4 (endpoint, storage), D4.5 (error order, no
effect), D4.6 (idempotency); invariants I25, I26, I27."""

import sqlite3
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

from harness import STAGE_DIR, ServerProcess
from test_history import HistoryCase, auth

if STAGE_DIR not in sys.path:
    sys.path.insert(0, STAGE_DIR)

from app import db  # noqa: E402

BUSY = (503, {"error": "busy"})


class ReversalCase(HistoryCase):
    def reverse(self, transfer_id, token, key=None, body=None, raw=None):
        headers = auth(token) if token else {}
        if key is not None:
            headers["Idempotency-Key"] = key
        return self.request("POST", f"/transfers/{transfer_id}/reverse",
                            {} if body is None and raw is None else body,
                            headers=headers, raw=raw)

    def moved(self, amount=30, funds=100, receiver_funds=0):
        """A sender, a recipient and one transfer of `amount` between them."""
        a = self.funded_account(funds, "sender")
        b = self.funded_account(receiver_funds, "recipient")
        status, transfer = self.transfer(a["id"], b["id"], amount, a["token"])
        self.assertEqual(status, 201, transfer)
        return a, b, transfer

    def reversal_rows(self, transfer_id):
        return self.query("SELECT reversal_id FROM reversals WHERE transfer_id = ?", (transfer_id,))


class ReverseTest(ReversalCase):
    """D4.4 and I27: a reversal is a transfer to -> from of the same amount."""

    def test_reverse_moves_the_amount_back(self):
        a, b, transfer = self.moved(30)
        status, body = self.reverse(transfer["id"], b["token"])
        self.assertEqual(status, 201, body)
        self.assertEqual(set(body), {"id", "from", "to", "amount", "reverses"})
        self.assertEqual((body["from"], body["to"], body["amount"], body["reverses"]),
                         (b["id"], a["id"], 30, transfer["id"]))
        self.assertNotEqual(body["id"], transfer["id"])
        self.assertEqual((self.balance(a["id"]), self.balance(b["id"])), (100, 0))
        # An ordinary transfers row plus the link, nothing else.
        self.assertEqual(self.query("SELECT from_id, to_id, amount FROM transfers WHERE id = ?",
                                    (body["id"],)), [(b["id"], a["id"], 30)])
        self.assertEqual(self.reversal_rows(transfer["id"]), [(body["id"],)])
        self.assertMoneyInvariants()

    def test_both_histories_link_the_reversal(self):
        a, b, transfer = self.moved(30)
        _, reversal = self.reverse(transfer["id"], b["token"])
        _, page_a = self.history(a["id"], a["token"])
        _, page_b = self.history(b["id"], b["token"])
        self.assertEqual(page_a["items"][0], {
            "id": reversal["id"], "type": "reversal_in", "amount": 30,
            "counterparty": b["id"], "created_at": page_a["items"][0]["created_at"],
            "reverses": transfer["id"]})
        self.assertEqual(page_b["items"][0], {
            "id": reversal["id"], "type": "reversal_out", "amount": 30,
            "counterparty": a["id"], "created_at": page_b["items"][0]["created_at"],
            "reverses": transfer["id"]})
        # The original stays an ordinary transfer item, with no "reverses".
        self.assertEqual([(i["id"], i["type"], "reverses" in i) for i in page_a["items"][1:2]],
                         [(transfer["id"], "transfer_out", False)])
        self.assertEqual([(i["id"], i["type"], "reverses" in i) for i in page_b["items"][1:2]],
                         [(transfer["id"], "transfer_in", False)])
        for account in (a, b):
            self.assertCompleteHistory(account, self.page_all(account, 1))

    def test_partly_spent_recipient_can_still_reverse_from_other_funds(self):
        # D4.7: reversible up to the recipient's current balance, whatever
        # the money's origin.
        a, b, transfer = self.moved(30, receiver_funds=10)
        self.assertEqual(self.withdraw(b["id"], 10, b["token"])[0], 200)
        self.assertEqual(self.reverse(transfer["id"], b["token"])[0], 201)
        self.assertEqual((self.balance(a["id"]), self.balance(b["id"])), (100, 0))
        self.assertMoneyInvariants()

    def test_only_post_is_routed(self):
        _, b, transfer = self.moved(1)
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, body = self.request(method, f"/transfers/{transfer['id']}/reverse",
                                            headers=auth(b["token"]))
                self.assertEqual((status, body), (404, {"error": "not_found"}))
        self.assertEqual(self.reversal_rows(transfer["id"]), [])


class ReverseErrorsTest(ReversalCase):
    """D4.5: each rejection in order, each with no effect (I6)."""

    def test_bad_request_400(self):
        a, b, transfer = self.moved(10)
        tid = transfer["id"]
        missing = str(uuid.uuid4())
        cases = {
            "body with a field": lambda: self.reverse(tid, b["token"], body={"x": 1}),
            "body with amount": lambda: self.reverse(tid, b["token"], body={"amount": 10}),
            "malformed id": lambda: self.reverse("not-a-uuid", b["token"]),
            "uppercase id": lambda: self.reverse(tid.upper(), b["token"]),
            "SQL in id": lambda: self.reverse("1%27%20OR%20%271%27%3D%271", b["token"]),
            "bad key": lambda: self.reverse(tid, b["token"], key="has space"),
            "bad body beats 404": lambda: self.reverse(missing, None, body={"x": 1}),
            "bad body beats 401": lambda: self.reverse(tid, a["token"], body={"x": 1}),
            "malformed id beats 401": lambda: self.reverse("xyz", None),
        }
        for name, call in cases.items():
            with self.subTest(case=name):
                self.assertRejectedFree(call, 400, "invalid_request")
        # A body that is not a JSON object: the stage-1 code for every
        # endpoint, still checked before 404/401.
        for raw in (b"[]", b"null", b"", b"{", b'"{}"', b"{}{}"):
            with self.subTest(raw=raw):
                self.assertRejectedFree(lambda: self.reverse(tid, b["token"], raw=raw),
                                        400, "invalid_json")
                self.assertRejectedFree(lambda: self.reverse(missing, None, raw=raw),
                                        400, "invalid_json")

    def test_two_authorization_headers_are_400(self):
        import http.client
        _, b, transfer = self.moved(10)
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        try:
            conn.putrequest("POST", f"/transfers/{transfer['id']}/reverse")
            conn.putheader("Authorization", f"Bearer {b['token']}")
            conn.putheader("Authorization", f"Bearer {b['token']}")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", "2")
            conn.endheaders(b"{}")
            resp = conn.getresponse()
            self.assertEqual((resp.status, resp.read()), (400, b'{"error":"invalid_request"}'))
        finally:
            conn.close()
        self.assertEqual(self.reversal_rows(transfer["id"]), [])

    def test_unknown_transfer_404_before_401(self):
        _, b, _ = self.moved(10)
        missing = str(uuid.uuid4())
        self.assertRejectedFree(lambda: self.reverse(missing, b["token"]), 404, "transfer_not_found")
        self.assertRejectedFree(lambda: self.reverse(missing, None), 404, "transfer_not_found")
        # An account id is not a transfer id.
        self.assertRejectedFree(lambda: self.reverse(b["id"], b["token"]), 404, "transfer_not_found")

    def test_only_the_recipient_token_401(self):
        a, b, transfer = self.moved(10)
        third = self.funded_account(50, "third")
        for name, token in (("sender", a["token"]), ("third party", third["token"]),
                            ("no token", None), ("wrong token", "x" * 43)):
            with self.subTest(token=name):
                self.assertRejectedFree(lambda: self.reverse(transfer["id"], token), 401, "unauthorized")
        status, body = self.request("POST", f"/transfers/{transfer['id']}/reverse", {},
                                    headers={"Authorization": f"bearer {b['token']}"})
        self.assertEqual((status, body), (401, {"error": "unauthorized"}))

    def test_already_reversed_409(self):
        _, b, transfer = self.moved(10, receiver_funds=100)
        self.assertEqual(self.reverse(transfer["id"], b["token"])[0], 201)
        self.assertRejectedFree(lambda: self.reverse(transfer["id"], b["token"]), 409, "already_reversed")

    def test_already_reversed_beats_insufficient_funds(self):
        _, b, transfer = self.moved(10)
        self.assertEqual(self.reverse(transfer["id"], b["token"])[0], 201)
        self.assertEqual(self.balance(b["id"]), 0)
        self.assertRejectedFree(lambda: self.reverse(transfer["id"], b["token"]), 409, "already_reversed")

    def test_reversal_is_not_reversible_422(self):
        a, b, transfer = self.moved(10)
        _, reversal = self.reverse(transfer["id"], b["token"])
        # The reversal's recipient is the original sender; only that token
        # gets past 401, and the answer is 422 even with funds available.
        self.assertRejectedFree(lambda: self.reverse(reversal["id"], b["token"]), 401, "unauthorized")
        self.assertRejectedFree(lambda: self.reverse(reversal["id"], a["token"]), 422, "not_reversible")
        self.assertEqual(self.withdraw(a["id"], 100, a["token"])[0], 200)
        self.assertRejectedFree(lambda: self.reverse(reversal["id"], a["token"]), 422, "not_reversible")

    def test_insufficient_funds_409_no_partial(self):
        a, b, transfer = self.moved(30)
        self.assertEqual(self.withdraw(b["id"], 1, b["token"])[0], 200)
        self.assertRejectedFree(lambda: self.reverse(transfer["id"], b["token"]), 409, "insufficient_funds")
        self.assertEqual((self.balance(a["id"]), self.balance(b["id"])), (70, 29))
        # Money comes back: the reversal goes through.
        self.assertEqual(self.deposit(b["id"], 1)[0], 200)
        self.assertEqual(self.reverse(transfer["id"], b["token"])[0], 201)

    def test_balance_limit_422(self):
        a, b, transfer = self.moved(10**12, funds=10**12)
        self.fill_to(a["id"], 10**12, 1000)  # a at the 10**15 cap
        self.assertEqual(self.balance(a["id"]), db.MAX_BALANCE)
        self.assertRejectedFree(lambda: self.reverse(transfer["id"], b["token"]), 422, "balance_limit")
        self.assertEqual(self.withdraw(a["id"], 1, a["token"])[0], 200)
        self.assertRejectedFree(lambda: self.reverse(transfer["id"], b["token"]), 422, "balance_limit")
        self.assertEqual(self.withdraw(a["id"], 10**12 - 1, a["token"])[0], 200)
        self.assertEqual(self.reverse(transfer["id"], b["token"])[0], 201)
        self.assertEqual(self.balance(a["id"]), db.MAX_BALANCE)
        self.assertMoneyInvariants()

    def test_insufficient_funds_beats_balance_limit(self):
        a, b, transfer = self.moved(10**12, funds=10**12)
        self.fill_to(a["id"], 10**12, 1000)
        self.assertEqual(self.withdraw(b["id"], 1, b["token"])[0], 200)
        self.assertRejectedFree(lambda: self.reverse(transfer["id"], b["token"]), 409, "insufficient_funds")


class ReverseIdempotencyTest(ReversalCase):
    """D4.6: Idempotency-Key on reverse, in the recipient's debit namespace."""

    def test_keyed_retry_replays_the_201(self):
        _, b, transfer = self.moved(10, receiver_funds=50)
        first = self.reverse(transfer["id"], b["token"], key="rev-1")
        self.assertEqual(first[0], 201)
        before = self.snapshot()
        self.assertEqual(self.reverse(transfer["id"], b["token"], key="rev-1"), first)
        self.assertEqual(self.snapshot(), before, "a replay changed the DB")
        # Without the key it is a second request: already reversed.
        self.assertEqual(self.reverse(transfer["id"], b["token"]), (409, {"error": "already_reversed"}))
        # Another fresh key: also already reversed, and nothing is stored.
        self.assertRejectedFree(lambda: self.reverse(transfer["id"], b["token"], key="rev-2"),
                                409, "already_reversed")

    def test_key_reuse_across_operations_is_422(self):
        a, b, transfer = self.moved(10, receiver_funds=50)
        _, other = self.transfer(a["id"], b["id"], 5, a["token"])
        self.assertEqual(self.request("POST", f"/accounts/{b['id']}/withdraw", {"amount": 1},
                                      headers={**auth(b["token"]), "Idempotency-Key": "w-1"})[0], 200)
        self.assertRejectedFree(lambda: self.reverse(transfer["id"], b["token"], key="w-1"),
                                422, "idempotency_key_reused")
        self.assertEqual(self.reverse(transfer["id"], b["token"], key="r-1")[0], 201)
        # The reverse key is now taken in b's debit namespace...
        status, body = self.request("POST", f"/accounts/{b['id']}/withdraw", {"amount": 1},
                                    headers={**auth(b["token"]), "Idempotency-Key": "r-1"})
        self.assertEqual((status, body), (422, {"error": "idempotency_key_reused"}))
        status, body = self.request("POST", "/transfers", {"from": b["id"], "to": a["id"], "amount": 1},
                                    headers={**auth(b["token"]), "Idempotency-Key": "r-1"})
        self.assertEqual((status, body), (422, {"error": "idempotency_key_reused"}))
        # ...and is bound to that transfer id.
        self.assertRejectedFree(lambda: self.reverse(other["id"], b["token"], key="r-1"),
                                422, "idempotency_key_reused")
        # The sender's namespace is separate: a's own key "r-1" is free.
        status, _ = self.request("POST", f"/accounts/{a['id']}/withdraw", {"amount": 1},
                                 headers={**auth(a["token"]), "Idempotency-Key": "r-1"})
        self.assertEqual(status, 200)

    def test_rejections_store_no_key(self):
        _, b, transfer = self.moved(10)
        self.assertEqual(self.withdraw(b["id"], 1, b["token"])[0], 200)
        self.assertEqual(self.reverse(transfer["id"], b["token"], key="k"),
                         (409, {"error": "insufficient_funds"}))
        self.assertEqual(self.query("SELECT count(*) FROM idempotency_keys WHERE key = 'k'"), [(0,)])
        self.assertEqual(self.deposit(b["id"], 1)[0], 200)
        self.assertEqual(self.reverse(transfer["id"], b["token"], key="k")[0], 201)


class ReverseAtMostOnceTest(ReversalCase):
    """I25: one reversal commits, sequential or concurrent, keyed or keyless,
    across a restart. The reversals PRIMARY KEY is the backstop."""

    def burst(self, calls, workers=64):
        barrier = threading.Barrier(min(workers, len(calls)))

        def run(call):
            try:
                barrier.wait(10)
            except threading.BrokenBarrierError:
                pass
            while True:
                result = call()
                if result != BUSY:  # 503 busy has no effect by contract
                    return result

        with ThreadPoolExecutor(workers) as pool:
            return list(pool.map(run, calls))

    def assertReversedOnce(self, a, b, transfer):
        self.assertEqual(len(self.reversal_rows(transfer["id"])), 1)
        self.assertEqual(self.query("SELECT count(*) FROM transfers WHERE from_id = ? AND to_id = ?",
                                    (b["id"], a["id"])), [(1,)])
        self.assertMoneyInvariants()

    def test_concurrent_keyless(self):
        a, b, transfer = self.moved(10, receiver_funds=1000)
        results = self.burst([lambda: self.reverse(transfer["id"], b["token"])] * 64)
        self.assertEqual(sum(r[0] == 201 for r in results), 1, results)
        self.assertEqual([r for r in results if r[0] != 201],
                         [(409, {"error": "already_reversed"})] * 63)
        self.assertReversedOnce(a, b, transfer)
        self.assertEqual(self.balance(b["id"]), 1000)

    def test_concurrent_same_key(self):
        a, b, transfer = self.moved(10, receiver_funds=1000)
        results = self.burst([lambda: self.reverse(transfer["id"], b["token"], key="same")] * 64)
        self.assertEqual({r[0] for r in results}, {201})
        self.assertEqual(len({r[1]["id"] for r in results}), 1, "replays differ")
        self.assertReversedOnce(a, b, transfer)

    def test_concurrent_mixed_keys(self):
        a, b, transfer = self.moved(10, receiver_funds=1000)
        calls = [lambda n=n: self.reverse(transfer["id"], b["token"],
                                          key=None if n % 3 == 0 else f"k{n % 5}")
                 for n in range(60)]
        results = self.burst(calls)
        # One commit; the winner's key replays it, every other request
        # (keyless or another key) finds the transfer already reversed.
        winners = {r[1]["id"] for r in results if r[0] == 201}
        self.assertEqual(len(winners), 1, results)
        self.assertEqual([r for r in results if r[0] != 201],
                         [(409, {"error": "already_reversed"})] * sum(r[0] != 201 for r in results))
        self.assertReversedOnce(a, b, transfer)

    def test_reversals_link_is_append_only_and_unique(self):
        _, b, transfer = self.moved(10, receiver_funds=100)
        _, reversal = self.reverse(transfer["id"], b["token"])
        conn = db.connect(self.db_path)
        try:
            other = str(uuid.uuid4())
            for sql, params in (
                ("INSERT INTO reversals (transfer_id, reversal_id) VALUES (?, ?)",
                 (transfer["id"], reversal["id"])),
                ("INSERT INTO reversals (transfer_id, reversal_id) VALUES (?, ?)",
                 (transfer["id"], other)),
                ("DELETE FROM reversals", ()),
                ("UPDATE reversals SET transfer_id = reversal_id", ()),
            ):
                with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                    with db.write_transaction(conn):
                        conn.execute(sql, params)
        finally:
            conn.close()
        self.assertEqual(self.reversal_rows(transfer["id"]), [(reversal["id"],)])


class ReverseAcrossRestartTest(ReversalCase):
    """I25 across a restart (graceful and kill -9): the link is durable."""

    def test_restart_then_retry(self):
        a, b, transfer = self.moved(10, receiver_funds=100)
        first = self.reverse(transfer["id"], b["token"], key="restart")
        self.assertEqual(first[0], 201)
        _, b2, transfer2 = self.moved(7, receiver_funds=100)
        for stop in ("stop", "kill"):
            with self.subTest(stop=stop):
                getattr(self.server, stop)()
                self.server = ServerProcess(self.db_path).start()
                type(self).server = self.server
                self.assertEqual(self.reverse(transfer["id"], b["token"], key="restart"), first)
                self.assertEqual(self.reverse(transfer["id"], b["token"]),
                                 (409, {"error": "already_reversed"}))
        self.assertEqual(len(self.reversal_rows(transfer["id"])), 1)
        self.assertEqual(self.reverse(transfer2["id"], b2["token"])[0], 201)
        self.assertMoneyInvariants()


class ReversalDrainRaceTest(ReversalCase):
    """I26: the recipient's own debits racing the reversal never overdraw:
    with exactly the amount on hand, exactly one of them wins."""

    def test_withdraw_races_reverse(self):
        for n in range(15):
            a, b, transfer = self.moved(25)
            barrier = threading.Barrier(4)

            def go(call):
                barrier.wait(10)
                while True:
                    result = call()
                    if result != BUSY:
                        return result

            calls = [lambda: self.reverse(transfer["id"], b["token"]),
                     lambda: self.reverse(transfer["id"], b["token"], key=f"race-{n}"),
                     lambda: self.withdraw(b["id"], 25, b["token"]),
                     lambda: self.transfer(b["id"], a["id"], 25, b["token"])]
            with ThreadPoolExecutor(4) as pool:
                results = list(pool.map(go, calls))
            wins = [r for r in results if r[0] in (200, 201)]
            self.assertEqual(len(wins), 1, results)
            self.assertEqual(self.balance(b["id"]), 0)
            reversed_ = len(self.reversal_rows(transfer["id"]))
            self.assertEqual(reversed_, int(results[0][0] == 201 or results[1][0] == 201))
            for status, body in results:
                if status not in (200, 201):
                    self.assertIn(body["error"], ("insufficient_funds", "already_reversed"))
        self.assertMoneyInvariants()
