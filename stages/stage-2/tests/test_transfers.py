"""HTTP-level checks for unit 1.3: POST /transfers. Every test ends with the
money sweep (I1 audit + file, I3, I5, I7 replay including transfers)."""

import json
import random
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from harness import CLIENT_TIMEOUT_S, ServerProcess
import test_money
from test_money import MAX_AMOUNT, MAX_BALANCE, MoneyTestCase


def raw_post(port, path, body, auth_values):
    """POST with the given Authorization header lines, sent byte for byte."""
    data = json.dumps(body).encode()
    request = (f"POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(data)}\r\n"
               + "".join(f"Authorization: {v}\r\n" for v in auth_values)
               + "\r\n").encode() + data
    with socket.create_connection(("127.0.0.1", port), timeout=CLIENT_TIMEOUT_S) as sock:
        sock.sendall(request)
        reply = b""
        while chunk := sock.recv(65536):
            reply += chunk
    head, _, payload = reply.partition(b"\r\n\r\n")
    return int(head.split(b" ", 2)[1]), json.loads(payload)


class TransferTestCase(MoneyTestCase):
    def fire(self, calls, workers):
        """Release all calls at once; each must answer within the client
        timeout with a 2xx, 409 or 503 busy."""
        barrier = threading.Barrier(min(workers, len(calls)))

        def run(call):
            barrier.wait(10)
            start = time.monotonic()
            result = call()
            return result, time.monotonic() - start

        with ThreadPoolExecutor(max_workers=workers) as pool:
            out = list(pool.map(run, calls))
        for (status, body), elapsed in out:
            self.assertLess(elapsed, CLIENT_TIMEOUT_S, "I11: request hung")
            self.assertTrue(status in (200, 201) or
                            (status, body.get("error")) in ((409, "insufficient_funds"),
                                                            (503, "busy")), (status, body))
        return [result for result, _ in out]

    def transfer_rows(self, from_id):
        return self.query("SELECT id, to_id, amount FROM transfers WHERE from_id = ?", (from_id,))


class I2ZeroSumTest(TransferTestCase):
    def test_i2_exactly_plus_minus_a_and_shape(self):
        a = self.funded_account(1000, "zs-a")
        b = self.funded_account(50, "zs-b")
        status, body = self.transfer(a["id"], b["id"], 300, a["token"])
        self.assertEqual(status, 201, body)
        self.assertEqual(set(body), {"id", "from", "to", "amount"})
        self.assertEqual((body["from"], body["to"], body["amount"]), (a["id"], b["id"], 300))
        self.assertEqual(str(uuid.UUID(body["id"])), body["id"])
        self.assertEqual(uuid.UUID(body["id"]).version, 4)
        self.assertNotIn(a["token"], json.dumps(body))
        self.assertEqual((self.balance(a["id"]), self.balance(b["id"])), (700, 350))
        self.assertEqual(self.transfer_rows(a["id"]), [(body["id"], b["id"], 300)])
        # Transfers are internal: the audit's external totals do not move.
        self.assertEqual(self.query("SELECT count(*) FROM external_moves WHERE account_id IN (?, ?)",
                                    (a["id"], b["id"])), [(2,)])

    def test_i2_credit_over_limit_is_422_and_source_untouched(self):
        full = self.create_account("full")
        self.fill_to(full["id"], MAX_AMOUNT, MAX_BALANCE // MAX_AMOUNT)
        self.assertEqual(self.balance(full["id"]), MAX_BALANCE)
        src = self.funded_account(10, "src")
        self.assertRejectedFree(lambda: self.transfer(src["id"], full["id"], 1, src["token"]),
                                422, "balance_limit")
        self.assertEqual(self.balance(src["id"]), 10)
        # 409 is decided before 422: an overdraw into a full account is 409.
        self.assertRejectedFree(lambda: self.transfer(src["id"], full["id"], 11, src["token"]),
                                409, "insufficient_funds")
        # Exactly up to the limit is fine.
        status, _ = self.withdraw(full["id"], 5, full["token"])
        self.assertEqual(status, 200)
        self.assertEqual(self.transfer(src["id"], full["id"], 5, src["token"])[0], 201)
        self.assertEqual((self.balance(src["id"]), self.balance(full["id"])), (5, MAX_BALANCE))


class TransferCheckOrderTest(TransferTestCase):
    def test_i6_every_rejection_is_free_and_in_order(self):
        a = self.funded_account(10, "ord-a")
        b = self.funded_account(10, "ord-b")
        c = self.funded_account(10, "ord-c")
        ghost = str(uuid.uuid4())
        auth_a = {"Authorization": f"Bearer {a['token']}"}
        auth_b = {"Authorization": f"Bearer {b['token']}"}

        def body(f, t, amount=1):
            return json.dumps({"from": f, "to": t, "amount": amount}).encode()

        cases = [
            # 400: body / shape. The amount code wins over the field code.
            (b"{", {}, 400, "invalid_json"),
            (b"[]", auth_a, 400, "invalid_json"),
            (body(ghost, ghost, 1.5), {}, 400, "invalid_amount"),
            (json.dumps({"from": a["id"], "to": b["id"]}).encode(), auth_a, 400, "invalid_amount"),
            (json.dumps({"from": 1, "to": b["id"]}).encode(), auth_a, 400, "invalid_amount"),
            (json.dumps({"to": b["id"], "amount": 1}).encode(), auth_a, 400, "invalid_request"),
            (json.dumps({"from": a["id"], "amount": 1}).encode(), auth_a, 400, "invalid_request"),
            (json.dumps({"from": a["id"], "to": b["id"], "amount": 1, "x": 1}).encode(), auth_a,
             400, "invalid_request"),
            (json.dumps({"from": [a["id"]], "to": b["id"], "amount": 1}).encode(), auth_a,
             400, "invalid_request"),
            (json.dumps({"from": a["id"], "to": None, "amount": 1}).encode(), auth_a,
             400, "invalid_request"),
            (json.dumps({"from": 1, "to": 2, "amount": 1}).encode(), auth_a, 400, "invalid_request"),
            (body(a["id"], a["id"]), auth_a, 400, "invalid_request"),
            (body(ghost, ghost), {}, 400, "invalid_request"),
            # 404 before 401: either side missing, whatever the token.
            (body(ghost, b["id"]), {}, 404, "account_not_found"),
            (body(a["id"], ghost), {}, 404, "account_not_found"),
            (body(a["id"], ghost), {"Authorization": "Bearer bad"}, 404, "account_not_found"),
            (body(a["id"], ghost), auth_a, 404, "account_not_found"),
            (body(a["id"], b["id"].upper()), auth_a, 404, "account_not_found"),
            (body("not-a-uuid", b["id"]), auth_a, 404, "account_not_found"),
            # 401 before 409.
            (body(a["id"], b["id"], 11), {}, 401, "unauthorized"),
            (body(a["id"], b["id"], 11), auth_b, 401, "unauthorized"),
            (body(a["id"], b["id"], 1), {"Authorization": f"Bearer {c['token']}"},
             401, "unauthorized"),
            (body(a["id"], b["id"], 11), auth_a, 409, "insufficient_funds"),
        ]
        for raw, headers, status, error in cases:
            with self.subTest(raw=raw[:70], status=status):
                self.assertRejectedFree(
                    lambda: self.request("POST", "/transfers", raw=raw, headers=headers),
                    status, error)
        self.assertEqual([self.balance(x["id"]) for x in (a, b, c)], [10, 10, 10])

    def test_repeated_authorization_is_400_and_free(self):
        a = self.funded_account(10, "dup-a")
        b = self.funded_account(0, "dup-b")
        good = f"Bearer {a['token']}"
        for to_id in (b["id"], str(uuid.uuid4())):
            for values in ([good, good], [good, "Bearer x"], ["Bearer x", good]):
                with self.subTest(known_to=to_id == b["id"], values=values[1][:8]):
                    self.assertRejectedFree(
                        lambda: raw_post(self.server.port, "/transfers",
                                         {"from": a["id"], "to": to_id, "amount": 1}, values),
                        400, "invalid_request")
        # The amount code wins when both apply.
        self.assertRejectedFree(
            lambda: raw_post(self.server.port, "/transfers",
                             {"from": a["id"], "to": b["id"], "amount": 0}, [good, good]),
            400, "invalid_amount")


class I3TransferBoundariesTest(TransferTestCase):
    def test_i3_exact_balance_plus_one_and_from_zero(self):
        a = self.funded_account(250, "b-a")
        b = self.funded_account(0, "b-b")
        self.assertRejectedFree(lambda: self.transfer(a["id"], b["id"], 251, a["token"]),
                                409, "insufficient_funds")
        self.assertEqual(self.transfer(a["id"], b["id"], 250, a["token"])[0], 201)
        self.assertEqual((self.balance(a["id"]), self.balance(b["id"])), (0, 250))
        self.assertRejectedFree(lambda: self.transfer(a["id"], b["id"], 1, a["token"]),
                                409, "insufficient_funds")


class I4TransferDoubleSpendTest(TransferTestCase):
    def drain(self, balance, amount, threads):
        src = self.funded_account(balance, f"src-{amount}")
        dsts = [self.funded_account(0, f"dst-{amount}-{k}") for k in range(20)]
        results = self.fire([(lambda d=dsts[i % 20]: self.transfer(src["id"], d["id"], amount,
                                                                   src["token"]))
                             for i in range(threads)], workers=threads)
        committed = [body for status, body in results if status == 201]
        total = amount * len(committed)
        self.assertLessEqual(total, balance, "I4: more than B committed")
        self.assertEqual(len(self.transfer_rows(src["id"])), len(committed),
                         "I4: count(2xx) != count(transfer rows)")
        self.assertEqual({body["id"] for body in committed},
                         {row[0] for row in self.transfer_rows(src["id"])},
                         "every 201 id is a transfers row id")
        self.assertEqual(self.balance(src["id"]), balance - total)
        self.assertEqual(sum(self.balance(d["id"]) for d in dsts), total)
        return len(committed), sum(status == 503 for status, _ in results)

    def test_i4_full_balance_by_60_threads(self):
        self.assertCommittedUpTo(*self.drain(1000, 1000, 60), limit=1)

    def test_i4_balance_over_k_by_100_threads(self):
        self.assertCommittedUpTo(*self.drain(1000, 100, 100), limit=10)

    def test_i4_same_transfer_twice_in_parallel(self):
        for round_ in range(20):
            a = self.funded_account(100, f"pair-a-{round_}")
            b = self.funded_account(0, f"pair-b-{round_}")
            results = self.fire([lambda: self.transfer(a["id"], b["id"], 100, a["token"])] * 2,
                                workers=2)
            committed = sum(status == 201 for status, _ in results)
            self.assertCommittedUpTo(committed, sum(s == 503 for s, _ in results), limit=1)
            self.assertEqual((self.balance(a["id"]), self.balance(b["id"])),
                             (100 - 100 * committed, 100 * committed))

    def test_i4_a_to_b_and_b_to_a_at_once(self):
        a = self.funded_account(1000, "x-a")
        b = self.funded_account(1000, "x-b")
        calls = []
        for i in range(100):
            if i % 2:
                calls.append(lambda: self.transfer(a["id"], b["id"], 7, a["token"]))
            else:
                calls.append(lambda: self.transfer(b["id"], a["id"], 7, b["token"]))
        self.fire(calls, workers=100)
        self.assertEqual(self.balance(a["id"]) + self.balance(b["id"]), 2000)

    def test_i4_withdraw_racing_transfer_on_same_funds(self):
        src = self.funded_account(600, "race-src")
        dst = self.funded_account(0, "race-dst")
        calls = []
        for i in range(120):
            if i % 2:
                calls.append(lambda: self.withdraw(src["id"], 100, src["token"]))
            else:
                calls.append(lambda: self.transfer(src["id"], dst["id"], 100, src["token"]))
        results = self.fire(calls, workers=120)
        committed = sum(status in (200, 201) for status, _ in results)
        self.assertCommittedUpTo(committed, sum(s == 503 for s, _ in results), limit=6)
        rows = (self.query("SELECT count(*) FROM external_moves "
                           "WHERE account_id = ? AND kind = 'withdrawal'", (src["id"],))[0][0]
                + len(self.transfer_rows(src["id"])))
        self.assertEqual(rows, committed, "I4: count(2xx) != ledger rows")
        self.assertEqual(self.balance(src["id"]), 600 - 100 * committed)


class I5TransferAmountsTest(TransferTestCase):
    def test_i5_amount_table_on_transfers(self):
        a = self.funded_account(1000, "amt-a")
        b = self.funded_account(0, "amt-b")
        auth = {"Authorization": f"Bearer {a['token']}"}
        template = '{"from": "%s", "to": "%s", "amount": ' % (a["id"], b["id"])
        for literal in test_money.I5IntegerMoneyTest.BAD_AMOUNTS + test_money.I5IntegerMoneyTest.INVALID_JSON:
            error = ("invalid_json" if literal in test_money.I5IntegerMoneyTest.INVALID_JSON
                     else "invalid_amount")
            with self.subTest(amount=literal[:20]):
                self.assertRejectedFree(
                    lambda: self.request("POST", "/transfers",
                                         raw=template.encode() + literal + b"}", headers=auth),
                    400, error)
        self.assertEqual(self.transfer(a["id"], b["id"], 1000, a["token"])[0], 201)
        self.assertEqual(self.query("SELECT DISTINCT typeof(amount) FROM transfers"),
                         [("integer",)])


class I8TransferAuthTest(TransferTestCase):
    def test_i8_only_the_from_token_debits(self):
        victim = self.funded_account(1000, "victim")
        thief = self.funded_account(0, "thief")
        third = self.funded_account(0, "third")
        for headers in ({}, {"Authorization": f"Bearer {thief['token']}"},
                        {"Authorization": f"Bearer {third['token']}"},
                        {"Authorization": "Bearer "}, {"Authorization": "Bearer wrong"},
                        {"Authorization": f"bearer {victim['token']}"},
                        {"Authorization": f"Bearer  {victim['token']}"},
                        {"Authorization": victim["token"]}):
            with self.subTest(headers=str(headers)[:40]):
                self.assertRejectedFree(
                    lambda: self.request("POST", "/transfers",
                                         {"from": victim["id"], "to": thief["id"], "amount": 1},
                                         headers=headers),
                    401, "unauthorized")
        self.assertEqual(self.balance(victim["id"]), 1000)

    def test_q5_surrounding_whitespace_is_trimmed_on_withdraw_and_transfer(self):
        a = self.funded_account(100, "ows-a")
        b = self.funded_account(0, "ows-b")
        t = a["token"]
        for value in (f" Bearer {t}", f"Bearer {t} ", f"\tBearer {t}\t", f"  Bearer {t} \t "):
            with self.subTest(value=repr(value)[:12]):
                self.assertEqual(raw_post(self.server.port, f"/accounts/{a['id']}/withdraw",
                                          {"amount": 1}, [value])[0], 200)
                self.assertEqual(raw_post(self.server.port, "/transfers",
                                          {"from": a["id"], "to": b["id"], "amount": 1},
                                          [value])[0], 201)
        # Interior whitespace stays exact.
        for value in (f"Bearer  {t}", f"Bearer\t{t}", f" Bearer  {t} "):
            with self.subTest(interior=repr(value)[:12]):
                self.assertRejectedFree(
                    lambda: raw_post(self.server.port, "/transfers",
                                     {"from": a["id"], "to": b["id"], "amount": 1}, [value]),
                    401, "unauthorized")
        self.assertEqual((self.balance(a["id"]), self.balance(b["id"])), (92, 4))


class I10TransferDurabilityTest(TransferTestCase):
    def test_i10_restart_keeps_transfers(self):
        a = self.funded_account(500, "dur-a")
        b = self.funded_account(0, "dur-b")
        status, body = self.transfer(a["id"], b["id"], 120, a["token"])
        self.assertEqual(status, 201)
        before = self.snapshot()
        self.server.stop()
        self.server = ServerProcess(self.db_path).start()
        type(self).server = self.server
        self.assertEqual(self.snapshot(), before)
        self.assertEqual((self.balance(a["id"]), self.balance(b["id"])), (380, 120))

    def test_i10_hard_kill_mid_burst(self):
        accounts = [self.funded_account(10**6, f"kill-{k}") for k in range(4)]
        acked, stop = [], threading.Event()

        def worker():
            while not stop.is_set():
                src, dst = random.sample(accounts, 2)
                try:
                    status, body = self.transfer(src["id"], dst["id"], random.randint(1, 100),
                                                 src["token"])
                except Exception:  # the server is being killed
                    return
                if status == 201:
                    acked.append(body["id"])

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for thread in threads:
            thread.start()
        time.sleep(1.5)
        self.server.kill()
        stop.set()
        for thread in threads:
            thread.join(15)
        self.server = ServerProcess(self.db_path).start()
        type(self).server = self.server
        self.assertGreater(len(acked), 0)
        have = {row[0] for row in self.query("SELECT id FROM transfers")}
        self.assertEqual([i for i in acked if i not in have], [],
                         "I10: acknowledged transfers lost after kill")
        self.assertEqual(sum(self.balance(x["id"]) for x in accounts), 4 * 10**6)
        # tearDown re-checks I1, I3, I5 and I7 on the recovered file.


class I11MixedLoadTest(TransferTestCase):
    def test_i11_mixed_load_with_audit_mid_flight(self):
        accounts = [self.funded_account(10_000, f"mix-{k}") for k in range(6)]
        stop = threading.Event()
        bad, samples = [], [0]

        def sampler():
            while not stop.is_set():
                status, audit = self.request("GET", "/audit")
                samples[0] += 1
                if status != 200 or audit["conserved"] is not True:
                    bad.append((status, audit))

        def operation(i):
            src, dst = random.sample(accounts, 2)
            amount = random.randint(1, 400)
            start = time.monotonic()
            if i % 3 == 0:
                result = self.deposit(src["id"], amount)
            elif i % 3 == 1:
                result = self.withdraw(src["id"], amount, src["token"])
            else:
                result = self.transfer(src["id"], dst["id"], amount, src["token"])
            return result, time.monotonic() - start

        samplers = [threading.Thread(target=sampler) for _ in range(3)]
        for thread in samplers:
            thread.start()
        try:
            with ThreadPoolExecutor(max_workers=40) as pool:
                results = list(pool.map(operation, range(450)))
        finally:
            stop.set()
            for thread in samplers:
                thread.join()
        for (status, body), elapsed in results:
            self.assertLess(elapsed, CLIENT_TIMEOUT_S, "I11: request hung")
            self.assertIn(status, (200, 201, 409, 503), body)
        self.assertGreater(samples[0], 10)
        self.assertEqual(bad[:5], [], "I1: audit not conserved mid-flight")
