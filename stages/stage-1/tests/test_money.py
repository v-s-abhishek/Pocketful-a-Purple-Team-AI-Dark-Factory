"""HTTP-level checks for unit 1.2: deposit, withdraw, audit. Each test class
is named after the invariant it proves; every money test ends with the I1,
I3, I5 and I7 sweep (MoneyTestCase.tearDown)."""

import json
import random
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from harness import CLIENT_TIMEOUT_S, ServerProcess, ServerTestCase

MAX_AMOUNT = 10**12
MAX_BALANCE = 10**15


class MoneyTestCase(ServerTestCase):
    def tearDown(self):
        self.assertMoneyInvariants()

    def assertCommittedUpTo(self, committed, busy, limit):
        """A 503 is not committed (contention ruling): at most `limit` commit,
        and only a 503 may explain any shortfall."""
        self.assertLessEqual(committed, limit, "I4: too many commits")
        self.assertGreaterEqual(committed + busy, limit,
                                f"I4: only {committed} committed and {busy} busy, limit {limit}")


class ShapeAndOrderTest(MoneyTestCase):
    def test_deposit_and_withdraw_shapes(self):
        account = self.create_account("shape")
        self.assertEqual(self.deposit(account["id"], 700),
                         (200, {"id": account["id"], "balance": 700}))
        self.assertEqual(self.withdraw(account["id"], 300, account["token"]),
                         (200, {"id": account["id"], "balance": 400}))
        self.assertEqual(self.request("GET", "/accounts/" + account["id"])[1]["balance"], 400)
        rows = self.query("SELECT kind, amount, typeof(amount), length(id) FROM external_moves "
                          "WHERE account_id = ? ORDER BY kind", (account["id"],))
        self.assertEqual(rows, [("deposit", 700, "integer", 36), ("withdrawal", 300, "integer", 36)])

    def test_withdraw_check_order(self):
        # body/amount 400 -> 404 account_not_found -> 401 unauthorized -> 409.
        a = self.funded_account(10, "order-a")
        b = self.funded_account(10, "order-b")
        ghost = str(uuid.uuid4())
        auth_a = {"Authorization": f"Bearer {a['token']}"}
        auth_b = {"Authorization": f"Bearer {b['token']}"}
        cases = [
            (ghost, b'{"amount": 1.5}', {}, 400, "invalid_amount"),
            (ghost, b"{", {}, 400, "invalid_json"),
            ("not-a-uuid", b'{"amount": 0}', auth_a, 400, "invalid_amount"),
            (a["id"], b'{"x": 1}', auth_a, 400, "invalid_amount"),
            (a["id"], b'{"amount": 1, "x": 1}', auth_a, 400, "invalid_request"),
            (ghost, b'{"amount": 1}', {}, 404, "account_not_found"),
            (ghost, b'{"amount": 1}', {"Authorization": "Bearer nope"}, 404, "account_not_found"),
            (ghost, b'{"amount": 1}', auth_a, 404, "account_not_found"),
            ("NOT-A-UUID", b'{"amount": 1}', auth_a, 404, "account_not_found"),
            (a["id"].upper(), b'{"amount": 1}', auth_a, 404, "account_not_found"),
            (a["id"], b'{"amount": 11}', {}, 401, "unauthorized"),
            (a["id"], b'{"amount": 11}', auth_b, 401, "unauthorized"),
            (a["id"], b'{"amount": 11}', auth_a, 409, "insufficient_funds"),
        ]
        for account_id, raw, headers, status, error in cases:
            with self.subTest(id=account_id[:8], raw=raw, status=status):
                self.assertRejectedFree(
                    lambda: self.request("POST", f"/accounts/{account_id}/withdraw",
                                         raw=raw, headers=headers),
                    status, error)

    def test_deposit_check_order(self):
        ghost = str(uuid.uuid4())
        a = self.funded_account(0, "dep-order")
        for account_id, raw, status, error in (
                (ghost, b'{"amount": -1}', 400, "invalid_amount"),
                (ghost, b"[]", 400, "invalid_json"),
                (a["id"], b'{"amount": 1, "token": "x"}', 400, "invalid_request"),
                (ghost, b'{"amount": 1}', 404, "account_not_found"),
                ("1%27%20OR%201=1", b'{"amount": 1}', 404, "account_not_found")):
            with self.subTest(id=account_id[:8], raw=raw):
                self.assertRejectedFree(
                    lambda: self.request("POST", f"/accounts/{account_id}/deposit", raw=raw),
                    status, error)

    def test_deposit_needs_no_token(self):
        a = self.create_account("dep-any")
        for headers in ({}, {"Authorization": "Bearer garbage"},
                        {"Authorization": "Basic Zm9vOmJhcg=="}):
            with self.subTest(headers=headers):
                status, body = self.request("POST", f"/accounts/{a['id']}/deposit",
                                            {"amount": 1}, headers=headers)
                self.assertEqual(status, 200, body)
        self.assertEqual(self.balance(a["id"]), 3)


class I3NoNegativeBalanceTest(MoneyTestCase):
    def test_i3_withdraw_boundaries(self):
        a = self.funded_account(250, "bounds")
        self.assertRejectedFree(lambda: self.withdraw(a["id"], 251, a["token"]),
                                409, "insufficient_funds")
        self.assertEqual(self.withdraw(a["id"], 250, a["token"]),
                         (200, {"id": a["id"], "balance": 0}))
        self.assertRejectedFree(lambda: self.withdraw(a["id"], 1, a["token"]),
                                409, "insufficient_funds")
        self.assertRejectedFree(lambda: self.withdraw(a["id"], MAX_AMOUNT, a["token"]),
                                409, "insufficient_funds")
        empty = self.create_account("zero")
        self.assertRejectedFree(lambda: self.withdraw(empty["id"], 1, empty["token"]),
                                409, "insufficient_funds")

    def test_i3_schema_refuses_negative_even_if_service_is_bypassed(self):
        a = self.funded_account(5, "schema-neg")
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE accounts SET balance = balance - 6 WHERE id = ?", (a["id"],))
        finally:
            conn.close()
        self.assertEqual(self.balance(a["id"]), 5)


class I4NoDoubleSpendTest(MoneyTestCase):
    def fire(self, calls, workers):
        """Release all calls at once; every one must answer within the timeout."""
        barrier = threading.Barrier(min(workers, len(calls)))

        def run(call):
            barrier.wait(10)
            start = time.monotonic()
            result = call()
            return result, time.monotonic() - start

        with ThreadPoolExecutor(max_workers=workers) as pool:
            out = list(pool.map(run, calls))
        for result, elapsed in out:
            self.assertLess(elapsed, CLIENT_TIMEOUT_S, "I11: request hung")
            self.assertIn(result[0], (200, 409, 503), result)
        return [result for result, _ in out]

    def check_drain(self, balance, amount, count):
        a = self.funded_account(balance, f"drain-{amount}")
        results = self.fire([lambda: self.withdraw(a["id"], amount, a["token"])] * count,
                            workers=count)
        committed = [body for status, body in results if status == 200]
        for status, body in results:
            if status != 200:
                self.assertIn(body["error"], ("insufficient_funds", "busy"))
        total = amount * len(committed)
        self.assertLessEqual(total, balance, "I4: more than B committed")
        rows = self.query("SELECT amount FROM external_moves "
                          "WHERE account_id = ? AND kind = 'withdrawal'", (a["id"],))
        self.assertEqual(len(rows), len(committed), "I4: count(2xx) != count(withdrawal rows)")
        self.assertEqual(self.balance(a["id"]), balance - total)
        # Each 200 reports the balance its own transaction produced.
        self.assertEqual(sorted(body["balance"] for body in committed),
                         sorted(balance - amount * k for k in range(1, len(committed) + 1)))
        busy = sum(status == 503 for status, _ in results)
        return len(committed), busy

    def test_i4_full_balance_withdrawn_by_60_threads(self):
        self.assertCommittedUpTo(*self.check_drain(1000, 1000, 60), limit=1)

    def test_i4_balance_over_k_withdrawn_by_60_threads(self):
        # B/k with k = 10: at most 10 of 60 can commit.
        self.assertCommittedUpTo(*self.check_drain(1000, 100, 60), limit=10)


class I5IntegerMoneyTest(MoneyTestCase):
    BAD_AMOUNTS = [
        b"1.5", b"1.0", b"0.30000000000000004", b"1e3", b"1E3", b"100e-2", b"-1", b"0",
        b"-0", b"0.0", b"1000000000001", str(2**63).encode(), str(2**64).encode(),
        b"9" * 400, b"1e400", b'"100"', b"true", b"false", b"null", b"[]", b"[100]",
        b"{}", b'{"v": 100}',
    ]
    INVALID_JSON = [b"NaN", b"Infinity", b"-Infinity"]

    def test_i5_malformed_amounts_on_deposit_and_withdraw(self):
        a = self.funded_account(1000, "amounts")
        auth = {"Authorization": f"Bearer {a['token']}"}
        for action, headers in (("deposit", {}), ("withdraw", auth)):
            path = f"/accounts/{a['id']}/{action}"
            for literal in self.BAD_AMOUNTS + self.INVALID_JSON:
                error = "invalid_json" if literal in self.INVALID_JSON else "invalid_amount"
                with self.subTest(action=action, amount=literal[:20]):
                    self.assertRejectedFree(
                        lambda: self.request("POST", path, raw=b'{"amount": ' + literal + b"}",
                                             headers=headers),
                        400, error)
            with self.subTest(action=action, amount="missing"):
                self.assertRejectedFree(
                    lambda: self.request("POST", path, raw=b"{}", headers=headers),
                    400, "invalid_amount")
            with self.subTest(action=action, amount="duplicate key"):
                self.assertRejectedFree(
                    lambda: self.request("POST", path, raw=b'{"amount": 1, "amount": 100}',
                                         headers=headers),
                    400, "invalid_json")
        self.assertEqual(self.balance(a["id"]), 1000)

    def test_i5_max_amount_and_stored_types(self):
        a = self.create_account("max")
        self.assertEqual(self.deposit(a["id"], MAX_AMOUNT),
                         (200, {"id": a["id"], "balance": MAX_AMOUNT}))
        self.assertEqual(self.withdraw(a["id"], MAX_AMOUNT, a["token"]),
                         (200, {"id": a["id"], "balance": 0}))
        self.assertEqual(self.query("SELECT DISTINCT typeof(amount) FROM external_moves"),
                         [("integer",)])
        self.assertEqual(self.query("SELECT DISTINCT typeof(balance) FROM accounts"),
                         [("integer",)])

    def test_i5_ledger_schema_rejects_bad_rows(self):
        a = self.create_account("ledger-schema")
        b = self.create_account("ledger-schema-b")
        conn = sqlite3.connect(self.db_path, timeout=5)
        conn.execute("PRAGMA foreign_keys = ON")
        bad_moves = [
            (a["id"], "deposit", 0), (a["id"], "deposit", -1), (a["id"], "deposit", 1.5),
            (a["id"], "deposit", "ten"), (a["id"], "deposit", MAX_AMOUNT + 1),
            (a["id"], "refund", 1), (str(uuid.uuid4()), "deposit", 1),
        ]
        bad_transfers = [(a["id"], a["id"], 1), (a["id"], b["id"], 0), (a["id"], b["id"], 1.5),
                         (a["id"], str(uuid.uuid4()), 1)]
        try:
            for account_id, kind, amount in bad_moves:
                with self.subTest(move=(kind, amount)):
                    with self.assertRaises(sqlite3.IntegrityError):
                        conn.execute("INSERT INTO external_moves (id, account_id, kind, amount) "
                                     "VALUES (?, ?, ?, ?)",
                                     (str(uuid.uuid4()), account_id, kind, amount))
            for from_id, to_id, amount in bad_transfers:
                with self.subTest(transfer=(from_id == to_id, amount)):
                    with self.assertRaises(sqlite3.IntegrityError):
                        conn.execute("INSERT INTO transfers (id, from_id, to_id, amount) "
                                     "VALUES (?, ?, ?, ?)",
                                     (str(uuid.uuid4()), from_id, to_id, amount))
        finally:
            conn.close()


class I8OnlyOwnerDebitsTest(MoneyTestCase):
    def test_i8_bad_tokens_are_401_and_free(self):
        victim = self.funded_account(1000, "victim")
        thief = self.funded_account(1000, "thief")
        path = f"/accounts/{victim['id']}/withdraw"
        for headers in (
                {},
                {"Authorization": ""},
                {"Authorization": "Bearer"},
                {"Authorization": "Bearer "},
                {"Authorization": f"Bearer {thief['token']}"},
                {"Authorization": f"Basic {victim['token']}"},
                {"Authorization": victim["token"]},
                {"Authorization": f"Bearer {victim['token'][:-1]}"},
                {"Authorization": f"Bearer {victim['token']}x"},
                {"Authorization": f"Bearer  {victim['token']}"},
                {"Authorization": f"bearer {victim['token']}"},
                {"Authorization": f"BEARER {victim['token']}"},
                {"Authorization": f"Bearer\t{victim['token']}"},
                {"Authorization": f"Bearer {victim['token']}, x"},
                {"Authorization": f"Bearer {self.query('SELECT token_hash FROM accounts WHERE id = ?', (victim['id'],))[0][0]}"},
                {"Authorization": "Bearer " + "A" * 60_000},
                {"X-Token": victim["token"]}):
            with self.subTest(headers=str(headers)[:50]):
                self.assertRejectedFree(
                    lambda: self.request("POST", path, {"amount": 1}, headers=headers),
                    401, "unauthorized")
        self.assertEqual(self.balance(victim["id"]), 1000)

    def withdraw_raw(self, account_id, auth_values):
        """Withdraw 1 with the given Authorization header lines, sent raw
        (http.client cannot send a header twice)."""
        import socket
        body = b'{"amount": 1}'
        request = (f"POST /accounts/{account_id}/withdraw HTTP/1.1\r\nHost: x\r\n"
                   f"Content-Length: {len(body)}\r\n"
                   + "".join(f"Authorization: {v}\r\n" for v in auth_values)
                   + "\r\n").encode() + body
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=10) as sock:
            sock.sendall(request)
            data = b""
            while chunk := sock.recv(65536):
                data += chunk
        head, _, payload = data.partition(b"\r\n\r\n")
        return int(head.split(b" ", 2)[1]), json.loads(payload)

    def test_i8_repeated_authorization_header_is_400_before_404_and_401(self):
        # 1.2 ruling: two or more Authorization headers -> 400 invalid_request.
        a = self.funded_account(10, "dup-auth")
        good, bad = f"Bearer {a['token']}", "Bearer wrong"
        for account_id in (a["id"], str(uuid.uuid4())):
            for values in ([good, good], [good, bad], [bad, good], [good, good, good]):
                with self.subTest(known=account_id == a["id"], values=len(values)):
                    self.assertRejectedFree(lambda: self.withdraw_raw(account_id, values),
                                            400, "invalid_request")
        self.assertEqual(self.withdraw_raw(a["id"], [good]), (200, {"id": a["id"], "balance": 9}))

    def test_i8_own_token_works_and_is_never_returned(self):
        a = self.funded_account(10, "owner")
        status, body = self.withdraw(a["id"], 1, a["token"])
        self.assertEqual(status, 200)
        self.assertNotIn(a["token"], repr(body))

    def test_i8_unknown_id_with_bad_token_is_404(self):
        self.assertRejectedFree(
            lambda: self.withdraw(str(uuid.uuid4()), 1, "bad-token"), 404, "account_not_found")


class BalanceLimitTest(MoneyTestCase):
    def test_deposit_up_to_exactly_the_limit_then_422(self):
        a = self.create_account("rich")
        self.fill_to(a["id"], MAX_AMOUNT, MAX_BALANCE // MAX_AMOUNT - 1)
        self.assertEqual(self.deposit(a["id"], MAX_AMOUNT - 1)[1]["balance"], MAX_BALANCE - 1)
        self.assertRejectedFree(lambda: self.deposit(a["id"], 2), 422, "balance_limit")
        self.assertEqual(self.deposit(a["id"], 1), (200, {"id": a["id"], "balance": MAX_BALANCE}))
        for amount in (1, MAX_AMOUNT):
            with self.subTest(amount=amount):
                self.assertRejectedFree(lambda: self.deposit(a["id"], amount),
                                        422, "balance_limit")
        # Withdrawing from a full account still works.
        self.assertEqual(self.withdraw(a["id"], 1, a["token"])[0], 200)


class I10DurableTest(MoneyTestCase):
    def test_i10_balances_ledger_and_audit_survive_restart(self):
        a = self.funded_account(900, "durable")
        self.withdraw(a["id"], 400, a["token"])
        before = (self.snapshot(), self.request("GET", "/audit"))
        self.server.stop()
        self.server = ServerProcess(self.db_path).start()
        type(self).server = self.server
        self.assertEqual((self.snapshot(), self.request("GET", "/audit")), before)
        self.assertEqual(self.request("GET", "/accounts/" + a["id"])[1]["balance"], 500)


class I11NoWedgeTest(MoneyTestCase):
    def test_i11_concurrent_money_with_audit_sampled_mid_flight(self):
        accounts = [self.funded_account(10_000, f"load-{k}") for k in range(5)]
        stop = threading.Event()
        bad_samples, samples = [], [0]

        def sampler():
            while not stop.is_set():
                status, audit = self.request("GET", "/audit")
                samples[0] += 1
                if status != 200 or audit["conserved"] is not True or \
                        audit["total_balances"] != audit["total_deposits"] - audit["total_withdrawals"]:
                    bad_samples.append((status, audit))

        def operation(i):
            account = random.choice(accounts)
            start = time.monotonic()
            if i % 2:
                result = self.deposit(account["id"], random.randint(1, 500))
            else:
                result = self.withdraw(account["id"], random.randint(1, 500), account["token"])
            return result, time.monotonic() - start

        threads = [threading.Thread(target=sampler) for _ in range(3)]
        for thread in threads:
            thread.start()
        try:
            with ThreadPoolExecutor(max_workers=40) as pool:
                results = list(pool.map(operation, range(400)))
        finally:
            stop.set()
            for thread in threads:
                thread.join()
        for (status, body), elapsed in results:
            self.assertLess(elapsed, CLIENT_TIMEOUT_S, "I11: request hung")
            self.assertIn(status, (200, 409, 503), body)
        self.assertGreater(samples[0], 10, "audit sampler barely ran")
        self.assertEqual(bad_samples[:5], [], "I1: audit not conserved mid-flight")


class LockTimeoutTest(MoneyTestCase):
    """A lock held past busy_timeout gives 503 busy with no effect, never a hang."""

    def test_lock_timeout_is_503_busy_and_free(self):
        a = self.funded_account(500, "locked")
        holder = sqlite3.connect(self.db_path, timeout=0, isolation_level=None)
        try:
            holder.execute("BEGIN IMMEDIATE")
            for name, call in (("deposit", lambda: self.deposit(a["id"], 7)),
                               ("withdraw", lambda: self.withdraw(a["id"], 7, a["token"]))):
                with self.subTest(op=name):
                    before = self.snapshot()
                    start = time.monotonic()
                    self.assertEqual(call(), (503, {"error": "busy"}))
                    self.assertLess(time.monotonic() - start, CLIENT_TIMEOUT_S)
                    self.assertEqual(self.snapshot(), before)
            # Readers are not blocked by the writer (WAL).
            self.assertEqual(self.request("GET", "/audit")[0], 200)
        finally:
            holder.execute("ROLLBACK")
            holder.close()
        self.assertEqual(self.deposit(a["id"], 7), (200, {"id": a["id"], "balance": 507}))
