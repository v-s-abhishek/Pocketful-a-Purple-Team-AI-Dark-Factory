"""HTTP-level checks for unit 2.1: Idempotency-Key on deposit, withdraw and
transfer (D2.1-D2.9, I12-I16). I17 is the stage-1 tests/ and attacks/ run
unchanged against this stage. Every test ends with the money sweep."""

import json
import random
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from harness import CLIENT_TIMEOUT_S, ServerProcess
from test_money import MAX_AMOUNT, MAX_BALANCE, MoneyTestCase


def raw_request(port, method, path, body, header_lines):
    """Send one request byte for byte. `header_lines` are raw bytes or str
    lines without CRLF. Returns (status, {lower-name: [values]}, body bytes)."""
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    head = f"{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(data)}\r\n".encode()
    for line in header_lines:
        head += (line if isinstance(line, bytes) else line.encode("latin-1")) + b"\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=CLIENT_TIMEOUT_S) as sock:
        sock.sendall(head + b"\r\n" + data)
        reply = b""
        while chunk := sock.recv(65536):
            reply += chunk
    head, _, payload = reply.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.decode("latin-1").partition(":")
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return int(lines[0].split(b" ", 2)[1]), headers, payload


class KeyedTestCase(MoneyTestCase):
    def keyed(self, method, path, body, key, token=None, extra=()):
        lines = [f"Idempotency-Key: {key}"] if key is not None else []
        if token is not None:
            lines.append(f"Authorization: Bearer {token}")
        return raw_request(self.server.port, method, path, body, lines + list(extra))

    def k_transfer(self, src, dst, amount, key, token=None):
        return self.keyed("POST", "/transfers",
                          {"from": src["id"], "to": dst["id"], "amount": amount},
                          key, src["token"] if token is None else token)

    def k_withdraw(self, acct, amount, key, token=None):
        return self.keyed("POST", f"/accounts/{acct['id']}/withdraw", {"amount": amount},
                          key, acct["token"] if token is None else token)

    def k_deposit(self, acct, amount, key):
        return self.keyed("POST", f"/accounts/{acct['id']}/deposit", {"amount": amount}, key)

    def replayed(self, headers):
        return headers.get("idempotent-replayed") == ["true"]

    def key_rows(self, account_id=None):
        if account_id is None:
            return self.query("SELECT account_id, scope, key, status FROM idempotency_keys")
        return self.query("SELECT scope, key, status FROM idempotency_keys WHERE account_id = ?",
                          (account_id,))

    def assertRejectedNoEffect(self, call, status, error):
        """I6 + D2.5: rejected, nothing changed, no key row recorded."""
        before = self.snapshot()
        got_status, headers, body = call()
        self.assertEqual((got_status, json.loads(body)), (status, {"error": error}))
        self.assertFalse(self.replayed(headers))
        self.assertEqual(self.snapshot(), before, "rejection changed the DB")


class I12AtMostOnceTest(KeyedTestCase):
    def fire(self, call, n):
        barrier = threading.Barrier(n)

        def run(_):
            barrier.wait(10)
            start = time.monotonic()
            result = call()
            self.assertLess(time.monotonic() - start, CLIENT_TIMEOUT_S, "I11: hung")
            return result

        with ThreadPoolExecutor(max_workers=n) as pool:
            return list(pool.map(run, range(n)))

    def check_once(self, results, success):
        ok = [r for r in results if r[0] == success]
        others = [(s, b) for s, _, b in results if s != success]
        self.assertEqual([b for s, b in others if (s, json.loads(b)) != (503, {"error": "busy"})],
                         [], "only the 2xx or 503 busy are allowed")
        self.assertGreater(len(ok), 0)
        self.assertEqual(len({body for _, _, body in ok}), 1, "I12: 2xx bodies differ")
        self.assertEqual(sum(not self.replayed(h) for _, h, _ in ok), 1,
                         "I12: exactly one original response")
        return json.loads(ok[0][2])

    def test_i12_60_concurrent_identical_transfers(self):
        a = self.funded_account(1000, "once-a")
        b = self.funded_account(0, "once-b")
        results = self.fire(lambda: self.k_transfer(a, b, 300, "pay-1"), 60)
        body = self.check_once(results, 201)
        self.assertEqual(self.query("SELECT id, amount FROM transfers WHERE from_id = ?",
                                    (a["id"],)), [(body["id"], 300)])
        self.assertEqual((self.balance(a["id"]), self.balance(b["id"])), (700, 300))
        self.assertEqual(self.key_rows(a["id"]), [("debit", "pay-1", 201)])

    def test_i12_concurrent_identical_withdrawals_and_deposits(self):
        a = self.funded_account(1000, "once-w")
        body = self.check_once(self.fire(lambda: self.k_withdraw(a, 400, "w-1"), 50), 200)
        self.assertEqual(body, {"id": a["id"], "balance": 600})
        body = self.check_once(self.fire(lambda: self.k_deposit(a, 5, "d-1"), 50), 200)
        self.assertEqual(body, {"id": a["id"], "balance": 605})
        self.assertEqual(self.balance(a["id"]), 605)
        self.assertEqual(self.query("SELECT kind, amount FROM external_moves WHERE account_id = ?"
                                    " ORDER BY created_at", (a["id"],)),
                         [("deposit", 1000), ("withdrawal", 400), ("deposit", 5)])

    def test_i12_sequential_repeats(self):
        a = self.funded_account(100, "seq-a")
        b = self.funded_account(0, "seq-b")
        first = self.k_transfer(a, b, 10, "seq")
        self.assertEqual(first[0], 201)
        self.assertFalse(self.replayed(first[1]))
        for _ in range(5):
            again = self.k_transfer(a, b, 10, "seq")
            self.assertEqual((again[0], again[2]), (201, first[2]))
            self.assertTrue(self.replayed(again[1]))
        self.assertEqual(self.balance(a["id"]), 90)


class I13FaithfulReplayTest(KeyedTestCase):
    def test_i13_replay_is_byte_identical_with_no_effect(self):
        a = self.funded_account(500, "rep-a")
        b = self.funded_account(0, "rep-b")
        first = self.k_transfer(a, b, 50, "t")
        before = self.snapshot()
        again = self.k_transfer(a, b, 50, "t")
        self.assertEqual(self.snapshot(), before, "I13: replay changed the DB")
        self.assertEqual((again[0], again[2]), (first[0], first[2]))
        self.assertEqual(again[1]["idempotent-replayed"], ["true"])
        self.assertEqual(again[1]["content-type"], ["application/json"])
        self.assertNotIn("idempotent-replayed", first[1])

    def test_i13_withdraw_replay_returns_balance_as_of_original(self):
        a = self.funded_account(500, "asof")
        first = self.k_withdraw(a, 100, "w")
        self.assertEqual(json.loads(first[2]), {"id": a["id"], "balance": 400})
        self.assertEqual(self.deposit(a["id"], 1000)[0], 200)
        self.assertEqual(self.k_withdraw(a, 100, "w")[2], first[2])
        self.assertEqual(self.balance(a["id"]), 1400)

    def test_i13_replay_after_source_drained_and_after_restart(self):
        a = self.funded_account(100, "drain-a")
        b = self.funded_account(0, "drain-b")
        first = self.k_transfer(a, b, 100, "all")
        self.assertEqual(first[0], 201)
        # Drained to 0: the lookup comes before the money rules, so no 409.
        self.assertEqual(self.k_transfer(a, b, 100, "all")[2], first[2])
        before = self.snapshot()
        self.server.stop()
        self.server = ServerProcess(self.db_path).start()
        type(self).server = self.server
        after = self.k_transfer(a, b, 100, "all")
        self.assertEqual((after[0], after[2]), (201, first[2]))
        self.assertTrue(self.replayed(after[1]))
        self.assertEqual(self.snapshot(), before)

    def test_d2_4_same_validated_request_replays(self):
        a = self.funded_account(500, "fp-a")
        b = self.funded_account(0, "fp-b")
        first = self.k_transfer(a, b, 7, "fp")
        port = self.server.port
        spaced = b'{ "amount" : 7 , "to" : "%s" , "from" : "%s" }' % (
            b["id"].encode(), a["id"].encode())
        again = raw_request(port, "POST", "/transfers", spaced,
                            ["Idempotency-Key: \t fp \t",
                             f"Authorization:   Bearer {a['token']}  "])
        self.assertEqual((again[0], again[2]), (201, first[2]))
        self.assertTrue(self.replayed(again[1]))
        # Header name is case-insensitive.
        lower = raw_request(port, "POST", "/transfers",
                            {"from": a["id"], "to": b["id"], "amount": 7},
                            ["idempotency-key: fp", f"Authorization: Bearer {a['token']}"])
        self.assertEqual(lower[2], first[2])
        self.assertEqual(self.balance(a["id"]), 493)

    def test_d2_7_replay_still_needs_the_token(self):
        a = self.funded_account(500, "tok-a")
        b = self.funded_account(0, "tok-b")
        self.assertEqual(self.k_transfer(a, b, 5, "k")[0], 201)
        self.assertRejectedNoEffect(lambda: self.k_transfer(a, b, 5, "k", token=b["token"]),
                                    401, "unauthorized")
        self.assertRejectedNoEffect(lambda: self.k_withdraw(a, 5, "w-none", token="x"),
                                    401, "unauthorized")


class I14MismatchTest(KeyedTestCase):
    def test_i14_matrix(self):
        a = self.funded_account(1000, "mm-a")
        b = self.funded_account(0, "mm-b")
        c = self.funded_account(0, "mm-c")
        self.assertEqual(self.k_transfer(a, b, 10, "K")[0], 201)
        for name, call in [
            ("amount", lambda: self.k_transfer(a, b, 11, "K")),
            ("to", lambda: self.k_transfer(a, c, 10, "K")),
            ("withdraw, same debit namespace", lambda: self.k_withdraw(a, 10, "K")),
        ]:
            with self.subTest(name):
                self.assertRejectedNoEffect(call, 422, "idempotency_key_reused")
        self.assertEqual(self.k_withdraw(a, 3, "W")[0], 200)
        self.assertRejectedNoEffect(lambda: self.k_transfer(a, b, 3, "W"),
                                    422, "idempotency_key_reused")
        self.assertEqual(self.k_deposit(b, 4, "D")[0], 200)
        self.assertRejectedNoEffect(lambda: self.k_deposit(b, 5, "D"),
                                    422, "idempotency_key_reused")

    def test_q2_a_namespaces_and_accounts_are_independent(self):
        a = self.funded_account(1000, "ns-a")
        b = self.funded_account(1000, "ns-b")
        # A deposit key never blocks, replays or mismatches a debit key.
        dep = self.k_deposit(a, 1, "same")
        self.assertEqual(dep[0], 200)
        tr = self.k_transfer(a, b, 50, "same")
        self.assertEqual(tr[0], 201)
        self.assertFalse(self.replayed(tr[1]))
        # The same key on another account is unrelated.
        other = self.k_transfer(b, a, 50, "same")
        self.assertEqual(other[0], 201)
        self.assertFalse(self.replayed(other[1]))
        self.assertEqual(sorted(self.key_rows(a["id"])),
                         [("debit", "same", 201), ("deposit", "same", 200)])
        self.assertEqual(self.key_rows(b["id"]), [("debit", "same", 201)])
        self.assertEqual((self.balance(a["id"]), self.balance(b["id"])), (1001, 1000))

    def test_i14_mismatch_racing_one_commits(self):
        a = self.funded_account(10**6, "race-a")
        b = self.funded_account(0, "race-b")
        amounts = [1 + i % 7 for i in range(56)]
        with ThreadPoolExecutor(max_workers=56) as pool:
            results = list(pool.map(lambda amt: self.k_transfer(a, b, amt, "R"), amounts))
        rows = self.query("SELECT amount FROM transfers WHERE from_id = ?", (a["id"],))
        self.assertEqual(len(rows), 1, "I12: same key, different amounts, more than one move")
        won = rows[0][0]
        for (status, headers, body), amt in zip(results, amounts):
            payload = json.loads(body)
            if status == 201:
                self.assertEqual(amt, won)
            elif status == 422:
                self.assertEqual(payload, {"error": "idempotency_key_reused"})
                self.assertNotEqual(amt, won)
            else:
                self.assertEqual((status, payload), (503, {"error": "busy"}))
        self.assertEqual(self.balance(a["id"]), 10**6 - won)


class I15RejectionsConsumeNothingTest(KeyedTestCase):
    def test_i15_409_then_fund_then_retry(self):
        a = self.funded_account(10, "fund-a")
        b = self.funded_account(0, "fund-b")
        self.assertRejectedNoEffect(lambda: self.k_transfer(a, b, 50, "later"),
                                    409, "insufficient_funds")
        self.assertEqual(self.deposit(a["id"], 40)[0], 200)
        first = self.k_transfer(a, b, 50, "later")
        self.assertEqual(first[0], 201)
        self.assertFalse(self.replayed(first[1]))
        again = self.k_transfer(a, b, 50, "later")
        self.assertEqual(again[2], first[2])
        self.assertTrue(self.replayed(again[1]))
        self.assertEqual((self.balance(a["id"]), self.balance(b["id"])), (0, 50))

    def test_i15_every_rejection_leaves_the_key_free(self):
        a = self.funded_account(100, "free-a")
        b = self.create_account("free-b")
        self.fill_to(b["id"], MAX_AMOUNT, MAX_BALANCE // MAX_AMOUNT)
        self.assertEqual(self.withdraw(b["id"], 5, b["token"])[0], 200)
        missing = {"id": str(uuid.uuid4()), "token": "t"}
        cases = [
            (lambda: self.k_transfer(a, b, 0, "k"), 400, "invalid_amount"),
            (lambda: self.k_transfer(a, missing, 5, "k"), 404, "account_not_found"),
            (lambda: self.k_transfer(a, b, 5, "k", token=b["token"]), 401, "unauthorized"),
            (lambda: self.k_transfer(a, b, 6, "k"), 422, "balance_limit"),
            (lambda: self.k_withdraw(a, 101, "k"), 409, "insufficient_funds"),
            (lambda: self.k_deposit(b, 6, "k"), 422, "balance_limit"),
            (lambda: self.k_deposit(missing, 6, "k"), 404, "account_not_found"),
        ]
        for call, status, error in cases:
            with self.subTest(error=error, status=status):
                self.assertRejectedNoEffect(call, status, error)
        for acct in (a, b, missing):
            self.assertEqual(self.key_rows(acct["id"]), [])
        self.assertEqual(self.k_transfer(a, b, 5, "k")[0], 201)
        self.assertEqual(self.k_deposit(a, 1, "k")[0], 200)

    def test_d2_2_key_format(self):
        a = self.funded_account(100, "fmt-a")
        good = "".join(chr(c) for c in range(0x21, 0x7F))
        bad = [b"Idempotency-Key:", b"Idempotency-Key:   ", b"Idempotency-Key: " + b"k" * 256,
               b"Idempotency-Key: a b", b"Idempotency-Key: a\tb", b"Idempotency-Key: a\x01b",
               b"Idempotency-Key: a\x7fb", "Idempotency-Key: café".encode("utf-8"),
               b"Idempotency-Key: \xff", b"Idempotency-Key: x\r\n continued"]
        for line in bad:
            with self.subTest(line=line):
                self.assertRejectedNoEffect(
                    lambda: raw_request(self.server.port, "POST",
                                        f"/accounts/{a['id']}/deposit", {"amount": 1}, [line]),
                    400, "invalid_request")
        self.assertRejectedNoEffect(
            lambda: raw_request(self.server.port, "POST", f"/accounts/{a['id']}/deposit",
                                {"amount": 1}, ["Idempotency-Key: a", "Idempotency-Key: a"]),
            400, "invalid_request")
        for key in ["k" * 255, good]:
            with self.subTest(key=key):
                self.assertEqual(self.k_deposit(a, 1, key)[0], 200)
        # The 400 comes with the request-shape checks: before 404 and 401.
        self.assertRejectedNoEffect(
            lambda: raw_request(self.server.port, "POST", "/transfers",
                                {"from": a["id"], "to": str(uuid.uuid4()), "amount": 1},
                                ["Idempotency-Key: a b"]),
            400, "invalid_request")


class I16TimeoutAndRetryTest(KeyedTestCase):
    def test_i16_disconnect_right_after_body_then_retry(self):
        a = self.funded_account(10**4, "dc-a")
        b = self.funded_account(0, "dc-b")
        for i in range(30):
            key = f"dc-{i}"
            data = json.dumps({"from": a["id"], "to": b["id"], "amount": 3}).encode()
            req = (f"POST /transfers HTTP/1.1\r\nHost: x\r\nContent-Length: {len(data)}\r\n"
                   f"Idempotency-Key: {key}\r\nAuthorization: Bearer {a['token']}\r\n\r\n"
                   ).encode() + data
            with socket.create_connection(("127.0.0.1", self.server.port)) as sock:
                sock.sendall(req)
            while True:
                status, _, body = self.k_transfer(a, b, 3, key)
                if status != 503:
                    break
            self.assertEqual(status, 201, body)
        self.assertEqual(self.query("SELECT count(*), sum(amount) FROM transfers"
                                    " WHERE from_id = ?", (a["id"],)), [(30, 90)])
        self.assertEqual(self.balance(a["id"]), 10**4 - 90)

    def test_i16_hard_kill_mid_burst_then_retry_every_key(self):
        accounts = [self.funded_account(10**6, f"kk-{k}") for k in range(4)]
        sent, lock, stop = [], threading.Lock(), threading.Event()

        def worker(w):
            n = 0
            while not stop.is_set():
                src, dst = random.sample(accounts, 2)
                key, amount = f"w{w}-{n}", random.randint(1, 100)
                n += 1
                with lock:
                    sent.append((src, dst, amount, key))
                try:
                    self.k_transfer(src, dst, amount, key)
                except Exception:  # the server is being killed
                    return

        threads = [threading.Thread(target=worker, args=(w,)) for w in range(12)]
        for thread in threads:
            thread.start()
        time.sleep(1.5)
        self.server.kill()
        stop.set()
        for thread in threads:
            thread.join(15)
        self.server = ServerProcess(self.db_path).start()
        type(self).server = self.server
        self.assertGreater(len(sent), 0)
        for src, dst, amount, key in sent:
            while True:
                status, _, body = self.k_transfer(src, dst, amount, key)
                if status != 503:
                    break
            self.assertEqual(status, 201, body)
            moved = self.query("SELECT count(*) FROM transfers WHERE id = ?",
                               (json.loads(body)["id"],))
            self.assertEqual(moved, [(1,)])
        ids = tuple(x["id"] for x in accounts)
        self.assertEqual(self.query("SELECT count(*) FROM transfers WHERE from_id IN (?, ?, ?, ?)",
                                    ids), [(len(sent),)], "I16: a key moved money more than once")
        self.assertEqual(self.query("SELECT count(*) FROM idempotency_keys"
                                    " WHERE account_id IN (?, ?, ?, ?)", ids), [(len(sent),)])
        self.assertEqual(sum(self.balance(x["id"]) for x in accounts), 4 * 10**6)


class KeylessUnchangedTest(KeyedTestCase):
    def test_i17_keyless_records_no_key_row_and_never_replays(self):
        a = self.funded_account(100, "nokey-a")
        b = self.funded_account(0, "nokey-b")
        first = self.k_transfer(a, b, 10, None)
        second = self.k_transfer(a, b, 10, None)
        self.assertEqual((first[0], second[0]), (201, 201))
        self.assertNotEqual(first[2], second[2])
        self.assertFalse(self.replayed(second[1]))
        self.assertEqual(self.key_rows(a["id"]), [])
        self.assertEqual(self.balance(a["id"]), 80)
