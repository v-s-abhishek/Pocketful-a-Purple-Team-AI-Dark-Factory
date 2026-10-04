"""Unit 1.3 gate attacks (Breaker, room 4c630aa4): the gaps a12 did not cover.

- Mixed storm: transfer cycles A->B->C->A plus deposits and withdrawals on the same accounts, with
  I1/I3/I7 read straight from SQLite (one read snapshot per sample) DURING the storm, and after it.
- 422 balance_limit racing 409 insufficient_funds on the same pair; every refused debit rolled back.
- Id spellings in from/to (uppercase, braces, urn:uuid:, no hyphens, whitespace, Unicode digits,
  JSON escapes) and from == to written two ways: never a 201 with a non-canonical id, never a
  self-transfer, never a 5xx, never an effect.
- Clients that disconnect (FIN or RST) right after the body, or mid-body: each transfer is either
  fully committed with its ledger row or absent, never half.
"""
import concurrent.futures as cf
import contextlib
import json
import random
import socket
import struct
import threading
import time
import uuid

from breaker_harness import MAX_AMOUNT, MAX_BALANCE, REQUEST_TIMEOUT, AttackCase

CRLF = bytes([13, 10])
BUSY = (503, "busy")

REPLAY_SQL = """
    SELECT a.id, a.balance,
      coalesce((SELECT sum(amount) FROM external_moves WHERE account_id = a.id AND kind = 'deposit'), 0)
    - coalesce((SELECT sum(amount) FROM external_moves WHERE account_id = a.id AND kind = 'withdrawal'), 0)
    + coalesce((SELECT sum(amount) FROM transfers WHERE to_id = a.id), 0)
    - coalesce((SELECT sum(amount) FROM transfers WHERE from_id = a.id), 0)
    FROM accounts a
"""


class GateCase(AttackCase):
    def setUp(self):
        self.need_route("POST", "/transfers", {})

    def check(self, r):
        self.assertTrue(r.status < 500 or (r.status, r.error) == BUSY, f"5xx / no response: {r}")
        return r

    def fire(self, fns, workers):
        barrier = threading.Barrier(min(workers, len(fns)))

        def run(fn):
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.wait(5)
            t0 = time.monotonic()
            out = fn()
            return out, time.monotonic() - t0

        with cf.ThreadPoolExecutor(workers) as ex:
            res = list(ex.map(run, fns))
        for _, dt in res:
            self.assertLess(dt, REQUEST_TIMEOUT, "I11: request exceeded 10s")
        return [o for o, _ in res]

    def db_sample(self):
        """One read transaction = one WAL snapshot: (negatives, I7 mismatches, I1 holds)."""
        with contextlib.closing(self.server.db()) as c:
            c.isolation_level = None
            c.execute("BEGIN")
            neg = c.execute("SELECT count(*) FROM accounts WHERE balance < 0").fetchone()[0]
            bad = [r for r in c.execute(REPLAY_SQL).fetchall() if r[1] != r[2]]
            bal, dep, wd = c.execute(
                "SELECT (SELECT coalesce(sum(balance),0) FROM accounts),"
                " (SELECT coalesce(sum(amount),0) FROM external_moves WHERE kind='deposit'),"
                " (SELECT coalesce(sum(amount),0) FROM external_moves WHERE kind='withdrawal')").fetchone()
            c.execute("COMMIT")
        return neg, bad, bal == dep - wd

    def transfer_rows(self, where="1=1", args=()):
        with contextlib.closing(self.server.db()) as c:
            return c.execute(f"SELECT id, from_id, to_id, amount FROM transfers WHERE {where}", args).fetchall()


class MixedStorm(GateCase):
    def test_cycles_plus_external_moves_checked_live(self):
        accts = [self.funded(100_000, f"st-{k}") for k in range(3)]
        ids = [a["id"] for a in accts]
        stop = threading.Event()
        samples, failures = [], []

        def sampler():
            while not stop.is_set():
                try:
                    neg, bad, i1 = self.db_sample()
                except Exception as exc:  # a locked read is not an invariant failure; record anyway
                    failures.append(f"sample error {exc!r}")
                    continue
                samples.append(1)
                if neg or bad or not i1:
                    failures.append((neg, bad[:3], i1))
                a = self.server.request("GET", "/audit")
                if a.status != 200 or a.json.get("conserved") is not True:
                    failures.append(("audit", a))

        th = threading.Thread(target=sampler)
        th.start()
        fns = []
        rnd = random.Random(1303)
        for i in range(600):
            k = i % 3
            src, dst = accts[k], accts[(k + 1) % 3]
            kind = rnd.choice("tttttdw")
            amt = rnd.randint(1, 9_000)
            if kind == "t":
                fns.append(lambda s=src, d=dst, a=amt: ("t", s["id"], d["id"], a,
                                                         self.server.transfer(s["id"], d["id"], a, s["token"])))
            elif kind == "d":
                fns.append(lambda s=src, a=amt: ("d", s["id"], None, a, self.server.deposit(s["id"], a)))
            else:
                fns.append(lambda s=src, a=amt: ("w", s["id"], None, a,
                                                 self.server.withdraw(s["id"], a, s["token"])))
        try:
            out = self.fire(fns, workers=80)
        finally:
            stop.set()
            th.join()
        for o in out:
            self.check(o[4])
            if o[0] == "t":
                self.assertIn((o[4].status, o[4].error), [(201, None), (409, "insufficient_funds"), BUSY], o)
        self.assertGreater(len(samples), 3, "sampler never ran during the storm")
        self.assertEqual(failures[:5], [], "I1/I3/I7 broken in a live snapshot")
        # exact expected balances from the client's view of what committed
        want = {i: 100_000 for i in ids}
        acked = {}
        for kind, s, d, a, r in out:
            if kind == "t" and r.status == 201:
                want[s] -= a
                want[d] += a
                acked[r.json["id"]] = (s, d, a)
            elif kind == "d" and r.status == 200:
                want[s] += a
            elif kind == "w" and r.status == 200:
                want[s] -= a
        self.assertEqual({i: self.server.balance(i) for i in ids}, want, "I2: balances != committed ops")
        have = {r[0]: tuple(r[1:]) for r in self.transfer_rows()}
        self.assertEqual(have, acked, "I4: ledger rows != 201s")


class LimitVsFunds(GateCase):
    def test_422_and_409_race_on_one_pair(self):
        for round_ in range(5):
            dst = self.funded(0, f"lf-dst{round_}")
            for _ in range(MAX_BALANCE // MAX_AMOUNT - 2):  # room for exactly 2 * MAX_AMOUNT
                self.assertEqual(self.server.deposit(dst["id"], MAX_AMOUNT).status, 200)
            src = self.funded(MAX_AMOUNT, f"lf-src{round_}")
            for _ in range(2):  # one deposit is capped at 10^12
                self.assertEqual(self.server.deposit(src["id"], MAX_AMOUNT).status, 200)
            before_dst = self.server.balance(dst["id"])
            fns = [lambda: ("t", self.server.transfer(src["id"], dst["id"], MAX_AMOUNT, src["token"]))
                   for _ in range(12)]
            fns += [lambda: ("w", self.server.withdraw(src["id"], MAX_AMOUNT, src["token"])) for _ in range(4)]
            random.shuffle(fns)
            out = self.fire(fns, workers=16)
            t_ok = sum(1 for k, r in out if k == "t" and r.status == 201)
            w_ok = sum(1 for k, r in out if k == "w" and r.status == 200)
            busy = self.busy_count([r for _, r in out])
            for k, r in out:
                self.check(r)
                allowed = [(201, None)] if k == "t" else [(200, None)]
                allowed += [(409, "insufficient_funds"), BUSY] + ([(422, "balance_limit")] if k == "t" else [])
                self.assertIn((r.status, r.error), allowed, (k, r))
            self.assertLessEqual(t_ok, 2, "credit above 10^15 cap")
            self.assertLessEqual(t_ok + w_ok, 3, "I4: debits beyond funds")
            # withdrawals never hit the cap, so every unit of funds is spent unless a 503 refused it
            self.assertCommitCount(t_ok + w_ok, busy, 3, "funds left unspent")
            self.assertEqual(self.server.balance(src["id"]), (3 - t_ok - w_ok) * MAX_AMOUNT,
                             "I2: a refused (409/422) debit stayed applied")
            self.assertEqual(self.server.balance(dst["id"]), before_dst + t_ok * MAX_AMOUNT)
            self.assertEqual(len(self.transfer_rows("from_id = ?", (src["id"],))), t_ok)

    def test_409_wins_over_422_when_both_apply(self):
        dst = self.funded(0, "both-dst")
        for _ in range(MAX_BALANCE // MAX_AMOUNT):
            self.assertEqual(self.server.deposit(dst["id"], MAX_AMOUNT).status, 200)
        src = self.funded(5, "both-src")
        self.assertRejectedFree(lambda: self.server.transfer(src["id"], dst["id"], 6, src["token"]),
                                409, "insufficient_funds")
        self.assertRejectedFree(lambda: self.server.transfer(src["id"], dst["id"], 5, src["token"]),
                                422, "balance_limit")


class IdSpellings(GateCase):
    def spellings(self, i):
        u = uuid.UUID(i)
        arabic = str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩")
        return [i.upper(), "{" + i + "}", "urn:uuid:" + i, u.hex, " " + i, i + " ", i + "\n", "\t" + i,
                i.translate(arabic), i.replace("-", "‐"), i + "\x00", i[:-1], i + "0",
                "../" + i, i + "' OR '1'='1", i.replace("a", "A", 1) if "a" in i else i.upper()]

    def test_noncanonical_ids_never_move_money(self):
        a, b = self.funded(1000, "sp-a"), self.funded(0, "sp-b")
        for bad in self.spellings(b["id"]):
            r = self.assertRejectedFree(
                lambda: self.server.transfer(a["id"], bad, 1, a["token"]), 404, "account_not_found")
        for bad in self.spellings(a["id"]):
            self.assertRejectedFree(
                lambda: self.server.transfer(bad, b["id"], 1, a["token"]), 404, "account_not_found")

    def test_from_equals_to_in_two_spellings(self):
        a = self.funded(1000, "self-a")
        for alt in self.spellings(a["id"]):
            for body in ({"from": a["id"], "to": alt, "amount": 1}, {"from": alt, "to": a["id"], "amount": 1}):
                r = self.server.request("POST", "/transfers", body, headers=self.server.auth(a["token"]))
                self.assertNotEqual(r.status, 201, f"self-transfer via {alt!r}: {r}")
                self.assertIn(r.status, (400, 404), (alt, r))
        self.assertEqual(self.transfer_rows(), [])
        self.assertEqual(self.server.balance(a["id"]), 1000)

    def test_same_nonexistent_id_twice_is_400_not_404(self):
        ghost = str(uuid.uuid4())
        a = self.funded(10, "gh-a")
        self.assertRejectedFree(lambda: self.server.request(
            "POST", "/transfers", {"from": ghost, "to": ghost, "amount": 1},
            headers=self.server.auth(a["token"])), 400, "invalid_request")

    def test_json_escaped_canonical_id_is_the_same_account(self):
        a, b = self.funded(10, "esc-a"), self.funded(0, "esc-b")
        esc = "".join(f"\\u{ord(ch):04x}" for ch in b["id"])
        raw = ('{"from": "%s", "to": "%s", "amount": 3}' % (a["id"], esc)).encode()
        r = self.server.request("POST", "/transfers", raw=raw, headers=self.server.auth(a["token"]))
        self.assertEqual(r.status, 201, r)
        self.assertEqual(r.json["to"], b["id"])
        self.assertEqual((self.server.balance(a["id"]), self.server.balance(b["id"])), (7, 3))
        # escaped self-transfer: decodes to an equal string, so it must be 400
        esc_a = "".join(f"\\u{ord(ch):04x}" for ch in a["id"])
        raw = ('{"from": "%s", "to": "%s", "amount": 1}' % (a["id"], esc_a)).encode()
        self.assertRejectedFree(lambda: self.server.request(
            "POST", "/transfers", raw=raw, headers=self.server.auth(a["token"])), 400, "invalid_request")

    def test_non_string_ids(self):
        a, b = self.funded(10, "ns-a"), self.funded(0, "ns-b")
        for v in (None, 1, 1.5, True, [b["id"]], {"id": b["id"]}, ""):
            self.assertRejectedFree(lambda: self.server.request(
                "POST", "/transfers", {"from": a["id"], "to": v, "amount": 1},
                headers=self.server.auth(a["token"])), *((400, "invalid_request") if v != "" else (404, None)))


class Disconnects(GateCase):
    def send_and_drop(self, body, token, mode):
        data = json.dumps(body).encode()
        head = (b"POST /transfers HTTP/1.1" + CRLF + b"Host: x" + CRLF +
                b"Content-Type: application/json" + CRLF +
                b"Content-Length: " + str(len(data)).encode() + CRLF +
                b"Authorization: Bearer " + token.encode() + CRLF + CRLF)
        s = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
        try:
            if mode == "midbody":
                s.sendall(head + data[: len(data) // 2])
            else:
                s.sendall(head + data)
            if mode in ("rst", "midbody"):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            elif mode == "fin":
                s.shutdown(socket.SHUT_WR)
        finally:
            s.close()

    def settle(self):
        """Wait until in-flight handlers are done (the server keeps answering; nothing changes)."""
        last = None
        for _ in range(100):
            snap = self.server.snapshot()
            if snap == last:
                return
            last = snap
            time.sleep(0.2)

    def test_drop_after_body_is_all_or_nothing(self):
        for mode in ("rst", "fin", "close"):
            src = self.funded(10_000, f"dc-src-{mode}")
            dst = self.funded(0, f"dc-dst-{mode}")
            amounts = list(range(1, 61))
            with cf.ThreadPoolExecutor(30) as ex:
                list(ex.map(lambda a: self.send_and_drop(
                    {"from": src["id"], "to": dst["id"], "amount": a}, src["token"], mode), amounts))
            self.settle()
            rows = self.transfer_rows("from_id = ?", (src["id"],))
            moved = sum(r[3] for r in rows)
            self.assertEqual(len({r[3] for r in rows}), len(rows), f"{mode}: one request applied twice")
            self.assertEqual((self.server.balance(src["id"]), self.server.balance(dst["id"])),
                             (10_000 - moved, moved), f"{mode}: half-applied transfer")
            self.check_invariants()

    def test_drop_mid_body_never_commits(self):
        src, dst = self.funded(1000, "mb-src"), self.funded(0, "mb-dst")
        before = self.server.snapshot()
        with cf.ThreadPoolExecutor(20) as ex:
            list(ex.map(lambda a: self.send_and_drop(
                {"from": src["id"], "to": dst["id"], "amount": a}, src["token"], "midbody"), range(1, 41)))
        self.settle()
        self.assertEqual(self.server.snapshot(), before, "a truncated body moved money")


class UnreadBodyOn404(GateCase):
    """Found at the 1.3 gate (flaked a11.test_path_and_id_tricks): a 404 not_found is sent and the
    socket closed WITHOUT reading a declared, in-limit body. If the body arrives after the close,
    the server's TCP stack answers it with RST, which discards the 404 before the client reads it.
    Contract: every response is JSON; a valid <= 16 KiB body must get its response."""

    def setUp(self):
        pass  # not transfer-specific

    def split_send(self, path, body=b'{"amount": 1}', method="POST"):
        c = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
        try:
            c.sendall(method.encode() + b" " + path.encode() + b" HTTP/1.1" + CRLF + b"Host: x" + CRLF +
                      b"Content-Type: application/json" + CRLF +
                      b"Content-Length: " + str(len(body)).encode() + CRLF + CRLF)
            time.sleep(0.2)  # headers alone are a complete request head; the server answers now
            with contextlib.suppress(OSError):
                c.sendall(body)
            time.sleep(0.2)
            try:
                data = c.recv(65536)
            except OSError as exc:
                return f"no response ({type(exc).__name__})"
            return data.split(CRLF, 1)[0].decode("latin-1") or "no response (EOF)"
        finally:
            c.close()

    def test_404_with_late_body_still_answers(self):
        a = self.server.create_account("late-body")
        for path in ["/nope", f"/accounts/{a['id']}//deposit", "/transfers/x"]:
            got = [self.split_send(path) for _ in range(3)]
            self.assertEqual(got, ["HTTP/1.0 404 Not Found"] * 3, path)

    def test_control_known_route_with_late_body(self):
        a = self.server.create_account("late-body-ok")
        self.assertEqual(self.split_send(f"/accounts/{a['id']}/deposit"), "HTTP/1.0 200 OK")

    def test_any_response_with_unread_body_still_answers(self):
        """Architect ruling on R1.3-A: drain a valid unread body before ANY response, not just 404."""
        a = self.server.create_account("late-body-any")
        i = a["id"]
        cases = [("GET", "/health", "HTTP/1.0 200 OK"), ("GET", "/audit", "HTTP/1.0 200 OK"),
                 ("GET", f"/accounts/{i}", "HTTP/1.0 200 OK"),
                 ("GET", "/transfers", "HTTP/1.0 404 Not Found"),        # wrong method, known path
                 ("DELETE", f"/accounts/{i}", "HTTP/1.0 404 Not Found"),
                 ("PUT", "/accounts", "HTTP/1.0 404 Not Found")]
        for method, path, want in cases:
            got = [self.split_send(path, method=method) for _ in range(3)]
            self.assertEqual(got, [want] * 3, f"{method} {path}")

    def test_unserved_http_version_with_late_body_still_answers(self):
        """R1.3-A follow-up: the R1.1-G version 400 is sent from handle_one_request, before
        _dispatch, after parse_request has read the headers, so the Content-Length is known."""
        for version in ("HTTP/2.0", "HTTP/0.9", "HTTP/1.2"):
            c = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
            try:
                body = b'{"owner": "x"}'
                c.sendall(b"POST /accounts " + version.encode() + CRLF + b"Host: x" + CRLF +
                          b"Content-Length: " + str(len(body)).encode() + CRLF + CRLF)
                time.sleep(0.2)
                with contextlib.suppress(OSError):
                    c.sendall(body)
                time.sleep(0.2)
                try:
                    got = c.recv(65536).split(CRLF, 1)[0].decode("latin-1") or "no response (EOF)"
                except OSError as exc:
                    got = f"no response ({type(exc).__name__})"
            finally:
                c.close()
            self.assertEqual(got, "HTTP/1.0 400 Bad Request", version)
