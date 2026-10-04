"""Unit 4.1: account history. D4.1-D4.3 (endpoint, items, keyset order on
one ledger sequence), D4.8 (startup line), D4.9 (stage-3 databases),
D4.10 (query and cursor parsing); invariants I22, I23, I24."""

import base64
import os
import random
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor

from harness import STAGE_DIR, ServerProcess, ServerTestCase

if STAGE_DIR not in sys.path:
    sys.path.insert(0, STAGE_DIR)

from app import db  # noqa: E402

CREDIT_TYPES = {"deposit", "transfer_in"}
DEBIT_TYPES = {"withdrawal", "transfer_out"}
ITEM_KEYS = {"id", "type", "amount", "counterparty", "created_at"}


def auth(token):
    return {"Authorization": f"Bearer {token}"}


class HistoryCase(ServerTestCase):
    def history(self, account_id, token, query=""):
        path = f"/accounts/{account_id}/transactions" + (f"?{query}" if query else "")
        return self.request("GET", path, headers=auth(token) if token else None)

    def page_all(self, account, limit, pause=0.0):
        """Every item, following next_cursor to the end."""
        items, query = [], f"limit={limit}"
        while True:
            status, body = self.history(account["id"], account["token"], query)
            self.assertEqual(status, 200, body)
            self.assertEqual(set(body), {"items", "next_cursor"})
            self.assertLessEqual(len(body["items"]), limit)
            items.extend(body["items"])
            if body["next_cursor"] is None:
                return items
            self.assertEqual(len(body["items"]), limit, "a short page that is not the last")
            query = f"limit={limit}&cursor={body['next_cursor']}"
            time.sleep(pause)

    def ledger_ids(self, account_id):
        """{row id: seq} of every ledger row touching the account, straight
        from the source tables (not from the ledger_accounts index)."""
        rows = self.query(
            "SELECT e.id, l.seq FROM external_moves e"
            " LEFT JOIN ledger l ON l.source = 'external_moves' AND l.row_id = e.id"
            " WHERE e.account_id = ?"
            " UNION ALL"
            " SELECT t.id, l.seq FROM transfers t"
            " LEFT JOIN ledger l ON l.source = 'transfers' AND l.row_id = t.id"
            " WHERE ? IN (t.from_id, t.to_id)", (account_id, account_id))
        ids = dict(rows)
        self.assertEqual(len(ids), len(rows), "a row id appears twice")
        self.assertNotIn(None, ids.values(), "a ledger row has no sequence")
        return ids

    def assertCompleteHistory(self, account, items):
        """I22 for one account: every ledger row touching it exactly once,
        newest first by sequence, and the items add up to its balance."""
        ids = self.ledger_ids(account["id"])
        got = [item["id"] for item in items]
        self.assertEqual(len(got), len(set(got)), "an item was served twice")
        self.assertEqual(set(got), set(ids), "history is not the account's ledger")
        seqs = [ids[i] for i in got]
        self.assertEqual(seqs, sorted(seqs, reverse=True), "not newest first by sequence")
        net = 0
        for item in items:
            self.assertEqual(set(item), ITEM_KEYS, item)
            self.assertIs(type(item["amount"]), int)
            self.assertGreater(item["amount"], 0)
            if item["type"] in ("deposit", "withdrawal"):
                self.assertIsNone(item["counterparty"])
            else:
                self.assertIn(item["type"], ("transfer_in", "transfer_out"))
                self.assertNotEqual(item["counterparty"], account["id"])
            net += item["amount"] if item["type"] in CREDIT_TYPES else -item["amount"]
        status, fetched = self.request("GET", f"/accounts/{account['id']}")
        self.assertEqual(net, fetched["balance"], "I22: credits - debits != balance")


class CompleteHistoryTest(HistoryCase):
    """I22: a random workload, then every account paged with several limits."""

    def test_random_workload_pages_to_exactly_the_ledger(self):
        rnd = random.Random(4122)
        accounts = [self.create_account(f"h{n}") for n in range(5)]
        for account in accounts:
            self.assertEqual(self.deposit(account["id"], 1000)[0], 200)

        def op(_):
            a, b = rnd.sample(accounts, 2)
            kind = rnd.choice(("deposit", "withdraw", "transfer", "transfer"))
            amount = rnd.randint(1, 120)
            if kind == "deposit":
                return self.deposit(a["id"], amount)[0]
            if kind == "withdraw":
                return self.withdraw(a["id"], amount, a["token"])[0]
            return self.transfer(a["id"], b["id"], amount, a["token"])[0]

        with ThreadPoolExecutor(8) as pool:
            statuses = list(pool.map(op, range(240)))
        self.assertEqual(set(statuses) - {200, 201, 409}, set(), statuses)
        for account in accounts:
            for limit in (1, 3, 7, 20, 100):
                with self.subTest(account=account["owner"], limit=limit):
                    self.assertCompleteHistory(account, self.page_all(account, limit))
        self.assertMoneyInvariants()

    def test_item_shapes(self):
        a, b = self.create_account("shape-a"), self.create_account("shape-b")
        self.deposit(a["id"], 50)
        _, moved = self.transfer(a["id"], b["id"], 20, a["token"])
        self.withdraw(a["id"], 5, a["token"])
        status, page = self.history(a["id"], a["token"])
        self.assertEqual(status, 200)
        self.assertIsNone(page["next_cursor"])
        self.assertEqual([(i["type"], i["amount"], i["counterparty"]) for i in page["items"]],
                         [("withdrawal", 5, None), ("transfer_out", 20, b["id"]),
                          ("deposit", 50, None)])
        self.assertEqual(page["items"][1]["id"], moved["id"], "a transfer item's id is the transfer id")
        _, other = self.history(b["id"], b["token"])
        self.assertEqual([(i["id"], i["type"], i["counterparty"]) for i in other["items"]],
                         [(moved["id"], "transfer_in", a["id"])])

    def test_empty_history_and_default_limit(self):
        empty = self.create_account("empty")
        self.assertEqual(self.history(empty["id"], empty["token"]),
                         (200, {"items": [], "next_cursor": None}))
        many = self.create_account("many")
        for _ in range(21):
            self.deposit(many["id"], 1)
        status, page = self.history(many["id"], many["token"])
        self.assertEqual((status, len(page["items"])), (200, 20), "default limit is 20")
        self.assertIsNotNone(page["next_cursor"])
        status, page = self.history(many["id"], many["token"], "limit=20")
        status, last = self.history(many["id"], many["token"], f"cursor={page['next_cursor']}")
        self.assertEqual((status, len(last["items"]), last["next_cursor"]), (200, 1, None))

    def test_a_page_ending_exactly_at_the_last_item_has_no_cursor(self):
        account = self.create_account("exact")
        for _ in range(4):
            self.deposit(account["id"], 1)
        status, page = self.history(account["id"], account["token"], "limit=4")
        self.assertEqual((len(page["items"]), page["next_cursor"]), (4, None))


class SequenceTest(HistoryCase):
    """D4.3: one strictly increasing sequence over both ledger tables,
    assigned inside the write transaction; append-only."""

    def test_every_ledger_row_has_one_sequence_in_commit_order(self):
        a, b = self.create_account("seq-a"), self.create_account("seq-b")
        self.deposit(a["id"], 100)
        expected = []
        for n in range(30):
            if n % 3 == 0:
                expected.append(("transfers", self.transfer(a["id"], b["id"], 1, a["token"])[1]["id"]))
            elif n % 3 == 1:
                self.deposit(b["id"], 1)
            else:
                self.withdraw(b["id"], 1, b["token"])
        ledger = self.query("SELECT seq, source, row_id FROM ledger ORDER BY seq")
        self.assertEqual(len(ledger), self.query(
            "SELECT (SELECT count(*) FROM external_moves) + (SELECT count(*) FROM transfers)")[0][0])
        self.assertEqual(len({(s, r) for _, s, r in ledger}), len(ledger))
        # Sequential requests: sequence order is request order.
        transfer_seqs = [seq for seq, source, row in ledger if source == "transfers"]
        self.assertEqual([row for _, source, row in ledger if source == "transfers"],
                         [row for _, row in expected])
        self.assertEqual(transfer_seqs, sorted(transfer_seqs))
        index = self.query("SELECT account_id, seq FROM ledger_accounts")
        self.assertEqual(len(index), self.query(
            "SELECT (SELECT count(*) FROM external_moves) + 2 * (SELECT count(*) FROM transfers)")[0][0])

    def test_rejections_take_no_sequence(self):
        a, b = self.create_account("rej-a"), self.create_account("rej-b")
        before = self.query("SELECT count(*) FROM ledger")[0][0]
        self.assertEqual(self.withdraw(a["id"], 1, a["token"])[0], 409)
        self.assertEqual(self.transfer(a["id"], b["id"], 1, a["token"])[0], 409)
        self.assertEqual(self.query("SELECT count(*) FROM ledger")[0][0], before)

    def test_ledger_is_append_only(self):
        account = self.create_account("append")
        self.deposit(account["id"], 1)
        conn = db.connect(self.db_path)
        try:
            for sql in ("UPDATE ledger SET seq = seq + 1000", "DELETE FROM ledger",
                        "UPDATE ledger_accounts SET seq = seq + 1000", "DELETE FROM ledger_accounts"):
                with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                    with db.write_transaction(conn):
                        conn.execute(sql)
        finally:
            conn.close()


class StablePagesTest(HistoryCase):
    """I23: paging slowly while writes to the account continue never repeats
    or skips an item that existed when the first page was read."""

    def test_paging_during_a_write_storm(self):
        hot, other = self.create_account("hot"), self.create_account("other")
        self.fill_to(hot["id"], 10, 60)
        stop = threading.Event()
        writes = [0]

        def storm():
            rnd = random.Random(23)
            while not stop.is_set():
                pick = rnd.random()
                if pick < 0.4:
                    result = self.deposit(hot["id"], 3)
                elif pick < 0.7:
                    result = self.transfer(hot["id"], other["id"], 2, hot["token"])
                else:
                    result = self.withdraw(hot["id"], 1, hot["token"])
                writes[0] += result[0] in (200, 201)

        writers = [threading.Thread(target=storm, daemon=True) for _ in range(6)]
        for thread in writers:
            thread.start()
        time.sleep(0.3)
        existing = self.ledger_ids(hot["id"])  # all of these exist before page 1
        try:
            items = self.page_all(hot, 7, pause=0.05)
        finally:
            stop.set()
            for thread in writers:
                thread.join(10)
        self.assertGreater(writes[0], 50, "the storm did not write while paging")
        got = [item["id"] for item in items]
        self.assertEqual(len(got), len(set(got)), "I23: an item was served twice")
        self.assertEqual(set(existing) - set(got), set(), "I23: an existing item was skipped")
        seqs = self.ledger_ids(hot["id"])
        self.assertEqual([seqs[i] for i in got], sorted((seqs[i] for i in got), reverse=True))
        # Pages after the first only reach back in time: nothing newer than
        # page 1's newest item appears.
        self.assertEqual(max(seqs[i] for i in got), seqs[got[0]])
        self.assertCompleteHistory(hot, self.page_all(hot, 100))


class PrivateHistoryTest(HistoryCase):
    """I24 and the D4.1 order: 400 -> 404 -> 401; no error leaks an item."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.a = cls.server.request("POST", "/accounts", {"owner": "private-a"})[1]
        cls.b = cls.server.request("POST", "/accounts", {"owner": "private-b"})[1]
        cls.server.request("POST", f"/accounts/{cls.a['id']}/deposit", {"amount": 7})

    def call(self, account_id, headers, query=""):
        path = f"/accounts/{account_id}/transactions" + (f"?{query}" if query else "")
        return self.request("GET", path, headers=headers)

    def test_token_matrix(self):
        a, b = self.a, self.b
        missing = str(uuid.uuid4())
        cases = {
            "own token": (a["id"], auth(a["token"]), "", 200),
            "no token": (a["id"], {}, "", 401),
            "wrong token": (a["id"], auth("x" * 43), "", 401),
            "other account's token": (a["id"], auth(b["token"]), "", 401),
            "lowercase scheme": (a["id"], {"Authorization": f"bearer {a['token']}"}, "", 401),
            "Basic scheme": (a["id"], {"Authorization": f"Basic {a['token']}"}, "", 401),
            "empty bearer": (a["id"], {"Authorization": "Bearer "}, "", 401),
            "unknown account": (missing, auth(a["token"]), "", 404),
            "unknown account, no token": (missing, {}, "", 404),
            "malformed id": ("not-a-uuid", auth(a["token"]), "", 404),
            "uppercase id": (a["id"].upper(), auth(a["token"]), "", 404),
            "SQL in id": ("' OR '1'='1", auth(a["token"]), "", 404),
            "bad limit beats 404": (missing, {}, "limit=0", 400),
            "bad limit beats 401": (a["id"], {}, "limit=101", 400),
            "bad cursor beats 401": (a["id"], auth(b["token"]), "cursor=AAAA", 400),
        }
        for name, (account_id, headers, query, expected) in cases.items():
            with self.subTest(case=name):
                status, body = self.call(account_id.replace("'", "%27").replace(" ", "%20"),
                                         headers, query)
                self.assertEqual(status, expected, body)
                if expected == 200:
                    self.assertEqual(len(body["items"]), 1)
                else:
                    self.assertEqual(set(body), {"error"}, f"an error leaked more: {body}")

    def test_two_authorization_headers_are_400(self):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        try:
            conn.putrequest("GET", f"/accounts/{self.a['id']}/transactions")
            conn.putheader("Authorization", f"Bearer {self.a['token']}")
            conn.putheader("Authorization", f"Bearer {self.a['token']}")
            conn.endheaders()
            resp = conn.getresponse()
            self.assertEqual((resp.status, resp.read()), (400, b'{"error":"invalid_request"}'))
        finally:
            conn.close()

    def test_only_get_is_routed(self):
        for method in ("POST", "PUT", "DELETE"):
            with self.subTest(method=method):
                status, body = self.request(method, f"/accounts/{self.a['id']}/transactions",
                                            headers=auth(self.a["token"]))
                self.assertEqual((status, body), (404, {"error": "not_found"}))


class QueryParsingTest(HistoryCase):
    """D4.10: query and cursor rules. Every rejection is 400 invalid_request."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.a = cls.server.request("POST", "/accounts", {"owner": "query-a"})[1]
        cls.b = cls.server.request("POST", "/accounts", {"owner": "query-b"})[1]
        for account in (cls.a, cls.b):
            for amount in range(1, 6):
                cls.server.request("POST", f"/accounts/{account['id']}/deposit", {"amount": amount})

    def get(self, query, account=None):
        account = account or self.a
        return self.request("GET", f"/accounts/{account['id']}/transactions?{query}",
                            headers=auth(account["token"]))

    def cursor(self, account=None):
        status, page = self.get("limit=2", account)
        self.assertEqual(status, 200)
        return page["next_cursor"]

    def test_limit_matrix(self):
        bad = ["limit=0", "limit=101", "limit=-1", "limit=%2B5", "limit=+5", "limit=05",
               "limit=1.5", "limit=1e1", "limit=%EF%BC%91%EF%BC%90", "limit=", "limit",
               "limit=1&limit=2", "limit=%201", "limit=1%20", "limit=0x10", "limit=1000",
               "limit=99999999999999999999", "limit=%00", "limit=1%00", "limit=%D9%A3"]
        for query in bad:
            with self.subTest(query=query):
                self.assertEqual(self.get(query), (400, {"error": "invalid_request"}))
        for limit in (1, 9, 10, 99, 100):
            with self.subTest(limit=limit):
                status, page = self.get(f"limit={limit}")
                self.assertEqual((status, len(page["items"])), (200, min(limit, 5)))

    def test_param_rules(self):
        bad = ["x=1", "limit=2&x=1", "LIMIT=2", "Limit=2", "cursor=", "limit=2&",
               "&limit=2", "limit=2&&cursor=x", "=2", "limit=2;cursor=x", "offset=1",
               "limit[]=2"]
        for query in bad:
            with self.subTest(query=query):
                self.assertEqual(self.get(query), (400, {"error": "invalid_request"}))
        # Decoded once: a percent-encoded name is that name.
        status, page = self.get("l%69mit=2")
        self.assertEqual((status, len(page["items"])), (200, 2))
        # A "?" with nothing after it is no query.
        status, page = self.get("")
        self.assertEqual((status, len(page["items"])), (200, 5))

    def test_cursor_matrix(self):
        good = self.cursor()
        raw = base64.urlsafe_b64decode(good + "=" * (-len(good) % 4))
        flipped = bytearray(raw)
        flipped[5] ^= 0x01  # the sequence, under the MAC
        forged_seq = base64.urlsafe_b64encode(bytes(flipped)).rstrip(b"=").decode()
        flipped = bytearray(raw)
        flipped[-1] ^= 0x01  # the MAC itself
        forged_mac = base64.urlsafe_b64encode(bytes(flipped)).rstrip(b"=").decode()
        version = base64.urlsafe_b64encode(b"\x02" + raw[1:]).rstrip(b"=").decode()
        bad = {
            "truncated": good[:-1],
            "truncated by half": good[:len(good) // 2],
            "extended": good + "A",
            "padded": good + "=",
            "forged sequence": forged_seq,
            "forged MAC": forged_mac,
            "other version": version,
            "other account's cursor": self.cursor(self.b),
            "not base64": "!!!!",
            "standard base64 alphabet": good.replace("-", "+").replace("_", "/") + "+/",
            "SQL metacharacters": "1%27%20OR%20%271%27%3D%271",
            "SQL in cursor": "1;DROP%20TABLE%20ledger",
            "a bare number": "3",
            "over 256 characters": "A" * 257,
            "unicode": "%C3%A9" * 10,
        }
        for name, cursor in bad.items():
            with self.subTest(case=name):
                self.assertEqual(self.get(f"cursor={cursor}"), (400, {"error": "invalid_request"}))
        self.assertEqual(self.get(f"cursor={good}&cursor={good}"),
                         (400, {"error": "invalid_request"}))
        self.assertEqual(len(self.query("SELECT * FROM ledger")) > 0, True)

    def test_cursor_replay_and_limit_change(self):
        cursor = self.cursor()
        first = self.get(f"cursor={cursor}&limit=2")
        self.assertEqual(first[0], 200)
        self.assertEqual(self.get(f"limit=2&cursor={cursor}"), first, "a replayed cursor differs")
        status, rest = self.get(f"cursor={cursor}&limit=100")
        self.assertEqual((status, len(rest["items"]), rest["next_cursor"]), (200, 3, None))
        self.assertEqual(rest["items"][:2], first[1]["items"])

    def test_cursor_is_url_safe_and_short(self):
        cursor = self.cursor()
        self.assertRegex(cursor, r"^[A-Za-z0-9_-]+$")
        self.assertLessEqual(len(cursor), 256)


class StartupLineTest(unittest.TestCase):
    """D4.8: one stderr line at startup says whether tune_malloc applied."""

    def test_tune_malloc_reports(self):
        tmp = tempfile.mkdtemp(prefix="pocketful-d48-")
        self.addCleanup(shutil.rmtree, tmp, True)
        server = ServerProcess(os.path.join(tmp, "wallet.db")).start()
        try:
            first = server.stderr().splitlines()[0]
        finally:
            server.stop()
        if sys.platform.startswith("linux"):
            self.assertEqual(first, "tune_malloc: applied (M_MMAP_THRESHOLD=131072, M_ARENA_MAX=2)")
        else:
            self.assertEqual(first, f"tune_malloc: skipped (platform {sys.platform}, not Linux)")


# The stage-3 schema: the four tables of stage 3, which stage 4 keeps as they
# are (copied-suite rule). Written out, not taken from app.db, so the test
# seeds what a stage-3 build actually wrote.
STAGE3_SCHEMA = """
CREATE TABLE accounts (
    id          TEXT    PRIMARY KEY CHECK (length(id) = 36),
    owner       TEXT    NOT NULL CHECK (length(owner) BETWEEN 1 AND 64
                                        AND instr(owner, char(0)) = 0),
    balance     INTEGER NOT NULL DEFAULT 0
                        CHECK (balance >= 0 AND balance <= 1000000000000000),
    token_hash  TEXT    NOT NULL CHECK (length(token_hash) = 64),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;
CREATE TABLE external_moves (
    id          TEXT    PRIMARY KEY CHECK (length(id) = 36),
    account_id  TEXT    NOT NULL REFERENCES accounts(id),
    kind        TEXT    NOT NULL CHECK (kind IN ('deposit', 'withdrawal')),
    amount      INTEGER NOT NULL CHECK (amount BETWEEN 1 AND 1000000000000),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;
CREATE INDEX external_moves_account ON external_moves (account_id);
CREATE TABLE transfers (
    id          TEXT    PRIMARY KEY CHECK (length(id) = 36),
    from_id     TEXT    NOT NULL REFERENCES accounts(id),
    to_id       TEXT    NOT NULL REFERENCES accounts(id),
    amount      INTEGER NOT NULL CHECK (amount > 0 AND amount <= 1000000000000),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (from_id <> to_id)
) STRICT;
CREATE INDEX transfers_from ON transfers (from_id);
CREATE INDEX transfers_to ON transfers (to_id);
CREATE TABLE idempotency_keys (
    account_id  TEXT    NOT NULL REFERENCES accounts(id),
    scope       TEXT    NOT NULL CHECK (scope IN ('debit', 'deposit')),
    key         TEXT    NOT NULL CHECK (length(key) BETWEEN 1 AND 255),
    fingerprint TEXT    NOT NULL,
    status      INTEGER NOT NULL CHECK (status BETWEEN 200 AND 299),
    response    TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (account_id, scope, key)
) STRICT;
"""


class Stage3DatabaseTest(HistoryCase):
    """D4.9: stage 4 starts on a database a stage-3 build wrote, with ledger
    rows and no sequence. Each row gets one, once, in created_at order
    (ties: external_moves first, then rowid), and I22 holds on it."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="pocketful-d49-")
        cls.db_path = os.path.join(cls.tmpdir, "wallet.db")
        cls.accounts, cls.expected_order = cls.seed(cls.db_path)
        cls.server = ServerProcess(cls.db_path).start()

    @staticmethod
    def seed(path):
        """Three accounts and a ledger with created_at ties across and
        within the two tables. Returns the accounts (with tokens) and the
        row ids in the D4.9 order."""
        from app.tokens import hash_token, new_token
        conn = sqlite3.connect(path, isolation_level=None)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(STAGE3_SCHEMA)
        accounts = [{"id": str(uuid.uuid4()), "token": new_token(), "owner": f"s3-{n}"}
                    for n in range(3)]
        a, b, c = (x["id"] for x in accounts)
        t1, t2, t3 = "2026-10-03T10:00:00.000Z", "2026-10-03T10:00:01.000Z", "2026-10-03T10:00:02.000Z"
        # (table, id, columns..., created_at), inserted in this rowid order.
        moves = [("e", a, "deposit", 100, t2), ("e", b, "deposit", 50, t1),
                 ("t", a, b, 30, t2), ("t", b, c, 10, t2), ("e", a, "deposit", 5, t2),
                 ("e", c, "withdrawal", 4, t3), ("t", b, a, 1, t1)]
        balances = {a: 100 - 30 + 5 + 1, b: 50 + 30 - 10 - 1, c: 10 - 4}
        conn.execute("BEGIN")
        for x in accounts:
            conn.execute("INSERT INTO accounts (id, owner, balance, token_hash) VALUES (?, ?, ?, ?)",
                         (x["id"], x["owner"], balances[x["id"]], hash_token(x["token"])))
        rows = []
        for n, move in enumerate(moves):
            row_id = str(uuid.uuid4())
            if move[0] == "e":
                conn.execute("INSERT INTO external_moves (id, account_id, kind, amount, created_at)"
                             " VALUES (?, ?, ?, ?, ?)", (row_id, *move[1:]))
            else:
                conn.execute("INSERT INTO transfers (id, from_id, to_id, amount, created_at)"
                             " VALUES (?, ?, ?, ?, ?)", (row_id, *move[1:]))
            rows.append((move[-1], 0 if move[0] == "e" else 1, n, row_id))
        conn.execute("COMMIT")
        conn.close()
        return accounts, [row_id for *_, row_id in sorted(rows)]

    def test_backfill_order_history_and_restart(self):
        ledger = self.query("SELECT row_id FROM ledger ORDER BY seq")
        self.assertEqual([r for (r,) in ledger], self.expected_order, "D4.9 order")
        self.assertIn("ledger: sequenced 7 rows written before stage 4 (D4.9)", self.server.stderr())
        for account in self.accounts:
            with self.subTest(account=account["owner"]):
                for limit in (1, 2, 100):
                    self.assertCompleteHistory(account, self.page_all(account, limit))
        self.assertMoneyInvariants()
        # A second start changes nothing; later rows get higher sequences.
        before = self.query("SELECT seq, source, row_id FROM ledger ORDER BY seq")
        index = self.query("SELECT account_id, seq FROM ledger_accounts ORDER BY 1, 2")
        self.server.stop()
        self.server = ServerProcess(self.db_path).start()
        type(self).server = self.server
        self.assertNotIn("ledger: sequenced", self.server.stderr())
        self.assertEqual(self.query("SELECT seq, source, row_id FROM ledger ORDER BY seq"), before)
        self.assertEqual(self.query("SELECT account_id, seq FROM ledger_accounts ORDER BY 1, 2"), index)
        a = self.accounts[0]
        self.assertEqual(self.deposit(a["id"], 2)[0], 200)
        newest = self.query("SELECT max(seq) FROM ledger")[0][0]
        self.assertGreater(newest, max(seq for seq, *_ in before))
        status, page = self.history(a["id"], a["token"], "limit=1")
        self.assertEqual(page["items"][0]["amount"], 2)
        self.assertCompleteHistory(a, self.page_all(a, 3))


class ReadPathTest(HistoryCase):
    """D3.2 for history: the read takes no writer lock, so a writer holding
    the SQLite write lock does not delay it."""

    def test_history_answers_while_the_write_lock_is_held(self):
        account = self.create_account("reader")
        self.deposit(account["id"], 9)
        holder = sqlite3.connect(self.db_path, isolation_level=None, timeout=5)
        try:
            holder.execute("BEGIN IMMEDIATE")
            holder.execute("UPDATE accounts SET balance = balance WHERE id = ?", (account["id"],))
            start = time.monotonic()
            status, page = self.history(account["id"], account["token"])
            elapsed = time.monotonic() - start
            holder.execute("ROLLBACK")
        finally:
            holder.close()
        self.assertEqual((status, len(page["items"])), (200, 1))
        self.assertLess(elapsed, 1.0, "the history read waited for the writer")


if __name__ == "__main__":
    unittest.main()
