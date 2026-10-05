"""Unit 4.1 attacks: transaction history (PLAN.md Stage 4, D4.1-D4.3, D4.8-D4.10, I22-I24).
Written from the contract before the build. Every class skips until
`GET /accounts/{id}/transactions` exists (it answers something other than the generic
404 `not_found`).

Spec in brief: GET /accounts/{id}/transactions?limit=<1..100, default 20>&cursor=<opaque> ->
200 {"items": [...], "next_cursor": str|null}. Bearer token of {id} required. Order: 400 (bad
limit/cursor, unknown or repeated param, empty value, parse error) -> 404 account_not_found ->
401. Items {"id","type","amount","counterparty","created_at"} (+ "reverses" on reversal items,
unit 4.2), newest first by one strictly increasing sequence across transfers and
external_moves, keyset pagination. Query decoded once with parse_qsl(strict_parsing=True,
keep_blank_values=True). limit: ASCII digits, no sign, no leading zero, 1..100. cursor:
URL-safe base64 without padding, <= 256 chars, HMAC-protected, bound to the account; forged,
truncated or other-account -> 400. A bare `?` is no query. D4.8: one startup stderr line says
whether tune_malloc() was applied or skipped. D4.9: a stage-3 DB gets sequences once at
startup, ordered by created_at, then external_moves before transfers, then rowid;
deterministic, idempotent, and later writes always sort newer.
"""
import concurrent.futures as cf
import contextlib
import hashlib
import json
import os
import random
import re
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid

import breaker_harness
from breaker_harness import REQUEST_TIMEOUT, STAGE_DIR, AttackCase, Server

# The accepted stage-3 tree, when this suite runs inside the repo (not in the image).
STAGE3_DIR = os.path.join(os.path.dirname(STAGE_DIR), "stage-3")

HIST = "/accounts/{}/transactions"
ITEM_KEYS = {"id", "type", "amount", "counterparty", "created_at"}
CREDITS = {"deposit", "transfer_in", "reversal_in"}
DEBITS = {"withdrawal", "transfer_out", "reversal_out"}
CURSOR_RE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


# -- helpers -------------------------------------------------------------------------------

def hist(s, acct, token=None, query=None, headers=None, timeout=REQUEST_TIMEOUT):
    path = HIST.format(acct) + ("" if query is None else "?" + query)
    h = dict(headers or {})
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    return s.request("GET", path, headers=h, timeout=timeout)


def ledger(s, acct):
    """Every ledger row touching `acct`, as the history item it must appear as."""
    with contextlib.closing(s.db()) as c:
        rows = {}
        for i, kind, amt, at in c.execute(
                "SELECT id, kind, amount, created_at FROM external_moves WHERE account_id = ?", (acct,)):
            rows[i] = {"id": i, "type": kind, "amount": amt, "counterparty": None, "created_at": at}
        for i, frm, to, amt, at in c.execute(
                "SELECT id, from_id, to_id, amount, created_at FROM transfers WHERE from_id = ? OR to_id = ?",
                (acct, acct)):
            out = frm == acct
            rows[i] = {"id": i, "type": "transfer_out" if out else "transfer_in", "amount": amt,
                       "counterparty": to if out else frm, "created_at": at}
        return rows


def flip(cursor, pos):
    """Change one cursor character so that its high bits change (content really differs)."""
    ch = cursor[pos]
    new = B64[B64.index(ch) ^ 32] if ch in B64 else "A"
    return cursor[:pos] + new + cursor[pos + 1:]


class HistoryMixin:
    """Paging and checking helpers, shared by every class here."""

    def need_history(self, s=None):
        s = s or self.server
        r = hist(s, uuid.uuid4())
        if r.status == 404 and r.error == "not_found":
            self.skipTest("GET /accounts/{id}/transactions not built yet")

    def page_all(self, s, acct, token, limit=None, pause=0.0, max_pages=5000):
        """Follow next_cursor to the end. Returns (items, pages)."""
        items, pages, cursor = [], [], None
        page_size = 20 if limit is None else limit
        for _ in range(max_pages):
            q = []
            if limit is not None:
                q.append(f"limit={limit}")
            if cursor is not None:
                q.append(f"cursor={cursor}")
            r = hist(s, acct, token, "&".join(q) if q else None)
            self.assertEqual(r.status, 200, r)
            self.assertIsInstance(r.json, dict, r)
            self.assertEqual(set(r.json), {"items", "next_cursor"}, r)
            page = r.json["items"]
            self.assertIsInstance(page, list, r)
            self.assertLessEqual(len(page), page_size, f"page larger than limit {page_size}")
            items += page
            pages.append(page)
            cursor = r.json["next_cursor"]
            if cursor is None:
                return items, pages
            self.assertIsInstance(cursor, str, r)
            self.assertRegex(cursor, CURSOR_RE, "D4.10: cursor is unpadded URL-safe base64, <= 256 chars")
            self.assertEqual(len(page), page_size, "a non-final page is short")
            if pause:
                time.sleep(pause)
        self.fail(f"history did not end within {max_pages} pages (cursor loop?)")

    def check_item(self, item, want):
        self.assertIsInstance(item, dict)
        self.assertEqual(set(item), ITEM_KEYS, f"D4.2 item keys: {item}")
        self.assertIs(type(item["amount"]), int, item)
        self.assertGreater(item["amount"], 0, item)
        self.assertIsInstance(item["created_at"], str, item)
        self.assertEqual(item, want, "item differs from its ledger row")

    def check_history(self, s, acct, token, limit=None, balance=None):
        """I22: every ledger row exactly once, item == ledger row, sum == balance, newest first."""
        items, _ = self.page_all(s, acct, token, limit)
        ids = [i["id"] for i in items]
        self.assertEqual(len(ids), len(set(ids)), f"I22: duplicate item (limit={limit})")
        want = ledger(s, acct)
        self.assertEqual(set(ids), set(want), f"I22: history != ledger rows (limit={limit})")
        net = 0
        for item in items:
            self.check_item(item, want[item["id"]])
            net += item["amount"] if item["type"] in CREDITS else -item["amount"]
        bal = s.balance(acct) if balance is None else balance
        self.assertEqual(net, bal, f"I22: credits - debits != balance (limit={limit})")
        stamps = [i["created_at"] for i in items]
        self.assertEqual(stamps, sorted(stamps, reverse=True),
                         "newest first: created_at increases in a later page (writes are serialized)")
        return items

    def check_cross_order(self, histories):
        """One sequence across the ledger: a pair of transfers seen in two accounts' histories
        must be in the same relative order in both."""
        ranks = {a: {it["id"]: n for n, it in enumerate(items)} for a, items in histories.items()}
        accts = list(ranks)
        for x in range(len(accts)):
            for y in range(x + 1, len(accts)):
                rx, ry = ranks[accts[x]], ranks[accts[y]]
                common = set(rx) & set(ry)
                self.assertEqual(sorted(common, key=rx.get), sorted(common, key=ry.get),
                                 "D4.3: two accounts disagree on the order of shared transfers")

    def assert_rejected_no_leak(self, r, status, error=None, secrets=()):
        self.assertEqual(r.status, status, r)
        self.assertIsInstance(r.json, dict, r)
        self.assertEqual(set(r.json), {"error"}, f"I24: a {status} must carry only an error: {r}")
        if error:
            self.assertEqual(r.error, error, r)
        for secret in secrets:
            self.assertNotIn(secret.encode(), r.raw, f"I24: {status} leaked {secret}")


class HistoryCase(HistoryMixin, AttackCase):
    def setUp(self):
        self.need_history()

    def account_with(self, n_rows, owner="hist"):
        """An account with exactly n_rows ledger rows (deposits of 1..n, sequential)."""
        a = self.server.create_account(owner)
        for k in range(n_rows):
            r = self.server.deposit(a["id"], k + 1)
            self.assertEqual(r.status, 200, r)
        return a


# -- D4.1 / D4.2 / D4.3: shape and order ----------------------------------------------------

class A18Shape(HistoryCase):

    def test_new_account_has_empty_history(self):
        a = self.server.create_account("empty")
        r = hist(self.server, a["id"], a["token"])
        self.assertEqual((r.status, r.json), (200, {"items": [], "next_cursor": None}))

    def test_every_type_shape_and_exact_reverse_of_commit_order(self):
        s = self.server
        a, b = s.create_account("a"), s.create_account("b")
        expect = []  # commit order (sequential, so it is the sequence order)

        def did(r, typ, amount, cp):
            self.assertIn(r.status, (200, 201), r)
            expect.append((typ, amount, cp))
        did(s.deposit(a["id"], 500), "deposit", 500, None)
        did(s.withdraw(a["id"], 120, a["token"]), "withdrawal", 120, None)
        did(s.transfer(a["id"], b["id"], 30, a["token"]), "transfer_out", 30, b["id"])
        s.deposit(b["id"], 7)  # B only: never in A's history
        did(s.transfer(b["id"], a["id"], 11, b["token"]), "transfer_in", 11, b["id"])
        self.assertEqual(s.transfer(a["id"], b["id"], 10**9, a["token"]).status, 409)  # no row
        did(s.deposit(a["id"], 1), "deposit", 1, None)
        items = self.check_history(s, a["id"], a["token"])
        self.assertEqual([(i["type"], i["amount"], i["counterparty"]) for i in items],
                         list(reversed(expect)), "D4.3: not newest first in commit order")
        self.assertNotIn("reverses", json.dumps(items), "4.1 has no reversal items")
        b_items = self.check_history(s, b["id"], b["token"])
        self.assertEqual([i["type"] for i in b_items], ["transfer_out", "deposit", "transfer_in"])

    def test_default_limit_is_20_and_limits_page_the_same_list(self):
        s = self.server
        a = self.account_with(45)
        r = hist(s, a["id"], a["token"])
        self.assertEqual(len(r.json["items"]), 20, "D4.1: default limit 20")
        self.assertIsNotNone(r.json["next_cursor"])
        full = self.check_history(s, a["id"], a["token"], limit=100)
        self.assertEqual([i["amount"] for i in full], list(range(45, 0, -1)))
        for limit in (1, 2, 7, 20, 44, 45, 46, None):
            items = self.check_history(s, a["id"], a["token"], limit=limit)
            self.assertEqual(items, full, f"limit={limit} pages a different list")

    def test_exactly_one_full_page_ends_cleanly(self):
        a = self.account_with(10)
        items, pages = self.page_all(self.server, a["id"], a["token"], limit=10)
        self.assertEqual(len(items), 10)
        self.assertIn(len(pages), (1, 2))
        if len(pages) == 2:
            self.assertEqual(pages[1], [], "a trailing page after an exact fit must be empty")

    def test_route_variants_are_not_history(self):
        s = self.server
        a = self.account_with(1)
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            r = s.request(method, HIST.format(a["id"]), raw=b"{}" if method != "DELETE" else None,
                          headers=s.auth(a["token"]))
            self.assert_rejected_no_leak(r, 404, "not_found")
        for path in (HIST.format(a["id"]) + "/", HIST.format(a["id"]) + "x",
                     HIST.format(a["id"]).replace("transactions", "Transactions"),
                     f"/accounts/{a['id']}//transactions"):
            r = s.request("GET", path, headers=s.auth(a["token"]))
            self.assertEqual(r.status, 404, (path, r))
            self.assertNotIn(b"items", r.raw, (path, r))

    def test_history_read_does_not_wait_for_the_writer_lock(self):
        """D3.2 + the 4.1 brief: the read takes no writer lock and is not blocked by a writer
        beyond WAL semantics. An outside process holds SQLite's write lock for 1.5 s."""
        s = self.server
        a = self.account_with(5)
        c = sqlite3.connect(s.db_path, timeout=10, isolation_level=None)
        try:
            c.execute("BEGIN IMMEDIATE")
            t0 = time.monotonic()
            r = hist(s, a["id"], a["token"])
            took = time.monotonic() - t0
            time.sleep(max(0.0, 1.5 - (time.monotonic() - t0)))
        finally:
            c.execute("ROLLBACK")
            c.close()
        self.assertEqual(r.status, 200, r)
        self.assertEqual(len(r.json["items"]), 5)
        self.assertLess(took, 1.0, f"history read blocked {took:.2f} s behind a writer")


# -- D4.10: query parsing -------------------------------------------------------------------

BAD_QUERIES = [
    # limit
    "limit=0", "limit=101", "limit=-1", "limit=%2B5", "limit=+5", "limit=05", "limit=00",
    "limit=1.5", "limit=1e1", "limit=1E1", "limit=0x10", "limit=1000", "limit=" + "9" * 40,
    "limit=%EF%BC%91%EF%BC%90",       # full-width 10
    "limit=%D9%A5",                   # Arabic-Indic 5 (int() accepts it)
    "limit=%C2%B2",                   # superscript 2 (isdigit() is true)
    "limit=%F0%9D%9F%93",             # mathematical bold 5
    "limit=5%20", "limit=%205", "limit=5%0A", "limit=5%00", "limit=%09%35", "limit=5_0",
    "limit=", "limit=true", "limit=null", "limit=[5]", "limit=5,6", "limit=-0",
    "limit=%FF", "limit=%", "limit=%2", "limit=%zz",
    # structure
    "limit=5&limit=5", "limit=5&limit=6", "cursor=", "limit=5&cursor=", "foo=1", "limit=5&foo=",
    "LIMIT=5", "Limit=5", "limit%20=5", "%256Cimit=5", "limit", "=5", "&", "&&", "limit=5&",
    "&limit=5", "limit=5;cursor=x", "limit=5&&cursor=x", "cursor", "limit=5=5", "a=1&b=2",
    "cursor=x&cursor=x", "%00=1", "limit[]=5", "limit.=5",
]
GOOD_QUERIES = {          # query -> items expected on the first page (account has 30 rows)
    None: 20, "": 20, "limit=1": 1, "limit=100": 30, "limit=99": 30, "limit=10": 10,
    "%6Cimit=5": 5,       # names are percent-decoded once (parse_qsl)
    "limit=%35": 5,       # so are values: "5"
    "limit=%31%30": 10,
}


class A18Query(HistoryCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        s = cls.server
        cls.a = s.create_account("q")
        for k in range(30):
            s.deposit(cls.a["id"], k + 1)
        cls.b = s.create_account("other")

    def test_bad_queries_are_400_invalid_request_without_items(self):
        s, a = self.server, self.a
        failures = []
        for q in BAD_QUERIES:
            r = hist(s, a["id"], a["token"], q)
            if not (r.status == 400 and r.json == {"error": "invalid_request"}):
                failures.append((q, r.status, r.raw[:120]))
        self.assertEqual(failures, [], "D4.10: these must be 400 invalid_request")

    def test_good_queries(self):
        s, a = self.server, self.a
        for q, n in GOOD_QUERIES.items():
            r = hist(s, a["id"], a["token"], q)
            self.assertEqual(r.status, 200, (q, r))
            self.assertEqual(len(r.json["items"]), n, q)

    def test_400_comes_before_404_and_401(self):
        s, a = self.server, self.a
        unknown = str(uuid.uuid4())
        for q in ("limit=0", "foo=1", "cursor=AAAA", "limit=5&limit=5"):
            for acct, tok in ((a["id"], None), (a["id"], "wrong"), (unknown, None),
                              (unknown, a["token"]), (self.b["id"], a["token"])):
                r = hist(s, acct, tok, q)
                self.assert_rejected_no_leak(r, 400, "invalid_request")

    def test_bare_question_mark_variants(self):
        """D4.10: a `?` with nothing after it is no query; anything after it is parsed."""
        s, a = self.server, self.a
        h = s.auth(a["token"])
        r = s.request("GET", HIST.format(a["id"]) + "?", headers=h)
        self.assertEqual((r.status, len(r.json["items"])), (200, 20), r)
        for tail in ("??", "?&", "?=", "?limit=5?", "?limit=5&?", "?%3F", "?limit%3D5"):
            r = s.request("GET", HIST.format(a["id"]) + tail, headers=h)
            self.assert_rejected_no_leak(r, 400, "invalid_request")

    def test_404_before_401(self):
        s = self.server
        for acct in (str(uuid.uuid4()), self.a["id"].upper(), self.a["id"] + "0", "x",
                     self.a["id"].replace("-", ""), "%2e%2e", "' OR '1'='1"):
            for tok in (None, "wrong", self.a["token"]):
                r = s.request("GET", HIST.format(acct.replace(" ", "%20")),
                              headers={} if tok is None else s.auth(tok))
                self.assertEqual(r.status, 404, (acct, tok, r))
                self.assertNotIn(b"items", r.raw)


# -- D4.10: cursors -------------------------------------------------------------------------

class A18Cursor(HistoryCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        s = cls.server
        cls.a, cls.b = s.create_account("ca"), s.create_account("cb")
        for k in range(30):
            s.deposit(cls.a["id"], k + 1)
            s.deposit(cls.b["id"], k + 1)

    def first_cursor(self, acct, limit=10):
        r = hist(self.server, acct["id"], acct["token"], f"limit={limit}")
        self.assertEqual(r.status, 200, r)
        self.assertIsNotNone(r.json["next_cursor"])
        return r.json["next_cursor"]

    def page(self, acct, cursor, limit=10, token=None):
        return hist(self.server, acct["id"], acct["token"] if token is None else token,
                    f"limit={limit}&cursor={cursor}")

    def test_cursor_replay_is_stable_across_new_writes(self):
        s, a = self.server, self.a
        c = self.first_cursor(a)
        p1 = self.page(a, c)
        p2 = self.page(a, c)
        self.assertEqual(p1.status, 200, p1)
        self.assertEqual(p1.json, p2.json, "replayed cursor gave a different page")
        self.assertEqual([i["amount"] for i in p1.json["items"]], list(range(20, 10, -1)))
        s.deposit(a["id"], 999)
        s.transfer(a["id"], self.b["id"], 1, a["token"])
        p3 = self.page(a, c)
        self.assertEqual(p3.json["items"], p1.json["items"],
                         "D4.3: rows committed after the cursor shifted an older page")

    def test_cursor_with_a_different_limit_continues_from_the_same_place(self):
        a = self.a
        c = self.first_cursor(a, limit=10)
        r = self.page(a, c, limit=3)
        self.assertEqual(r.status, 200, r)
        ten = self.page(a, c, limit=10).json["items"]
        self.assertEqual(r.json["items"], ten[:3])

    def test_forged_truncated_extended_and_padded_cursors(self):
        a = self.a
        c = self.first_cursor(a)
        bad = {flip(c, 0), flip(c, len(c) // 2), flip(c, len(c) - 1), c[:-1], c[1:], c[: len(c) // 2],
               c + "A", c + "AAAA", c + "%3D", c + "%3D%3D", c.swapcase() if c.swapcase() != c else c + "B",
               c[::-1], c + c, "A" * len(c), "A" * 257, "A" * 4000,
               c.replace("-", "%2B").replace("_", "%2F") if ("-" in c or "_" in c) else c + "%2B",
               c[:-2] + "%2E%2E", "%00" + c, c + "%00", c + "%20", "%20" + c}
        bad.discard(c)
        failures = []
        for x in sorted(bad):
            r = self.page(a, x)
            if not (r.status == 400 and r.json == {"error": "invalid_request"}):
                failures.append((x[:60], r.status, r.raw[:100]))
        self.assertEqual(failures, [], "D4.10: forged/truncated cursors must be 400")

    def test_every_single_character_change_is_rejected(self):
        """Integrity, not just format: change each position in turn (high bits flipped)."""
        a = self.a
        c = self.first_cursor(a)
        accepted = []
        for pos in range(len(c)):
            r = self.page(a, flip(c, pos))
            if r.status != 400:
                accepted.append((pos, r.status, r.raw[:80]))
        self.assertEqual(accepted, [], "D4.10: a modified cursor was accepted")

    def test_other_accounts_cursor_is_400(self):
        a, b = self.a, self.b
        cb = self.first_cursor(b)
        for tok in (a["token"], b["token"], "wrong"):
            r = self.page(a, cb, token=tok)
            self.assert_rejected_no_leak(r, 400, "invalid_request", secrets=[b["id"]])
        ca = self.first_cursor(a)
        half = len(ca) // 2
        for spliced in (ca[:half] + cb[half:], cb[:half] + ca[half:]):
            if spliced not in (ca, cb):
                r = self.page(a, spliced)
                self.assert_rejected_no_leak(r, 400, "invalid_request")

    def test_sql_metacharacters_in_cursor_change_nothing(self):
        s, a = self.server, self.a
        before = s.snapshot()
        for x in ("%27%20OR%201%3D1--", "1%3BDROP%20TABLE%20transfers", "%27", "%22", "0", "-1",
                  "9999999999999999999999", "AAAA%27--", "*", "%25", "NULL", "1%20UNION%20SELECT%201"):
            r = self.page(a, x)
            self.assert_rejected_no_leak(r, 400, "invalid_request")
        self.assertEqual(s.snapshot(), before)

    def test_cursor_is_not_a_bare_number_or_plain_json(self):
        """An unsigned cursor would decode to the sequence/rowid in plain text."""
        import base64
        c = self.first_cursor(self.a)
        raw = base64.urlsafe_b64decode(c + "=" * (-len(c) % 4))
        for n in range(0, 200):  # a forged "start below n" cursor built the obvious ways
            for forged in (str(n).encode(), json.dumps({"seq": n}).encode(),
                           json.dumps({"s": n, "a": self.a["id"]}).encode()):
                f = base64.urlsafe_b64encode(forged).decode().rstrip("=")
                if f == c:
                    continue
                r = self.page(self.a, f)
                self.assertEqual(r.status, 400, (forged, r))
            if n > 40:
                break
        self.assertGreater(len(raw), 8, "cursor too short to carry an HMAC")


class A18CursorSecret(HistoryMixin, unittest.TestCase):
    """D4.10: the HMAC key is per database. A cursor minted by a database with another key is
    400 even for the same account id and sequence; the key survives a restart."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.kill()
        self._tmp.cleanup()

    def start(self, name):
        s = Server(os.path.join(self._tmp.name, name)).start()
        self.servers.append(s)
        self.need_history(s)
        return s

    def keys(self, s):
        """Every BLOB/TEXT value in a small non-ledger table that looks like a secret."""
        with contextlib.closing(s.db()) as c:
            out = []
            for t in s.tables():
                if t in ("accounts", "external_moves", "transfers", "idempotency_keys",
                         "ledger", "ledger_accounts", "reversals"):
                    continue
                for row in c.execute(f'SELECT * FROM "{t}"'):
                    out += [v for v in row if isinstance(v, (bytes, str)) and len(v) >= 16]
            return out

    def test_cursor_from_a_database_with_another_secret_is_400(self):
        s1 = self.start("one.db")
        a = s1.create_account("sec")
        for k in range(30):
            s1.deposit(a["id"], k + 1)
        r = hist(s1, a["id"], a["token"], "limit=10")
        c = r.json["next_cursor"]
        want = hist(s1, a["id"], a["token"], f"limit=10&cursor={c}").json
        s1.kill()
        # same rows, same account id, same token -- only the secret differs
        copy = os.path.join(self._tmp.name, "two.db")
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(s1.db_path + suffix):
                shutil.copyfile(s1.db_path + suffix, copy + suffix)
        with contextlib.closing(sqlite3.connect(copy, isolation_level=None)) as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            tables = [t for (t,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            changed = 0
            for t in tables:
                if t in ("accounts", "external_moves", "transfers", "idempotency_keys",
                         "ledger", "ledger_accounts", "reversals"):
                    continue
                cols = [x[1] for x in db.execute(f'PRAGMA table_info("{t}")')]
                for rowid, *vals in db.execute(f'SELECT rowid, * FROM "{t}"').fetchall():
                    for col, v in zip(cols, vals):
                        if isinstance(v, bytes) and len(v) >= 16:
                            db.execute(f'UPDATE "{t}" SET "{col}" = ? WHERE rowid = ?',
                                       (os.urandom(len(v)), rowid))
                            changed += 1
            if not changed:
                self.skipTest("no per-database secret found in the DB to rotate")
        s2 = self.start("two.db")
        r = hist(s2, a["id"], a["token"], f"limit=10&cursor={c}")
        self.assert_rejected_no_leak(r, 400, "invalid_request")
        fresh = hist(s2, a["id"], a["token"], "limit=10").json["next_cursor"]
        self.assertNotEqual(fresh, c, "two secrets minted the same cursor")
        self.assertEqual(hist(s2, a["id"], a["token"], f"limit=10&cursor={fresh}").json["items"],
                         want["items"], "same rows, another key: the page must still match")
        # the original database still honours its own cursor after a restart (key persisted)
        s1.start()
        r = hist(s1, a["id"], a["token"], f"limit=10&cursor={c}")
        self.assertEqual((r.status, r.json), (200, want), "cursor died across a restart")
        r = hist(s1, a["id"], a["token"], f"limit=10&cursor={fresh}")
        self.assert_rejected_no_leak(r, 400, "invalid_request")

    def test_two_fresh_databases_get_different_secrets(self):
        s1, s2 = self.start("x.db"), self.start("y.db")
        k1, k2 = self.keys(s1), self.keys(s2)
        self.assertTrue(k1 and k2, "no per-database secret stored")
        self.assertFalse(set(k1) & set(k2), "two databases share a cursor secret")
        for s, ks in ((s1, k1), (s2, k2)):
            r = s.request("GET", "/audit")
            for k in ks:
                needle = k if isinstance(k, bytes) else k.encode()
                self.assertNotIn(needle, r.raw, "secret leaked by /audit")
                self.assertNotIn(needle.hex().encode(), r.raw, "secret leaked by /audit")


# -- I24: private history -------------------------------------------------------------------

class A18Privacy(HistoryCase):

    def test_token_matrix(self):
        s = self.server
        a, b = s.create_account("pa"), s.create_account("pb")
        s.deposit(a["id"], 1234)
        s.transfer(a["id"], b["id"], 17, a["token"])
        secrets = [a["token"], b["token"]]
        with contextlib.closing(s.db()) as c:
            secrets += [r[0] for r in c.execute("SELECT id FROM external_moves WHERE account_id = ?", (a["id"],))]
        tok = a["token"]
        variants = {
            "none": {}, "empty": {"Authorization": ""}, "bearer only": {"Authorization": "Bearer"},
            "bearer space": {"Authorization": "Bearer "}, "lowercase": {"Authorization": f"bearer {tok}"},
            "two spaces": {"Authorization": f"Bearer  {tok}"}, "basic": {"Authorization": f"Basic {tok}"},
            "other account": {"Authorization": f"Bearer {b['token']}"},
            "suffix": {"Authorization": f"Bearer {tok}x"}, "prefix": {"Authorization": f"Bearer x{tok}"},
            "truncated": {"Authorization": f"Bearer {tok[:-1]}"},
            "token as id": {"Authorization": f"Bearer {a['id']}"},
        }
        for name, h in variants.items():
            r = hist(s, a["id"], headers=h)
            self.assertEqual(r.status, 401, (name, r))
            self.assertEqual(set(r.json or {}), {"error"}, (name, r))
            for x in secrets:
                self.assertNotIn(x.encode(), r.raw, (name, "leaked"))
        # two Authorization headers: 400 (stage-1 rule) or 401, never items
        status, raw = s.raw_http(
            (f"GET {HIST.format(a['id'])} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {tok}\r\n"
             f"Authorization: Bearer {tok}\r\n\r\n").encode())
        self.assertIn(status, (400, 401), raw)
        self.assertNotIn(b"items", raw)
        # B sees the transfer in, never A's deposit
        bi = self.check_history(s, b["id"], b["token"])
        self.assertEqual([i["type"] for i in bi], ["transfer_in"])
        # A's token on B, B's token on A
        self.assertEqual(hist(s, b["id"], a["token"]).status, 401)
        self.assertEqual(hist(s, a["id"], b["token"]).status, 401)
        # whitespace around the value is trimmed, as for withdraw (stage-1 rule)
        r = hist(s, a["id"], headers={"Authorization": f"Bearer {tok} \t"})
        self.assertEqual(r.status, 200, r)

    def test_unknown_account_404_leaks_nothing(self):
        s = self.server
        a = s.create_account("x")
        r = hist(s, uuid.uuid4(), a["token"])
        self.assert_rejected_no_leak(r, 404, "account_not_found", secrets=[a["id"]])


# -- I22: random workload, several limits ---------------------------------------------------

class A18RandomWorkload(HistoryCase):

    def test_random_workload_complete_history_at_every_limit(self):
        s = self.server
        rnd = random.Random(4101)
        accts = [s.create_account(f"w{i}") for i in range(6)]
        for a in accts:
            s.deposit(a["id"], 10_000)

        def op(n):
            a, b = rnd.sample(accts, 2)
            kind = n % 4
            if kind == 0:
                return s.deposit(a["id"], rnd.randint(1, 500))
            if kind == 1:
                return s.withdraw(a["id"], rnd.randint(1, 3000), a["token"])
            return s.transfer(a["id"], b["id"], rnd.randint(1, 4000), a["token"])

        with cf.ThreadPoolExecutor(16) as pool:
            statuses = [r.status for r in pool.map(op, range(600))]
        self.assertTrue(set(statuses) <= {200, 201, 409}, set(statuses))
        histories = {}
        for a in accts:
            first = None
            for limit in (1, 3, None, 37, 100):
                items = self.check_history(s, a["id"], a["token"], limit=limit)
                if first is None:
                    first = items
                self.assertEqual(items, first, f"limit={limit} gave a different list")
            histories[a["id"]] = first
        self.check_cross_order(histories)


# -- I23: paging during a write storm -------------------------------------------------------

class A18WriteStorm(HistoryCase):

    def storm_page(self, limit, pause, workers=12):
        s = self.server
        a, b = s.create_account("sa"), s.create_account("sb")
        s.deposit(a["id"], 10**9)
        s.deposit(b["id"], 10**9)
        for k in range(120):
            s.deposit(a["id"], k + 1)
        stop = threading.Event()
        errors = []

        def writer(n):
            rnd = random.Random(n)
            while not stop.is_set():
                k = rnd.randrange(3)
                if k == 0:
                    r = s.deposit(a["id"], rnd.randint(1, 9))
                elif k == 1:
                    r = s.transfer(a["id"], b["id"], rnd.randint(1, 9), a["token"])
                else:
                    r = s.transfer(b["id"], a["id"], rnd.randint(1, 9), b["token"])
                if r.status == 503 and r.error == "busy" and workers > 64:
                    busy.append(r)  # D3: shedding at 200 writers is allowed, a wrong answer is not
                elif r.status not in (200, 201):
                    errors.append(r)

        busy = []
        threads = [threading.Thread(target=writer, args=(n,), daemon=True) for n in range(workers)]
        for t in threads:
            t.start()
        try:
            time.sleep(0.5)
            before = set(ledger(s, a["id"]))
            items, cursor, first = [], None, True
            after_first = None
            for _ in range(5000):
                q = f"limit={limit}" + (f"&cursor={cursor}" if cursor else "")
                r = hist(s, a["id"], a["token"], q)
                self.assertEqual(r.status, 200, r)
                items += r.json["items"]
                if first:
                    after_first = set(ledger(s, a["id"]))
                    first = False
                cursor = r.json["next_cursor"]
                if cursor is None:
                    break
                time.sleep(pause)
        finally:
            stop.set()
            for t in threads:
                t.join(30)
        self.assertEqual(errors, [], "writers failed during the storm")
        ids = [i["id"] for i in items]
        self.assertEqual(len(ids), len(set(ids)), "I23: an item repeated across pages")
        self.assertEqual(before - set(ids), set(), "I23: an item that existed at page 1 was skipped")
        self.assertEqual(set(ids) - after_first, set(),
                         "I23: a row committed after page 1 appeared on a later page")
        final, _ = self.page_all(s, a["id"], a["token"], limit=100)
        rank = {it["id"]: n for n, it in enumerate(final)}
        self.assertEqual([rank[i] for i in ids], sorted(rank[i] for i in ids),
                         "I23: pages are not strictly newest first")
        want = ledger(s, a["id"])
        for it in items:
            self.check_item(it, want[it["id"]])
        self.check_history(s, a["id"], a["token"], limit=50)
        self.check_history(s, b["id"], b["token"], limit=50)

    def test_storm_small_pages(self):
        self.storm_page(limit=5, pause=0.05)

    def test_storm_large_pages(self):
        self.storm_page(limit=50, pause=0.2)

    def test_storm_200_writers(self):
        """The minimum abuse set: page during a 200-worker write storm."""
        self.storm_page(limit=7, pause=0.02, workers=200)


# -- D4.3 sequence across kill -9 -----------------------------------------------------------

class A18SequenceCrash(HistoryMixin, unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.server = Server(os.path.join(self._tmp.name, "wallet.db")).start()
        self.need_history()

    def tearDown(self):
        self.server.kill()
        self._tmp.cleanup()

    def read_all(self, accts):
        return {a["id"]: self.check_history(self.server, a["id"], a["token"], limit=13) for a in accts}

    def test_kill_mid_burst_no_duplicate_or_reorder(self):
        s = self.server
        accts = [s.create_account(f"k{i}") for i in range(4)]
        for a in accts:
            s.deposit(a["id"], 10**9)
        stop = threading.Event()

        def burst(n):
            rnd = random.Random(n)
            while not stop.is_set():
                a, b = rnd.sample(accts, 2)
                if rnd.random() < 0.3:
                    s.deposit(a["id"], rnd.randint(1, 50), timeout=3)
                else:
                    s.transfer(a["id"], b["id"], rnd.randint(1, 50), a["token"], timeout=3)

        threads = [threading.Thread(target=burst, args=(n,), daemon=True) for n in range(24)]
        for t in threads:
            t.start()
        time.sleep(1.5)
        s.kill()
        stop.set()
        for t in threads:
            t.join(15)
        s.start()
        h1 = self.read_all(accts)
        self.check_cross_order(h1)
        for a in accts:  # rows written after the crash are newer than everything before it
            r = s.deposit(a["id"], 4242)
            self.assertEqual(r.status, 200, r)
            items = self.check_history(s, a["id"], a["token"], limit=7)
            self.assertEqual(items[0]["amount"], 4242, "a post-crash write is not newest")
            self.assertEqual(items[1:], h1[a["id"]], "post-crash write reordered older rows")
        h2 = self.read_all(accts)
        s.restart()
        self.assertEqual(self.read_all(accts), h2, "a clean restart reordered history")

    def test_cursor_taken_mid_storm_continues_after_kill(self):
        """kill -9 mid-storm, then page on from a cursor read before the kill: the rest of the
        pages are exactly the committed rows older than that cursor, no repeat, no skip."""
        s = self.server
        a, b = s.create_account("kc"), s.create_account("kd")
        s.deposit(a["id"], 10**9)
        s.deposit(b["id"], 10**9)
        for k in range(60):
            s.deposit(a["id"], k + 1)
        stop = threading.Event()

        def burst(n):
            rnd = random.Random(n)
            while not stop.is_set():
                x, y = (a, b) if rnd.random() < 0.5 else (b, a)
                s.transfer(x["id"], y["id"], rnd.randint(1, 9), x["token"], timeout=3)

        threads = [threading.Thread(target=burst, args=(n,), daemon=True) for n in range(32)]
        for t in threads:
            t.start()
        time.sleep(0.7)
        r = hist(s, a["id"], a["token"], "limit=9")
        self.assertEqual(r.status, 200, r)
        first, cursor = r.json["items"], r.json["next_cursor"]
        time.sleep(0.5)
        s.kill()
        stop.set()
        for t in threads:
            t.join(15)
        s.start()
        rest, cur = [], cursor
        while cur:
            r = hist(s, a["id"], a["token"], f"limit=9&cursor={cur}")
            self.assertEqual(r.status, 200, r)
            rest += r.json["items"]
            cur = r.json["next_cursor"]
        full = self.check_history(s, a["id"], a["token"], limit=100)
        ids = [i["id"] for i in full]
        self.assertIn(first[-1]["id"], ids, "a row served before the kill is gone after it")
        cut = ids.index(first[-1]["id"])
        self.assertEqual(rest, full[cut + 1:], "I23: pre-kill cursor did not continue exactly")
        self.assertFalse({i["id"] for i in first} & {i["id"] for i in rest}, "I23: repeat")


# -- D4.9: a stage-3 database; D4.8: startup line ------------------------------------------

STAGE3_SCHEMA = """
CREATE TABLE accounts (id TEXT PRIMARY KEY CHECK (length(id) = 36), owner TEXT NOT NULL
  CHECK (length(owner) BETWEEN 1 AND 64 AND instr(owner, char(0)) = 0), balance INTEGER NOT NULL
  DEFAULT 0 CHECK (balance >= 0 AND balance <= 1000000000000000), token_hash TEXT NOT NULL
  CHECK (length(token_hash) = 64), created_at TEXT NOT NULL DEFAULT
  (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))) STRICT;
CREATE TABLE external_moves (id TEXT PRIMARY KEY CHECK (length(id) = 36), account_id TEXT NOT NULL
  REFERENCES accounts(id), kind TEXT NOT NULL CHECK (kind IN ('deposit', 'withdrawal')),
  amount INTEGER NOT NULL CHECK (amount BETWEEN 1 AND 1000000000000), created_at TEXT NOT NULL
  DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))) STRICT;
CREATE INDEX external_moves_account ON external_moves (account_id);
CREATE TABLE transfers (id TEXT PRIMARY KEY CHECK (length(id) = 36), from_id TEXT NOT NULL
  REFERENCES accounts(id), to_id TEXT NOT NULL REFERENCES accounts(id), amount INTEGER NOT NULL
  CHECK (amount > 0 AND amount <= 1000000000000), created_at TEXT NOT NULL DEFAULT
  (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), CHECK (from_id <> to_id)) STRICT;
CREATE INDEX transfers_from ON transfers (from_id);
CREATE INDEX transfers_to ON transfers (to_id);
CREATE TABLE idempotency_keys (account_id TEXT NOT NULL REFERENCES accounts(id), scope TEXT NOT NULL
  CHECK (scope IN ('debit', 'deposit')), key TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 255),
  fingerprint TEXT NOT NULL, status INTEGER NOT NULL CHECK (status BETWEEN 200 AND 299),
  response TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (account_id, scope, key)) STRICT;
"""


def seed_stage3_db(path):
    """A stage-3 DB with ledger rows whose rowid order, created_at order and table order all
    disagree, plus ties, plus a row stamped in the future. Returns (accounts, expected order)."""
    rnd = random.Random(49)
    accts = []
    for i in range(3):
        tok = f"stage3-token-{i}-" + uuid.UUID(int=rnd.getrandbits(128)).hex
        accts.append({"id": str(uuid.UUID(int=rnd.getrandbits(128), version=4)), "token": tok, "balance": 0})
    T = "2026-10-0{}T00:00:0{}.000Z"
    # (table, account/from, to, kind, amount, created_at) in INSERT (rowid) order
    plan = [
        ("ext", 0, None, "deposit", 1000, T.format(1, 0)),
        ("ext", 1, None, "deposit", 1000, T.format(1, 0)),          # tie, same table: rowid
        ("tr", 0, 1, None, 100, T.format(2, 0)),                     # tie across tables:
        ("ext", 2, None, "deposit", 500, T.format(2, 0)),            #   ext before transfers
        ("tr", 1, 2, None, 40, T.format(3, 5)),
        ("ext", 0, None, "withdrawal", 25, T.format(3, 1)),          # earlier stamp, later rowid
        ("tr", 2, 0, None, 60, T.format(3, 5)),                      # tie with the transfer above
        ("ext", 1, None, "deposit", 9, "2099-01-01T00:00:00.000Z"),  # stamped in the future
        ("tr", 0, 2, None, 3, T.format(4, 0)),
        ("ext", 2, None, "withdrawal", 1, T.format(4, 0)),
    ]
    c = sqlite3.connect(path, isolation_level=None)
    c.execute("PRAGMA journal_mode = WAL")
    c.executescript(STAGE3_SCHEMA)
    for a in accts:
        c.execute("INSERT INTO accounts (id, owner, balance, token_hash) VALUES (?, 'stage3', 0, ?)",
                  (a["id"], hashlib.sha256(a["token"].encode()).hexdigest()))
    rows = []
    for table, x, y, kind, amt, at in plan:
        rid = str(uuid.UUID(int=rnd.getrandbits(128), version=4))
        if table == "ext":
            cur = c.execute("INSERT INTO external_moves (id, account_id, kind, amount, created_at) "
                            "VALUES (?, ?, ?, ?, ?)", (rid, accts[x]["id"], kind, amt, at))
            accts[x]["balance"] += amt if kind == "deposit" else -amt
        else:
            cur = c.execute("INSERT INTO transfers (id, from_id, to_id, amount, created_at) "
                            "VALUES (?, ?, ?, ?, ?)", (rid, accts[x]["id"], accts[y]["id"], amt, at))
            accts[x]["balance"] -= amt
            accts[y]["balance"] += amt
        rows.append((at, 0 if table == "ext" else 1, cur.lastrowid, rid))
    for a in accts:
        assert a["balance"] >= 0
        c.execute("UPDATE accounts SET balance = ? WHERE id = ?", (a["balance"], a["id"]))
    c.close()
    order = [r[3] for r in sorted(rows)]  # D4.9: created_at, ext before transfers, rowid
    return accts, order


class A18StageThreeDatabase(HistoryMixin, unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = os.path.join(self._tmp.name, "stage3.db")
        self.accts, self.order = seed_stage3_db(self.path)
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.kill()
        self._tmp.cleanup()

    def start(self, path):
        s = Server(path).start()
        self.servers.append(s)
        self.server = s
        self.need_history(s)
        return s

    def histories(self, s):
        return {a["id"]: self.check_history(s, a["id"], a["token"], limit=2, balance=a["balance"])
                for a in self.accts}

    def test_backfill_order_idempotence_and_later_writes(self):
        copy = os.path.join(self._tmp.name, "copy.db")
        shutil.copyfile(self.path, copy)
        s = self.start(self.path)
        h = self.histories(s)
        for a in self.accts:
            want = [r for r in reversed(self.order) if r in ledger(s, a["id"])]
            self.assertEqual([i["id"] for i in h[a["id"]]], want,
                             "D4.9: backfill order is not created_at, ext before transfers, rowid")
        self.check_cross_order(h)
        s.restart()
        self.assertEqual(self.histories(s), h, "D4.9: a second start changed the history")
        other = self.start(copy)
        self.assertEqual(self.histories(other), h, "D4.9: backfill is not deterministic")
        for a in self.accts:  # newer than the row stamped 2099
            r = s.deposit(a["id"], 77)
            self.assertEqual(r.status, 200, r)
            a["balance"] += 77
            items = self.check_history_unsorted(s, a)
            self.assertEqual(items[0]["amount"], 77, "D4.9: a later write is not the newest item")
            self.assertEqual(items[1:], h[a["id"]])

    def check_history_unsorted(self, s, a):
        # check_history asserts created_at order; the 2099 row legitimately breaks that here
        items, _ = self.page_all(s, a["id"], a["token"], limit=3)
        want = ledger(s, a["id"])
        self.assertEqual(sorted(i["id"] for i in items), sorted(want))
        for it in items:
            self.check_item(it, want[it["id"]])
        return items

    @unittest.skipUnless(os.path.exists(os.path.join(STAGE3_DIR, "app", "parking.py")),
                         "the stage-3 tree is not next to this stage")
    def test_db_written_by_the_real_stage3_server(self):
        """D4.9 with a DB the accepted stage-3 code wrote (not a hand-built schema)."""
        path = os.path.join(self._tmp.name, "real3.db")
        saved = breaker_harness.STAGE_DIR
        breaker_harness.STAGE_DIR = STAGE3_DIR
        try:
            old = Server(path).start()
        finally:
            breaker_harness.STAGE_DIR = saved
        try:
            accts = [old.create_account(f"r{i}") for i in range(3)]
            for k in range(25):
                a, b = accts[k % 3], accts[(k + 1) % 3]
                self.assertEqual(old.deposit(a["id"], 100 + k).status, 200)
                self.assertEqual(old.transfer(a["id"], b["id"], 1 + k, a["token"]).status, 201)
            with contextlib.closing(old.db()) as c:
                rows = sorted(
                    [(at, 0, rowid, i) for rowid, i, at in c.execute(
                        "SELECT rowid, id, created_at FROM external_moves")]
                    + [(at, 1, rowid, i) for rowid, i, at in c.execute(
                        "SELECT rowid, id, created_at FROM transfers")])
        finally:
            old.kill()
        order = [r[3] for r in rows]
        s = self.start(path)
        h = {}
        for a in accts:
            h[a["id"]] = self.check_history(s, a["id"], a["token"], limit=4)
            want = [r for r in reversed(order) if r in ledger(s, a["id"])]
            self.assertEqual([i["id"] for i in h[a["id"]]], want, "D4.9 order on a real stage-3 DB")
        self.check_cross_order(h)
        s.restart()
        for a in accts:
            self.assertEqual(self.check_history(s, a["id"], a["token"], limit=4), h[a["id"]])

    def test_startup_line_says_whether_tune_malloc_ran(self):
        """D4.8: one stderr line at startup, applied or skipped, with the reason."""
        s = self.start(self.path)
        time.sleep(0.3)
        lines = [l for l in s.read_log().splitlines() if re.search(r"malloc", l, re.I)]
        self.assertEqual(len(lines), 1, f"D4.8: expected one tune_malloc line, got {lines}")
        self.assertRegex(lines[0], re.compile(r"applied|skipped", re.I), lines[0])
        if os.name == "posix" and os.path.exists("/lib/x86_64-linux-gnu/libc.so.6"):
            self.assertRegex(lines[0], re.compile(r"applied", re.I), "glibc present but not applied")


if __name__ == "__main__":
    unittest.main()
