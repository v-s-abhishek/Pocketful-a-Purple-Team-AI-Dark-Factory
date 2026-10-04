"""Unit 3.1, D3.3a: a connection gets a handler slot and thread only once its
request head is complete. Until then it is parked and read by a fixed pool,
which applies every stage-1 head rule itself, without a slot. Q3.1-B: a
parked-head memory budget. Q3.1-C: bytes past the head reach the handler."""

import ctypes
import http.client
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from harness import STAGE_DIR, ServerProcess

if STAGE_DIR not in sys.path:
    sys.path.insert(0, STAGE_DIR)

from app import db, parking  # noqa: E402
from app import server as server_module  # noqa: E402
from app.server import Handler, WalletServer  # noqa: E402

POOL_THREADS = len(range(0, parking.PARKED_MAX, parking.SHARD_SIZE)) + 1  # shards + dispatcher


def read_all(sock):
    reply = b""
    try:
        while chunk := sock.recv(65536):
            reply += chunk
    except ConnectionError:
        pass
    return reply


def parse(reply):
    head, _, payload = reply.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    return status_line, json.loads(payload) if payload else None


def handler_threads():
    return [t for t in threading.enumerate() if "process_request_thread" in t.name]


def pool_threads():
    return [t for t in threading.enumerate() if t.name.startswith("pocketful-")]


class InProcess(unittest.TestCase):
    """A live WalletServer in this process, counting handler activations."""

    max_handlers = 256

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="pocketful-park-")
        self.addCleanup(shutil.rmtree, self.tmpdir, True)
        db_path = os.path.join(self.tmpdir, "wallet.db")
        db.init_db(db_path)
        self.handled, self.active, self.peak = 0, 0, 0
        counter = threading.Lock()
        test = self

        class CountingHandler(Handler):
            def handle(self):
                with counter:
                    test.handled += 1
                    test.active += 1
                    test.peak = max(test.peak, test.active)
                try:
                    super().handle()
                finally:
                    with counter:
                        test.active -= 1

        self.server = WalletServer(("127.0.0.1", 0), db_path, max_handlers=self.max_handlers)
        self.server.RequestHandlerClass = CountingHandler
        self.port = self.server.server_address[1]
        thread = threading.Thread(target=self.server.serve_forever,
                                  kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()

        def stop():
            self.server.shutdown()
            self.server.server_close()
            thread.join(5)

        self.addCleanup(stop)

    def connect(self, timeout=20):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        self.addCleanup(sock.close)
        return sock

    def exchange(self, data, timeout=20):
        sock = self.connect(timeout)
        sock.sendall(data)
        return read_all(sock)


class HeadRulesWhileParkedTest(InProcess):
    """Each stage-1 head rule answers exactly as before, from the parked
    phase: no handler ever runs for these."""

    CASES = {
        "malformed request line": (b"NONSENSE\r\n\r\n", 400),
        "blank request line": (b"\r\n", 400),
        "request line over 64 KiB": (b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n", 400),
        "HTTP/0.9 with a body (R1.1-G, drained)":
            (b"POST /accounts HTTP/0.9\r\nContent-Length: 3\r\n\r\nabc", 400),
        "HTTP/2.0 with a body (505 -> 400, drained)":
            (b"POST /accounts HTTP/2.0\r\nContent-Length: 3\r\n\r\nabc", 400),
        "header line over 64 KiB": (b"GET /health HTTP/1.1\r\nX: " + b"a" * 70000 + b"\r\n\r\n", 431),
        "more than 100 headers": (b"GET /health HTTP/1.1\r\n" + b"X: y\r\n" * 101 + b"\r\n", 431),
    }

    def test_head_errors_take_no_slot(self):
        for name, (data, status) in self.CASES.items():
            with self.subTest(case=name):
                status_line, body = parse(self.exchange(data))
                self.assertEqual(status_line.split(b" ")[:2], [b"HTTP/1.0", str(status).encode()])
                self.assertEqual(body, {"error": "invalid_request"})
        self.assertEqual(self.handled, 0, "a head error was answered by a handler")

    def test_drained_body_arriving_late_still_gets_the_400(self):
        """R1.3-A2 from the parked phase: the reply waits for the declared
        body, so it is not lost to a reset."""
        sock = self.connect()
        sock.sendall(b"POST /accounts HTTP/0.9\r\nContent-Length: 5\r\n\r\nab")
        time.sleep(0.5)
        sock.sendall(b"cde")
        self.assertEqual(parse(read_all(sock)), (b"HTTP/1.0 400 Bad Request",
                                                 {"error": "invalid_request"}))
        self.assertEqual(self.handled, 0)

    def test_stalled_head_gets_408_at_10s_from_connect(self):
        sock = self.connect()
        start = time.monotonic()
        sock.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n")
        status_line, body = parse(read_all(sock))
        elapsed = time.monotonic() - start
        self.assertEqual((status_line.split(b" ")[1], body), (b"408", {"error": "request_timeout"}))
        self.assertGreater(elapsed, 9.5)
        self.assertLess(elapsed, 11.5)
        self.assertEqual(self.handled, 0)

    def test_one_deadline_across_parked_and_handler_phases(self):
        """A head trickled for 6 s, then a body that never completes: 408 at
        10 s from connect, not 10 s from when the handler started."""
        sock = self.connect()
        start = time.monotonic()
        head = b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Length: 40\r\n\r\n"
        for i in range(0, len(head), 4):
            sock.sendall(head[i:i + 4])
            time.sleep(6 / (len(head) / 4))
        sock.sendall(b'{"owner"')
        status_line, body = parse(read_all(sock))
        elapsed = time.monotonic() - start
        self.assertEqual((status_line.split(b" ")[1], body), (b"408", {"error": "request_timeout"}))
        self.assertGreater(elapsed, 9.5)
        self.assertLess(elapsed, 11.5, "the handler restarted the 10 s deadline")
        self.assertEqual(self.handled, 1)


class SlowHeadsTest(InProcess):
    max_handlers = 2

    def test_byte_at_a_time_heads_cost_no_slot(self):
        """Slowloris on the head: 20 clients sending one byte every 50 ms
        hold no handler, so the two slots stay free for others."""
        head = b"GET /health HTTP/1.1\r\nHost: x\r\nX-Pad: abcdefghij\r\n\r\n"
        socks = [self.connect() for _ in range(20)]
        replies = [None] * len(socks)

        def trickle(n):
            for byte in head:
                socks[n].sendall(bytes([byte]))
                time.sleep(0.05)
            replies[n] = parse(read_all(socks[n]))

        threads = [threading.Thread(target=trickle, args=(n,)) for n in range(len(socks))]
        for thread in threads:
            thread.start()
        time.sleep(1)
        self.assertEqual(self.handled, 0, "a partial head took a handler")
        self.assertEqual(handler_threads(), [])
        # Both slots are free for a complete request meanwhile.
        self.assertEqual(parse(self.exchange(b"GET /health HTTP/1.1\r\n\r\n")),
                         (b"HTTP/1.0 200 OK", {"ok": True}))
        for thread in threads:
            thread.join(20)
        self.assertEqual(replies, [(b"HTTP/1.0 200 OK", {"ok": True})] * len(socks))
        self.assertLessEqual(self.peak, 2)


class HandoffTest(InProcess):
    def test_bytes_after_the_head_reach_the_handler(self):
        """Q3.1-C: the body in the same segment as the head, and anything
        after it, is handed over intact. One request per connection."""
        body = json.dumps({"owner": "same-segment"}).encode()
        data = (b"POST /accounts HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(body) + body
                + b"GET /health HTTP/1.1\r\n\r\n")
        reply = self.exchange(data)
        status_line, payload = parse(reply)
        self.assertEqual(status_line, b"HTTP/1.0 201 Created")
        self.assertEqual(payload["owner"], "same-segment")
        self.assertEqual(reply.count(b"HTTP/1.0 "), 1, "a second request was served")

    def test_body_split_across_parked_and_handler_phases(self):
        body = json.dumps({"owner": "split-body"}).encode()
        sock = self.connect()
        sock.sendall(b"POST /accounts HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(body)
                     + body[:7])
        time.sleep(0.3)
        sock.sendall(body[7:])
        status_line, payload = parse(read_all(sock))
        self.assertEqual((status_line, payload["owner"]), (b"HTTP/1.0 201 Created", "split-body"))

    def test_handlers_never_exceed_the_cap_and_the_pool_is_fixed(self):
        """300 requests whose bodies stall hold the 256 slots; 500 idle and
        500 half-headed connections are parked. Threads stay at 256 + pool.

        A3.1-4: every connection has a 10 s deadline from connect, and 1300
        sequential connects on bare Windows took 10-13 s, so the stalled
        bodies got their 408 before the check. Connects run in parallel
        (about 3 s for all 1300), the parked load first, and the wait for
        the slots to fill starts once the last head is sent."""
        body = json.dumps({"owner": "slow-body"}).encode()
        start = time.monotonic()
        with ThreadPoolExecutor(32) as pool:
            idle = list(pool.map(lambda _: self.connect(30), range(500)))
            half = list(pool.map(lambda _: self.connect(30), range(500)))
        for sock in half:
            sock.sendall(b"GET /health HTTP/1.1\r\nHost:")
        with ThreadPoolExecutor(32) as pool:
            slow = list(pool.map(lambda _: self.connect(30), range(300)))
        for sock in slow:
            sock.sendall(b"POST /accounts HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(body)
                         + body[:5])
        setup = time.monotonic() - start
        self.assertLess(setup, 6, f"connecting took {setup:.1f} s: the 10 s deadlines "
                                  "would end the test's load before the check")
        deadline = time.monotonic() + 3
        while self.active < 256 and time.monotonic() < deadline:
            time.sleep(0.01)
        peak_threads = 0
        for _ in range(20):
            peak_threads = max(peak_threads, len(handler_threads()))
            time.sleep(0.02)
        self.assertEqual(self.active, 256)
        self.assertEqual(sum(shard.count for shard in self.server._lot.shards), 1000,
                         "the idle and half-headed connections are not all parked")
        self.assertLessEqual(peak_threads, 256)
        self.assertEqual(len(pool_threads()), POOL_THREADS, [t.name for t in pool_threads()])
        for sock in slow:
            sock.sendall(body[5:])
        for sock in slow:
            self.assertEqual(parse(read_all(sock))[0], b"HTTP/1.0 201 Created")
        self.assertLessEqual(self.peak, 256)
        for sock in idle + half:
            sock.close()


class ParkedCapTest(InProcess):
    def setUp(self):
        patcher = mock.patch.object(parking, "PARKED_MAX", 40)
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()

    def test_over_the_parked_cap_connections_wait_in_the_backlog(self):
        idle = [self.connect() for _ in range(40)]
        time.sleep(0.3)
        late = self.connect()
        late.sendall(b"GET /health HTTP/1.1\r\n\r\n")
        late.settimeout(0.7)
        with self.assertRaises(socket.timeout, msg="accepted beyond the parked cap"):
            late.recv(1)
        self.assertEqual(self.handled, 0)
        idle[0].close()  # one parked connection ends: the next is accepted
        late.settimeout(10)
        self.assertEqual(parse(read_all(late)), (b"HTTP/1.0 200 OK", {"ok": True}))


class ReadyQueueExpiryTest(InProcess):
    """A3.1-2: a complete head whose deadline passes while it waits for a
    slot gets a JSON 408 from its handler once it gets one, and both its
    parked and handler slots come back."""

    max_handlers = 1

    def setUp(self):
        patcher = mock.patch.object(server_module, "REQUEST_DEADLINE_S", 2)
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()
        self.gate, self.entered = threading.Event(), threading.Event()
        self.addCleanup(self.gate.set)
        gate, entered, counting = self.gate, self.entered, self.server.RequestHandlerClass
        first = [True]

        class GatedHandler(counting):
            def handle(self):
                if first:
                    first.pop()
                    entered.set()
                    gate.wait(10)  # the first request holds the only slot
                super().handle()

        self.server.RequestHandlerClass = GatedHandler

    def test_deadline_passing_in_the_ready_queue_is_a_408(self):
        holder = self.connect()
        holder.sendall(b"GET /health HTTP/1.1\r\n\r\n")
        self.assertTrue(self.entered.wait(5), "the holder never reached a handler")
        queued = self.connect()
        queued.sendall(b'POST /accounts HTTP/1.1\r\nContent-Length: 20\r\n\r\n{"owner"')
        time.sleep(2.5)  # its 2 s deadline passes while it waits for the slot
        released = time.monotonic()
        self.gate.set()
        self.assertEqual(parse(read_all(holder)), (b"HTTP/1.0 200 OK", {"ok": True}))
        status_line, body = parse(read_all(queued))
        self.assertEqual((status_line, body),
                         (b"HTTP/1.0 408 Request Timeout", {"error": "request_timeout"}))
        self.assertLess(time.monotonic() - released, 2, "the expired request hung in its handler")
        self.assertEqual(self.handled, 2)
        deadline = time.monotonic() + 5
        while self.active and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.1)  # the slot is given back just after handle() returns
        self.assertEqual(self.server._handler_slots._value, 1, "handler slot not returned")
        self.assertEqual(self.server._parked_slots._value, parking.PARKED_MAX,
                         "parked slot not returned")
        self.assertEqual(self.server._lot.head_bytes(), 0, "head bytes still charged")


class ProcessCase(unittest.TestCase):
    env = {}

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="pocketful-park-proc-")
        self.addCleanup(shutil.rmtree, self.tmpdir, True)
        with mock.patch.dict(os.environ, self.env):
            self.server = ServerProcess(os.path.join(self.tmpdir, "wallet.db")).start()
        self.addCleanup(self.server.stop)
        self.port = self.server.port

    def request(self, method, path, body=None, headers=None, timeout=15):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            start = time.monotonic()
            conn.request(method, path, body=None if body is None else json.dumps(body),
                         headers=headers or {})
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read()), time.monotonic() - start
        finally:
            conn.close()

    def open_many(self, count, payload=b""):
        socks = []
        for _ in range(count):
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            if payload:
                sock.sendall(payload)
            socks.append(sock)
        self.addCleanup(lambda: [s.close() for s in socks])
        return socks

    def deposit_burst(self, account, count=40):
        with ThreadPoolExecutor(count) as pool:
            return list(pool.map(lambda _: self.request(
                "POST", f"/accounts/{account}/deposit", {"amount": 1}), range(count)))


class IdleFloodTest(ProcessCase):
    def test_1500_idle_and_600_half_sent_do_not_starve(self):
        self.open_many(1500)
        self.open_many(600, b"POST /accounts HTTP/1.1")
        status, body, elapsed = self.request("GET", "/health")
        self.assertEqual((status, body), (200, {"ok": True}))
        self.assertLess(elapsed, 2, f"/health took {elapsed:.2f} s")
        status, account, _ = self.request("POST", "/accounts", {"owner": "flood"})
        self.assertEqual(status, 201)
        results = self.deposit_burst(account["id"])
        self.assertEqual([r[0] for r in results], [200] * 40, "refusals under the idle flood")
        self.assertLess(max(r[2] for r in results), 10)


def peak_rss_bytes(pid):
    """Peak resident set of a process: VmHWM on Linux, PeakWorkingSetSize
    on Windows."""
    if sys.platform == "win32":
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t)]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        handle = kernel32.OpenProcess(0x1000 | 0x0010, False, pid)
        try:
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                raise OSError(ctypes.get_last_error())
            return counters.PeakWorkingSetSize
        finally:
            kernel32.CloseHandle(handle)
    with open(f"/proc/{pid}/status", encoding="ascii") as fh:
        for line in fh:
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    raise OSError("VmHWM not found")


class HeadMemoryBudgetTest(ProcessCase):
    """Q3.1-B: 60 connections each trickling about 6 MB of headers (within
    the stage-1 per-line and per-count limits) cannot grow the process
    without bound, and small legitimate requests keep being served."""

    FLOODERS = 60
    LINE = b"X-Big: " + b"a" * 60000 + b"\r\n"  # under the 64 KiB line limit

    def test_large_head_flood_is_bounded_and_small_requests_answer(self):
        status, account, _ = self.request("POST", "/accounts", {"owner": "legit"})
        self.assertEqual(status, 201)
        base_rss = peak_rss_bytes(self.server.proc.pid)
        stop = threading.Event()
        sent = [0] * self.FLOODERS

        def flood(n):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=15) as sock:
                    sock.sendall(b"GET /health HTTP/1.1\r\n")
                    for _ in range(99):
                        if stop.is_set():
                            return
                        sock.sendall(self.LINE)
                        sent[n] += len(self.LINE)
                    read_all(sock)
            except OSError:
                pass  # paused, then 408 and closed: expected

        flooders = [threading.Thread(target=flood, args=(n,), daemon=True)
                    for n in range(self.FLOODERS)]
        for thread in flooders:
            thread.start()
        time.sleep(2)  # let the parked heads grow past the budget
        results = self.deposit_burst(account["id"])
        stop.set()
        for thread in flooders:
            thread.join(20)
        peak = peak_rss_bytes(self.server.proc.pid)
        sys.stderr.write(f"\n[Q3.1-B] flood sent {sum(sent) / 2**20:.0f} MiB of headers; server "
                         f"peak RSS {peak / 2**20:.1f} MiB (before the flood {base_rss / 2**20:.1f})\n")
        self.assertEqual([r[0] for r in results], [200] * 40)
        self.assertLess(max(r[2] for r in results), 10, "I19 under the head flood")
        # Offered: FLOODERS x 99 lines x 60 KB, about 340 MiB. What the
        # kernel took is less, because paused heads are not read.
        self.assertGreater(sum(sent), parking.HEAD_BUDGET_BYTES, "the flood never hit the budget")
        # Budget 64 MiB + at most 16 KiB per small head, plus the process.
        self.assertLess(peak - base_rss, 160 * 2**20, f"peak RSS grew {peak - base_rss} bytes")



class CompletedHeadBudgetTest(ProcessCase):
    """A3.1-1: complete heads waiting for a handler slot stay charged to the
    Q3.1-B budget. With the 4 slots held by stalled bodies, 8 clients send a
    complete ~6 MB head (48 MB, under the budget) and queue for a slot; then
    52 more flood ~6 MB heads. If queued heads stopped counting, the flood
    would be read in full (~300 MB). Memory stays bounded, the 8 queued heads
    are answered 200 once the slots free, and every other client that got
    its head in gets 200 or 408."""

    env = {"MAX_HANDLERS": "4"}
    QUEUED = 8
    CLIENTS = 60
    LINE = b"X-Big: " + b"a" * 60000 + b"\r\n"

    def test_complete_large_heads_waiting_for_slots_are_bounded(self):
        body = json.dumps({"owner": "holder"}).encode()
        holders = []
        for _ in range(4):
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=20)
            self.addCleanup(sock.close)
            sock.sendall(b"POST /accounts HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(body)
                         + body[:3])
            holders.append(sock)
        time.sleep(0.3)
        base_rss = peak_rss_bytes(self.server.proc.pid)
        outcomes = [None] * self.CLIENTS
        head = b"GET /health HTTP/1.1\r\n" + self.LINE * 99 + b"\r\n"

        def client(n):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=20) as sock:
                    sock.sendall(head)
                    reply = read_all(sock)
                outcomes[n] = ("sent", parse(reply)[0].split(b" ")[1] if reply else b"none")
            except OSError as exc:
                outcomes[n] = ("cut", type(exc).__name__)  # paused, then 408 and closed

        clients = [threading.Thread(target=client, args=(n,), daemon=True)
                   for n in range(self.CLIENTS)]
        for thread in clients[:self.QUEUED]:
            thread.start()
        time.sleep(1.5)  # these heads complete and queue behind the held slots
        for thread in clients[self.QUEUED:]:
            thread.start()
        time.sleep(2.5)
        # Parked + queued heads only: no handler has run yet. Q3.1-B +
        # A3.1-1: together they stay near the 64 MiB budget (plus at most
        # 16 KiB per small head and one large head being parsed).
        queued_peak = peak_rss_bytes(self.server.proc.pid)
        self.assertLess(queued_peak - base_rss, 128 * 2**20,
                        f"parked + queued heads grew RSS by {(queued_peak - base_rss) / 2**20:.0f} MiB")
        for sock in holders:
            sock.sendall(body[3:])
        for sock in holders:
            self.assertEqual(parse(read_all(sock))[0], b"HTTP/1.0 201 Created")
        for thread in clients:
            thread.join(30)
        peak = peak_rss_bytes(self.server.proc.pid)
        sent = [o[1] for o in outcomes if o and o[0] == "sent"]
        sys.stderr.write(f"\n[A3.1-1] {self.CLIENTS} ~6 MB heads behind 4 held slots: outcomes "
                         f"{sorted({o: outcomes.count(o) for o in set(outcomes)}.items())}; "
                         f"peak RSS with heads parked/queued {queued_peak / 2**20:.1f} MiB, "
                         f"overall (4 handlers parsing 6 MB heads) {peak / 2**20:.1f} MiB, "
                         f"before {base_rss / 2**20:.1f} MiB\n")
        self.assertNotIn(None, outcomes, "a client never finished")
        self.assertEqual(outcomes[:self.QUEUED], [("sent", b"200")] * self.QUEUED,
                         "a complete head queued for a slot was not served")
        # Flooders: 200, 408, or reset by the 408's close while their head
        # sat unread (stage 1: 408 closes without draining).
        self.assertEqual(set(sent) - {b"200", b"408", b"none"}, set(), outcomes)
        status, body_json, elapsed = self.request("GET", "/health")
        self.assertEqual((status, body_json), (200, {"ok": True}))
        self.assertLess(elapsed, 2)


class HandlerHeadBudgetTest(ProcessCase):
    """A3.1-3: a head handed to a handler stays charged to the Q3.1-B budget
    until the handler ends, because the handler holds it (raw and parsed)
    that long. 60 clients, 0.1 s apart, each send a complete ~6.4 MB POST
    head and stall on the body, so a handler that takes one holds it to the
    10 s deadline. If handed-off heads stopped counting, most of the 60
    would be held at once (several hundred MiB, raw and parsed); charged,
    about 64 MiB of them are. Small requests keep answering meanwhile."""

    CLIENTS = 60
    LINE = b"X-Big: " + b"a" * 64991 + b"\r\n"  # 65000 bytes, under the 64 KiB line limit

    def test_heads_held_by_handlers_are_bounded(self):
        status, account, _ = self.request("POST", "/accounts", {"owner": "legit"})
        self.assertEqual(status, 201)
        base_rss = peak_rss_bytes(self.server.proc.pid)
        body = json.dumps({"owner": "stalled"}).encode()
        head = (b"POST /accounts HTTP/1.1\r\nContent-Length: %d\r\n" % len(body)
                + self.LINE * 98 + b"\r\n")
        outcomes = [None] * self.CLIENTS

        def client(n):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=20) as sock:
                    sock.sendall(head + body[:1])
                    reply = read_all(sock)
                outcomes[n] = parse(reply)[0].split(b" ")[1] if reply else b"none"
            except OSError as exc:
                outcomes[n] = type(exc).__name__  # paused, then 408 and closed

        clients = [threading.Thread(target=client, args=(n,), daemon=True)
                   for n in range(self.CLIENTS)]
        for thread in clients:
            thread.start()
            time.sleep(0.1)
        results = self.deposit_burst(account["id"])
        for thread in clients:
            thread.join(30)
        peak = peak_rss_bytes(self.server.proc.pid)
        sys.stderr.write(f"\n[A3.1-3] {self.CLIENTS} stalled ~6.4 MB heads, 0.1 s apart: outcomes "
                         f"{sorted({str(o): outcomes.count(o) for o in set(outcomes)}.items())}; "
                         f"peak RSS {peak / 2**20:.1f} MiB (before {base_rss / 2**20:.1f})\n")
        self.assertEqual([r[0] for r in results], [200] * 40)
        self.assertLess(max(r[2] for r in results), 10, "I19 while handlers hold large heads")
        self.assertNotIn(None, outcomes, "a client never finished")
        # The stalled bodies never complete: 408 from a handler or the
        # parked phase, or reset / broken pipe from the 408's close while
        # the head sat unread (paused).
        self.assertEqual(set(outcomes) - {b"408", b"none", "ConnectionResetError",
                                          "ConnectionAbortedError", "BrokenPipeError"},
                         set(), outcomes)
        # Charged: at most ~64 MiB of large heads (plus small ones), each
        # also parsed in its handler, plus one being probed in the parked
        # phase. Measured 170-230 MiB on bare Windows; unbounded, 600+.
        self.assertLess(peak - base_rss, 400 * 2**20,
                        f"heads held by handlers grew RSS by {(peak - base_rss) / 2**20:.0f} MiB")
        status, body_json, elapsed = self.request("GET", "/health")
        self.assertEqual((status, body_json), (200, {"ok": True}))
        self.assertLess(elapsed, 2)


if __name__ == "__main__":
    unittest.main()
