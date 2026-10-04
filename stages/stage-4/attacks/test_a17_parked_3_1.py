"""Unit 3.1 attacks, round 3 (Breaker reviewer-stqg): the D3.3a parked phase, written from the
ruling before the build.

D3.3a (2026-10-04): a connection takes a handler slot only once its complete request head has
arrived. Until then it is parked on a fixed pool of selector reader threads; the accept loop keeps
accepting. Stage-1 head rules hold in the parked phase with unchanged statuses and JSON (408 at
10 s from connect, 431 for a header line > 64 KiB or > 100 headers, 400 for a malformed/over-long
request line or a non-1.0/1.1 version, with an HTTP/1.0 status line), sent without a slot. One
10 s deadline from connect to end of body across both phases. Head bytes and anything after the
head are handed to the handler intact. >= 1500 parked on bare Windows and Linux (Windows select()
caps one selector at 512 sockets); parked capped (~4096), the excess waits in the backlog.

Most attacks here run against a server with a tiny handler cap and every slot held by a client
whose head is complete but whose body is slow (Q3-A: that does hold a slot). Anything answered
then was necessarily answered from the parked phase.

Skipped until the build has a parked phase (a module in app/ uses `selectors`), unless
ATTACK_FORCE_3A=1.
"""
import concurrent.futures as cf
import contextlib
import json
import os
import socket
import sys
import threading
import time
import unittest
import uuid

from breaker_harness import SLOW, STAGE_DIR
from breaker_stress import parse_response
from test_a15_concurrency_3_1 import KEY, LINGER0, C3Case, built
from test_a16_saturation_3_1 import Holder, SmallCapCase, fast_connect, get_health

CRLF = b"\r\n"
slow = unittest.skipUnless(SLOW, "set ATTACK_SLOW=1")


def _has_parked_phase():
    app = os.path.join(STAGE_DIR, "app")
    with contextlib.suppress(OSError):
        for name in os.listdir(app):
            if name.endswith(".py"):
                with open(os.path.join(app, name), encoding="utf-8") as f:
                    if "selectors" in f.read():
                        return True
    return False


PARKED = _has_parked_phase() or os.environ.get("ATTACK_FORCE_3A") == "1"
parked = unittest.skipUnless(PARKED, "D3.3a parked phase not built yet (ATTACK_FORCE_3A=1 forces)")


class Conn:
    """A raw client connection with timing. t0 is taken right after connect."""

    def __init__(self, port, timeout=30):
        self.sock = fast_connect(port, timeout)
        self.t0 = time.monotonic()

    def send(self, data):
        self.sock.sendall(data)
        return self

    def trickle(self, data, gap):
        for i in range(len(data)):
            self.sock.sendall(data[i:i + 1])
            time.sleep(gap)
        return self

    def read_all(self):
        """Read to EOF. Returns (raw bytes, seconds since connect). A reset counts as EOF."""
        got = b""
        with contextlib.suppress(OSError):
            while True:
                c = self.sock.recv(65536)
                if not c:
                    break
                got += c
        return got, time.monotonic() - self.t0

    def close(self, rst=False):
        with contextlib.suppress(OSError):
            if rst:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
            self.sock.close()


def status_line(raw):
    return raw.split(CRLF, 1)[0]


def assert_json_reply(tc, raw, status, error=None):
    p = parse_response(raw)
    tc.assertIsNotNone(p, f"no complete HTTP response: {raw[:200]!r}")
    tc.assertEqual(p[0], status, raw[:300])
    body = json.loads(p[2])
    if error:
        tc.assertEqual(body.get("error"), error, raw[:300])
    return p


def deposit_request(acct_id, amount, key=None, version=b"HTTP/1.1"):
    body = json.dumps({"amount": amount}).encode()
    head = (b"POST /accounts/" + acct_id.encode() + b"/deposit " + version + CRLF + b"Host: x" + CRLF
            + b"Content-Type: application/json" + CRLF + b"Content-Length: %d" % len(body) + CRLF)
    if key:
        head += KEY.encode() + b": " + key.encode() + CRLF
    return head + CRLF, body


# --------------------------------------------------------------------------------------------
@built
@parked
class ParkedWhileSlotsFull(SmallCapCase):
    """CAP=4 slots, all held by complete-head/slow-body clients. Everything below must still be
    answered, which proves it was answered from the parked phase without a slot."""

    CAP = 4

    def setUp(self):
        super().setUp()
        self.holders = [Holder(self.server.port) for _ in range(self.CAP)]
        time.sleep(0.4)
        # sanity: the slots really are full (a complete request is not answered)
        out = {}
        th = threading.Thread(target=lambda: out.update(r=get_health(self.server.port, 15)), daemon=True)
        th.start()
        th.join(1.0)
        self.assertTrue(th.is_alive(), "setup: slots not full, the attacks below would prove nothing")
        self.blocked = th

    def tearDown(self):
        for h in self.holders:
            h.release()
        self.blocked.join(15)
        super().tearDown()

    def quick(self, payload, timeout=5):
        c = Conn(self.server.port, timeout=timeout)
        c.send(payload)
        raw, dt = c.read_all()
        c.close()
        return raw, dt

    def test_431_header_line_over_64k_without_a_slot(self):
        raw, dt = self.quick(b"GET /health HTTP/1.1" + CRLF + b"X-Pad: " + b"a" * 70_000 + CRLF + CRLF)
        assert_json_reply(self, raw, 431, "invalid_request")
        self.assertLess(dt, 2.0, "the 431 waited for a handler slot")

    def test_431_over_100_headers_without_a_slot(self):
        raw, dt = self.quick(b"GET /health HTTP/1.1" + CRLF
                             + b"".join(b"H%d: v" % i + CRLF for i in range(101)) + CRLF)
        assert_json_reply(self, raw, 431, "invalid_request")
        self.assertLess(dt, 2.0)

    def test_400_bad_request_lines_without_a_slot(self):
        for req in (b"GARBAGE" + CRLF + CRLF,
                    b"GET /health HTTP/9.9" + CRLF + CRLF,
                    b"GET /health HTTP/0.9" + CRLF + CRLF,
                    b"GET /health HTTP/1.2" + CRLF + CRLF,
                    CRLF,
                    b"GET /" + b"a" * 70_000 + b" HTTP/1.1" + CRLF + CRLF):
            with self.subTest(req=req[:24]):
                raw, dt = self.quick(req)
                self.assertTrue(raw, "no reply to a malformed head while every slot was held")
                assert_json_reply(self, raw, 400, "invalid_request")
                self.assertTrue(status_line(raw).startswith(b"HTTP/1.0 "),
                                f"R1.1-G: status line {status_line(raw)!r}")
                self.assertLess(dt, 2.0)

    def test_408_idle_head_without_a_slot(self):
        """Head never completes: 408 JSON at 10 s from connect, from the parked phase."""
        c = Conn(self.server.port)
        c.send(b"POST /transfers HTTP/1.1" + CRLF + b"Host: x" + CRLF)
        raw, dt = c.read_all()
        c.close()
        assert_json_reply(self, raw, 408, "request_timeout")
        self.assertGreater(dt, 9.0, "408 before the 10 s deadline")
        self.assertLess(dt, 11.5, f"408 at {dt:.2f}s: the parked deadline is not 10 s from connect")

    def test_slowloris_heads_cost_no_slot(self):
        """60 byte-at-a-time heads park; a 5th complete request beyond the 4 held slots is still
        blocked, but once ONE holder frees its slot the next complete request gets it within 1 s,
        i.e. none of the 60 dribblers took a slot."""
        stop = threading.Event()

        def dribble():
            with contextlib.suppress(OSError):
                c = Conn(self.server.port)
                c.send(b"GET /health HTTP/1.1" + CRLF)
                while not stop.is_set():
                    c.send(b"X")
                    time.sleep(0.2)
                c.close(rst=True)

        ts = [threading.Thread(target=dribble, daemon=True) for _ in range(60)]
        for t in ts:
            t.start()
        time.sleep(1.0)
        try:
            self.holders.pop().release()
            # the request blocked since setUp gets the freed slot first (FIFO through the backlog
            # is not promised, so allow either it or a fresh one to be served)
            self.blocked.join(2.0)
            st, dt = get_health(self.server.port, 5) if not self.blocked.is_alive() else (None, None)
            self.assertFalse(self.blocked.is_alive(), "a freed slot was taken by a dribbling head")
            self.assertEqual(st, 200, "a second complete request was not served: a dribbler holds a slot")
        finally:
            stop.set()
            for t in ts:
                t.join(5)


# --------------------------------------------------------------------------------------------
@built
@parked
class OneDeadlineAcrossPhases(C3Case):
    def test_slow_head_then_slow_body_is_408_at_10s_from_connect(self):
        """Head trickled over ~6 s, then the body trickled: the 408 must come ~10 s after connect,
        not 10 s after the head completed (that would give a client up to 20 s)."""
        a = self.funded(0, "dl")
        head, body = deposit_request(a["id"], 5, key=f"dl-{uuid.uuid4().hex}")
        c = Conn(self.server.port)
        c.trickle(head, 6.0 / len(head))
        result = {}
        rd = threading.Thread(target=lambda: result.update(r=c.read_all()), daemon=True)
        rd.start()
        with contextlib.suppress(OSError):
            for i in range(len(body)):
                if not rd.is_alive():
                    break
                c.sock.sendall(body[i:i + 1])
                time.sleep(1.0)
        rd.join(20)
        c.close()
        raw, dt = result["r"]
        assert_json_reply(self, raw, 408, "request_timeout")
        self.assertLess(dt, 11.5, f"408 at {dt:.2f}s after connect: the deadline restarted at hand-off")
        self.assertEqual(self.server.balance(a["id"]), 0, "I6: a 408 moved money")

    def test_head_at_9s_body_at_once_is_served(self):
        """The same deadline is not cut short: head completes at ~9 s, body right after -> 200."""
        a = self.funded(0, "dl9")
        key = f"dl9-{uuid.uuid4().hex}"
        head, body = deposit_request(a["id"], 7, key=key)
        c = Conn(self.server.port)
        c.send(head[:-4])
        time.sleep(max(0.0, c.t0 + 9.0 - time.monotonic()))
        c.send(head[-4:] + body)
        raw, dt = c.read_all()
        c.close()
        assert_json_reply(self, raw, 200)
        self.assertEqual(self.server.balance(a["id"]), 7)

    def test_idle_connection_no_bytes_is_closed_by_10s(self):
        c = Conn(self.server.port)
        raw, dt = c.read_all()
        c.close()
        self.assertLess(dt, 11.5, f"an idle connection was kept {dt:.2f}s")
        if raw:
            assert_json_reply(self, raw, 408, "request_timeout")


# --------------------------------------------------------------------------------------------
@built
@parked
class HandOffBytes(C3Case):
    """Bytes read while parked are handed over exactly once, at every split around the head end."""

    def test_every_split_around_the_head_end(self):
        a = self.funded(0, "split")
        n = 0
        for cut_from_end in range(0, 6):
            for body_with_head in (0, 1, 5):
                with self.subTest(cut=cut_from_end, body_with_head=body_with_head):
                    head, body = deposit_request(a["id"], 1, key=f"sp-{uuid.uuid4().hex}")
                    data = head + body
                    split = len(head) - cut_from_end + body_with_head
                    c = Conn(self.server.port)
                    c.send(data[:split])
                    time.sleep(0.15)
                    c.send(data[split:])
                    raw, _ = c.read_all()
                    c.close()
                    assert_json_reply(self, raw, 200)
                    n += 1
                    self.assertEqual(self.server.balance(a["id"]), n, "a split head/body lost or doubled bytes")

    def test_head_and_body_in_one_segment_with_trailing_bytes(self):
        """A second request pipelined right behind the first: the first is answered correctly from
        the handed-over bytes and moves money exactly once; the trailing request may be ignored
        (one request per connection) but never applied twice nor corrupt the first."""
        a = self.funded(0, "pipe")
        k1, k2 = f"p1-{uuid.uuid4().hex}", f"p2-{uuid.uuid4().hex}"
        h1, b1 = deposit_request(a["id"], 3, key=k1)
        h2, b2 = deposit_request(a["id"], 100, key=k2)
        c = Conn(self.server.port)
        c.send(h1 + b1 + h2 + b2)
        raw, _ = c.read_all()
        c.close()
        p = assert_json_reply(self, raw, 200)
        self.assertEqual(json.loads(p[2])["balance"], 3, raw[:300])
        self.settle()
        bal = self.server.balance(a["id"])
        self.assertIn(bal, (3, 103), "the pipelined bytes were misparsed")

    def test_head_then_fin(self):
        """Client sends the full request and half-closes (SHUT_WR) while still parked."""
        a = self.funded(0, "fin")
        head, body = deposit_request(a["id"], 2)
        c = Conn(self.server.port)
        c.send(head + body)
        c.sock.shutdown(socket.SHUT_WR)
        raw, _ = c.read_all()
        c.close()
        assert_json_reply(self, raw, 200)


# --------------------------------------------------------------------------------------------
@built
@parked
class ManyParked(C3Case):
    """> 512 parked sockets (one Windows select() set) and the 4096 parked cap."""

    def open_idle(self, n, payload=b""):
        socks, refused = [], 0
        for _ in range(n):
            try:
                s = fast_connect(self.server.port, 5)
                if payload:
                    s.sendall(payload)
                socks.append(s)
            except OSError:
                refused += 1
        return socks, refused

    def test_1200_heads_completed_late_are_all_served(self):
        """1200 connections park with a partial head, then each completes it. If any selector
        shard were not polled (e.g. sockets beyond the first 512), those would never be read and
        would 408 instead of 200."""
        t_open = time.monotonic()
        socks, refused = self.open_idle(1200, b"GET /health HTTP/1.1" + CRLF)
        try:
            self.assertEqual(refused, 0, f"{refused} of 1200 connections refused")
            time.sleep(0.5)
            for s in socks:
                s.sendall(b"Host: x" + CRLF + CRLF)
            # every head must complete well inside its own 10 s deadline, or the attack proves
            # nothing (a 408 would then be correct)
            self.assertLess(time.monotonic() - t_open, 8.0, "attack too slow: heads completed late")

            def read(s):
                got = b""
                with contextlib.suppress(OSError):
                    s.settimeout(15)
                    while True:
                        c = s.recv(65536)
                        if not c:
                            break
                        got += c
                p = parse_response(got)
                return p[0] if p else None

            with cf.ThreadPoolExecutor(64) as ex:
                statuses = list(ex.map(read, socks))
            bad = [st for st in statuses if st != 200]
            print(f"\n[a17] 1200 late heads: {len(bad)} not 200 ({set(bad)})", file=sys.stderr)
            self.assertEqual(bad, [], "parked connections beyond one selector were never served")
        finally:
            for s in socks:
                with contextlib.suppress(OSError):
                    s.close()

    def test_parked_rst_churn_leaks_nothing(self):
        """3000 connections that park and are reset by the client: no parked entry or fd may leak.
        Afterwards 1500 idle connections still fit and /health answers < 2 s."""
        for _ in range(3):
            socks, _ = self.open_idle(1000, b"GET /he")
            for s in socks:
                with contextlib.suppress(OSError):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
                    s.close()
        time.sleep(1.0)
        socks, refused = self.open_idle(1500)
        try:
            self.assertEqual(refused, 0, f"{refused} of 1500 refused after RST churn (leaked parked slots?)")
            st, dt = get_health(self.server.port, 10)
            self.assertEqual(st, 200)
            self.assertLess(dt, 2.0, f"/health {dt:.2f}s with 1500 idle after churn")
        finally:
            for s in socks:
                s.close()

    @slow
    def test_over_4096_parked(self):
        """4500 idle connections: above the parked cap the server stops accepting (the excess waits
        in the backlog or is refused); it must not crash or spawn threads, and must recover (I20)
        once they go."""
        socks, refused = self.open_idle(4500)
        try:
            print(f"\n[a17] 4500 idle: {len(socks)} connected, {refused} refused", file=sys.stderr)
            self.assertGreaterEqual(len(socks), 1500)
            time.sleep(1.0)
            self.assertIsNone(self.server.proc.poll(), "server died with > 4096 parked")
        finally:
            for s in socks:
                with contextlib.suppress(OSError):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
                    s.close()
        time.sleep(1.0)
        st, dt = get_health(self.server.port, 5)
        self.assertEqual(st, 200)
        self.assertLess(dt, 1.0, f"I20: /health {dt:.2f}s after the parked flood")

    def test_parked_flood_with_money_burst(self):
        """1500 idle + 600 half-sent request lines, then a 40-way keyed deposit burst: zero
        refusals, every deposit 200 (<= 100 writers: zero 503), /health < 2 s."""
        idle, r1 = self.open_idle(1500)
        half, r2 = self.open_idle(600, b"POST /accounts/x/withdraw HTTP/1.1")
        try:
            self.assertEqual((r1, r2), (0, 0), "connections refused while parking")
            st, dt = get_health(self.server.port, 10)
            self.assertEqual(st, 200)
            self.assertLess(dt, 2.0)
            from breaker_stress import Op, build_request, send
            acct = self.server.create_account("flood3a")
            ops = [Op("deposit", None, acct["id"], 1, f"f3a-{uuid.uuid4().hex}", i) for i in range(40)]
            with cf.ThreadPoolExecutor(40) as ex:
                res = list(ex.map(lambda op: send(self.server.port, build_request(op, {})), ops))
            self.assertEqual([r[0] for r in res], [200] * 40, [r[:3] for r in res if r[0] != 200][:3])
            self.assertEqual(self.server.balance(acct["id"]), 40)
        finally:
            for s in idle + half:
                with contextlib.suppress(OSError):
                    s.close()


def peak_rss_mb(pid):
    """Peak resident memory of a process in MiB (Linux VmHWM, Windows PeakWorkingSet64)."""
    if sys.platform.startswith("linux"):
        with open(f"/proc/{pid}/status", encoding="ascii") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) / 1024
        return None
    import subprocess
    out = subprocess.run(["powershell", "-NoProfile", "-Command",
                          f"(Get-Process -Id {pid}).PeakWorkingSet64"],
                         capture_output=True, text=True, timeout=30).stdout.strip()
    return int(out) / 2**20 if out.isdigit() else None


@built
@parked
@slow
class HeadMemoryFlood(C3Case):
    """Q3.1-B: parked heads are budgeted at 64 MiB; while over it, heads already > 16 KiB stop
    being read, small heads keep flowing. Bound 64 MiB + 4096 x 16 KiB = 128 MiB of head bytes.
    Attack: 600 connections each pushing a legal-length but endless head (99 lines of 60 KB,
    never a blank line, 3.5 GB offered in total) while 40 small keyed deposits must be answered
    within I19 and the server's peak RSS stays bounded."""

    LINE = b"X-Fill: " + b"f" * 60_000 + CRLF
    RSS_LIMIT_MB = 400  # 128 MiB of heads + interpreter + 266 thread stacks, with room

    def test_large_head_flood(self):
        base = peak_rss_mb(self.server.proc.pid)
        stop = threading.Event()
        sent = []

        def pusher():
            with contextlib.suppress(OSError):
                c = Conn(self.server.port, timeout=20)
                c.send(b"POST /transfers HTTP/1.1" + CRLF)
                n = 0
                for _ in range(99):
                    if stop.is_set():
                        break
                    c.sock.sendall(self.LINE)
                    n += len(self.LINE)
                sent.append(n)
                c.read_all()
                c.close()

        pushers = [threading.Thread(target=pusher, daemon=True) for _ in range(600)]
        old = threading.stack_size(256 * 1024)
        try:
            for t in pushers:
                t.start()
        finally:
            threading.stack_size(old)
        time.sleep(2.0)  # the budget is now exceeded and the big heads are paused
        from breaker_stress import Op, build_request, send
        acct = self.server.create_account("memflood")
        ops = [Op("deposit", None, acct["id"], 1, f"mf-{uuid.uuid4().hex}", i) for i in range(40)]
        with cf.ThreadPoolExecutor(40) as ex:
            res = list(ex.map(lambda op: send(self.server.port, build_request(op, {})), ops))
        stop.set()
        for t in pushers:
            t.join(30)
        peak = peak_rss_mb(self.server.proc.pid)
        slowest = max(r[3] for r in res)
        print(f"\n[a17] head flood: 40 deposits {sorted({r[0] for r in res})}, slowest {slowest:.2f}s, "
              f"peak RSS {base} -> {peak} MiB", file=sys.stderr)
        self.assertEqual([r[0] for r in res], [200] * 40, [r[:3] for r in res if r[0] != 200][:3])
        self.assertLess(slowest, 10.0, "I19: a small request waited >= 10 s behind the head flood")
        self.assertEqual(self.server.balance(acct["id"]), 40)
        if peak is not None:
            self.assertLess(peak, self.RSS_LIMIT_MB, f"Q3.1-B: peak RSS {peak:.0f} MiB under the head flood")


if __name__ == "__main__":
    unittest.main()
