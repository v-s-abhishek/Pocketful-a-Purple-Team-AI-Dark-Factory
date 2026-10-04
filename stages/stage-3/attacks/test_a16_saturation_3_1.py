"""Unit 3.1 attacks, round 2 (Breaker reviewer-stqg): the D3.3 handler cap under full saturation,
which test_a15 only exercised at 64 slow connections.

Q3-A: saturating all 256 slots is out of scope for I19's 10 s bound, but even then: no 5xx, never
more than 256 handlers, and I20 recovery once the slow connections end. D3.3: further connections
wait in the listen backlog and are served (not dropped) when a slot frees.

The cap is observed black-box: a connection beyond the cap gets no answer while every slot is
held, and is answered once one frees. MAX_HANDLERS (app/__main__.py) shrinks the cap so the
property can be shown in seconds; the 256 default is attacked in FullSaturation.
"""
import contextlib
import json
import os
import socket
import sys
import threading
import time
import unittest
import uuid

from breaker_harness import NO_RESPONSE, REQUEST_TIMEOUT, SLOW, AttackCase, Server
from breaker_stress import parse_response
from test_a15_concurrency_3_1 import LINGER0, C3Case, built

CRLF = b"\r\n"
slow = unittest.skipUnless(SLOW, "set ATTACK_SLOW=1")


def fast_connect(port, timeout):
    """Connect blocking, then set the timeout. On Windows a connect made with a timeout waits in
    select() and costs one ~15.6 ms timer tick each, so 1000 sequential connects would take
    15 s and the first ones would pass the server's 10 s deadline before the attack even starts."""
    s = socket.create_connection(("127.0.0.1", port))
    s.settimeout(timeout)
    return s


class Holder:
    """One connection that holds a handler slot: headers sent, body half sent, then nothing.
    release() closes it (the handler sees EOF and frees the slot); otherwise the server's own
    10 s request deadline ends it with a JSON 408."""

    BODY = json.dumps({"owner": "holder"}).encode()

    def __init__(self, port):
        self.sock = fast_connect(port, 30)
        self.sock.sendall(b"POST /accounts HTTP/1.1" + CRLF + b"Host: x" + CRLF
                          + b"Content-Type: application/json" + CRLF
                          + b"Content-Length: %d" % len(self.BODY) + CRLF + CRLF + self.BODY[:4])
        self.t0 = time.monotonic()
        self.reply, self.at = b"", None

    def wait_reply(self):
        with contextlib.suppress(OSError):
            while True:
                c = self.sock.recv(65536)
                if not c:
                    break
                self.reply += c
        self.at = time.monotonic()
        with contextlib.suppress(OSError):
            self.sock.close()
        return self

    def release(self):
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            self.sock.close()


def get_health(port, timeout):
    """GET /health on a fresh connection; (status, seconds) with status NO_RESPONSE on failure."""
    t0 = time.monotonic()
    try:
        with fast_connect(port, timeout) as s:
            s.sendall(b"GET /health HTTP/1.1" + CRLF + b"Host: x" + CRLF + CRLF)
            data = b""
            while True:
                c = s.recv(65536)
                if not c:
                    break
                data += c
        p = parse_response(data)
        return (p[0] if p else NO_RESPONSE), time.monotonic() - t0
    except OSError:
        return NO_RESPONSE, time.monotonic() - t0


class SmallCapCase(C3Case):
    """A server started with MAX_HANDLERS=CAP so the cap is visible quickly."""

    CAP = 8

    @classmethod
    def setUpClass(cls):
        old = os.environ.get("MAX_HANDLERS")
        os.environ["MAX_HANDLERS"] = str(cls.CAP)
        try:
            super().setUpClass()
        finally:
            if old is None:
                os.environ.pop("MAX_HANDLERS", None)
            else:
                os.environ["MAX_HANDLERS"] = old


@built
class HandlerCapBlackBox(SmallCapCase):
    def test_request_beyond_cap_waits_then_is_served(self):
        """CAP slots held -> a /health on a new connection is not answered; free one slot -> it
        is answered within 1 s. Proves both 'never more than CAP handlers' and 'backlog, not
        dropped'."""
        holders = [Holder(self.server.port) for _ in range(self.CAP)]
        time.sleep(0.5)  # every holder now has a handler blocked in the body read
        out = {}
        th = threading.Thread(target=lambda: out.update(r=get_health(self.server.port, 20)))
        th.start()
        th.join(1.5)
        self.assertTrue(th.is_alive(), f"D3.3: /health answered while all {self.CAP} slots were held "
                                       f"({out.get('r')}): more than {self.CAP} handlers ran at once")
        t_free = time.monotonic()
        holders[0].release()
        th.join(5)
        self.assertFalse(th.is_alive(), "the queued request was not served after a slot freed")
        st, _ = out["r"]
        self.assertEqual(st, 200, "D3.3: a connection waiting in the backlog was dropped")
        self.assertLess(time.monotonic() - t_free, 1.0, "I20: slot not handed over within 1 s")
        for h in holders[1:]:
            h.release()

    def test_cap_slots_are_returned_on_every_path(self):
        """Cycle CAP x 20 connections through every way a handler can end (full request, client
        reset mid-body, EOF mid-headers, oversized body, 404, 408-free early close). If any path
        leaked a slot, the server would wedge after at most CAP leaks."""
        port = self.server.port
        a = self.funded(10**6, "slots")
        body = json.dumps({"amount": 1}).encode()
        ok_req = (f"POST /accounts/{a['id']}/deposit HTTP/1.1\r\nHost: x\r\nContent-Type: "
                  f"application/json\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
        shapes = [
            ok_req,
            ok_req[:-3],                                         # EOF mid-body
            b"POST /accounts HTTP/1.1\r\nHost: x\r\nConte",       # EOF mid-headers
            b"POST /accounts HTTP/1.1\r\nContent-Length: 2000000\r\n\r\nxx",  # > drain limit
            b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n",
            b"\r\n",
            b"",                                                 # connect then close
        ]
        for i in range(self.CAP * 20):
            payload = shapes[i % len(shapes)]
            with contextlib.suppress(OSError):
                s = fast_connect(port, 5)
                if payload:
                    s.sendall(payload)
                if i % 3 == 0:  # hard reset instead of a FIN
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
                s.close()
        time.sleep(0.5)
        # every slot must be free again: CAP holders are all accepted, and one more request
        # beyond them still waits (the cap did not grow either)
        holders = [Holder(port) for _ in range(self.CAP)]
        time.sleep(0.5)
        for h in holders:
            h.release()
        st, dt = get_health(port, 5)
        self.assertEqual(st, 200)
        self.assertLess(dt, 1.0, f"I20: /health took {dt:.2f}s after {self.CAP * 20} odd connections "
                                 "(a handler slot leaked)")


@built
class FullSaturation(C3Case):
    """The default 256 cap, saturated by slow clients (Q3-A). Each holder has a complete head and
    a half-sent body, so it holds a slot (D3.3a). The deadline runs from connect, so the 44 beyond
    the cap get their JSON 408 as soon as a slot frees at ~10 s, not 10 s later (D3.3a). That the
    cap itself is never exceeded is shown black-box in HandlerCapBlackBox."""

    N = 300  # > 256

    def test_300_slow_clients_cap_and_recover(self):
        holders = [Holder(self.server.port) for _ in range(self.N)]
        t0 = time.monotonic()
        threads = [threading.Thread(target=h.wait_reply, daemon=True) for h in holders]
        for t in threads:
            t.start()
        # while saturated a writer is not served (that is the point of the cap), but no request
        # may be answered with a 5xx or dropped
        for t in threads:
            t.join(40)
        alive = sum(t.is_alive() for t in threads)
        self.assertEqual(alive, 0, f"{alive} slow clients never got an answer or a close in 40 s")
        late = [round(h.at - h.t0, 2) for h in holders if h.at - h.t0 > 11.5]
        statuses = {}
        bad = []
        for h in holders:
            p = parse_response(h.reply) if h.reply else None
            st = p[0] if p else None
            statuses[st] = statuses.get(st, 0) + 1
            if h.reply and (p is None or st != 408):
                bad.append(h.reply[:200])
            elif p:
                json.loads(p[2])
        print(f"\n[a16] {self.N} slow clients: statuses {statuses}, last answer "
              f"{max(h.at for h in holders) - t0:.2f}s after the first connect", file=sys.stderr)
        self.assertEqual(bad, [], "Q3-A: a slow client got something other than a JSON 408")
        self.assertNotIn(None, statuses, "D3.3: a slow client in the backlog was closed without an answer")
        self.assertEqual(late[:10], [], "one deadline from connect: a 408 came > 11.5 s after connect")
        # I20: recovered (assertNoWedge in tearDown also checks /health + two fresh writes < 1 s)


@built
@slow
class SaturatedWriters(C3Case):
    """Writers, not slow clients, filling every slot: 600 keyed deposits at once on one account
    while an external writer holds SQLite's lock for 1.5 s. Every full request must get a JSON
    200 or 503 busy (no effect) and every 200 must be in the ledger; I19 (< 10 s) is reported and
    asserted, since these clients send their whole request at once (note 2)."""

    def test_600_writers_behind_external_lock(self):
        from test_a15_concurrency_3_1 import ExternalLock
        from breaker_stress import Op, build_request, send
        import concurrent.futures as cf

        a = self.funded(0, "sat")
        ops = [Op("deposit", None, a["id"], 1, f"sat-{uuid.uuid4().hex}", i) for i in range(600)]
        lk = ExternalLock(self.server.db_path, 1.5).start()
        with cf.ThreadPoolExecutor(600) as ex:
            res = list(ex.map(lambda op: send(self.server.port, build_request(op, {}), timeout=30), ops))
        lk.join()
        self.settle()
        with contextlib.closing(self.server.db()) as c:
            committed = {r[0] for r in c.execute(
                "SELECT key FROM idempotency_keys WHERE account_id = ?", (a["id"],))}
        counts, lost, effect, slowest = {}, [], [], 0.0
        for op, (st, _, body, dt) in zip(ops, res):
            counts[st] = counts.get(st, 0) + 1
            slowest = max(slowest, dt)
            if st == 200 and op.key not in committed:
                lost.append(op.key)
            if st != 200 and op.key in committed:
                effect.append((st, body[:100]))
        lat = sorted(r[3] for r in res)
        print(f"\n[a16] 600 writers: {counts}, p50 {lat[300]:.2f}s p99 {lat[593]:.2f}s max {slowest:.2f}s",
              file=sys.stderr)
        self.assertEqual(lost, [], "a 2xx is not in the ledger")
        self.assertEqual(effect, [], "a non-2xx had an effect (or the client saw no answer to a commit)")
        self.assertEqual(set(counts) - {200, 503}, set(), f"unexpected statuses {counts}")
        self.assertLess(slowest, REQUEST_TIMEOUT, f"I19: a request took {slowest:.2f}s")


if __name__ == "__main__":
    unittest.main()
