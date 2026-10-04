"""D3.3a: a connection waits here, with no handler thread and no handler
slot, until its request head (request line + headers up to the blank line)
has arrived. A fixed pool of reader threads (one selector each) reads the
heads. The decisions themselves are made by the server's head probe, which
runs the handler's own head-parsing code on the bytes received so far, so
every stage-1 head rule and reply is the one a handler would give.

Per connection, the shard only tracks where lines end. It asks the probe
only when that can settle something: the request line is complete, a blank
line ends the head, a line is over the 64 KiB limit, there are more lines
than 100 headers allow, the peer closed, or the deadline passed."""

import collections
import math
import selectors
import socket
import sys
import threading
import time

PARKED_MAX = 4096
# Windows select() handles at most 512 sockets per call; one is the wake socket.
SHARD_SIZE = 500
# Q3.1-B: while parked heads hold more than this in total, connections whose
# head is already over SMALL_HEAD_BYTES are not read until it frees.
HEAD_BUDGET_BYTES = 64 * 1024 * 1024
SMALL_HEAD_BYTES = 16 * 1024
# Stage-1 head limits (http.client): a line over 64 KiB; more than 100
# header lines (the terminating blank line counts), plus the request line.
MAX_LINE = 65536
MAX_HEAD_LINES = 1 + 100
RECV_BYTES = 65536
# Parked replies are a few hundred bytes; they never wait on a slow reader.
REPLY_TIMEOUT_S = 1
MAX_WAIT_S = 0.5

HEAD_COMPLETE = "head complete"


class Parked:
    """One connection that has not finished its request head."""

    __slots__ = ("sock", "addr", "deadline", "buf", "eof", "lines", "line_start", "scanned",
                 "paused", "drain_left", "reply", "timeout_reply", "shard")

    def __init__(self, sock, addr, deadline):
        self.sock, self.addr, self.deadline = sock, addr, deadline
        self.buf = bytearray()
        self.eof = False
        self.lines = 0          # complete lines seen
        self.line_start = 0     # where the current, unfinished line starts
        self.scanned = 0        # bytes already searched for line ends
        self.paused = False     # not read while the head budget is exceeded
        self.drain_left = 0     # body bytes to discard before `reply` is sent
        self.reply = None
        self.timeout_reply = None
        self.shard = None

    def scan(self):
        """Track line ends in the new bytes. True if the probe can now
        settle the head (or reject it)."""
        buf, settle = self.buf, False
        pos = self.scanned
        while (end := buf.find(b"\n", pos)) >= 0:
            self.lines += 1
            length = end + 1 - self.line_start
            if (self.lines == 1 or length > MAX_LINE or self.lines > MAX_HEAD_LINES
                    or buf[self.line_start:end + 1] in (b"\r\n", b"\n")):
                settle = True
            self.line_start = pos = end + 1
        self.scanned = len(buf)
        return settle or len(buf) - self.line_start > MAX_LINE


class ParkingLot:
    """The shards plus the shared head budget. `probe(addr, data, eof,
    expired)` returns None (more bytes needed), HEAD_COMPLETE, or
    (reply, drain_left, timeout_reply). `ready(conn)` takes a connection
    whose head is complete; `released()` is called once for every
    connection that leaves the lot any other way."""

    def __init__(self, probe, ready, released):
        self.probe, self.ready, self.released = probe, ready, released
        self.stopping = threading.Event()
        self._lock = threading.Lock()
        self._head_bytes = 0
        self.large_probe = threading.Lock()
        self.shards = [Shard(self, n) for n in range(math.ceil(PARKED_MAX / SHARD_SIZE))]

    def start(self):
        for shard in self.shards:
            shard.start()

    def stop(self):
        self.stopping.set()
        for shard in self.shards:
            shard.wake()
        for shard in self.shards:
            if shard.is_alive():
                shard.join(5)

    def park(self, sock, addr, deadline):
        conn = Parked(sock, addr, deadline)
        with self._lock:
            shard = min(self.shards, key=lambda s: s.count)
            shard.count += 1
        conn.shard = shard
        shard.add(conn)

    def head_bytes(self, delta=0):
        with self._lock:
            self._head_bytes += delta
            return self._head_bytes

    def over_budget(self):
        return self.head_bytes() > HEAD_BUDGET_BYTES

    def left(self, conn, keep_head=False):
        """`conn` no longer belongs to its shard (idempotent). With
        keep_head, its bytes stay charged to the budget (A3.1-1): a complete
        head waiting for a handler slot still holds that memory, until
        release_head()."""
        with self._lock:
            if conn.shard is None:
                return
            conn.shard.count -= 1
            conn.shard = None
            if keep_head:
                return
            self._head_bytes -= len(conn.buf)
        conn.buf = bytearray()

    def release_head(self, conn):
        """A complete head left the ready queue (to a handler, or closed):
        stop charging its bytes. Returns them."""
        head = bytes(conn.buf)
        with self._lock:
            self._head_bytes -= len(conn.buf)
        conn.buf = bytearray()
        return head


class Shard(threading.Thread):
    def __init__(self, lot, index):
        super().__init__(name=f"pocketful-parked-{index}", daemon=True)
        self.lot = lot
        self.count = 0  # guarded by the lot's lock
        self._inbox = collections.deque()
        self._conns = set()
        self._paused = set()
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self._wake_w.setblocking(False)
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._wake_r, selectors.EVENT_READ)

    def add(self, conn):
        self._inbox.append(conn)
        self.wake()

    def wake(self):
        try:
            self._wake_w.send(b"\0")
        except OSError:
            pass  # already pending (buffer full) or shutting down

    def run(self):
        try:
            while not self.lot.stopping.is_set():
                self._take_inbox()
                for key, _ in self._selector.select(self._wait()):
                    if key.fileobj is self._wake_r:
                        self._clear_wake()
                    else:
                        self._guarded(self._on_readable, key.data)
                self._expire()
                if self._paused and not self.lot.over_budget():
                    for conn in list(self._paused):
                        self._resume(conn)
        finally:
            while self._inbox:
                self._close(self._inbox.popleft())
            for conn in list(self._conns):
                self._close(conn)
            self._selector.close()
            self._wake_r.close()
            self._wake_w.close()

    # --- bookkeeping ------------------------------------------------------

    def _take_inbox(self):
        while self._inbox:
            conn = self._inbox.popleft()
            try:
                conn.sock.setblocking(False)
                self._selector.register(conn.sock, selectors.EVENT_READ, conn)
            except (OSError, ValueError):
                self._close(conn)
                continue
            self._conns.add(conn)

    def _clear_wake(self):
        try:
            while self._wake_r.recv(4096):
                pass
        except OSError:
            pass

    def _wait(self):
        if not self._conns:
            return MAX_WAIT_S
        soonest = min(conn.deadline for conn in self._conns)
        return min(MAX_WAIT_S, max(0.0, soonest - time.monotonic()))

    def _detach(self, conn, keep_head=False):
        if conn in self._conns:
            self._conns.discard(conn)
            self._paused.discard(conn)
            if not conn.paused:
                try:
                    self._selector.unregister(conn.sock)
                except (KeyError, ValueError):
                    pass
            self.lot.left(conn, keep_head)

    def _close(self, conn):
        """Close a connection that never reached a handler."""
        self._detach(conn)
        self.lot.left(conn)
        try:
            conn.sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        conn.sock.close()
        self.lot.released()

    def _send_and_close(self, conn, reply):
        if reply:
            try:
                conn.sock.settimeout(REPLY_TIMEOUT_S)
                conn.sock.sendall(reply)
            except OSError:
                pass  # the client is gone
        self._close(conn)

    def _pause(self, conn):
        self._selector.unregister(conn.sock)
        conn.paused = True
        self._paused.add(conn)

    def _resume(self, conn):
        self._paused.discard(conn)
        conn.paused = False
        self._selector.register(conn.sock, selectors.EVENT_READ, conn)

    def _guarded(self, step, conn, *args):
        try:
            step(conn, *args)
        except Exception as exc:  # one connection must never stop the shard
            sys.stderr.write(f"parked connection {conn.addr}: {exc!r}\n")
            self._close(conn)

    # --- the head ---------------------------------------------------------

    def _on_readable(self, conn):
        if conn.reply is not None:
            return self._drain(conn)
        size = RECV_BYTES
        over = self.lot.over_budget()
        if over:
            size = max(1, SMALL_HEAD_BYTES + 1 - len(conn.buf))
        try:
            data = conn.sock.recv(size)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            return self._close(conn)  # reset: nothing to answer
        if not data:
            conn.eof = True
        else:
            conn.buf += data
            self.lot.head_bytes(len(data))
        if conn.scan() or conn.eof:
            self._settle(conn, expired=False)
        if conn in self._conns and over and len(conn.buf) > SMALL_HEAD_BYTES:
            self._pause(conn)

    def _settle(self, conn, expired):
        if len(conn.buf) > SMALL_HEAD_BYTES:
            # Parsing a head briefly needs several times its size (line
            # copies, the decoded text, the header object): one large head
            # at a time keeps that bounded across shards.
            with self.lot.large_probe:
                result = self.lot.probe(conn.addr, conn.buf, conn.eof, expired)
        else:
            result = self.lot.probe(conn.addr, conn.buf, conn.eof, expired)
        if result is None:
            return
        if result == HEAD_COMPLETE:
            self._detach(conn, keep_head=True)
            return self.lot.ready(conn)
        reply, drain_left, timeout_reply = result
        if drain_left == 0 or conn.eof:
            return self._send_and_close(conn, reply)
        if expired:
            return self._send_and_close(conn, timeout_reply)
        # R1.3-A: the declared body is read and discarded before the reply.
        conn.reply, conn.timeout_reply, conn.drain_left = reply, timeout_reply, drain_left
        self.lot.head_bytes(-len(conn.buf))
        conn.buf = bytearray()
        if conn.paused:
            self._resume(conn)

    def _drain(self, conn):
        try:
            data = conn.sock.recv(min(RECV_BYTES, conn.drain_left))
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            return self._close(conn)
        conn.drain_left -= len(data)
        if not data or conn.drain_left <= 0:
            self._send_and_close(conn, conn.reply)

    def _expire(self):
        now = time.monotonic()
        for conn in [c for c in self._conns if c.deadline <= now]:
            if conn.reply is not None:
                self._guarded(self._send_and_close, conn, conn.timeout_reply)
            else:
                self._guarded(self._settle, conn, True)
