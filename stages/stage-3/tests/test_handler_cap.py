"""Unit 3.1, D3.3: at most MAX_HANDLERS requests are handled at once; more
complete requests wait for a slot without a thread (D3.3a: parked, see
test_parking.py), and every complete request still gets a JSON answer once a
slot frees."""

import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from harness import STAGE_DIR, ServerProcess

if STAGE_DIR not in sys.path:
    sys.path.insert(0, STAGE_DIR)

from app import db  # noqa: E402
from app.server import MAX_HANDLERS, Handler, WalletServer  # noqa: E402

CAP = 4


def read_response(sock):
    reply = b""
    while chunk := sock.recv(65536):
        reply += chunk
    head, _, payload = reply.partition(b"\r\n\r\n")
    return int(head.split(b" ", 2)[1]), json.loads(payload)


def handler_threads():
    return [t for t in threading.enumerate()
            if t.is_alive() and "process_request_thread" in t.name]


class SlowAccountCreate:
    """A POST /accounts whose body is only half sent, holding a handler."""

    BODY = json.dumps({"owner": "slow-client"}).encode()

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=15)
        head = (f"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(self.BODY)}\r\n\r\n").encode()
        self.sock.sendall(head + self.BODY[:5])

    def send_rest(self):
        self.sock.sendall(self.BODY[5:])

    def answer(self):
        try:
            return read_response(self.sock)
        finally:
            self.sock.close()

    def finish(self):
        self.send_rest()
        return self.answer()


class HandlerCapInProcessTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="pocketful-cap-")
        self.addCleanup(shutil.rmtree, self.tmpdir, True)
        db_path = os.path.join(self.tmpdir, "wallet.db")
        db.init_db(db_path)
        self.active, self.peak = 0, 0
        counter = threading.Lock()
        test = self

        class CountingHandler(Handler):
            def handle(self):
                with counter:
                    test.active += 1
                    test.peak = max(test.peak, test.active)
                try:
                    super().handle()
                finally:
                    with counter:
                        test.active -= 1

        self.server = WalletServer(("127.0.0.1", 0), db_path, max_handlers=CAP)
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

    def test_default_cap_is_256_with_backlog_1024(self):
        self.assertEqual(MAX_HANDLERS, 256)
        self.assertEqual(WalletServer.request_queue_size, 1024)

    def test_slow_connections_never_exceed_the_cap_and_all_get_answers(self):
        slow = [SlowAccountCreate(self.port) for _ in range(3 * CAP)]
        deadline = time.monotonic() + 5
        while self.active < CAP and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.3)  # give any excess connection the chance to be spawned
        self.assertEqual(self.active, CAP)
        self.assertEqual(len(handler_threads()), CAP, [t.name for t in handler_threads()])

        fast_results = []

        def fast(path):
            with socket.create_connection(("127.0.0.1", self.port), timeout=15) as sock:
                sock.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
                fast_results.append(read_response(sock))

        fast_threads = [threading.Thread(target=fast, args=("/health",)) for _ in range(5)]
        for thread in fast_threads:
            thread.start()
        time.sleep(0.5)
        self.assertEqual(fast_results, [], "a request was handled beyond the cap")
        self.assertLessEqual(len(handler_threads()), CAP)

        # Every body completes now. D3.3a: the 10 s deadline runs from connect,
        # so a client still waiting for a slot must not be held back further.
        for s in slow:
            s.send_rest()
        answers = [s.answer() for s in slow]
        for thread in fast_threads:
            thread.join(15)
        for status, body in answers:
            self.assertEqual(status, 201, body)
            self.assertEqual(body["owner"], "slow-client")
        self.assertEqual(fast_results, [(200, {"ok": True})] * 5)
        self.assertLessEqual(self.peak, CAP, "more handlers than the cap ran at once")

    def test_shutdown_returns_while_every_slot_is_held(self):
        """serve_forever must stop even when get_request is waiting for a
        slot, i.e. all slots held and another connection in the backlog."""
        slow = [SlowAccountCreate(self.port) for _ in range(CAP)]
        self.addCleanup(lambda: [s.sock.close() for s in slow])
        deadline = time.monotonic() + 5
        while self.active < CAP and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.active, CAP)
        waiting = socket.create_connection(("127.0.0.1", self.port), timeout=15)
        self.addCleanup(waiting.close)
        waiting.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        time.sleep(0.3)  # the serving thread is now blocked on a free slot

        done = threading.Event()
        threading.Thread(target=lambda: (self.server.shutdown(), done.set()),
                         daemon=True).start()
        self.assertTrue(done.wait(3), "shutdown() hung while every handler slot was held")
        self.assertEqual(self.active, CAP, "shutdown must not cut off running handlers")
        # The held requests still complete normally after the stop.
        for status, body in [s.finish() for s in slow]:
            self.assertEqual(status, 201, body)


class HandlerCapEnvTest(unittest.TestCase):
    """MAX_HANDLERS is honoured by `python -m app` (black box)."""

    def test_env_cap_holds_extra_requests_until_a_slot_frees(self):
        tmpdir = tempfile.mkdtemp(prefix="pocketful-cap-env-")
        self.addCleanup(shutil.rmtree, tmpdir, True)
        with mock.patch.dict(os.environ, {"MAX_HANDLERS": "2"}):
            server = ServerProcess(os.path.join(tmpdir, "wallet.db")).start()
        self.addCleanup(server.stop)
        slow = [SlowAccountCreate(server.port) for _ in range(2)]
        time.sleep(0.3)
        with socket.create_connection(("127.0.0.1", server.port), timeout=15) as sock:
            sock.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            sock.settimeout(0.7)
            with self.assertRaises(socket.timeout, msg="third request served beyond MAX_HANDLERS=2"):
                sock.recv(1)
            sock.settimeout(15)
            self.assertEqual([s.finish()[0] for s in slow], [201, 201])
            self.assertEqual(read_response(sock), (200, {"ok": True}))


if __name__ == "__main__":
    unittest.main()
