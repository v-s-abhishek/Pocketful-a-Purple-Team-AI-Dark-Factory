"""A3.1-3 measurement: how much memory do complete large heads take once
they are held by handlers?

Starts `python -m app` (MAX_HANDLERS default 256) and opens --clients
connections. Each sends a complete POST /accounts head of about 6.4 MB
(98 header lines of --line bytes, under the stage-1 64 KiB / 100-header
limits) plus the first byte of its body, then stalls, so a handler that
takes it holds the parsed head until the 10 s deadline (408). Prints one
JSON line: the server's peak RSS before and after, and the replies.

    python stress/measure_handler_heads.py --clients 256
"""

import argparse
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time

STAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(STAGE_DIR, "tests"))

from harness import ServerProcess  # noqa: E402
from test_parking import peak_rss_bytes  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clients", type=int, default=256)
    parser.add_argument("--line", type=int, default=65000, help="bytes per header line")
    parser.add_argument("--stagger", type=float, default=0.0,
                        help="seconds between client starts (so heads complete one after another)")
    args = parser.parse_args()

    tmpdir = tempfile.mkdtemp(prefix="pocketful-a313-")
    server = ServerProcess(os.path.join(tmpdir, "wallet.db")).start()
    try:
        line = b"X-Big: " + b"a" * (args.line - 9) + b"\r\n"
        body = json.dumps({"owner": "a313"}).encode()
        head = (b"POST /accounts HTTP/1.1\r\nContent-Length: %d\r\n" % len(body)
                + line * 98 + b"\r\n")
        base = peak_rss_bytes(server.proc.pid)
        replies = [None] * args.clients

        def client(n):
            try:
                with socket.create_connection(("127.0.0.1", server.port), timeout=30) as sock:
                    sock.sendall(head + body[:1])
                    data = b""
                    while chunk := sock.recv(65536):
                        data += chunk
                replies[n] = data.split(b" ", 2)[1].decode() if data else "none"
            except OSError as exc:
                replies[n] = type(exc).__name__

        start = time.monotonic()
        threads = [threading.Thread(target=client, args=(n,), daemon=True)
                   for n in range(args.clients)]
        for thread in threads:
            thread.start()
            time.sleep(args.stagger)
        for thread in threads:
            thread.join(40)
        peak = peak_rss_bytes(server.proc.pid)
        counts = {r: replies.count(r) for r in set(replies)}
        print(json.dumps({
            "clients": args.clients,
            "head_bytes": len(head),
            "offered_mib": round(args.clients * len(head) / 2**20, 1),
            "base_peak_rss_mib": round(base / 2**20, 1),
            "peak_rss_mib": round(peak / 2**20, 1),
            "growth_mib": round((peak - base) / 2**20, 1),
            "replies": counts,
            "seconds": round(time.monotonic() - start, 1),
        }))
    finally:
        server.stop()
        shutil.rmtree(tmpdir, True)


if __name__ == "__main__":
    main()
