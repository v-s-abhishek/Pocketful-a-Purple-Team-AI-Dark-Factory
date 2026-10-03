"""Standalone reproductions for unit 1.1 findings (Breaker). Not a unittest module.

Usage:  python attacks/repro_1_1.py <port>     (against a running `python -m app`)
Prints EXPECTED vs ACTUAL per repro, exit 1 if any repro still reproduces.
"""
import json
import socket
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080


def raw(req):
    with socket.create_connection(("127.0.0.1", PORT), timeout=10) as s:
        s.sendall(req)
        out = b""
        while True:
            c = s.recv(65536)
            if not c:
                return out
            out += c


def post_accounts(body_bytes, cl=None):
    cl = str(len(body_bytes)).encode() if cl is None else cl
    return raw(b"POST /accounts HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: "
               + cl + b"\r\nConnection: close\r\n\r\n" + body_bytes)


def status(resp):
    return int(resp.split(b" ", 2)[1]) if resp.startswith(b"HTTP/") else None


REPROS = [
    ("R1.1-A owner containing NUL -> 500",
     lambda: post_accounts(json.dumps({"owner": "\x00"}).encode()),
     "400 invalid_request"),
    ("R1.1-B Content-Length '\\xb2' (superscript two) -> 500",
     lambda: post_accounts(b'{"owner":"a"}', cl=b"\xb2"),
     "400 invalid_json"),
    ("R1.1-C HEAD/OPTIONS/any unhandled method -> 501 HTML",
     lambda: raw(b"OPTIONS /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
     "404 not_found (JSON)"),
    ("R1.1-D over-long header line -> 431 HTML",
     lambda: raw(b"GET /health HTTP/1.1\r\nX: " + b"a" * 70000 + b"\r\nConnection: close\r\n\r\n"),
     "4xx JSON {\"error\": ...}"),
    ("R1.1-G request version HTTP/0.9 -> body with no status line",
     lambda: raw(b"GET /health HTTP/0.9\r\n\r\n"),
     "HTTP/1.x status line + JSON (400 invalid_request, or 200)"),
]

failed = 0
for name, fn, expected in REPROS:
    resp = fn()
    head, _, body = resp.partition(b"\r\n\r\n")
    st = status(resp)
    is_json = b"application/json" in head
    bad = st is None or st >= 500 or not is_json
    failed += bad
    print(f"{'REPRODUCES' if bad else 'fixed     '} {name}\n    expected: {expected}\n"
          f"    actual:   {st} json={is_json} body={body[:80]!r}")
sys.exit(1 if failed else 0)
