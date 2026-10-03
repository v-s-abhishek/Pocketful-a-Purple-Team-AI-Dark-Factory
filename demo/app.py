"""
pocketful — demo web app.

Serves a single-page wallet console and proxies /api/* to the real pocketful
wallet service, so the browser only ever talks to this one origin (no CORS,
and the frozen Stage 1 service is never modified).

Env:
  PORT        port to listen on (Render sets this; default 3000)
  WALLET_URL  base URL of the pocketful wallet API
              (default http://127.0.0.1:8080 for local testing)
"""
import json
import os
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
WALLET_URL = os.environ.get("WALLET_URL", "http://127.0.0.1:8080").rstrip("/")
PORT = int(os.environ.get("PORT", "3000"))

with open(os.path.join(HERE, "index.html"), "rb") as f:
    INDEX = f.read()

FORWARD_HEADERS = ("Authorization", "Content-Type", "Idempotency-Key")


def forward(method, api_path, body, headers):
    """Forward a request to the wallet API. api_path begins with '/'."""
    url = WALLET_URL + api_path
    req = urllib.request.Request(url, data=body, method=method)
    for h in FORWARD_HEADERS:
        v = headers.get(h)
        if v is not None:
            req.add_header(h, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read(), resp.headers.get("Content-Type", "application/json")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("Content-Type", "application/json")
    except Exception as e:  # noqa: BLE001 — surface any proxy/network failure as JSON
        return 502, json.dumps({"error": "proxy_error", "detail": str(e)}).encode(), "application/json"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, Idempotency-Key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(n) if n else None

    def do_OPTIONS(self):
        self._send(204, b"")

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            return self._send(200, INDEX, "text/html; charset=utf-8")
        if self.path.startswith("/api/"):
            status, body, ctype = forward("GET", self.path[4:], None, self.headers)
            return self._send(status, body, ctype)
        self._send(404, json.dumps({"error": "not_found"}).encode())

    def do_POST(self):
        if self.path.startswith("/api/"):
            body = self._read_body()
            status, rbody, ctype = forward("POST", self.path[4:], body, self.headers)
            return self._send(status, rbody, ctype)
        self._send(404, json.dumps({"error": "not_found"}).encode())

    def log_message(self, *args):
        pass  # keep logs quiet


if __name__ == "__main__":
    print(f"demo on 0.0.0.0:{PORT}  ->  wallet {WALLET_URL}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
