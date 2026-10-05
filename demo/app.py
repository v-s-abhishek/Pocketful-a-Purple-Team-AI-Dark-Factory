"""
pocketful — product + factory demo (single self-contained service).

This one process:
  1. launches the VERIFIED wallet service (the factory's Stage-3 output,
     bundled in ./wallet) on an internal port, and
  2. serves the product web app (login / signup / wallet) plus a Factory
     dashboard built from the real BAND room export.

Because the wallet runs inside this same service, the demo can never hit
"wallet unreachable" from a missing cross-service URL.

Secrets never reach the browser: password hashes and each user's wallet
token are stored server-side only; the browser holds a session cookie.

Env:
  PORT        port this app listens on (Render sets this; default 3000)
  APP_DB      path to the product user/session DB (default ./data/app.db)
"""
import binascii, hashlib, hmac, json, os, re, secrets, sqlite3, subprocess, sys, time
import urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "3000"))
APP_DB = os.environ.get("APP_DB", os.path.join(HERE, "data", "app.db"))
WALLET_PORT = int(os.environ.get("WALLET_PORT", "8090"))
WALLET_URL = "http://127.0.0.1:%d" % WALLET_PORT
PBKDF_ITERS = 120_000
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

with open(os.path.join(HERE, "index.html"), "rb") as f:
    INDEX = f.read()
try:
    with open(os.path.join(HERE, "factory_data.json"), "rb") as f:
        FACTORY = f.read()
except OSError:
    FACTORY = b'{"error":"no factory data"}'


# ---------- bundled wallet service ----------
def start_wallet():
    """Launch the verified wallet (./wallet) as a child process."""
    walletdir = os.path.join(HERE, "wallet")
    env = dict(os.environ)
    env["PORT"] = str(WALLET_PORT)
    env["DB_PATH"] = os.environ.get("WALLET_DB_PATH", os.path.join(walletdir, "data", "wallet.db"))
    os.makedirs(os.path.dirname(env["DB_PATH"]), exist_ok=True)
    try:
        subprocess.Popen([sys.executable, "-m", "app"], cwd=walletdir, env=env)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("could not start wallet: %r\n" % e)


def wait_for_wallet(timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(WALLET_URL + "/health", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


# ---------- storage ----------
def db():
    os.makedirs(os.path.dirname(APP_DB), exist_ok=True)
    c = sqlite3.connect(APP_DB); c.row_factory = sqlite3.Row; return c


def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY, salt TEXT, pwhash TEXT,
            account_id TEXT, token TEXT, created_at REAL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS sessions(
            sid TEXT PRIMARY KEY, username TEXT, created_at REAL)""")


def hash_pw(pw, salt=None):
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF_ITERS)
    return binascii.hexlify(salt).decode(), binascii.hexlify(dk).decode()


def verify_pw(pw, salt_hex, hash_hex):
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), binascii.unhexlify(salt_hex), PBKDF_ITERS)
    return hmac.compare_digest(binascii.hexlify(dk).decode(), hash_hex)


# ---------- wallet API client ----------
def wallet(method, path, body=None, token=None):
    url = WALLET_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read(); return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, (json.loads(raw) if raw else None)
        except Exception:
            return e.code, {"error": "http_error"}
    except Exception as e:  # noqa: BLE001
        return 0, {"error": "wallet_unreachable", "detail": str(e)}


# ---------- http handler ----------
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "pocketful-demo"

    def _send(self, status, obj, set_cookie=None, clear_cookie=False):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if set_cookie:
            self.send_header("Set-Cookie",
                "sid=%s; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800" % set_cookie)
        if clear_cookie:
            self.send_header("Set-Cookie", "sid=; HttpOnly; Path=/; Max-Age=0")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _raw(self, body, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        if not n: return {}
        try: return json.loads(self.rfile.read(n) or b"{}")
        except Exception: return {}

    def _user(self):
        ck = SimpleCookie(self.headers.get("Cookie", ""))
        if "sid" not in ck: return None
        with db() as c:
            s = c.execute("SELECT username FROM sessions WHERE sid=?", (ck["sid"].value,)).fetchone()
            if not s: return None
            u = c.execute("SELECT * FROM users WHERE username=?", (s["username"],)).fetchone()
            return dict(u) if u else None

    def _session(self, username):
        sid = secrets.token_urlsafe(32)
        with db() as c:
            c.execute("INSERT INTO sessions VALUES(?,?,?)", (sid, username, time.time()))
        return sid

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"): return self._raw(INDEX, "text/html; charset=utf-8")
        if p == "/healthz": return self._send(200, {"ok": True})
        if p == "/factory": return self._raw(FACTORY, "application/json")
        if p == "/me": return self._me()
        if p == "/users": return self._users()
        if p == "/wallet/audit":
            st, res = wallet("GET", "/audit")
            return self._send(200 if st == 200 else 502, res or {"error": "wallet_unreachable"})
        return self._send(404, {"error": "not_found"})

    def do_POST(self):
        p = self.path.split("?")[0]
        if p == "/auth/signup": return self._signup()
        if p == "/auth/login": return self._login()
        if p == "/auth/logout": return self._logout()
        if p == "/wallet/deposit": return self._deposit()
        if p == "/wallet/send": return self._sendmoney()
        return self._send(404, {"error": "not_found"})

    def _signup(self):
        d = self._json()
        u = (d.get("username") or "").strip(); pw = d.get("password") or ""
        if not USER_RE.match(u):
            return self._send(400, {"error": "bad_username", "message": "3–32 chars: letters, numbers, . _ -"})
        if len(pw) < 6:
            return self._send(400, {"error": "weak_password", "message": "Password must be at least 6 characters."})
        with db() as c:
            if c.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
                return self._send(409, {"error": "username_taken", "message": "That username is taken."})
        st, acc = wallet("POST", "/accounts", {"owner": u})
        if st != 201 or not acc or "id" not in acc:
            return self._send(503, {"error": "wallet_unavailable", "message": "Wallet is waking up — try again in a few seconds."})
        salt, h = hash_pw(pw)
        with db() as c:
            c.execute("INSERT INTO users VALUES(?,?,?,?,?,?)", (u, salt, h, acc["id"], acc["token"], time.time()))
        return self._send(201, {"username": u, "account_id": acc["id"]}, set_cookie=self._session(u))

    def _login(self):
        d = self._json()
        u = (d.get("username") or "").strip(); pw = d.get("password") or ""
        with db() as c:
            row = c.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not row or not verify_pw(pw, row["salt"], row["pwhash"]):
            return self._send(401, {"error": "invalid_credentials", "message": "Wrong username or password."})
        return self._send(200, {"username": u, "account_id": row["account_id"]}, set_cookie=self._session(u))

    def _logout(self):
        ck = SimpleCookie(self.headers.get("Cookie", ""))
        if "sid" in ck:
            with db() as c:
                c.execute("DELETE FROM sessions WHERE sid=?", (ck["sid"].value,))
        return self._send(200, {"ok": True}, clear_cookie=True)

    def _me(self):
        u = self._user()
        if not u: return self._send(401, {"error": "not_authenticated"})
        st, acc = wallet("GET", "/accounts/" + u["account_id"])
        bal = acc.get("balance") if (st == 200 and acc) else None
        return self._send(200, {"username": u["username"], "account_id": u["account_id"],
                                "balance": bal, "wallet_ok": st == 200})

    def _users(self):
        u = self._user()
        if not u: return self._send(401, {"error": "not_authenticated"})
        with db() as c:
            rows = c.execute("SELECT username FROM users WHERE username<>? ORDER BY username", (u["username"],)).fetchall()
        return self._send(200, {"users": [r["username"] for r in rows]})

    def _deposit(self):
        u = self._user()
        if not u: return self._send(401, {"error": "not_authenticated"})
        amt = self._json().get("amount")
        if not isinstance(amt, int) or amt < 1: return self._send(400, {"error": "invalid_amount"})
        st, res = wallet("POST", "/accounts/%s/deposit" % u["account_id"], {"amount": amt})
        return self._send(st or 502, res or {"error": "wallet_unreachable"})

    def _sendmoney(self):
        u = self._user()
        if not u: return self._send(401, {"error": "not_authenticated"})
        d = self._json(); to = (d.get("to") or "").strip(); amt = d.get("amount")
        if not isinstance(amt, int) or amt < 1: return self._send(400, {"error": "invalid_amount"})
        if to == u["username"]: return self._send(400, {"error": "cannot_send_to_self", "message": "You can't send to yourself."})
        with db() as c:
            r = c.execute("SELECT account_id FROM users WHERE username=?", (to,)).fetchone()
        if not r: return self._send(404, {"error": "recipient_not_found", "message": "No user with that username."})
        st, res = wallet("POST", "/transfers",
                         {"from": u["account_id"], "to": r["account_id"], "amount": amt}, token=u["token"])
        return self._send(st or 502, res or {"error": "wallet_unreachable"})

    def log_message(self, *a):  # quiet
        pass


if __name__ == "__main__":
    init_db()
    start_wallet()
    ok = wait_for_wallet()
    print("product app on 0.0.0.0:%d  ->  wallet %s (%s)" %
          (PORT, WALLET_URL, "ready" if ok else "NOT READY"), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
