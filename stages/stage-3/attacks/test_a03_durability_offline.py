"""I9 (starts offline) and I10 (committed means durable)."""
import ast
import concurrent.futures as cf
import os
import subprocess
import sys
import threading
import unittest

from breaker_harness import DOCKER, STAGE_DIR, AttackCase


class Durability(AttackCase):
    def test_created_accounts_survive_hard_kill(self):
        accts = [self.server.create_account(f"d{i}") for i in range(20)]
        self.server.restart()  # hard kill, same DB
        for a in accts:
            r = self.server.request("GET", f"/accounts/{a['id']}")
            self.assertEqual(r.status, 200, f"I10: 201'd account lost after restart: {r}")
            self.assertEqual(r.json["owner"], a["owner"])

    def test_kill_during_creation_burst(self):
        """Every 201 seen before the kill must exist after restart; nothing half-written."""
        created, stop = [], threading.Event()

        def worker(i):
            while not stop.is_set():
                try:
                    r = self.server.request("POST", "/accounts", {"owner": f"k{i}"}, timeout=5)
                except OSError:
                    return
                if r.status == 201:
                    created.append(r.json)

        with cf.ThreadPoolExecutor(16) as ex:
            futs = [ex.submit(worker, i) for i in range(16)]
            while len(created) < 100 and not all(f.done() for f in futs):
                stop.wait(0.01)
            self.server.kill()
            stop.set()
        self.server.start()
        self.assertGreater(len(created), 0)
        for a in created:
            r = self.server.request("GET", f"/accounts/{a['id']}")
            self.assertEqual(r.status, 200, f"I10: acknowledged account missing after kill: {a['id']}")
        # the old token must still authorize (tokens persisted, not in-memory)
        a = created[0]
        if self.server.has_route("POST", f"/accounts/{a['id']}/withdraw", {"amount": 1}):
            r = self.server.withdraw(a["id"], 1, a["token"])
            self.assertEqual((r.status, r.error), (409, "insufficient_funds"),
                             f"token rejected after restart: {r}")

    def test_restart_twice_is_idempotent_on_schema(self):
        a = self.server.create_account("schema")
        before = self.server.snapshot()
        self.server.restart()
        self.server.restart()
        self.assertEqual(self.server.snapshot(), before, "startup/migration rewrote existing data")
        self.assertEqual(self.server.request("GET", f"/accounts/{a['id']}").status, 200)

    def test_db_pragmas(self):
        with __import__("contextlib").closing(self.server.db()) as c:
            mode = c.execute("PRAGMA journal_mode").fetchone()[0]
            ddl = c.execute("SELECT sql FROM sqlite_master WHERE name='accounts'").fetchone()[0]
        self.assertEqual(mode.lower(), "wal", "PLAN requires WAL")
        norm = " ".join(ddl.lower().split())
        self.assertIn("strict", norm, "accounts table is not STRICT")
        self.assertIn("check", norm, f"no CHECK constraint on accounts: {ddl}")


class Offline(unittest.TestCase):
    def test_app_imports_only_stdlib(self):
        app_dir = os.path.join(STAGE_DIR, "app")
        local = {os.path.splitext(f)[0] for f in os.listdir(app_dir)} | {"app"}
        bad = []
        for root, _, files in os.walk(app_dir):
            for f in files:
                if not f.endswith(".py"):
                    continue
                tree = ast.parse(open(os.path.join(root, f), encoding="utf-8").read())
                for node in ast.walk(tree):
                    names = []
                    if isinstance(node, ast.Import):
                        names = [n.name for n in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                        names = [node.module]
                    for n in names:
                        top = n.split(".")[0]
                        if top not in sys.stdlib_module_names and top not in local:
                            bad.append(f"{f}: {n}")
        self.assertEqual(bad, [], "I9: non-stdlib import (needs network to install)")

    def test_dockerfile_has_no_install(self):
        path = os.path.join(STAGE_DIR, "Dockerfile")
        self.assertTrue(os.path.exists(path), "no Dockerfile")
        lines = open(path, encoding="utf-8").read().lower().splitlines()
        text = "\n".join(l.split("#", 1)[0] for l in lines)  # ignore comments
        for bad in ["pip install", "apt-get", "apk add", "curl ", "wget ", "npm "]:
            self.assertNotIn(bad, text, f"I9: Dockerfile fetches from network: {bad!r}")

    @unittest.skipUnless(DOCKER, "set ATTACK_DOCKER=1")
    def test_docker_no_network(self):
        tag = "pocketful-breaker-stage1"
        b = subprocess.run(["docker", "build", "--network=none", "-t", tag, STAGE_DIR],
                           capture_output=True, text=True, timeout=600)
        self.assertEqual(b.returncode, 0, b.stderr[-3000:])
        script = ("import urllib.request,time,subprocess,sys\n"
                  "p=subprocess.Popen([sys.executable,'-m','app'])\n"
                  "t=time.time()\n"
                  "while time.time()-t<10:\n"
                  " try:\n"
                  "  r=urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=1);print(r.status);sys.exit(0)\n"
                  " except Exception: time.sleep(0.2)\n"
                  "sys.exit(1)\n")
        r = subprocess.run(["docker", "run", "--rm", "--network=none", "--entrypoint", "python", tag, "-c", script],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
