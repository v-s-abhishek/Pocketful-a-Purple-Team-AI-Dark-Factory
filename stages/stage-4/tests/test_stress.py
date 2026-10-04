"""Unit 3.1, D3.4: stress/run_stress.py is run by a test. A short clean run
must pass every invariant with zero 503s (<= 100 writers, Q3-C), and the
harness must catch a balance changed behind the service's back, so a green
run means something. The full I18 run (>= 60 s, >= 200 workers) is the
gate's job: see README.md."""

import argparse
import importlib.util
import json
import os
import socket
import subprocess
import sys
import unittest

from harness import STAGE_DIR

SCRIPT = os.path.join(STAGE_DIR, "stress", "run_stress.py")


def load_harness():
    spec = importlib.util.spec_from_file_location("run_stress", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_stress(*args):
    proc = subprocess.run([sys.executable, SCRIPT, *args], cwd=STAGE_DIR,
                          capture_output=True, text=True, timeout=120)
    try:
        summary = json.loads(proc.stdout)
    except ValueError:
        raise AssertionError(f"no JSON summary (rc={proc.returncode}): "
                             f"{proc.stdout[-2000:]!r} {proc.stderr[-2000:]!r}") from None
    return proc.returncode, summary


class StressHarnessTest(unittest.TestCase):
    def test_short_run_holds_every_invariant(self):
        rc, summary = run_stress("--seconds", "4", "--workers", "40", "--accounts", "3",
                                 "--seed", "7")
        self.assertEqual(rc, 0, json.dumps(summary, indent=2))
        self.assertTrue(summary["ok"])
        self.assertTrue(all(summary["invariants"].values()), summary["invariants"])
        self.assertEqual(summary["busy_503"], 0)
        self.assertEqual(summary["violations"], [])
        self.assertGreater(summary["ops"], 0)
        self.assertGreaterEqual(summary["samples"], 3, "I1/I3/I7 not sampled about once a second")
        self.assertLess(summary["latency_ms"]["max"], 10_000)
        self.assertIsNotNone(summary["lock"], "no writer-lock statistics")
        self.assertGreater(summary["lock"]["acquired"], 0)
        for kind in ("transfer", "pair", "cycle", "withdraw", "deposit", "read", "retry",
                     "disconnect_after_send", "disconnect_mid_body"):
            self.assertIn(kind, summary["ops_by_kind"])

    def test_non_positive_or_non_finite_arguments_are_refused(self):
        """A NaN or infinite --seconds would give a run with no load (or no
        end) that could still print a green summary."""
        for args in (["--seconds", "nan"], ["--seconds", "inf"], ["--seconds", "-inf"],
                     ["--seconds", "0"], ["--seconds", "-1"], ["--workers", "0"],
                     ["--accounts", "1"]):
            with self.subTest(args=args):
                proc = subprocess.run([sys.executable, SCRIPT, *args], cwd=STAGE_DIR,
                                      capture_output=True, text=True, timeout=30)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(proc.stdout, "")

    def test_refused_connect_is_counted_not_a_violation(self):
        """R3.1-B: a connect refused before any byte is sent is a number in
        the summary, not a violation, and is not tracked as a lost request."""
        rs = load_harness()
        with socket.socket() as probe:  # a port with nothing listening
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        class NoServer:
            pass

        server = NoServer()
        server.port = port
        args = argparse.Namespace(workers=1, seed=1)
        stress = rs.Stress(args, server)
        account = {"id": "a", "token": "t"}
        stress.model = rs.Model([account])
        req = rs.Request("deposit", [account], 5, "k1", account)
        self.assertIsNone(stress.send(req, "deposit"))
        self.assertEqual(stress.results.refused, 1)
        self.assertEqual(stress.results.violations, [])
        self.assertEqual(stress.model.unresolved, {}, "a request never sent was marked lost")

    def test_tampered_balance_is_caught(self):
        rc, summary = run_stress("--seconds", "3", "--workers", "10", "--accounts", "3",
                                 "--seed", "7", "--self-test-tamper")
        self.assertEqual(rc, 1, json.dumps(summary, indent=2))
        self.assertFalse(summary["ok"])
        for name in ("I1", "I7", "I18"):
            self.assertFalse(summary["invariants"][name], f"{name} missed the tampered balance")


if __name__ == "__main__":
    unittest.main()
