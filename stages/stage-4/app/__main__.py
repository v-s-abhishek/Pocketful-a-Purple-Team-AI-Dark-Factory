"""Entry point: python -m app

Environment:
  PORT            listen port on 0.0.0.0 (default 8080; 0 picks a free port)
  DB_PATH         SQLite file (default ./data/wallet.db)
  LOG_REQUESTS    set to 1 to log each request to stderr
  MAX_HANDLERS    requests handled at once (default 256, D3.3)
  LOCK_STATS_PATH if set, writer-lock wait/hold statistics are written to
                  this JSON file about once a second (used by stress/)
"""

import ctypes
import json
import os
import signal
import sys
import threading
import time

from . import db
from .server import MAX_HANDLERS, WalletServer

LOCK_STATS_INTERVAL_S = 1.0
# glibc mallopt parameters.
M_MMAP_THRESHOLD = -3
M_ARENA_MAX = -8
MMAP_THRESHOLD_BYTES = 128 * 1024


def write_lock_stats(path):
    """Replace `path` atomically with the current writer-lock summary."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(db.LOCK_STATS.summary(), fh)
    os.replace(tmp, path)


def start_lock_stats(path):
    db.LOCK_STATS.enabled = True

    def loop():
        while True:
            time.sleep(LOCK_STATS_INTERVAL_S)
            try:
                write_lock_stats(path)
            except OSError as exc:
                sys.stderr.write(f"lock stats not written: {exc!r}\n")

    threading.Thread(target=loop, name="lock-stats", daemon=True).start()


def tune_malloc():
    """Q3.1-B / A3.1-3 on Linux. glibc's defaults let a flood of large heads
    use several times the head budget: its mmap threshold rises after the
    first large buffer is freed, so later growing head buffers come from the
    heap and leave holes, and each reader and handler thread gets its own
    arena. Measured in Docker with 65 MiB of heads charged: peak RSS 423 MiB
    by default, 126 MiB with these two settings. No-op elsewhere.
    Returns the D4.8 startup line: applied or skipped, and why."""
    if not sys.platform.startswith("linux"):
        return f"tune_malloc: skipped (platform {sys.platform}, not Linux)"
    try:
        mallopt = ctypes.CDLL(None).mallopt
    except (OSError, AttributeError) as exc:
        return f"tune_malloc: skipped (no glibc mallopt: {exc!r})"
    results = (mallopt(M_MMAP_THRESHOLD, MMAP_THRESHOLD_BYTES), mallopt(M_ARENA_MAX, 2))
    if results != (1, 1):
        return f"tune_malloc: not applied (mallopt returned {results}, expected (1, 1))"
    return (f"tune_malloc: applied (M_MMAP_THRESHOLD={MMAP_THRESHOLD_BYTES}, "
            f"M_ARENA_MAX=2)")


def main():
    # D4.8: one line, so it is visible that this ran (or why not).
    sys.stderr.write(tune_malloc() + "\n")
    port = int(os.environ.get("PORT", "8080"))
    db_path = os.environ.get("DB_PATH", "./data/wallet.db")
    max_handlers = int(os.environ.get("MAX_HANDLERS", str(MAX_HANDLERS)))
    if max_handlers < 1:
        raise SystemExit("MAX_HANDLERS must be at least 1")
    backfilled = db.init_db(db_path)
    if backfilled:
        sys.stderr.write(f"ledger: sequenced {backfilled} rows written before stage 4 (D4.9)\n")
    stats_path = os.environ.get("LOCK_STATS_PATH")
    if stats_path:
        start_lock_stats(stats_path)
    server = WalletServer(
        ("0.0.0.0", port), db_path,
        log_requests=os.environ.get("LOG_REQUESTS") == "1",
        max_handlers=max_handlers,
    )

    def stop(signum, frame):
        raise SystemExit(0)

    # As PID 1 in a container SIGTERM is ignored unless handled.
    signal.signal(signal.SIGTERM, stop)

    host, bound_port = server.server_address[:2]
    # The test harness reads this line to learn the port.
    print(f"LISTENING {host} {bound_port}", flush=True)
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
