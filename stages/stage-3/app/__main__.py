"""Entry point: python -m app

Environment:
  PORT            listen port on 0.0.0.0 (default 8080; 0 picks a free port)
  DB_PATH         SQLite file (default ./data/wallet.db)
  LOG_REQUESTS    set to 1 to log each request to stderr
  MAX_HANDLERS    requests handled at once (default 256, D3.3)
  LOCK_STATS_PATH if set, writer-lock wait/hold statistics are written to
                  this JSON file about once a second (used by stress/)
"""

import json
import os
import signal
import sys
import threading
import time

from . import db
from .server import MAX_HANDLERS, WalletServer

LOCK_STATS_INTERVAL_S = 1.0


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


def main():
    port = int(os.environ.get("PORT", "8080"))
    db_path = os.environ.get("DB_PATH", "./data/wallet.db")
    max_handlers = int(os.environ.get("MAX_HANDLERS", str(MAX_HANDLERS)))
    if max_handlers < 1:
        raise SystemExit("MAX_HANDLERS must be at least 1")
    db.init_db(db_path)
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
