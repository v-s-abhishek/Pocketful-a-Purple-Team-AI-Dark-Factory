"""Entry point: python -m app

Environment:
  PORT          listen port on 0.0.0.0 (default 8080; 0 picks a free port)
  DB_PATH       SQLite file (default ./data/wallet.db)
  LOG_REQUESTS  set to 1 to log each request to stderr
"""

import os
import signal
import sys

from . import db
from .server import WalletServer


def main():
    port = int(os.environ.get("PORT", "8080"))
    db_path = os.environ.get("DB_PATH", "./data/wallet.db")
    db.init_db(db_path)
    server = WalletServer(
        ("0.0.0.0", port), db_path, log_requests=os.environ.get("LOG_REQUESTS") == "1"
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
