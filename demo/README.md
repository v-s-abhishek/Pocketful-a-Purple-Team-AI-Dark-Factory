# pocketful — demo (wallet + factory, single service)

A self-contained demo: one web service that

1. launches the **verified Stage-3 wallet** (bundled in `./wallet/`) on an
   internal port, and
2. serves the **product web app** (sign up / log in / deposit / send, with
   overdraft & double-spend blocked by the ledger) plus a **Factory
   dashboard** built from the real BAND room export (`factory_data.json`).

Because the wallet runs inside the same process, the demo can never fail with
"wallet unreachable".

## Run locally
```
cd demo
python app.py            # serves on http://localhost:3000
```

## Deploy on Render (one Web Service)
- **New → Web Service**, connect the repo.
- **Root Directory:** `demo`
- **Runtime:** Docker (uses `demo/Dockerfile`), or Python 3 with
  **Start Command:** `python app.py`
- **No `WALLET_URL` needed** — the wallet is bundled and started internally.
- Render provides `PORT` automatically.

Stdlib only (Python 3.11) — no dependencies to install.
