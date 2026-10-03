# pocketful — live demo app

A tiny single-page wallet console for showing the pocketful API in action.

It serves `index.html` and proxies `/api/*` to the real pocketful wallet
service, so the browser only talks to this one origin (no CORS, and the
verified Stage 1 service is never modified).

## Run locally
```sh
WALLET_URL=http://127.0.0.1:8080 PORT=3000 python app.py
# open http://127.0.0.1:3000
```

## Deploy (Render)
New Web Service → this repo → Root Directory `demo` → Docker → Free.
Add one environment variable:
  WALLET_URL = https://<your-wallet-service>.onrender.com
