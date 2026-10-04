# pocketful — wallet product app

A real wallet product (login, signup, send money) on top of the pocketful
wallet API. The verified wallet service enforces every money rule — no
double-spend, no overdraft, integer cents. This app adds the product layer:
user accounts with passwords, sessions, and send-by-username.

Secrets stay server-side: password hashes (PBKDF2) and each user's wallet
token live in this app's DB only; the browser holds just a session cookie.

## Run locally
```sh
WALLET_URL=http://127.0.0.1:8080 PORT=3000 python app.py
# open http://127.0.0.1:3000
```

## Deploy (Render)
Web Service -> this repo -> Root Directory `demo` -> Docker -> Free.
Set ONE environment variable (this is required, or you get "wallet unreachable"):
  WALLET_URL = https://<your-wallet-service>.onrender.com

## Integrate a later stage
This app only uses the Stage-1 wallet contract, which every later stage keeps.
When the band finishes Stage 4, deploy that stage as the wallet service and
point WALLET_URL at it — no change to this app needed.

Note: the user/session store is SQLite in the container (ephemeral on Render's
free tier). It resets on redeploy/sleep; fine for a demo.
