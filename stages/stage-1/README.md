# pocketful — stage 1

Wallet service. Python 3.11 standard library only (`http.server` + `sqlite3`);
nothing is installed, so it builds and runs with no network access.

Unit 1.1: `GET /health`, `POST /accounts`, `GET /accounts/{id}`.
Unit 1.2: `POST /accounts/{id}/deposit`, `POST /accounts/{id}/withdraw`,
`GET /audit`. Unit 1.3 (this build): `POST /transfers`.
The contract and invariants are in `../../PLAN.md`.

## Run on bare Python 3.11 (offline)

```sh
cd stages/stage-1
python -m app                         # 0.0.0.0:8080, DB at ./data/wallet.db
PORT=9000 DB_PATH=/tmp/w.db python -m app
```

PowerShell: `$env:PORT=9000; $env:DB_PATH="$env:TEMP\w.db"; python -m app`

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `8080` | listen port on `0.0.0.0` (`0` = pick a free port) |
| `DB_PATH` | `./data/wallet.db` | SQLite file; parent directory is created |
| `LOG_REQUESTS` | unset | `1` logs each request to stderr |

On start the process prints `LISTENING <host> <port>` on stdout.

## Tests

```sh
cd stages/stage-1
python -m unittest discover -s tests          # add -v for names
```

The suite starts `python -m app` as a subprocess on a free port against a
temporary database, so it needs no running server and no network.

## Container (offline)

The only network step is having the base image locally, once:
`docker pull python:3.11-slim`. After that:

```sh
cd stages/stage-1
docker build --network=none -t pocketful:stage-1 .
docker run --rm --network=none --name pocketful-s1 pocketful:stage-1
# health, from inside the same network namespace (there is no network):
docker exec pocketful-s1 python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/health').read())"
# tests and the Breaker's attack suite inside the image:
docker run --rm --network=none pocketful:stage-1 python -m unittest discover -s tests
docker run --rm --network=none pocketful:stage-1 python -m unittest discover -s attacks
```

Data lives in the `/data` volume (`-v pocketful-data:/data` to keep it).
With `--network=none` the port cannot be published to the host; to reach it
from the host instead, run with `-p 8080:8080` (networking on, still no
downloads at run time).

## Behaviour notes (unit 1.1 choices)

- Every response is JSON, including protocol errors.
- Unknown path, known path with a wrong method, and any method without a
  route (`HEAD`, `OPTIONS`, `TRACE`, `CONNECT`, made-up methods) all return
  `404 {"error":"not_found"}`. No 405 or 501 is ever returned.
- Only `HTTP/1.0` and `HTTP/1.1` are served. Any other explicit version
  (`HTTP/0.9`, `HTTP/1.2`, `HTTP/2.0`, ...), or a malformed request line or
  one over 64 KiB → `400 invalid_request` with an `HTTP/1.0` status line; a
  header line over 64 KiB or more than 100 headers → `431 invalid_request`.
- One 10 s deadline per connection, from connect to the end of the request
  body, however slowly bytes arrive. On expiry: `408 request_timeout`,
  then close.
- `POST /accounts` accepts exactly `{"owner": <1-64 char string>}`. The
  owner is rejected if it is whitespace-only (Unicode whitespace, e.g.
  U+00A0, U+3000) or contains any code point of category `Cc` (C0, DEL, C1),
  `Cf` (U+200B, U+202E, U+FEFF, tags), `Zl` or `Zp`. Interior spaces are
  allowed. Unknown fields (e.g. `id`, `balance`) → `400 invalid_request`.
- Body rules (shared parser `app/validation.py:parse_json_object`, used by
  every endpoint with a body): a single JSON object, ≤ 16 KiB, UTF-8, no
  duplicate keys, no `NaN`/`Infinity`. Missing body, any
  `Transfer-Encoding`, a repeated `Content-Length`, or one that is not 1–7
  ASCII digits, or anything else → `400 invalid_json`. Numeric headers are
  parsed with `parse_header_int` (never `str.isdigit()`). `Content-Type`
  is not checked.
- `GET /accounts/{id}` with anything other than a canonical lowercase UUID
  → `404 account_not_found` (no database lookup).
- The token is returned only in the `201` from `POST /accounts`. Only its
  SHA-256 hex digest is stored.
- SQLite lock timeout → `503 {"error":"busy"}`; unexpected error →
  `500 {"error":"internal"}` (details go to stderr only). Either way the
  transaction is rolled back in full.

## Behaviour notes (unit 1.2)

- Deposit and withdraw take exactly `{"amount": <int 1..10^12>}`. A missing
  or bad amount → `400 invalid_amount`; a valid amount plus any other field
  → `400 invalid_request`.
- Deposit: no auth (any `Authorization` header is ignored). Check order:
  body 400 → `404 account_not_found` → `422 balance_limit` (balance would
  exceed 10^15). One `BEGIN IMMEDIATE`: conditional
  `UPDATE ... WHERE balance + a <= 10^15 RETURNING balance` + an
  `external_moves` row, then commit.
- Withdraw: check order body 400 / two or more `Authorization` headers
  `400 invalid_request` → `404` → `401 unauthorized` → `409
  insufficient_funds`. The credential is exactly `Authorization: Bearer
  <token>` (case-sensitive scheme, one space; leading/trailing spaces and
  tabs around the value are trimmed); anything else is 401. The
  token's SHA-256 is compared with `hmac.compare_digest`. The debit is
  `UPDATE ... WHERE balance >= a RETURNING balance` inside one
  `BEGIN IMMEDIATE` together with its ledger row.
- The `balance` in a 200 is the one that request's own transaction produced.
- `GET /audit` reads all three sums in one SQL statement (one snapshot) and
  returns integers; `conserved` is `total_balances == total_deposits −
  total_withdrawals`.
- Schema: `external_moves` and `transfers` are STRICT with foreign keys,
  amount CHECKs and `CHECK (from_id <> to_id)`.

## Behaviour notes (unit 1.3)

- `POST /transfers` takes exactly `{"from", "to", "amount"}` and the bearer
  token of `from`; it returns `201 {"id", "from", "to", "amount"}`, where `id`
  is the `transfers` row id.
- Check order: 400 (`invalid_json`, then `invalid_amount`, then
  `invalid_request` for missing/extra/non-string ids, `from == to`, or two or
  more `Authorization` headers) → `404 account_not_found` if either account
  is missing → `401` → `409 insufficient_funds` → `422 balance_limit` (the
  credit would push `to` above 10^15).
- One `BEGIN IMMEDIATE`: conditional debit of `from`, conditional credit of
  `to`, `transfers` row, commit. A 409 or 422 rolls back the whole
  transaction, so the debit is never left applied on its own.
- Transfers are internal: `/audit` totals count only deposits and
  withdrawals, and conservation is unchanged.
- Under heavy write contention a request can wait past the 5 s
  `busy_timeout` and get `503 busy` (no effect; safe to retry).
