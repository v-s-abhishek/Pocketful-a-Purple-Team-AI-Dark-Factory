# pocketful — stage 2

Wallet service. Python 3.11 standard library only (`http.server` + `sqlite3`);
nothing is installed, so it builds and runs with no network access.

Unit 1.1: `GET /health`, `POST /accounts`, `GET /accounts/{id}`.
Unit 1.2: `POST /accounts/{id}/deposit`, `POST /accounts/{id}/withdraw`,
`GET /audit`. Unit 1.3: `POST /transfers`. Unit 2.1 (this build): optional
`Idempotency-Key` on deposit, withdraw and transfer.
The contract and invariants are in `../../PLAN.md`. Stage 2 is a copy of stage 1
at the S1 gate plus unit 2.1; the stage-1 `tests/` and `attacks/` are included
unchanged and must stay green (I17).

## Run on bare Python 3.11 (offline)

```sh
cd stages/stage-2
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
cd stages/stage-2
python -m unittest discover -s tests          # add -v for names
```

The suite starts `python -m app` as a subprocess on a free port against a
temporary database, so it needs no running server and no network.

## Container (offline)

The only network step is having the base image locally, once:
`docker pull python:3.11-slim`. After that:

```sh
cd stages/stage-2
docker build --network=none -t pocketful:stage-2 .
docker run --rm --network=none --name pocketful-s2 pocketful:stage-2
# health, from inside the same network namespace (there is no network):
docker exec pocketful-s2 python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/health').read())"
# tests and the Breaker's attack suite inside the image:
docker run --rm --network=none pocketful:stage-2 python -m unittest discover -s tests
docker run --rm --network=none pocketful:stage-2 python -m unittest discover -s attacks
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

## Behaviour notes (unit 2.1: idempotency)

- `Idempotency-Key` is optional on `POST /transfers`,
  `POST /accounts/{id}/withdraw` and `POST /accounts/{id}/deposit`. Without
  it every request behaves exactly as in stage 1.
- Format: exactly one header (name case-insensitive); after trimming
  leading/trailing spaces and tabs, 1–255 characters, each visible ASCII
  `0x21`–`0x7E`, matched case-sensitively. Empty, longer, interior
  whitespace, control or non-ASCII bytes, an obs-folded value, or two or more
  headers → `400 invalid_request`, checked with the other request-shape 400s
  (before 404 and 401).
- Scope: each account has two separate key namespaces. `debit` covers
  withdraw and transfer (the transfer's `from`); `deposit` covers deposits
  (the credited account). The same string in the two namespaces, or on two
  accounts, is two unrelated keys.
- Fingerprint: the validated request `(operation, account, to, amount)`.
  Whitespace, key order and a different valid `Authorization` spelling do not
  change it.
- Order: request-shape 400 → 404 → 401 → `BEGIN IMMEDIATE` → key lookup →
  replay, or `422 idempotency_key_reused` if the stored request differs →
  money rules (409/422 `balance_limit`) → write the movement, its ledger row
  and the key row → commit. Concurrent requests with the same key are
  serialized by the write lock, so the second one sees the first's row; the
  `(account_id, scope, key)` primary key is the backstop and is handled as a
  replay.
- Only 2xx outcomes are stored. Any rejection (4xx, 503) rolls back and
  stores nothing, so the same key can be retried once the cause is fixed.
- A replay returns the original status and byte-identical body (the same
  transfer `id`; deposit/withdraw report the balance as of the original) plus
  `Idempotent-Replayed: true`. It moves no money and writes nothing. Replays
  of withdraw/transfer still need the right token (401 otherwise).
- Keys are kept forever (table `idempotency_keys(account_id, scope, key,
  fingerprint, status, response, created_at)`, STRICT, foreign keys).
- Use unguessable keys (UUIDv4 recommended). Deposits are unauthenticated,
  so someone who knows a depositor's key can make that depositor's later
  deposit with that key get 422 (different amount) or a replay (same amount,
  which means the attacker's own money was credited). This accepted risk
  is limited to the deposit namespace.
