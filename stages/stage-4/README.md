# pocketful — stage 4

Wallet service. Python 3.11 standard library only (`http.server` + `sqlite3`);
nothing is installed, so it builds and runs with no network access.

Unit 1.1: `GET /health`, `POST /accounts`, `GET /accounts/{id}`.
Unit 1.2: `POST /accounts/{id}/deposit`, `POST /accounts/{id}/withdraw`,
`GET /audit`. Unit 1.3: `POST /transfers`. Unit 2.1: optional `Idempotency-Key` on
deposit, withdraw and transfer. Unit 3.1: one write chokepoint, a fair FIFO
writer lock, at most 256 handler threads, and a stress harness. Unit 4.1
(this build): a ledger sequence and `GET /accounts/{id}/transactions`.
The contract and invariants are in `../../PLAN.md`. Stage 4 is a copy of stage 3
at the S3 gate (ce98f4d) plus unit 4.1; the stage-1, 2 and 3 `tests/` and
`attacks/` are included under the copied-suite rule and must stay green.

## Run on bare Python 3.11 (offline)

```sh
cd stages/stage-4
python -m app                         # 0.0.0.0:8080, DB at ./data/wallet.db
PORT=9000 DB_PATH=/tmp/w.db python -m app
```

PowerShell: `$env:PORT=9000; $env:DB_PATH="$env:TEMP\w.db"; python -m app`

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `8080` | listen port on `0.0.0.0` (`0` = pick a free port) |
| `DB_PATH` | `./data/wallet.db` | SQLite file; parent directory is created |
| `LOG_REQUESTS` | unset | `1` logs each request to stderr |
| `MAX_HANDLERS` | `256` | requests handled at once (D3.3); must be ≥ 1 |
| `LOCK_STATS_PATH` | unset | if set, writer-lock wait/hold statistics are written to this JSON file about once a second (the stress harness uses it) |

On start the process prints `LISTENING <host> <port>` on stdout.

## Tests

```sh
cd stages/stage-4
python -m unittest discover -s tests          # add -v for names
```

The suite starts `python -m app` as a subprocess on a free port against a
temporary database, so it needs no running server and no network.

## Container (offline)

The only network step is having the base image locally, once:
`docker pull python:3.11-slim`. After that:

```sh
cd stages/stage-4
docker build --network=none -t pocketful:stage-4 .
docker run --rm --network=none --name pocketful-s4 pocketful:stage-4
# health, from inside the same network namespace (there is no network):
docker exec pocketful-s4 python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/health').read())"
# tests and the Breaker's attack suite inside the image:
docker run --rm --network=none pocketful:stage-4 python -m unittest discover -s tests
docker run --rm --network=none pocketful:stage-4 python -m unittest discover -s attacks
# the I18 stress run inside the image (DB on the container's own filesystem):
docker run --rm --network=none pocketful:stage-4 python stress/run_stress.py --seconds 60 --workers 200 --accounts 8
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
- Lock timeout (writer lock or SQLite) → `503 {"error":"busy"}`; unexpected error →
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
- Under heavy write contention a request can get `503 busy` (no effect;
  safe to retry). From stage 3 the bounds are the 4 s writer lock and the
  3 s `busy_timeout` (see unit 3.1).

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

## Behaviour notes (unit 3.1: concurrency hardening)

- **One write chokepoint (D3.1).** Every write, including `POST /accounts`
  and the schema setup, goes through `db.write_transaction`. Each connection
  has an SQLite authorizer that refuses any write statement outside it
  (`not authorized`), and the statement cache is off so a write prepared
  inside is never reused outside.
- **Fair writer lock (D3.2, I19).** `write_transaction` first takes a
  process-wide FIFO lock (`db.FifoLock`: one condition per waiter, granted
  strictly in the order `acquire` was called), then runs `BEGIN IMMEDIATE …
  COMMIT`. The lock covers only that span: the body read, the 404/401 reads
  and the send happen outside it, and readers (`GET`s, `/audit`) never take
  it. Not acquired within **4 s → `503 busy`**, no effect, and the timed-out
  waiter leaves no place in the queue. It is released on every path
  (rejection, exception, client disconnect). A writer whose client has
  disconnected still commits.
- **`busy_timeout` = 3000 ms** (Q3-B as amended by Q3.1-A). It is only the
  backstop for writers in other processes. Worst case 4 s lock + 3 s busy +
  commit stays under the 10 s bound.
- **Bounded handlers (D3.3, D3.3a).** At most `MAX_HANDLERS` (256) requests
  are handled at once, and a connection gets a handler slot and thread only
  once its complete request head (request line + headers) has arrived.
  Until then it is *parked* (`app/parking.py`): the accept loop keeps
  accepting, and a fixed pool of reader threads (9 shards of at most 500
  sockets, because Windows `select()` handles 512, plus one dispatcher) reads
  the heads. Thread count stays at 256 handlers + that pool of 10.
- **Head rules while parked.** The parked phase runs the handler's own head
  code on the bytes received so far, so every stage-1 head rule answers
  exactly as before without taking a slot: 10 s from connect → `408`,
  header line > 64 KiB or > 100 headers → `431`, malformed or over-long
  request line and non-1.0/1.1 versions → `400` (HTTP/1.0 status line,
  declared body drained first as in R1.3-A2). The 10 s deadline is one
  deadline from connect to the end of the body, across both phases.
- **Hand-off.** Everything received past the head (the body and anything
  after it in the same read) is handed to the handler; nothing is read twice
  or lost. One request per connection, as in stage 1.
- **Parked cap.** At most 4096 connections are parked or waiting for a slot;
  above that the accept loop stops and the excess waits in the listen
  backlog (1024), never as threads. `server.shutdown()` returns even while
  every slot is held.
- **Head memory budget (Q3.1-B).** While parked heads hold more than 64 MiB
  in total, connections whose head is already over 16 KiB are not read until
  the total drops (or they get their `408` at the deadline). Heads of 16 KiB
  or less keep being read, so a flood of huge heads cannot starve small
  requests. Worst case about 64 MiB + 4096 × 16 KiB.
- With ≤ 100 concurrent writers there are no 503s at all (Q3-C).

## Stress harness (D3.4)

`stress/run_stress.py` (standard library only) starts `python -m app` on a
free port against a fresh temporary database (or `--db`), creates and funds
`--accounts` accounts, and runs `--workers` client threads for `--seconds`.
The mix covers transfers, A↔B pairs, A→B→C→A cycles, withdrawals, deposits,
reads, keyed and keyless requests, keyed retries of earlier requests, and
clients that disconnect after sending or in the middle of the body. It
samples I1/I3/I7 straight from SQLite twice a second, keeps a client-side
model of every 2xx, settles every unanswered keyed request by retrying its
key, then probes I20 (`/health` and two fresh writes, each < 1 s).

```sh
cd stages/stage-4
# the I18 run: >= 60 s, >= 200 workers, <= 8 accounts
python stress/run_stress.py --seconds 60 --workers 200 --accounts 8 --seed 1
# in the image, no network (DB on the container's own filesystem):
docker run --rm --network=none pocketful:stage-4 python stress/run_stress.py --seconds 60 --workers 200 --accounts 8
```

It prints one JSON summary: `ops`, `statuses`, `latency_ms`
(p50/p99/max, client side), `busy_503`, `lock` (writer-lock `wait_ms` and
`hold_ms` p50/p99/max, from the server), `samples`, `invariants` and
`violations`. It exits 1 on any violation: I1/I3/I7 in any sample, I18
(model ≠ database), I19 (a request ≥ 10 s, or any 503 with ≤ 100
workers), I13, I20, a 5xx other than `503 busy`, an unexpected status, or a
complete request without a full JSON answer. `tests/test_stress.py` runs a
short version, plus a self-test that changes a balance behind the service's
back and must be caught.

## Behaviour notes (unit 4.1: history)

- **Ledger sequence (D4.3).** Every ledger row (each `external_moves` and
  `transfers` row) gets one number from a single strictly increasing
  sequence, in the same write transaction that inserts it. AFTER INSERT
  triggers add a row to `ledger(seq INTEGER PRIMARY KEY, source, row_id)`, so
  `seq` is max + 1 under the FIFO writer lock. They also add one row per
  account touched to `ledger_accounts(account_id, seq)`. Both tables are
  STRICT and append-only (UPDATE and DELETE abort). The stage 1–3 tables are
  unchanged. The three new tables (`ledger`, `ledger_accounts`, `settings`)
  are what the tolerated table-inventory assertion sees. A rejected request
  writes nothing, so it takes no number; gaps come only from a crash.
- **`GET /accounts/{id}/transactions?limit=&cursor=` (D4.1).** Needs the
  bearer token of `{id}`. 200 `{"items": [...], "next_cursor": <string|null>}`,
  newest first by sequence; `next_cursor` is `null` on the last page. Check
  order: 400 `invalid_request` (query, repeated `Authorization`, a cursor not
  issued for this account) → 404 `account_not_found` → 401 `unauthorized`.
  Errors carry no items.
- **Items (D4.2).** `{"id", "type", "amount", "counterparty", "created_at"}`.
  `type` is `deposit`, `withdrawal`, `transfer_in` or `transfer_out`. `id` is
  the row id (the transfer id for transfers). `counterparty` is the other
  account for transfers and `null` otherwise. `amount` is positive.
- **Query (D4.10).** Decoded once with `parse_qsl(strict_parsing=True,
  keep_blank_values=True)`. Only `limit` and `cursor` are allowed, each at
  most once and never empty; a bare `?` is no query. `limit` is ASCII
  digits, no sign or leading zero, 1–100, default 20. The cursor is URL-safe
  base64 without padding, 55 characters. It holds a version, the sequence of
  the last item served, and an HMAC-SHA256 over the account id and that
  sequence. The HMAC key is per database (`settings.cursor_key`, 32 random
  bytes created on first start). Only the exact spelling the server issued
  is accepted.
- **Pages (I23).** Keyset on the sequence (`seq < cursor`), never `OFFSET`.
  Rows committed while a client pages are newer than its cursor, so they
  never cause a repeat or a skip. Each page is one read transaction (one
  snapshot) and takes no writer lock.
- **Stage-3 databases (D4.9).** On start, rows without a sequence get one,
  once, in one write transaction: by `created_at`, ties `external_moves`
  before `transfers`, then rowid. When it does this, startup logs
  `ledger: sequenced N rows written before stage 4 (D4.9)`. A second start
  changes nothing.
- **Startup line (D4.8).** The first stderr line says whether the glibc
  allocator settings were applied: `tune_malloc: applied (...)` on Linux,
  `tune_malloc: skipped (<reason>)` elsewhere.
