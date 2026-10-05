# PLAN — pocketful wallet service

Owner: Architect (architect-6mhf from 2026-10-05 Stage 4 resume; architect-xxsf from 2026-10-04 third resume; architect-stqd earlier 2026-10-04; architect-zf65 earlier 2026-10-04; architect-7xff on 2026-10-03; architect-mn2c before). The Architect updates this file as units complete. Only the Verifier marks a unit done.

## Status board

| Unit | Stage | Goal | Builder | Breaker | Verifier |
| --- | --- | --- | --- | --- | --- |
| 1.1 | 1 | Skeleton: server, schema, accounts (create/get), test harness, offline container | done (48 tests) | could not break 1.1c (104 OK) | **ACCEPTED** 2026-10-01 |
| 1.2 | 1 | External money: deposit, withdraw, audit endpoint | done (67 tests) | could not break (124 OK, slow incl.) | **ACCEPTED** 2026-10-01 |
| 1.3 | 1 | Atomic transfer (no overdraw, no double-spend) | done (84 tests; R1.3-A/A2 fixed: one drain chokepoint in `_send`) | could not break after R1.3-A/A2 fix (152 OK normal + slow; a13 = 14 attacks) | **ACCEPTED** 2026-10-03 |
| S1 | 1 | Stage 1 gate: full attack suite + invariants from a clean no-network build | 84 OK | 152 OK (normal; slow + docker, 0 skipped) | **ACCEPTED** 2026-10-03 (server.py sha256 89a52478…8d1a38) |
| 2.1 | 2 | Idempotency keys, timeout-and-retry (D2.1–D2.9, I12–I17) | done (101 tests; server.py fd1c36bf…, idempotency.py 509c9cc2…) | could not break (181 OK normal + slow; a14 = 31 attacks) | **ACCEPTED** 2026-10-03; stage-1 regression green; I17: stage-1 suites unmodified vs stage-2 code green except the tolerated table-list assertion |
| S2 | 2 | Stage 2 gate | (= 2.1, the only unit) | | **ACCEPTED** 2026-10-03 |
| 3.1 | 3 | Concurrency hardening: write chokepoint, FIFO writer lock, handler cap, stress harness (D3.1–D3.4, I18–I21) | handed off 2026-10-04 (server.py f759db71…, parking.py 7918e45b…; 136 tests OK bare + Docker; I18 60 s/200 w 0×503 bare + Docker; Windows refusals 1118 → 0); Architect review: A3.1-1 HIGH completed heads leave the Q3.1-B budget (fix in 5da709f: kept charged until handler hand-off; test in test_parking.py), A3.1-2 ready-queue 408 test (in 5da709f), A3.1-3 MEDIUM handed-off heads were outside any budget (HEAD: 256 × 6.37 MB heads → +1275 MiB RSS): **fixed** (working tree): heads stay charged until the handler thread ends; `HandlerHeadBudgetTest` (<400 MiB; HEAD 778/788 MiB, fix 166–209 MiB), A3.1-4 HIGH handler-cap test flaky: **fixed**, harness artefact (sequential connects 10–13 s hit the 10 s deadline), parallel connects + setup assert, A3.1-5 Linux glibc malloc grew RSS to 423 MiB for 65 MiB of charged heads: **fixed** by `tune_malloc()` in `app/__main__.py` (mmap threshold 128 KiB, arena max 2 → 126 MiB). Re-handed off 2026-10-05: 139 tests OK bare + Docker, server.py 72a835dc…, parking.py 85c55b64…, __main__.py c8ed55e6…. Accepted consequence: while ~64 MiB of large heads are held by handlers, other heads > 16 KiB get 408 at 10 s; small requests unaffected. Accepted: `tune_malloc()` applies only through the `python -m app` entry point (the only supported entry, I9); code that imports `WalletServer` directly on Linux runs on glibc defaults | pre-D3.3a tree: could not break apart from R3.1-A (216 slow incl.; I18 60 s/250 w 0 violations; 100 w 0×503; kill -9 retry 0 violations; Docker 500 w/2 acct 0×503, 0 refused); run_stress.py must count pre-byte refusals (R3.1-B); a17 (15 parked-phase attacks) ready. **Re-attack 2026-10-05 on the re-hand-off (hashes match): could not break.** attacks/ 232 OK bare + Docker; slow a15–a17 51 OK bare + Docker; run_stress 500 w/2 acct 60 s bare + Docker: 0×503, 0 refused, 0 violations; A3.1-3 256 × 6.37 MB heads +91–177 MiB; charge-leak probe (every connection-end path) left no charge; A3.1-1 in Docker 3/3 OK | **ACCEPTED** 2026-10-05 (clean byte-exact worktree of ce98f4d; tests 139 OK + attacks 232 OK slow incl., bare + Docker `--network=none`; I18 200 w/8 acct 60 s 0×503, 0 violations bare + Docker) |
| S3 | 3 | Stage 3 gate | (= 3.1, the only unit) | | **ACCEPTED** 2026-10-05; regression: stage-2 tests 101 OK + attacks 181 OK, stage-1 attacks 152 OK, stage-1 tests 84 with only the tolerated table-inventory failure (`test_database_pragmas`, 4 tables incl. `idempotency_keys`), bare + Docker |
| 4.1 | 4 | Ledger sequence + `GET /accounts/{id}/transactions` (D4.1–D4.3, I22–I24) | handed off 2026-10-05 dd390305 (db.py 29ac22f7…, server.py e3ca03e7…, history.py 381cc598…, __main__.py 152eec9f…; 158 tests OK bare + Docker; attacks 263 OK). Architect review: approved for attack + gate (158 tests OK re-run by the Architect) | **could not break** dd390305 (a18 final in 8a18ca6, sha256 1b122a9f…): a01–a18 263 OK slow incl., bare (clean LF worktree, 0 skipped) + Docker `--network=none` (4 environmental skips, all green bare) | **ACCEPTED** 2026-10-05 (gated together with 4.2 and S4 on a97d9c9; 4.1-only gate on dd390305 also green: 158 tests + 263 attacks bare + Docker) |
| 4.2 | 4 | `POST /transfers/{id}/reverse` (D4.4–D4.7, I25–I27) | handed off 2026-10-05 cdf013c8 (db.py bf73c3de…, server.py 5f464f49…, history.py e5843b30…; 181 tests OK bare + Docker). Architect review: approved for attack + gate (181 tests OK re-run by the Architect from a clean LF worktree). Rulings D4.11 (non-object body `invalid_json`; POST query ignored) | **could not break** cdf013c8 (a19 in a97d9c9, sha256 bc5e9bb9…): a01–a19 291 OK slow incl., bare (clean LF worktree, 0 skipped) + Docker `--network=none` (4 environmental skips, green bare). I25 100/100/200-way + kill -9 mid-burst retry; I26 80 reverses × 40 withdrawals; D4.5 pairwise order; D4.11 | **ACCEPTED** 2026-10-05 (clean LF worktree of a97d9c9, hashes checked on host and in image; tests 181 OK + attacks 291 OK slow incl., bare + Docker `--network=none`) |
| S4 | 4 | Stage 4 gate: stage 1–4 suites from a clean no-network build (I28) | (= 4.1 + 4.2 at a97d9c9) | | **ACCEPTED** 2026-10-05 on a97d9c9: I9 `docker build --no-cache --network=none` + run, /health 200 in 612 ms (bare 585 ms); D4.8 line present (container: applied; Windows: skipped); I18 run_stress 60 s / 200 w / 8 acct bare 21968 ops + Docker 21124 ops, 0×503, 0 refused, 0 violations; I28 stage-1/2/3 tests 84/101/139 with only the tolerated `test_database_pragmas` (superset inventory) and attacks 152/181/232 OK, bare + Docker, suites byte-identical |

## Architecture decisions (binding for all stages)

- **Stack: Python 3.11, standard library only.** `http.server.ThreadingHTTPServer` + `sqlite3` + `json`. No third-party packages means nothing to download: the no-network build cannot fail on a missing dependency. Tests use `unittest` plus `urllib`/`threading`/`concurrent.futures`.
- **Layout:** each stage is self-contained in `stages/stage-N/` (a copy of the previous stage plus the changes). A stage never imports from another stage folder.
  - `app/` service code, `tests/` Builder checks, `attacks/` Breaker suite, `Dockerfile`, `README.md` (how to build, run, and test).
  - Entry point: `python -m app` → listens on `0.0.0.0:${PORT:-8080}`, DB at `${DB_PATH:-./data/wallet.db}`.
  - Tests: `python -m unittest discover -s tests` (starts the server on a random port against a temp DB).
  - Attacks: `python -m unittest discover -s attacks` (same harness, owned by the Breaker; grows only).
- **Container:** `FROM python:3.11-slim`, no `pip install`. Must pass `docker build --network=none` and run with `docker run --network=none`.
- **Money is enforced by the database, not by Python.** SQLite has no row locks, so the equivalent is:
  - every money-moving operation runs in **one** `BEGIN IMMEDIATE` transaction (takes the write lock up front, so no read-then-write race).
  - debits are **conditional updates**: `UPDATE accounts SET balance = balance - :a WHERE id = :src AND balance >= :a`, then check `rowcount == 1`. No "read balance in Python, then decide."
  - schema-level defense in depth: `STRICT` tables, `balance INTEGER NOT NULL CHECK (balance >= 0)`, `amount INTEGER NOT NULL CHECK (amount > 0)`, foreign keys ON.
  - one connection per request (or per thread), `busy_timeout` ≥ 5000 ms, WAL journal mode, `synchronous=FULL`.
- **Money representation:** integer minor units (cents) end to end. The JSON parser must reject floats, `NaN`/`Infinity`, exponent forms, booleans, strings, and out-of-range integers. No `float` anywhere in the money path.

## Stage 1 API contract (Builder builds it, Breaker attacks it)

All bodies are JSON. Errors are `{"error": "<code>"}` with the status below. Unknown routes → 404 `not_found`.

| Method + path | Body | Success | Notes |
| --- | --- | --- | --- |
| `GET /health` | — | 200 `{"ok": true}` | |
| `POST /accounts` | `{"owner": "<1-64 chars>"}` | 201 `{"id", "owner", "balance": 0, "token"}` | `token` is shown once; it authorizes debits from this account |
| `GET /accounts/{id}` | — | 200 `{"id", "owner", "balance"}` | no token returned |
| `POST /accounts/{id}/deposit` | `{"amount"}` | 200 `{"id", "balance"}` | external money in; no auth (anyone may pay money in) |
| `POST /accounts/{id}/withdraw` | `{"amount"}` | 200 `{"id", "balance"}` | external money out; needs `Authorization: Bearer <token>` of `{id}` |
| `POST /transfers` | `{"from", "to", "amount"}` | 201 `{"id", "from", "to", "amount"}` | needs the bearer token of `from` |
| `GET /audit` | — | 200 `{"total_balances", "total_deposits", "total_withdrawals", "conserved": bool}` | the conservation check the Verifier runs |

Error codes and statuses:

| Status | `error` | When |
| --- | --- | --- |
| 400 | `invalid_json` | body is not a single JSON object, has duplicate keys, or is over 16 KiB (over 1 MiB: 400 is sent, then the connection is closed without draining) |
| 400 | `invalid_amount` | amount missing, not a JSON integer, `< 1`, or `> 1_000_000_000_000` (10^12 minor units) |
| 400 | `invalid_request` | missing/extra-typed fields, `from == to`, bad owner, malformed request line or headers, any method without a route |
| 408 | `request_timeout` | headers + body not fully received within 10 s of the request starting (connection then closed) |
| 431 | `invalid_request` | header line > 64 KiB or > 100 headers |
| 503 | `busy` | database lock not obtained within `busy_timeout`; no effect |
| 401 | `unauthorized` | missing or wrong bearer token for the debited account |
| 404 | `account_not_found` | any referenced account does not exist (checked **before** auth is reported, see I8) |
| 409 | `insufficient_funds` | the debit would take the balance below 0 |
| 422 | `balance_limit` | a credit would push a balance above 10^15 minor units |

Account ids are server-generated (UUID4 strings); the client never chooses one.

Rulings added during unit 1.1:
- **Every response is JSON**, including protocol-level errors and unsupported methods. The stdlib's HTML error pages and 501 must never reach a client.
- **`owner`:** 1–64 code points; rejected (400 `invalid_request`) if it contains any C0 control character (U+0000–U+001F) or U+007F. The schema CHECK must be NUL-safe (`instr(owner, char(0)) = 0`), because SQLite's `length()` stops at a NUL.
- **Numeric headers** (Content-Length and any later header) are parsed as ASCII digits only; `str.isdigit()` accepts Unicode digits and must not be used.
- **Client input never produces a 500.** A 500 on any client-controlled input is a blocking defect.
- **HTTP version:** only `HTTP/1.0` and `HTTP/1.1` are served. Any other explicit version (incl. `HTTP/0.9`, `HTTP/2.0`) → 400 `invalid_request` with an HTTP/1.0 status line and JSON body (R1.1-G).
- **`owner` (added 1.1c):** also rejected (400 `invalid_request`) if it contains any code point of Unicode category `Cc`, `Cf`, `Zl` or `Zp` (covers U+200B, U+202E, U+2028/2029, U+FEFF, U+E0001), or if it is whitespace-only (`owner.strip() == ""` with Python's Unicode whitespace, covers U+00A0, U+3000). Interior spaces stay allowed.
- **`Authorization` (1.2):** exactly one header, value exactly `Bearer <token>` (scheme case-sensitive, single space). Two or more `Authorization` headers → 400 `invalid_request` (checked with the other request-shape 400s, before 404/401). Any other form → 401. Q5 (applied in 1.3): the value is first trimmed of leading/trailing OWS (SP/HTAB, RFC 9110), then matched exactly, so `" Bearer t"` and `"Bearer t "` both authorize; interior whitespace is still exact. Absolute-form request targets (`POST http://host/path`) are routed by path (RFC 9112); known, accepted behaviour.
- **Contention 503s (1.3 finding):** at ≥50-way in-process write contention SQLite's polling busy handler can return a few 503 `busy` (no effect) before 10 s. Within contract for stage 1. Attacks asserting exact success counts must treat 503 as not committed: assert `committed ≤ limit` and `committed + count(503) ≥ limit`, never `committed == limit` alone. **Stage 3 must fix the fairness:** in-process writer lock (≈4 s acquire timeout → 503) in front of `BEGIN IMMEDIATE`, total wait < 10 s (I11).
- **Unread bodies (R1.3-A, 2026-10-03):** before any response, a valid, still-unread declared body (≤ 1 MiB) is read and discarded within the request deadline, so the response isn't lost to a TCP RST. This applies to 404 `not_found`, routed GETs, and early raises alike. Closing without draining stays only for > 1 MiB, `Transfer-Encoding`, a bad or repeated Content-Length, and 408. The drain runs on the send path, so it also covers the R1.1-G version 400 (R1.3-A2). A malformed request line (no headers parsed) is out of scope: the 400 is sent and the connection closed without draining.
- **Deferred to stage 4 (Q3):** owners that render blank but are not Cc/Cf/Zl/Zp/whitespace (U+3164, U+115F, U+FFA0, U+2800, lone combining mark, private use). Ruled when history/display opens; until then the Breaker asserts only no-5xx + exact round-trip.
- **Ledger table names, fixed now so attacks can bind to them:** `transfers(id, from_id, to_id, amount, created_at)`, whose `id` equals the transfer response `id`, and `external_moves(id, account_id, kind CHECK (kind IN ('deposit','withdrawal')), amount, created_at)`.

## Stage 1 — invariants (testable rules)

Every invariant has at least one Builder check in `tests/` and at least one Breaker attack in `attacks/`.

| ID | Invariant | How it is checked |
| --- | --- | --- |
| **I1 Conservation** | `Σ balances == Σ deposits − Σ withdrawals` at every observable moment, including while transfers are in flight. | `GET /audit` → `conserved == true`; and an independent query on the SQLite file. Sampled during and after every attack. |
| **I2 Zero-sum transfer** | A committed transfer of `a` lowers `from` by exactly `a` and raises `to` by exactly `a` in the same transaction. A transfer is either fully applied or not at all. | Before/after balances for both accounts; crash-in-the-middle test (kill the process during load, restart, and I1 + I7 still hold). |
| **I3 No negative balance** | No balance is ever `< 0`. A debit larger than the balance returns 409 and changes nothing. | Direct DB scan `SELECT count(*) FROM accounts WHERE balance < 0` == 0 after every test; boundary: withdraw/transfer exactly `balance` succeeds, `balance + 1` fails. |
| **I4 No double-spend** | Given balance `B`, any set of concurrent debits (transfers and/or withdrawals, any number of threads) commits a total of at most `B`, and every 2xx corresponds to exactly one ledger row. | N threads (N ≥ 50) each try to move `B` (or `B/k`) out of one account at once; assert `Σ committed ≤ B`, `count(2xx) == count(ledger rows)`, final balance == `B − Σ committed`. |
| **I5 Integer money** | Amounts are JSON integers in `[1, 10^12]`. Floats (`1.5`, `1.0`, `1e2`), `NaN`, `Infinity`, `-0`, booleans, strings, `null`, and larger integers are rejected with 400 and no effect. No stored value is ever a float. | Table of malformed amounts; `SELECT typeof(balance)` / `typeof(amount)` is always `integer`. |
| **I6 Rejections are free** | Any non-2xx response leaves every balance and every ledger table exactly as it was. | Snapshot the DB (balances + row counts) before and after each rejected request. |
| **I7 Ledger agrees with balances** | For every account, `balance == Σ credits − Σ debits` replayed from the ledger (deposits, withdrawals, transfers in/out). | Replay query per account after every test. |
| **I8 Only the owner debits** | Withdraw and transfer need the bearer token of the debited account. A token for account A cannot debit account B. Credits need no token. Tokens are compared in constant time and never returned after creation. | Missing/wrong/other-account tokens → 401 and no effect; `GET /accounts/{id}` never shows a token. |
| **I9 Starts offline** | `docker build --network=none` and `docker run --network=none` succeed; `GET /health` returns 200 within 10 s. Same for `python -m app` on a bare Python 3.11. | Verifier runs this on every accepted unit. |
| **I10 Committed means durable** | A 2xx money operation survives a restart of the process; a request that did not get a 2xx is not half-applied after restart. | Restart the server on the same DB file, re-check I1, I3, I7. |
| **I11 No wedge** | Under concurrent load the service keeps answering: no request hangs for more than 10 s, and a lock timeout returns an error (503 `busy`) with no effect rather than a hang or a partial write. | Concurrency attacks run with a client timeout; any hang is a failure. |

## Stage 1 — abuse cases (the Breaker's starting list)

| Target | Abuse case |
| --- | --- |
| I4, I3 | 50–200 concurrent transfers draining the same source; the same transfer fired twice in parallel; A→B and B→A at the same time; one source feeding many destinations; withdraw and transfer racing on the same funds. |
| I4, I2 | Interleaving: deposit into the source while it is being drained; transfer into an account that is being drained. |
| I3 | Exactly-balance, balance+1, balance of 0, amount 1 against balance 0. |
| I5 | `1.5`, `1.0`, `0.1+0.2` style amounts, `1e3`, `-1`, `0`, `-0`, `10**12`, `10**12+1`, `2**63`, `2**64`, `"100"`, `true`, `null`, `NaN`, `Infinity`, arrays, nested objects. |
| I1, overflow | Deposit repeatedly toward 10^15; attempt to push a balance past the int64 limit; many large transfers into one account. |
| I8 | No token, wrong token, token of the destination, token of another account, token in wrong scheme, empty bearer, very long header. |
| I6 | Every rejection above followed by an audit + ledger snapshot comparison. |
| Malformed | Non-JSON, empty body, JSON array/scalar body, duplicate keys (`{"amount":1,"amount":100}`), huge body, wrong Content-Type, unknown fields, `from == to`, non-existent `from` or `to`, id with SQL metacharacters or path traversal. |
| I10, I2 | Kill the server (SIGKILL) during a burst of transfers; restart on the same DB; check I1, I3, I7. |
| I11 | Sustained parallel load for 30 s; verify no request exceeds the timeout and the audit stays conserved throughout. |

## Stage 2 — idempotency and retries (ACCEPTED 2026-10-03)

`stages/stage-2/` = a copy of stage 1 at S1 plus the changes below. The stage-1 `tests/` and `attacks/` are copied unchanged and must stay green against stage 2.

Decisions (Architect, 2026-10-03):
- **D2.1 The key is optional.** `Idempotency-Key` is accepted on `POST /transfers`, `/accounts/{id}/withdraw` and `/accounts/{id}/deposit`. Without it, stage-1 behaviour is unchanged. (The outline said "required"; that would break the rule that stages 1–3 suites keep passing against later stages. A client that wants retry safety sends a key.)
- **D2.2 Format.** Exactly one header. Value is 1–255 chars, each in visible ASCII `0x21`–`0x7E`; it's matched exactly (case-sensitive) after trimming leading and trailing OWS. Empty, too long, other bytes, or two or more headers → 400 `invalid_request`, checked with the other request-shape 400s.
- **D2.3 Scope (amended by Q2-A).** A key belongs to one account and one of two namespaces. `debit` covers withdraw and transfer, keyed on the debited account. `deposit` covers deposits, keyed on the credited account. Different accounts, and the two namespaces, are independent: a deposit key can never block, replay or mismatch a debit key. Inside the `debit` namespace, the same key used for withdraw and then transfer is a mismatch (422). Keyed deposits stay unauthenticated ("anyone may pay money in"). Accepted residual risk, deposit namespace only: someone who guesses a depositor's key can make that depositor's later deposit get 422 (different amount) or a replay (same account, key and amount, which means the guesser's own money was credited). Clients use unguessable keys (UUIDv4).
- **Header details (Q2-B).** The header name is case-insensitive. Interior SP/HTAB or an obs-folded value → 400 `invalid_request`. A keyed request rejected for any reason consumes nothing. A replay is served even after `from` was drained (the lookup comes before the money rules), and with a different but valid `Authorization` spelling.
- **D2.4 Fingerprint.** The stored fingerprint is the *validated* request: `(operation, account, to, amount)`, not raw bytes. Different whitespace, key order or a different but still valid `Authorization` spelling still counts as the same request.
- **D2.5 Only 2xx outcomes are recorded.** The key row goes in the **same `BEGIN IMMEDIATE` transaction** as the money movement and its ledger row. A rejection (any 4xx/503) rolls back and records nothing (I6 covers the key table too), so a later retry with the same key is evaluated fresh.
- **D2.6 Lookup happens inside the write transaction.** Order: body/headers 400 → 404 → 401 → `BEGIN IMMEDIATE` → key lookup → replay or 422 → money rules (409/422 balance_limit) → write → commit. Two in-flight requests with the same key are serialized by the write lock. The second one sees the committed row and replays, so `409 in_progress` is never needed. The `PRIMARY KEY(account_id, scope, key)` is the database backstop: if the constraint fires, it's handled as a replay, never as a 500.
- **D2.7 Replay.** The response has the original status and byte-identical JSON body (the same transfer `id`; deposit and withdraw return the balance *as of the original*), plus the header `Idempotent-Replayed: true`. A replay never moves money and never writes a ledger row. Replays still require the 401 check, so a wrong token can't read a replay.
- **D2.8 Mismatch.** Same account and key with a different fingerprint → 422 `idempotency_key_reused`, no effect.
- **D2.9 Retention.** Keys are kept forever in stage 2 (no expiry). The table: `idempotency_keys(account_id, scope CHECK (scope IN ('debit','deposit')), key, fingerprint, status, response, created_at, PRIMARY KEY(account_id, scope, key))`, STRICT, with foreign keys.

Copied-suite rule (Verifier pre-gate, 2026-10-03): in a later stage's copy of an earlier suite, a schema-inventory assertion may be extended to list new tables, as long as it stays at least as strict. Every other line stays byte-identical. Regression gate = the earlier suites unmodified against the new code. The only tolerated failure is that inventory assertion.

Stage 2 invariants (added to I1–I11, which all still hold):

| ID | Invariant | How it is checked |
| --- | --- | --- |
| **I12 At most once** | For any `(account, key)`, at most one money movement ever commits, whether the requests are sequential, concurrent (N ≥ 50 at once), or spread across a restart. | N identical keyed requests: exactly one ledger row, balance moved once, every 2xx carries the same body. |
| **I13 Faithful replay** | A replay returns the original status + byte-identical body + `Idempotent-Replayed: true`, with zero effect, even after the account's balance changes or the process restarts. | Compare bodies; DB snapshot before/after the replay. |
| **I14 Mismatch is rejected** | Same key + different operation/to/amount → 422 `idempotency_key_reused`, no effect. | Matrix of differing fields, endpoints. |
| **I15 Rejections consume nothing** | A non-2xx keyed request records no key row. A retry after the cause is fixed (e.g. funds arrive) succeeds once. | 409 → deposit → retry same key → 201; then retry again → replay. |
| **I16 Timeout-and-retry is safe** | A client that times out or disconnects after sending, then retries with the same key, ends with exactly one movement, whether or not the first one committed. | Disconnect right after the body is sent; SIGKILL the server mid-burst, then restart and retry every key. |
| **I17 Keyless = stage 1** | Requests without the header behave exactly as in stage 1. | Stage-1 `tests/` + `attacks/` run unchanged against stage 2. |

Stage 2 abuse cases: 50–200 parallel copies of one keyed transfer; same key raced with different amounts; same key across transfer/withdraw on one account; same key on two different accounts; key replay with a wrong/other token; key with control chars, spaces, 256 chars, non-ASCII, duplicate header; disconnect-then-retry; kill-mid-burst then retry every key; replay after the balance moved; 409 then fund then retry; key-table rows never exist for a non-2xx (direct DB check).

## Stage 3 — concurrency hardening (ACCEPTED 2026-10-05)

`stages/stage-3/` = a copy of stage 2 at its accepted state plus the changes below. The stage-1 and stage-2 suites are copied (copied-suite rule) and must stay green against stage 3.

Decisions (Architect, 2026-10-03):
- **D3.1 One write chokepoint.** Every database write goes through `db.write_transaction`, including `POST /accounts` (today an implicit autocommit insert). No other code path may write.
- **D3.2 Fair in-process writer lock (the 1.3 finding).** `write_transaction` first acquires a process-wide **FIFO** lock (a ticket lock or a `Condition` queue; `threading.Lock` is not FIFO), then runs `BEGIN IMMEDIATE`. The acquire timeout is 4 s → 503 `busy`, no effect. The lock is released in `finally` on every path (rejection, exception, client disconnect). SQLite's `busy_timeout` stays as the backstop for writers in other processes. Readers (GETs, `/audit`) never take the lock.
- **D3.3 Bounded handler threads.** At most 256 requests are handled at once. Further connections wait in the listen backlog, never as unbounded threads, and every request still answers within I11's 10 s.
- **D3.4 Stress harness.** `stress/run_stress.py` (stdlib only, in the stage folder, also run by a test): `--seconds`, `--workers`, `--accounts`, `--seed`. It runs a random mix over a small account set: transfers including A→B→C→A cycles and A↔B pairs, withdrawals, deposits, keyed and keyless requests, keyed retries of earlier requests, and clients that disconnect mid-request. It samples I1/I3/I7 straight from SQLite at least once a second. It keeps a client-side model of every 2xx and prints one JSON summary: ops, statuses, p50/p99/max latency, 503 count, invariant results. It exits non-zero on any violation.

Rulings on Builder questions (Q3, 2026-10-03):
- **Q3-A Slow clients vs I19.** I19's 10 s bound holds while fewer than the 256 handler slots are held by slow clients. Stress and I19 checks use at most 64 concurrent slowloris connections. Saturating all 256 slots is a capacity attack for a front proxy, so it's out of scope. Even then: no 5xx, never more than 256 handlers, and I20 recovery once the slow connections end. The stage-1 10 s / 408 contract is unchanged.
- **Q3-B** (amended by Q3.1-A, 2026-10-04: **3000 ms**, because the copied stage-1 attack a11 `test_short_lock_is_waited_out_not_refused` holds the lock ~2 s and must be waited out; budget 4 s lock + 3 s busy + commit ≈ 7 s < 10 s) `busy_timeout` = 2000 ms from stage 3 on (cross-process backstop; the FIFO lock serializes in-process writers). This amends "≥ 5000 ms" in the architecture decisions for stage 3+. Worst case: 4 s lock + 2 s busy + commit, under 10 s.
- **Q3-C** "Zero 503 at ≤ 100 writers" binds on both the bare run and the Docker run, with the DB on the container's own filesystem. The stress summary reports lock wait and lock hold p50/p99/max. `synchronous=FULL` stays.
- **Q3-D** The lock covers only `BEGIN IMMEDIATE`..`COMMIT` (body read, 404/401 reads and the send happen outside it). A waiter whose client disconnected still commits. `POST /accounts` may return 503. The 256 cap is a semaphore before the thread spawn, with backlog 1024. With 1000 connections at once, a connect the kernel refuses is acceptable, but every accepted complete request gets a full JSON response and no 2xx is lost. The FIFO test imports `app.db` directly.

Rulings on the Breaker's 3.1 interim (Architect, 2026-10-04):
- **D3.3a (amends D3.3; R3.1-A).** A connection takes a handler slot and thread only once its complete request head (request line + headers up to the blank line) has arrived. Before that it is parked: the accept loop keeps accepting, and a small fixed pool of reader threads reads heads with `selectors` (sharded, since Windows `select()` caps a selector at 512 sockets). Every stage-1 head rule (10 s deadline from connect → 408, 64 KiB line / 100 headers → 431, malformed line / version → 400 R1.1-G) is enforced in the parked phase with unchanged replies, sent without a slot; the 10 s deadline is one deadline across both phases. Head bytes (and any pipelined bytes) are handed to the handler. At least 1500 parked connections on bare Windows and Linux; parked connections capped (4096), beyond which accepting stops and the excess waits in the backlog. Threads stay bounded at 256 + the pool. Reason: copied stage-1 attacks a08 `ConnectionLimits.test_idle_connections_do_not_starve` and a11 `ConnectionFlood.test_idle_flood_does_not_wedge_money_path` are accepted guarantees; the copied-suite rule is **not** amended to tolerate them.
- **Q3.1-B (parked-head memory).** Total parked-head budget 64 MiB. While over budget, reading pauses only for parked connections already holding > 16 KiB of head bytes; smaller heads keep being read and handed off. Bound: 64 MiB + 4096 × 16 KiB = 128 MiB. Paused heads resume when budget frees or get the normal 408 at 10 s. Stage-1 per-head limits unchanged (no new 431 rule). Checked by a large-head memory flood with 40 small legit requests answering within I19 and bounded peak RSS.
- **Q3.1-C.** One request per connection, as in stage 1 (no keep-alive). Bytes read past the head in the same read (body and beyond) reach the handler intact.
- **R3.1-B.** Measurement note 4 holds at any load: on bare Windows (listen backlog capped near 200), a connect refused or reset before any request byte is sent is reported, not a violation. Anything after the first byte is a violation. In Docker (Linux), refusals must be 0 for runs up to 600 connections.

How I18–I21 are measured (Breaker's reading, agreed by the Architect):
1. "Arrival order" (I19) = the order writers call the lock acquire, which comes after the body read and 404/401, not TCP connect order. Black-box check: an external process holds the SQLite write lock for about 1.5 s (under the 2 s `busy_timeout`). Then 20 keyless transfers, each from a **different** source account, are sent 50 ms apart. After the release, the `transfers` rowid/`created_at` order equals the send order, with zero 503. This sits alongside the Builder's direct `app.db` FIFO unit test.
2. I19 latency is measured client-side, from the first byte sent to the last byte received, for clients that send the whole request at once. Slowloris clients are attack load and aren't measured (cap 64, Q3-A).
3. "The writer lock isn't held" (I20) is checked black-box: after the load ends, a fresh keyed write answers 2xx within 1 s, and so does a second write right behind it.
4. With 1000 connections at once, a connect refused or reset before any request byte is accepted is fine. A full request that was sent must get a full JSON response, and every 2xx must be in the ledger. A write that commits while its client saw a reset is a lost 2xx and a **failure**. Other resets are reported as numbers.
5. The Breaker keeps its own stress driver in `attacks/`, independent of `stress/run_stress.py`, and also runs `run_stress.py` with hostile parameters (`--workers 500 --accounts 2`).

Stage 3 invariants (added to I1–I17):

| ID | Invariant | How it is checked |
| --- | --- | --- |
| **I18 No lost update** | After a stress run (≥ 60 s, ≥ 200 workers, ≤ 8 accounts), each final balance equals the initial balance + Σ effects of the 2xx responses the clients observed (keyed replays counted once). I1, I3 and I7 hold in every sample. | `run_stress.py` model vs DB; continuous sampler. |
| **I19 Fair, bounded wait** | No request takes ≥ 10 s. With ≤ 100 concurrent writers there are **zero** 503s, so drain attacks at ≤ 100-way assert `committed == limit` exactly (the 1.3 slack rule is retired for stage 3 at that size). Above that, a 503 means no effect. Writers are served in arrival order. | Drain ×100 with exact counts; latency max from the harness; a FIFO-order check on the lock itself. |
| **I20 No wedge** | After stress, after clients killed mid-request, and after slowloris bodies, `/health` and a fresh write each answer within 1 s, and the writer lock isn't held. | Post-stress probe; lock-state check. |
| **I21 Crash under stress** | SIGKILL during stress, restart on the same DB: I1/I3/I7 hold, and retrying every keyed request the clients sent moves money at most once in total (I12 across the crash). | Kill-mid-stress test. |

Stage 3 abuse cases: 200–500 writers on 2–3 accounts; pure cycles (A→B, B→C, C→A at once); one hot account both debited and credited by everyone; drains at exactly 100-way with exact counts; keyed retries racing originals under stress; mass client disconnects while holding the lock's turn; slowloris connections taking up handler slots during stress; 1000 connections opened at once (D3.3); kill -9 mid-stress, then restart and retry everything.

## Stage 4 — history and reversal (ACCEPTED 2026-10-05 on a97d9c9)

`stages/stage-4/` = a copy of stage 3 at S3 (ce98f4d) plus the changes below. The stage-1, 2 and 3 `tests/` and `attacks/` are copied (copied-suite rule) and must stay green against stage 4.

Decisions (Architect, 2026-10-04):
- **D4.1 History endpoint.** `GET /accounts/{id}/transactions?limit=<1..100, default 20>&cursor=<opaque>` → 200 `{"items": [...], "next_cursor": <string|null>}`. It needs the bearer token of `{id}` (history shows counterparties and amounts, so it is private, unlike the stage-1 balance read). Order: 400 (bad `limit`/`cursor`/unknown query param/duplicate param) → 404 `account_not_found` → 401. A cursor from another account → 400 `invalid_request`.
- **D4.2 Item shape.** `{"id", "type", "amount", "counterparty", "created_at"}` plus `"reverses"` on reversal items. `type` is one of `deposit`, `withdrawal`, `transfer_in`, `transfer_out`, `reversal_in`, `reversal_out`. `id` is the ledger row id (the transfer id for transfers and reversals). `counterparty` is the other account id for transfers/reversals and `null` for deposits/withdrawals. `amount` is a positive integer; the direction is in `type`. No owner names appear in history, so the Q3 blank-owner question stays deferred (no display surface yet).
- **D4.3 Stable order.** Newest first, by a strictly increasing integer sequence assigned to every ledger row inside its write transaction (one sequence across `transfers` and `external_moves`; the FIFO writer lock already serializes writers). Never order by `created_at` alone (ties, clock steps). Pagination is keyset on that sequence, never `OFFSET`, so rows committed while a client pages never cause a duplicate or a skip in the pages it has not read yet. How the sequence is stored is the Builder's call, within the copied-suite rule (a new table is tolerated; a changed column set on an existing table must keep every copied suite green unmodified).
- **D4.4 Reversal endpoint.** `POST /transfers/{id}/reverse`, body exactly `{}`. A reversal moves the original amount from the original recipient (`to`) back to the original sender (`from`). It is a debit of `to`, so it needs the bearer token of `to` (I8); the sender can't pull money back. It is stored as an ordinary `transfers` row `to → from` (so I1, I2 and the stage-1 ledger replay I7 hold unchanged) plus a link row in a new STRICT table `reversals(transfer_id PRIMARY KEY REFERENCES transfers(id), reversal_id UNIQUE REFERENCES transfers(id), created_at)`, written in the same `write_transaction`. The PRIMARY KEY is the database backstop for "at most once". 201 `{"id", "from", "to", "amount", "reverses"}`, where `id` is the new transfer id and `from`/`to` are the reversal's direction.
- **D4.5 Reversal errors.** Order: 400 (body not exactly `{}`, malformed id) → 404 `transfer_not_found` (unknown id) → 401 (not the token of the original `to`) → inside the lock: idempotency lookup → 409 `already_reversed` (the transfer was already reversed) → 422 `not_reversible` (the transfer is itself a reversal) → 409 `insufficient_funds` (the original recipient's balance is below the amount; no partial reversal) → 422 `balance_limit` (the sender would exceed 10^15) → write. Every rejection has no effect (I6).
- **D4.6 Idempotency on reverse.** `Idempotency-Key` is accepted with the D2.2 format rules, in the `debit` namespace of the original `to` account, fingerprint `(reverse, to, transfer_id)`. The same key used earlier for a withdraw/transfer on that account is a 422 mismatch. Without a key, a second reverse is 409 `already_reversed`; with the same key it is a replay of the original 201.
- **D4.8 Carry-over from 3.1 (Architect, 2026-10-05).** Stage 4's `app/__main__.py` logs one stderr line at startup saying whether `tune_malloc()` was applied or skipped, and why, so the Verifier can see it ran in the container. (It was kept out of stage 3 so the attacked and gated hashes stayed frozen.)
- **D4.9 Existing databases (Architect, 2026-10-05).** Stage 4 must start on a database written by stage 3 that already has ledger rows. At startup, any row without a sequence gets one, once, inside one `write_transaction`. The order is `created_at`, ties broken by `external_moves` before `transfers`, then rowid. It is deterministic and idempotent (a second start changes nothing), and rows written later always get higher sequences. Checked by a test that seeds a stage-3 schema DB, starts stage 4, and checks I22 on it.
- **D4.10 Query parsing (Architect, 2026-10-05).** The query string is decoded once with `urllib.parse.parse_qsl(strict_parsing=True, keep_blank_values=True)`. Only `limit` and `cursor` are allowed; anything else, a repeated name, an empty value, or a parse error → 400 `invalid_request`. `limit` is ASCII digits only, no sign, no leading zero, 1..100 (so `0`, `101`, `-1`, `+5`, `05`, `1.5`, `1e1`, `１０` are 400). `cursor` is the server's opaque string, URL-safe base64 without padding, ≤ 256 chars, integrity-protected (HMAC with a per-database secret kept in the DB) and bound to the account. Anything forged, truncated, or from another account → 400. A cursor whose row was reversed later stays valid (keyset on sequence). A `?` with nothing after it counts as no query.
- **D4.11 Reverse body and query (Architect, 2026-10-05).** A reverse body that is not a JSON object (empty, broken JSON, `[]`, `null`, a number) is 400 `invalid_json`, like every POST since stage 1; a JSON object other than `{}` is 400 `invalid_request`. POST routes, reverse included, match on the path and ignore the query string, as since stage 1; the strict query rule (D4.10) is for `GET /transactions` only.
- **D4.7 Unchanged.** Deposit, withdraw, transfer, audit and every stage 1–3 rule stay exactly as accepted. A transfer whose recipient later spent the money is still reversible only up to the recipient's current balance (all-or-nothing, D4.5).

Stage 4 invariants (added to I1–I21):

| ID | Invariant | How it is checked |
| --- | --- | --- |
| **I22 Complete history** | Paging an account's history to the end yields every ledger row touching it exactly once, and `Σ credits − Σ debits` over those items equals its balance. | Random workload, then page with several `limit` values; compare with the DB and the balance. |
| **I23 Stable pages** | While writes to the account continue, pages fetched by following `next_cursor` never repeat or skip an item that existed when the first page was read; the order is strictly newest first by sequence. | Page slowly during a write storm; check the union against the DB. |
| **I24 Private history** | Only the token of `{id}` reads its history. Missing/wrong/other-account token → 401; unknown account → 404; malformed `limit`/`cursor` → 400; none of these leaks items. | Matrix of tokens and params. |
| **I25 Reverse at most once** | For any transfer, at most one reversal ever commits: sequential, N ≥ 50 concurrent, keyed or keyless, across a restart. | Concurrent reverse burst → exactly one 201, one `reversals` row; the rest 409 or replays. |
| **I26 Reversal can't overdraw** | If the original recipient's balance is below the amount, the reversal is 409 `insufficient_funds` with no effect; reversal and the recipient's own debits racing never take the balance below 0 or double-spend. | Drain-race: recipient withdraws while reversals fire. |
| **I27 Reversal is a transfer** | A committed reversal moves exactly the original amount `to → from`, appears in both accounts' histories linked by `reverses`, and keeps I1, I2, I3, I7 true. A reversal can't itself be reversed. | Before/after balances, history items, ledger replay. |
| **I28 Earlier stages hold** | Stage 1–3 `tests/` and `attacks/`, unmodified except the tolerated inventory assertion, pass against stage 4. | Verifier regression gate. |

Stage 4 abuse cases: 50–200 concurrent reverses of one transfer (keyed and keyless); reverse with the sender's token, a third party's token, no token; reverse a reversal; reverse after the recipient spent part of it; recipient withdraw racing the reversal; reverse into a sender near 10^15; reverse of a nonexistent / malformed / SQL-meta id; body other than `{}`; key reuse across reverse and transfer; history with `limit` 0, 101, `-1`, `1.5`, `1e1`, repeated params, unknown params, forged/truncated/other-account cursors, cursors with SQL metacharacters; paging during a write storm; kill -9 mid-reverse-burst then retry.

## Later stages (outline; invariants are written when each stage opens)
- **Stage 3 — concurrency proof.** Stress harness (hundreds of threads, random transfers across a small account set, including cycles), deadlock and lock-timeout behavior, the audit checked continuously; I1–I11 re-proven under load.
- **Stage 4 — history + reversal.** `GET /accounts/{id}/transactions` (paginated, stable order); `POST /transfers/{id}/reverse` that is itself idempotent, can reverse a transfer at most once, may not overdraw the original recipient, and preserves I1–I11. Stages 1–3 suites must still pass against stage 4.

## Workflow

Seats (from 2026-10-05, Stage 4 resume): Architect = architect-6mhf, Builder = builder-6mhg, Breaker = breaker-6mhh, Verifier = verifier-6mhj, all four in one room `c73fc622`. Earlier, from 2026-10-04, third resume at 3.1: Architect = architect-xxsf, Builder = developer-xxsg, Breaker = reviewer-xxsh, Verifier = product-owner-xxsj, all four in one room `748d30f0`. Second resume at 3.1: Architect = architect-stqd, Builder = developer-stqf, Breaker = reviewer-stqg, Verifier = product-owner-stqh, all four in one room `4f53f46f`. Earlier 2026-10-04: Architect = architect-zf65, Builder = developer-zf66, Breaker = reviewer-zf67, Verifier = product-owner-zf68, all four in one room `0916f3df`. Before that (2026-10-03, resumed mid-1.3): Architect = architect-7xff, Builder = developer-7xfg, Breaker = reviewer-7xfh, Verifier = product-owner-7xfj, all four in one room `4c630aa4`. Earlier (1.1–1.3 handoff): architect/developer/reviewer/product-owner-mn2c in three pairwise rooms (34c9533c, ce3dd3d7, 79ddc4c3), relayed by the Architect.

1. The Architect posts one unit to the Builder and the same invariants to the Breaker.
2. The Builder implements the unit with its checks and posts: what changed, why, and how to run it.
3. The Breaker attacks that build and posts either reproductions (blocking, to the Builder) or "could not break; tried X".
4. The Verifier rebuilds from clean with no network, runs `tests/` + `attacks/` + earlier stages, and posts ACCEPT or REJECT with evidence.
5. The Architect updates this board and opens the next unit.
