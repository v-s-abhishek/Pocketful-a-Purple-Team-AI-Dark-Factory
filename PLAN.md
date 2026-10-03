# PLAN — pocketful wallet service

Owner: Architect (architect-7xff; architect-mn2c before 2026-10-03). The Architect updates this file as units complete. Only the Verifier marks a unit done.

## Status board

| Unit | Stage | Goal | Builder | Breaker | Verifier |
| --- | --- | --- | --- | --- | --- |
| 1.1 | 1 | Skeleton: server, schema, accounts (create/get), test harness, offline container | done (48 tests) | could not break 1.1c (104 OK) | **ACCEPTED** 2026-10-01 |
| 1.2 | 1 | External money: deposit, withdraw, audit endpoint | done (67 tests) | could not break (124 OK, slow incl.) | **ACCEPTED** 2026-10-01 |
| 1.3 | 1 | Atomic transfer (no overdraw, no double-spend) | done (84 tests; R1.3-A/A2 fixed: one drain chokepoint in `_send`) | could not break after R1.3-A/A2 fix (152 OK normal + slow; a13 = 14 attacks) | **ACCEPTED** 2026-10-03 |
| S1 | 1 | Stage 1 gate: full attack suite + invariants from a clean no-network build | 84 OK | 152 OK (normal; slow + docker, 0 skipped) | **ACCEPTED** 2026-10-03 (server.py sha256 89a52478…8d1a38) |
| 2.1 | 2 | Idempotency keys, timeout-and-retry (D2.1–D2.9, I12–I17) | handed off (server.py fd1c36bf…; idempotency.py 509c9cc2…) | attacking (a14) | |
| 3.x | 3 | Concurrency stress test, lock/deadlock hardening (incl. fair in-process writer lock, see 1.3 finding) | planned | | |
| 4.x | 4 | Transaction history, reversal/refund, stage 1–3 regression | planned | | |

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

## Stage 2 — idempotency and retries (OPEN since 2026-10-03, after S1 ACCEPT)

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

## Later stages (outline; invariants are written when each stage opens)
- **Stage 3 — concurrency proof.** Stress harness (hundreds of threads, random transfers across a small account set, including cycles), deadlock and lock-timeout behavior, the audit checked continuously; I1–I11 re-proven under load.
- **Stage 4 — history + reversal.** `GET /accounts/{id}/transactions` (paginated, stable order); `POST /transfers/{id}/reverse` that is itself idempotent, can reverse a transfer at most once, may not overdraw the original recipient, and preserves I1–I11. Stages 1–3 suites must still pass against stage 4.

## Workflow

Seats (from 2026-10-03, resumed mid-1.3): Architect = architect-7xff, Builder = developer-7xfg, Breaker = reviewer-7xfh, Verifier = product-owner-7xfj, all four in one room `4c630aa4`. Earlier (1.1–1.3 handoff): architect/developer/reviewer/product-owner-mn2c in three pairwise rooms (34c9533c, ce3dd3d7, 79ddc4c3), relayed by the Architect.

1. The Architect posts one unit to the Builder and the same invariants to the Breaker.
2. The Builder implements the unit with its checks and posts: what changed, why, and how to run it.
3. The Breaker attacks that build and posts either reproductions (blocking, to the Builder) or "could not break; tried X".
4. The Verifier rebuilds from clean with no network, runs `tests/` + `attacks/` + earlier stages, and posts ACCEPT or REJECT with evidence.
5. The Architect updates this board and opens the next unit.
