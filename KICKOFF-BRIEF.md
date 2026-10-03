# Kickoff brief — paste this into the BAND room to start the run

> This is the task. All track-specific detail lives here, never in the seat mandates.

Build a wallet-and-payments service (a clean-room clone in the style of Venmo), as a factory, one stage at a time. Architect, plan and set the invariants first; Builder implements; Breaker attacks every build; Verifier independently gates each stage. Ask me only for a genuine product decision. Work autonomously otherwise.

## Non-negotiable invariants (the whole point)
- Money is conserved: the sum of all balances never changes except through an explicit external deposit or withdrawal.
- No money is created or destroyed by any transfer.
- No double-spend: the same funds cannot be spent twice, even under concurrent transfers, retries, or interleaving.
- No negative balances: a transfer that would overdraw is rejected atomically.
- Idempotent operations: a transfer submitted with the same client key more than once moves money at most once.
- Correct rounding: amounts use integer minor units (e.g. cents); no floating-point money.

## Build constraints
- The service must build and start from a clean container with NO outbound network.
- Keep the stack simple and deterministic: a single service with an embedded database (e.g. Python + FastAPI + SQLite, or Node + SQLite). Use real database transactions and row locking to enforce the invariants — this is what defeats double-spend, not application-level checks.
- Each stage is a complete, buildable service in its own folder: stages/stage-1 ... stage-4.

## Stages
- Stage 1 — Core wallet: create accounts, hold balances, and a single atomic transfer between two accounts that cannot double-spend or overdraw. Minimum to be eligible.
- Stage 2 — Idempotency & retries: a client-supplied idempotency key so a retried transfer never moves money twice; safe behaviour on timeout-and-retry.
- Stage 3 — Concurrency hardening: many parallel transfers touching the same accounts with no lost updates, no overdraft, no deadlock-wedge; prove it under a concurrency stress test.
- Stage 4 — Extend without breaking: add transaction history and a reversal/refund that itself respects every invariant, and prove stages 1–3 still pass.

## Done, per stage
A stage is done only when: the Breaker has run its full attack suite and has no open reproduction, the Verifier has independently re-run those attacks and the invariant checks and confirmed they pass from a clean no-network build, and no earlier stage has regressed.
