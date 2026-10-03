# FACTORY.md — pocketful (Purple-Team Factory)

> How this factory is built, why it is shaped this way, and how it catches and recovers from bad work.

## What the factory produces
A wallet-and-payments service (Venmo-style, clean-room) whose core money invariants hold under concurrency, retries and rounding — built stage by stage by a band of coding agents that attacks its own work before accepting it.

## The band (seats)
Four seats, each with a generic mandate (see `mandates/`). Seats may share a runtime and model.

| Seat | Role | Never does |
| --- | --- | --- |
| Architect / Threat-modeler | Plans work, sets invariants + abuse cases, accepts stages | Writes feature code |
| Builder | Implements one unit at a time to the invariants | Marks its own work done |
| Breaker | Attacks every build, files reproducible exploits | Approves work |
| Verifier | Independently re-runs attacks + checks, gates "done" | Trusts unrun claims |

## Why this shape (design rationale)
- **The hard part is adversarial, so the factory is adversarial.** Both tracks fail on concurrency/retries/rounding, not on features. A dedicated Breaker seat turns that failure mode into a first-class citizen instead of hoping unit tests catch it.
- **Separation of build and judgement.** The Builder cannot declare its own work done; an independent Verifier re-runs everything. This is what makes the factory trustworthy without a human in the loop.
- **Invariants before code.** The Architect writes testable invariants up front, and the Breaker attacks the same invariants the Builder builds to — so attack and defence are aligned.
- **Generic mandates.** No mandate names an endpoint, field, or error. The task (KICKOFF-BRIEF.md) carries all track detail. The same band could build a different product unchanged.

## How it catches bad work
- Every build passes through the Breaker's attack suite (concurrent duplicates, replay/retry, interleaving, boundary/rounding, unauthorized access).
- Every fix is re-verified independently by the Verifier from a clean, no-network build.
- The attack suite only grows, so a regression of a previously fixed bug is caught on the next run.

## How it recovers from failure
- A Breaker reproduction is blocking evidence handed to the Builder; the Builder fixes the root cause and hands it back; the Verifier confirms before the stage advances.
- A regression in an earlier stage rejects the current unit until fixed.

## Seat setup (reproduce this factory)
1. Install Claude Code and BAND Desktop; pass BAND readiness (CLI + band-peer plugin).
2. Open four Claude Code sessions. Give each the matching file from `mandates/` as its standing instruction.
3. Start the Architect first; it creates the room and invites the others.
4. Paste `KICKOFF-BRIEF.md` into the room. Let the band run; answer only genuine product decisions.

## Measured results

- **Stages completed:** Stage 1 (Core wallet) — **complete and accepted**. Units 1.1 (skeleton + accounts), 1.2 (deposit / withdraw / audit) and 1.3 (atomic transfer) and the Stage 1 gate (S1) all passed the Verifier from a clean `--network=none` build. The accepted build is pinned at `app/server.py` sha256 `89a52478…8d1a38`. Stage 2 (Idempotency & retries) unit 2.1 was then built and handed off, and was under the Breaker's attack / Verifier gate at the time of writing. Stages 3 (concurrency proof) and 4 (history + reversal) are specified and planned.

- **Total run cost:** four Claude Code seats (Architect, Builder, Breaker, Verifier) running on Claude Opus across two working sessions (2026-10-01 and 2026-10-03). Exact token spend is available in the Claude usage dashboard for those dates.

- **Reproductions found and fixed:** 1 blocking reproduction in the documented run. The Breaker could **not** break units 1.1 or 1.2 (104 and 124 attacks passed, slow included). On unit 1.3 (atomic transfer) it filed one blocking reproduction — a lost-response bug (R1.3-A, extended to a second surface as R1.3-A2). The Builder fixed the root cause with a single response-path change, the Breaker re-attacked (152 attacks, normal + slow, could not break), and the Verifier confirmed from a clean no-network build before Stage 1 was accepted. The attack suite grew from this (new split-send attacks in `attacks/test_a13_*`) so the bug can never silently return.

- **Notable exploit the Breaker caught:** a **split-send lost-response** defect. When an HTTP request's body arrived in a separate TCP segment *after* its headers, a response sent while the declared body was still unread got reset (RST) before it reached the client — so the caller received *no* response at all. It hit 404s, routed GETs, and the HTTP-version 400 path, breaking the service's own ruling that every response is JSON. The fix drains any valid still-unread body (up to 1 MiB) within the request deadline before sending, at one central chokepoint in `_send`; no status codes or check order changed. This is exactly the class of bug unit tests on the happy path miss and a dedicated adversarial seat catches.

- **Known limitation:** under very high in-process write contention (≥50 concurrent debits on one account) SQLite's polling busy handler can return a few `503 busy` (no effect, safe to retry) before the 10 s deadline. This is within the Stage 1 contract — money is never created, destroyed, or double-spent — but it is not yet *fair*. The planned fix is an in-process writer lock in front of `BEGIN IMMEDIATE` (≈4 s acquire → 503, total wait < 10 s), scheduled for Stage 3's concurrency hardening (invariant I11).
