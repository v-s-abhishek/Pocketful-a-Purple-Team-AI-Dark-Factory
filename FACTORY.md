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

- **Stages completed:** **All four planned stages built, attacked, and accepted** by the Verifier from clean `--network=none` builds (bare + Docker).
  - **Stage 1 — Core wallet** (accounts, deposit/withdraw/audit, atomic transfer). No double-spend, no negative balance, conservation. `server.py` sha256 `89a52478…8d1a38`.
  - **Stage 2 — Idempotency & retries.** A network retry can never move money twice.
  - **Stage 3 — Concurrency hardening.** FIFO writer lock, bounded handlers, parked-connection phase. 139 tests + 232 attacks OK (bare + Docker); stress 500 workers / 2 accounts and 200 workers / 8 accounts for 60 s → 0×503, 0 refused, 0 money violations; Windows connect-refusals driven 1118 → 0.
  - **Stage 4 — History & reversal.** Paginated private transaction history (stable keyset order) and a reversal that commits at most once, never overdraws, and is itself idempotent and non-reversible. Final gate: **181 tests + 291 attacks OK (slow incl.), bare + Docker `--network=none`**, `/health` 200 in ~0.6 s, and the stage-1/2/3 suites still green (I28).

- **Total run cost:** four Claude Code seats (Architect, Builder, Breaker, Verifier) on Claude Opus across working sessions on 2026-10-01, -03, -04 and -05. Exact token spend is in the Claude usage dashboard for those dates.

- **Reproductions found and fixed (adversarial seat earned its place):** the Breaker filed blocking reproductions a happy-path test suite would have shipped, and each was fixed at root cause and re-verified under attack:
  - **Split-send lost response (Stage 1, R1.3-A/A2):** a request whose body arrived in a later TCP segment got its response reset before the client read it — the caller received *no* response. Fixed by draining the unread body within the deadline at one `_send` chokepoint; new split-send attacks (`attacks/test_a13_*`) keep it from returning.
  - **Head-flood memory blow-up (Stage 3, A3.1-3):** a flood of oversized request heads could push RSS past ~1 GB (a denial-of-service). Fixed with a parked-head memory budget plus glibc malloc tuning; peak RSS bounded to a few hundred MiB under the same attack.

- **Notable exploit the Breaker caught:** the **split-send lost-response** defect above — when a request body arrived in a separate TCP segment after its headers, a response sent while the declared body was still unread was reset (RST) before reaching the client, so the caller got *no* response at all. It hit 404s, routed GETs and the HTTP-version 400 path, breaking the service's own "every response is JSON" ruling. Exactly the class of bug happy-path unit tests miss and a dedicated adversarial seat catches.

- **Known limitation (now resolved):** the Stage-1 contention unfairness — under ≥50 concurrent debits on one account SQLite's busy handler could return a few `503 busy` before the deadline — was the one documented Stage-1 limitation. It was **fixed in Stage 3** as planned: an in-process FIFO writer lock in front of `BEGIN IMMEDIATE` (≈4 s acquire → 503, total wait < 10 s), so at ≤100 concurrent writers there are now **zero** 503s. Money was never created, destroyed, or double-spent at any stage.
