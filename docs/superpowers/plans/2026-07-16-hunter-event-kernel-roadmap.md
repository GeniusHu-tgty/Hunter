# Hunter Event Kernel Roadmap

**Date:** 2026-07-16
**Authority:** `docs/superpowers/specs/2026-07-16-hunter-event-kernel-hardening-design.md` at commit `d56f2d8`
**Boundary:** New `core/workflow/event_kernel/` package and independent `tests/acceptance/event_kernel/` suite only. Legacy workflow files, production entry points, and `sessions/` remain untouched.

> This document is a sequencing roadmap, not a directly executable implementation plan. Each stage requires its own detailed `writing-plans` document with exact files, complete tests and implementation, RED/GREEN commands, boundary checks, and commit steps.

## Review protocol for every stage

Each stage closes with two separate reviews:

1. **Specification-compliance review:** verify every requirement, invariant, public contract, event name, error code, and scope boundary against the authoritative design.
2. **Code-quality and verification review:** inspect maintainability, type/API consistency, test quality, command output, forbidden diffs, and regressions before the next stage starts.

A stage is not complete until both reviews pass and their findings are resolved.

## Ten stages

| Stage | Focus | Deliverable and exit gate | Required detailed plan |
|---|---|---|---|
| 1 | Contracts and envelope | Frozen public contracts, stable command/event enums, typed errors, strict canonical JSON, digests, IDs, schema 2.0 event construction/validation, and explicit exports. Focused tests, `compileall`, legacy forbidden diff, and full test collection pass. | `2026-07-16-hunter-event-kernel-task1-contracts-envelope.md` |
| 2 | Replay and upcast | One binary pass, schema 1.0 lazy upcast, one reducer boundary, compact indexes, exact semantic prefix, data-only `ReplayIssue`, and strict issue conversion. | A separate Task2 replay/upcast plan |
| 3 | Store and CAS | Existing workflow lock, same-command-before-CAS ordering, revision/hash conflict separation, one-event fsynced append, and non-authoritative cache semantics. | A separate Task3 store/CAS plan |
| 4 | Action and attempt | Generation-visible logical action identity, merge restrictions, deferred/blocked transitions, lock-owned attempt numbering, terminal rules, and budget accounting. | A separate Task4 action/attempt plan |
| 5 | Evidence and verdict | Typed attestation observations, exact generation/action/attempt binding, verdict supersession, atomic optional finding creation, and global finding uniqueness. | A separate Task5 evidence/verdict plan |
| 6 | Process | Attempt-bound process lifecycle, kernel-owned output sequence, absolute counters, 4,096-byte redacted excerpts, marker rejection, and process-before-attempt terminal ordering. | A separate Task6 process plan |
| 7 | Outbox | Deterministic outbox IDs, dedupe equality/conflict behavior, absolute delivery attempts, deterministic pending order, and replay with no SQLite side effects. | A separate Task7 outbox plan |
| 8 | Checkpoint and recovery | Durable one-event checkpoint protocol, sidecar binding, full-source CAS, authorized maximum-prefix recovery, complete backup, one atomic replacement, and crash-point acceptance. | A separate Task8 checkpoint/recovery plan |
| 9 | Performance | Deterministic 10,000-event compact/excerpt fixtures, one replay per command, decode/reducer counts, median/p95/RSS gates, bounded cache/checkpoint size, and lock metrics. | A separate Task9 performance plan |
| 10 | Compatibility | Frozen 17-log corpus, exact legacy-unbound manifest behavior, unchanged bytes/hashes, 32-thread and 8-process races, immutable legacy boundary, and final acceptance integration gate. | A separate Task10 compatibility plan |

## Sequencing rule

Stages are implemented in order. Later plans may import stable public contracts from earlier stages, but may not silently revise them. Any required contract change returns to the owning stage, receives both reviews again, and is recorded explicitly before dependent work continues.
