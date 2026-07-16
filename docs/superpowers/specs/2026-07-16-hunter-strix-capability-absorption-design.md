# Hunter Strix Capability Absorption Design
**Date:** 2026-07-16
**Status:** Approved direction; implementation plans required per lane
**Repository:** `C:\Users\Administrator\.agents\skills\hunter`
**Reference snapshot:** `link17789016-jpg/strix-redteam-workbench@620c0b009859666cd56f3d0fe4f2c67bbd7d99c9`
**Authority:** Additive to the Hunter unified proof-engine and Event Kernel specifications

## 1. Decision

Hunter will absorb selected Strix control-plane invariants through a clean-room
implementation. Hunter will not merge, vendor, install, or import the Strix
repository and will not copy its monolithic quality-state service.

The intended result is a stronger Hunter architecture:

- Hunter remains MCP-first and model-neutral;
- the Event Kernel remains the authoritative workflow mutation boundary;
- tools remain Hunter's execution plane;
- typed assignments, capability manifests, evidence receipts, proof profiles,
  replay obligations, and completion gates become the control plane;
- every confirmed finding remains derivable from immutable typed evidence;
- recovery and completion remain correct after process loss and concurrent use.

This design does not modify the Event Kernel Stage 1 public contract while that
stage is under implementation. Any later contract change must reopen the owning
stage, update its acceptance tests first, and pass both review gates again.

## 2. Why selective absorption

The Strix snapshot demonstrates several useful invariants:

1. role capabilities are compiled from one policy authority and hashed;
2. discovery and independent validation have separate assignments and context;
3. runtime-observed evidence is represented by an opaque, bound receipt;
4. deterministic category-specific proof gates outrank model confidence;
5. state-changing replay persists cleanup responsibility before mutation;
6. a run cannot finish while evidence, validation, cleanup, coverage, reporting,
   or child work remains unresolved;
7. final report export is frozen against a ledger revision.

The snapshot also contains implementation choices Hunter must reject:

- a roughly 15,000-line quality-state module;
- process-local evidence receipt storage;
- command-text regular expressions presented as an outbound security boundary;
- powerful sandbox capabilities and host-gateway exposure by default;
- floating container and tool dependencies;
- performance scripts without latency, memory, or queue thresholds;
- synthetic proof fixtures presented too close to real-world effectiveness
  evidence.

Hunter therefore ports the invariants, not the implementation shape.

## 3. Existing Hunter baseline and gaps

Hunter already contains the foundations needed for the absorption:

- `core/workflow/event_kernel/` defines typed actions, attempts, evidence,
  verdicts, processes, outbox records, checkpoints, replay results, and hashes;
- `core/evidence/verdict_engine.py` provides category-specific heuristics;
- `core/evidence/execution_anchor.py` blocks some speculative language;
- `core/process_runner.py` provides process-tree termination;
- `core/agents.py` declares agent prerequisites and required tools;
- `core/tool_catalog.py` and MCP registration define the actual tool surface;
- memory and report components already consume findings and evidence.

The remaining gaps are architectural rather than tool-count gaps:

- `AgentDefinition.tools_required` is descriptive and is not an immutable,
  runtime-verified capability grant;
- the execution anchor infers proof from text patterns instead of trusted
  runtime observations;
- legacy verdict inputs are mutable dictionaries and repetition alone can
  upgrade a strong heuristic signal;
- raw process output can cross boundaries without an opaque receipt;
- no durable, single-binding evidence receipt joins runtime output to typed
  attestation;
- no deterministic replay contract persists cleanup before a state change;
- no production completion gate freezes the exact event head and rejects new
  mutations while finalizing;
- outbound scope is not yet enforced at the network boundary;
- current performance evidence does not cover all future control-plane paths.

## 4. Non-negotiable principles

### 4.1 Event Kernel ownership

All durable domain truth introduced by this work must be represented by or
cryptographically bound to Event Kernel state. No new JSON file, TUI state,
model transcript, report, cache, or SQLite projection may become a competing
source of truth.

### 4.2 Model-neutral enforcement

Security properties must be enforced outside prompts. A model may propose an
action, proof fact, or report statement, but cannot:

- grant itself a tool;
- change an assignment scope;
- mark its own discovery independently verified;
- mint trusted evidence from arbitrary text;
- bypass a cleanup obligation;
- declare a run complete;
- mutate a frozen finalization revision.

### 4.3 Trusted observation boundary

Only a trusted adapter that directly observes a Hunter tool, browser, proxy,
or supervised process result may mint evidence material. The model receives an
opaque reference plus a bounded redacted projection.

### 4.4 Fail closed

Unknown role, missing mandatory tool, manifest drift, stale generation,
receipt mismatch, unsupported proof category, replay scope drift, incomplete
cleanup, and finalization-head drift all reject the operation with a stable
typed error.

### 4.5 Bounded state

Indexes, receipts, output excerpts, manifests, model-visible projections,
replay bundles, worklists, and error text have explicit byte and item limits.
Large raw evidence remains in a content-addressed artifact store outside model
context and is bound by digest.

## 5. Target architecture

The work is split into four independent lanes. The paths below are ownership
boundaries for detailed plans, not permission to implement before those plans
are approved.

### 5.1 Lane A: Agent control and assignment policy

Target package:

```text
core/agent_control/
    __init__.py
    contracts.py
    policy.py
    service.py
```

Responsibilities:

- `contracts.py`: frozen `AgentRole`, `AssignmentContract`,
  `CapabilityManifest`, `CapabilityKind`, and manifest result types;
- `policy.py`: the only role-to-capability policy authority and canonical
  manifest compiler;
- `service.py`: assignment claim, context-isolation attestation, manifest
  verification, and Event Kernel action/attempt binding;
- `__init__.py`: explicit stable exports only.

Required properties:

- a manifest includes policy version, role, exact MCP tool names, non-MCP
  capabilities, assignment ID, generation, scope digest, and expiry policy;
- the manifest digest uses strict canonical JSON and SHA-256;
- every listed MCP tool must exist in the runtime's validated tool catalog;
- missing mandatory tools and extra runtime tools both fail closed;
- only the root/operator policy may create child assignments;
- discovery and validator assignments use different IDs, attempt IDs, session
  namespaces, and context digests;
- a validator cannot spawn another agent or inherit discovery conclusions;
- reporter assignments cannot execute network, browser, proxy-write, shell, or
  process capabilities;
- remediation can modify only an explicitly bound local artifact or repository
  scope and cannot change verdict truth.

`core/agents.py` remains a catalog during migration. Production execution may
use a catalog entry only after it compiles to a valid manifest. Descriptive
`tools_required` fields never grant authority by themselves.

### 5.2 Lane B: Durable evidence receipts and proof profiles

Target package extensions:

```text
core/evidence/
    receipts.py
    proof_profiles.py
    proof_service.py
```

Responsibilities:

- `receipts.py`: frozen receipt contracts, content-addressed payload binding,
  redacted projection, and durable redemption protocol;
- `proof_profiles.py`: deterministic category-specific proof evaluators;
- `proof_service.py`: convert a bound receipt plus typed observations into an
  Event Kernel evidence attestation and verdict command.

Receipt identity includes:

- receipt ID and receipt digest;
- workflow ID and generation;
- logical action ID and execution attempt ID;
- process/browser/proxy/tool source identity;
- assignment ID, agent role, and session namespace;
- evidence kind and content digest;
- capture timestamp and bounded expiry policy;
- redaction-policy digest;
- exact source-reference digest.

Receipt rules:

1. Raw bytes are frozen before the model receives a receipt ID.
2. The raw artifact is content addressed and durably written before receipt
   publication.
3. The model cannot supply or override source bytes, source identity, digest,
   action ID, attempt ID, or generation.
4. Redemption is idempotent for the same command and exact binding.
5. Reuse with a different binding is a conflict.
6. Process death between publication and attestation cannot lose the receipt.
7. Replay never writes evidence or consumes a receipt as a side effect.
8. Model-visible excerpts are redacted, UTF-8 bounded, and never authoritative.

The first proof-profile set must cover at least:

- SQL injection;
- XSS;
- SSRF;
- IDOR/BOLA/BFLA and authorization bypass;
- authentication material replay;
- command execution/RCE;
- file read/path traversal;
- unsafe file upload;
- XXE;
- SSTI;
- CSRF with state change;
- race/business invariant violation;
- exposed service versus mere reachability;
- hardening observation versus demonstrated exploit.

Every profile evaluates typed facts derived from verification and reproduction
observations. A positive verdict requires category-specific baseline, exploit,
negative-control, and impact facts. Repetition count, HTTP 2xx, scanner labels,
model confidence, response length alone, or a reflected payload alone cannot
produce `VERIFIED`.

Existing `VerdictEngine` remains a candidate-signal generator during migration.
It cannot directly create a final finding after the proof service is enabled.
Existing `ExecutionAnchorEngine` remains a user-message quality filter only and
must never be treated as evidence validation.

### 5.3 Lane C: Replay, cleanup, completion, and finalization

Target package:

```text
core/workflow/replay/
    __init__.py
    contracts.py
    scope.py
    executor.py
    cleanup.py
core/workflow/completion.py
```

Replay bundle requirements:

- immutable schema version and deterministic bundle ID;
- workflow, generation, action, attempt, assignment, and surface-snapshot
  bindings;
- exact allowed schemes, hosts, normalized ports, path templates, methods, and
  redirect policy;
- secret handles instead of literal credentials;
- typed request values, extraction rules, and assertions;
- baseline, exploit, negative-control, and cleanup stages;
- maximum step, redirect, response-byte, timeout, and request-budget limits;
- canonical bundle digest independent of mutable artifact projections.

For a state-changing replay, the Event Kernel must durably register a cleanup
obligation before the first mutating request. Completion of the main request
cannot erase that obligation. Cleanup has independent attempt state, evidence,
idempotency, retry policy, and terminal outcome.

Completion is a pure evaluation over one materialized Event Kernel head. It
returns `COMPLETED`, `PARTIAL`, or `BLOCKED` plus typed issues. Hard blockers
include:

- active attempts or processes;
- unresolved candidate/reproduced findings;
- verified findings lacking report disposition;
- pending or failed cleanup without an exact operator waiver;
- unresolved replay cleanup obligations;
- invalid or changed evidence;
- manifest or assignment drift;
- mixed writer or replay issue;
- pending memory outbox entries required for finalization;
- event-head change during finalization.

Partial completion requires an authenticated operator command, a bounded
reason, and only partial-eligible issues. It can never waive evidence integrity,
cleanup, mixed-writer, active-process, or finalization-conflict issues.

Finalization uses a short-lived lease bound to workflow ID, generation,
revision, head hash, owner, and expiry. Final report export must match the exact
set of accepted reportable findings and chains at that head. Any intervening
mutation invalidates the lease and export command.

### 5.4 Lane D: Sandbox, process, supply chain, and performance

Target package extensions are selected by a separate detailed design after the
Event Kernel process stage. The implementation must provide:

- default-deny egress at the network boundary;
- exact assignment allowlists enforced independently of command text;
- DNS resolution and redirect peer validation on every connection boundary;
- proxy-only HTTP where capture is required, with direct-egress prevention;
- no `SYS_ADMIN`, host gateway, host PID namespace, Docker socket, or writable
  host mount by default;
- narrowly scoped, time-bounded capability escalation for raw-socket tools;
- immutable image digest allowlists;
- SBOM, tool-version manifest, signature/provenance verification, and runtime
  image identity binding;
- supervised process groups/jobs, attempt-bound lifecycle, bounded redacted
  output receipts, and verified tree termination;
- resource limits for CPU, memory, PIDs, output bytes, wall clock, open files,
  and concurrent network requests.

Command-text inspection may remain a usability guard but is not a security
boundary and cannot satisfy an egress acceptance test.

## 6. Event Kernel stage mapping

| Event Kernel stage | Absorbed requirement | Rule |
|---|---|---|
| 1 Contracts/envelope | Preserve IDs, enums, typed observations, state, outbox, errors | No silent contract edits while Stage 1 is open |
| 2 Replay/upcast | Compact indexes and semantic replay support later policy/completion reads | No side effects during replay |
| 3 Store/CAS | Same-command idempotency before revision/head-hash CAS | Receipt and finalization services reuse this ordering |
| 4 Action/attempt | Assignment binds to logical action; execution binds to attempt | Discovery and validator never share an attempt |
| 5 Evidence/verdict | Receipt binding and deterministic proof profiles | Only typed attestation can support verified verdicts |
| 6 Process | Trusted output capture and attempt isolation | Raw output never becomes model-authored evidence |
| 7 Outbox | Durable external delivery | Receipt publication and memory delivery cannot be silently lost |
| 8 Checkpoint/recovery | Cleanup/finalization recovery binding | Recovery preserves every unresolved obligation |
| 9 Performance | Real thresholds | Include p50, p95, RSS, event size, lock queue, and process contention |
| 10 Compatibility | Production gate and role drift tests | Legacy routes cannot mutate claimed workflows |

Agent control, production completion, and sandbox enforcement are integration
work after the independent Event Kernel acceptance suite passes. They may be
planned in parallel but cannot claim production authority early.

## 7. Parallel implementation protocol

After Event Kernel Stage 1 is committed, four planning/research lanes may run
in parallel because their initial write sets are disjoint:

| Lane | Initial write scope | Integration dependency |
|---|---|---|
| A Agent control | `core/agent_control/`, dedicated acceptance tests | Event Kernel action/attempt API |
| B Evidence/proof | `core/evidence/receipts.py`, `proof_profiles.py`, `proof_service.py`, dedicated tests | Event Kernel evidence/verdict API |
| C Replay/completion | `core/workflow/replay/`, `core/workflow/completion.py`, dedicated tests | Replay/store/checkpoint APIs |
| D Sandbox/performance | New sandbox design, process and benchmark tests only until Stage 6/9 | Process API and production integration |

Rules for all lanes:

1. Each lane receives a separate detailed implementation plan.
2. Every behavior begins with a focused failing acceptance test.
3. Workers own disjoint files and do not edit Event Kernel owner files without
   an explicit stage-reopen decision.
4. Specification compliance review precedes code-quality review.
5. Findings from either review return to the same implementation lane and are
   re-reviewed.
6. Integration commits occur only after the owning Event Kernel stage passes.
7. Full tests, `compileall`, contract checks, explicit-root tests, and forbidden
   legacy diffs run before each integration commit.

## 8. Acceptance gates

### 8.1 Agent control

- exact role enum and exact policy version are locked by tests;
- manifest serialization and digest are stable across process and key order;
- unknown, missing, duplicate, colliding, or extra tools fail closed;
- a policy/catalog change causes manifest drift, not silent acceptance;
- validator context contains only neutral assignment facts and opaque evidence
  handles;
- forbidden tool calls are rejected before dispatch and generate a typed audit
  event;
- 32-thread and 8-process assignment claim races produce one owner.

### 8.2 Evidence and proof

- mutation after receipt publication is detected;
- process restart preserves an outstanding receipt;
- same-command redemption is idempotent;
- cross-generation, cross-attempt, cross-assignment, cross-session, expired,
  oversized, and wrong-kind redemption fail with exact errors;
- raw secrets never appear in event payloads, logs, errors, or model excerpts;
- every proof category has positive, negative, ambiguous, baseline-collision,
  and falsification fixtures;
- unknown categories remain inconclusive and cannot create findings;
- a `VERIFIED` verdict is impossible without an independently bound attempt and
  exact evidence IDs.

### 8.3 Replay and completion

- canonical bundle hash changes for every semantic request or scope change;
- redirect, DNS rebinding, peer mismatch, secret unavailability, snapshot drift,
  request-budget exhaustion, and output overflow are typed outcomes;
- cleanup obligation commits before mutation and survives injected crashes at
  every persistence boundary;
- retry is idempotent and cannot erase a failed cleanup attempt;
- completion issues are deterministic and sorted;
- active process, evidence damage, unresolved cleanup, or head drift can never
  be waived to partial;
- final export uses revision plus head hash CAS and exact report-set equality.

### 8.4 Sandbox and performance

- an indirect socket implementation cannot bypass assignment egress policy;
- unapproved DNS answer, redirect peer, IP literal, protocol, port, or host is
  blocked at the network boundary;
- direct egress remains blocked when proxy environment variables are removed;
- containers run without dangerous capabilities unless a typed lease grants a
  specific capability for one attempt;
- image digest or tool-manifest drift fails startup;
- compact and 4,096-byte evidence workloads meet explicit median, p95, RSS,
  event-size, and lock-queue limits;
- performance gates run in CI on declared hardware classes and never return a
  hard-coded pass result.

## 9. Effectiveness evaluation

Unit and acceptance tests prove correctness, not vulnerability-discovery
effectiveness. Hunter must maintain a separate versioned evaluation corpus:

- known-positive and known-negative vulnerable applications;
- authenticated multi-role authorization cases;
- business-logic and race cases with observable final state;
- browser-only XSS and session cases;
- SSRF/OOB cases;
- source-assisted and black-box variants;
- deliberately misleading scanner signals and baseline collisions;
- interrupted-run and cleanup-recovery scenarios.

Metrics include:

- independently verified precision and recall;
- candidate-to-verified conversion;
- false-positive rejection rate;
- coverage denominator completion;
- cleanup success and recovery rate;
- duplicate action and duplicate finding rate;
- median/p95 time and cost per verified finding;
- evidence completeness and replay success;
- cross-model variance using the same frozen assignments and tool catalog.

No historical upstream benchmark may be presented as evidence for the current
Hunter implementation. Every published score binds to code commit, corpus
version, model policy, tool manifest, container digest, and budget.

## 10. Provenance and licensing

The default implementation method is clean-room reimplementation from publicly
observable invariants and this design. If any Strix source text or substantial
code is copied later:

- the exact upstream file and commit must be recorded;
- Apache-2.0 license and NOTICE obligations must be preserved;
- modifications must be documented;
- copied code must receive Hunter-specific security and concurrency tests;
- a provenance review must pass before commit.

Installing Strix into Hunter's environment, importing Strix modules at runtime,
or depending on Strix container tags is outside this design.

## 11. Definition of done

This absorption program is complete only when:

1. all four lanes have approved detailed plans and committed implementations;
2. every acceptance gate above has fresh passing evidence;
3. Event Kernel ownership, idempotency, replay, recovery, and performance suites
   remain green;
4. the exact core and extension MCP tool contracts remain valid;
5. production entry points enforce capability, evidence, completion, and legacy
   mutation gates rather than merely documenting them;
6. sandbox egress and capability tests prove network-level enforcement;
7. the effectiveness corpus reports current commit-bound results;
8. case state and exported engineering evidence are current;
9. no competing truth store or unbounded model-visible payload was introduced;
10. specification and code-quality reviews have no unresolved findings.
