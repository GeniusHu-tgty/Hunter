# Hunter Unified Proof Engine Design

**Date:** 2026-07-15
**Status:** Approved
**Implementation scope:** P0–P2
**Repository:** `C:\Users\Administrator\.agents\skills\hunter`

## 1. Goal

Turn Hunter from a broad collection of scanners and MCP wrappers into a
single evidence-driven proof engine that can:

1. discover an attack surface;
2. form and rank testable hypotheses;
3. execute permitted actions rather than merely describing them;
4. verify results through reproducible evidence;
5. learn only from final verdicts;
6. survive cancellation, timeout, restart, and partial external-tool failure;
7. expose compatible high-level and atomic interfaces with identical
   execution, budget, recovery, and evidence semantics.

The first implementation round covers correctness and reliability only:

- **P0:** repair the execution, coverage, verdict, and memory correctness gaps;
- **P1:** consolidate all high-level entry points onto one event-sourced
  orchestration path;
- **P2:** introduce a supervised, cancellable, deadline-aware process runtime.

Tool-surface reduction, new scanners, and benchmark expansion are deferred
until P0–P2 are verified.

## 2. Current Baseline

The current working tree contains substantial in-progress hardening:

- 113 Hunter MCP tool functions;
- an additional 105 `re_*` tools merged into the same FastMCP registry;
- 709 collected tests in the observed full run;
- 708 passing tests and one registry-contract failure;
- a synthetic four-agent DAG benchmark with approximately 3.97× speedup;
- an event-sourced Workflow Kernel, an Orchestrator Runner, an attack
  reasoner, a verdict engine, target and technique memory, browser handoffs,
  and an initial external process runner.

These components are individually useful, but four critical integration gaps
prevent the system from making trustworthy end-to-end claims.

## 3. Confirmed P0 Correctness Gaps

### 3.1 Explicit reasoner actions are deferred instead of executed

`UnifiedOrchestrationBridge.stage_attack_execution` recognizes a reasoner
action's explicit `tool`, but the execution condition excludes explicit tools.
Allowlisted `hunter_auto_*` actions therefore become deferred handoffs even
when an injected executor is available.

Consequences:

- `hunter_auto_attack` may describe a complete automatic pipeline without
  actually executing the generated proof action;
- attempt counts and downstream confirmation evidence remain empty;
- reasoner quality cannot be measured from real outcomes.

### 3.2 The reasoner queue replaces general attack-surface coverage

`OrchestratorRunner.run` obtains a general `attack_queue` from
`stage_attack_surface`, but executes only strategies returned by
`AttackReasoner.reason`.

Consequences:

- an empty or narrow reasoner can suppress SQLi, XSS, SSTI, GraphQL, and other
  general candidates;
- requested phase/module behavior can diverge between entry points;
- improving the reasoner can accidentally reduce scanner coverage.

### 3.3 Transport success is recorded as technique success

Technique-memory updates currently treat many non-blocked HTTP responses as a
successful attack attempt even when the normalized result reports
`vulnerable=false` or no confirmed proof.

Consequences:

- HTTP transport behavior contaminates security-effectiveness statistics;
- future strategy ranking is trained on false positives;
- confirmation cannot reliably correct an already-recorded attempt;
- TargetMemory and TechniqueMemory disagree about endpoints, attack history,
  and confirmed vulnerabilities.

### 3.4 Confirmation bypasses VerdictEngine

The current confirmation stage can promote a passive response signature
directly to `confirmed` through `PatternEngine.match_response`.

Consequences:

- a single SQL error string can be treated as proof without a baseline,
  control request, reproduction, or differential;
- nested tool metadata converted to text can match a vulnerability regex even
  when the target response body does not;
- existing verdict policies are not the authority for final findings.

## 4. Design Principles

### 4.1 Proof over tool execution

The primary unit of success is a reproducible, evidence-backed verdict, not a
completed HTTP request or successful CLI exit code.

### 4.2 One orchestration truth

`WorkflowKernel`'s hash-chained event log is the sole authoritative state.
Materialized workflow JSON, scan-session summaries, reports, and memory
records are projections of that log.

### 4.3 One confirmation authority

`VerdictEngine` is the only component allowed to produce a verified finding.
`PatternEngine`, fingerprints, scanners, and the reasoner produce candidates,
signals, and proposed validation actions.

### 4.4 Preserve coverage when adding intelligence

Reasoning augments the general attack surface. It never replaces it.

### 4.5 Explicit lifecycle semantics

Transport, execution, signal, and proof outcomes are separate fields. No
component may infer one from another.

### 4.6 Compatibility through adapters

Existing MCP tool names and accepted parameters remain available. Compatibility
wrappers translate old calls into the unified engine rather than maintaining
separate execution implementations.

### 4.7 Bounded and resumable execution

Every action has a budget, deadline, idempotency key, cancellation path,
checkpoint, and bounded result.

## 5. Target Architecture

```text
MCP compatibility entry points
    hunter_auto_attack
    hunter_unified_scan
    hunter_auto_pentest
    hunter_workflow_run
                 |
                 v
        Unified Proof Engine
                 |
     +-----------+-----------+
     |                       |
WorkflowKernel          Tool Broker
(event authority)       (execution boundary)
     |                       |
     v                       v
Fact Blackboard       Process Supervisor
     |                       |
     v                       v
Action Planner        Normalized Tool Result
     |                       |
     +-----------+-----------+
                 |
                 v
          Evidence Normalizer
                 |
                 v
            VerdictEngine
                 |
      +----------+----------+
      |                     |
Evidence Ledger       Memory Projectors
      |                     |
      +----------+----------+
                 |
                 v
          Findings and Report
```

### 5.1 Unified Proof Engine

The unified engine coordinates stages but stores no independent authoritative
state. Every durable change is appended through `WorkflowKernel`.

The logical stages remain:

1. memory preflight;
2. reconnaissance;
3. attack-surface construction;
4. action planning and execution;
5. confirmation;
6. evidence and learning projection;
7. report projection.

The stage list is a workflow view, not a separate state machine.

### 5.2 Fact Blackboard

The blackboard is a materialized workflow projection containing normalized:

- targets and origins;
- technologies and fingerprints;
- endpoints, parameters, methods, forms, and authentication observations;
- cookies and session references;
- WAF, rate-limit, CAPTCHA, and transport observations;
- source, JavaScript, browser, Burp, and reverse-analysis evidence;
- existing hypotheses, actions, results, and verdicts.

Facts retain source evidence IDs. A fact without provenance cannot directly
produce a verified finding.

### 5.3 Action Planner

The planner merges:

1. general attack-surface actions;
2. deterministic reasoner actions;
3. memory recommendations;
4. operator-requested phases and modules;
5. approved external handoffs;
6. confirmation follow-ups.

The merge is additive and deterministic.

Each canonical action includes:

```json
{
  "action_id": "act-...",
  "tool": "hunter_auto_sqli",
  "arguments": {},
  "source": ["attack-surface", "reasoner"],
  "priority": "P0",
  "estimated_cost": 1.0,
  "expected_evidence": ["differential-response"],
  "budget_class": "active-proof",
  "requires_approval": false,
  "idempotency_key": "...",
  "status": "pending"
}
```

Deduplication uses the canonical tool, normalized arguments, target origin,
session identity, and proof goal. If two sources propose the same action, the
merged action preserves all source explanations and the highest priority.

The planner applies filters in this order:

1. target scope and allowed origin;
2. requested phases and modules;
3. policy and approval requirements;
4. duplicate or already-completed idempotency key;
5. per-action and workflow budgets;
6. priority and estimated information gain.

### 5.4 Tool Broker

The Tool Broker is the only component that executes an atomic Hunter tool or
emits an external MCP handoff.

It maintains an allowlist of locally executable tools. An explicit allowlisted
reasoner action executes when:

- an executor is configured;
- the action is inside scope;
- the policy permits it;
- any required approval descriptor matches;
- the action budget remains available.

Otherwise the broker returns a normalized deferred or blocked result with a
specific reason. It never silently converts an executable action into a
handoff.

### 5.5 Evidence Normalizer

Every tool result is converted into a common evidence envelope:

```json
{
  "evidence_id": "ev-...",
  "action_id": "act-...",
  "tool": "hunter_auto_sqli",
  "target": "https://target/path",
  "request": {},
  "response": {},
  "baseline": {},
  "controls": [],
  "payload": {},
  "transport": {},
  "reproduction_count": 0,
  "signal": {},
  "artifact_paths": [],
  "started_at": "...",
  "finished_at": "...",
  "sha256": "..."
}
```

Raw target response fields are kept separate from tool diagnostics and MCP
metadata. Confirmation classifiers may inspect only declared evidence fields.

### 5.6 Verdict Engine

The verdict lifecycle is:

```text
OBSERVED -> CANDIDATE -> LIKELY -> VERIFIED
                                -> REFUTED
                                -> INCONCLUSIVE
```

Rules:

- `PatternEngine` may create `CANDIDATE`;
- scanners may create `CANDIDATE` or `LIKELY`;
- only `VerdictEngine` may create `VERIFIED`, `REFUTED`, or `INCONCLUSIVE`;
- only `VERIFIED` maps to a confirmed finding;
- `LIKELY` maps to pending review or a generated follow-up action;
- findings retain the verdict ID and all supporting evidence IDs.

For differential classes such as SQLi, XSS, SSTI, SSRF, and access control,
verdict policies must declare their required baseline, control, reproduction,
or browser/OOB proof.

If the baseline already contains the candidate SQL error, the verdict cannot
be `VERIFIED` from that error alone.

### 5.7 Memory Projectors

Execution outcomes use distinct fields:

```json
{
  "transport_success": true,
  "probe_executed": true,
  "signal_detected": false,
  "vulnerability_confirmed": false,
  "verdict": "REFUTED"
}
```

Definitions:

- `transport_success`: a request or process produced a usable response;
- `probe_executed`: the intended proof action actually ran;
- `signal_detected`: the action produced a candidate security signal;
- `vulnerability_confirmed`: the final verdict is `VERIFIED`.

TechniqueMemory effectiveness is updated only after confirmation:

- `VERIFIED` increments confirmed success;
- `REFUTED` records an executed negative result;
- `INCONCLUSIVE` records insufficient evidence;
- timeout, cancellation, WAF blocking, scope rejection, and tool failure are
  separate outcome classes;
- deferred actions do not count as executed attempts.

TargetMemory is projected from workflow events and records endpoint inventory,
attack history, verdicts, and evidence references consistently.

### 5.8 Finding promotion and report projection

Finding promotion consumes a specific verdict, not an undifferentiated list of
all evidence produced during the workflow.

Rules:

- every promoted finding references exactly one final verdict ID;
- the verdict lists the evidence IDs that support or refute that finding;
- evidence from unrelated actions is not attached automatically;
- missing proof evidence cannot be replaced with a synthetic
  `pattern-confirmation` note;
- a candidate without a verified verdict remains a lead or pending-review
  item;
- report generation reads promoted `state["findings"]` and their evidence
  graph, not raw pre-promotion confirmation output;
- reports include verdict status, proof strength, evidence references,
  reproduction metadata, and known false-positive controls;
- high-impact follow-up approval does not block persistence of the verified
  finding and its report.

The workflow report path and the existing `hunter_report` compatibility entry
point are adapted to the same report projection so a workflow slug can produce
the same evidence-backed report as other supported session identifiers.

## 6. Workflow Event Model

The following event types are added or normalized:

- `facts.updated`;
- `action.proposed`;
- `action.merged`;
- `action.started`;
- `action.deferred`;
- `action.blocked`;
- `action.completed`;
- `action.cancelled`;
- `evidence.registered`;
- `verdict.created`;
- `finding.promoted`;
- `memory.projected`;
- `process.started`;
- `process.output`;
- `process.terminated`;
- `checkpoint.created`;
- `workflow.deadline_exceeded`.

Each event contains:

- workflow ID and generation;
- monotonic revision;
- correlation ID;
- action ID where applicable;
- idempotency key where applicable;
- timestamp;
- bounded JSON-safe payload;
- previous-event hash and event hash.

`workflow.json`, scan summaries, and reports are rebuilt from valid event
prefixes. Direct mutation of materialized workflow state is prohibited.

## 7. Entry-Point Consolidation

All high-level tools call the same engine with presets:

| Entry point | Preset |
|---|---|
| `hunter_auto_attack` | six-stage compatibility preset |
| `hunter_unified_scan` | requested-phase compatibility preset |
| `hunter_auto_pentest` | seven-stage policy-aware preset |
| `hunter_workflow_run` | existing-case preset |

The current `use_runner` split is removed after compatibility tests prove
equivalent behavior. There is one runner, one planner, one Tool Broker, one
evidence path, and one verdict path.

Legacy return fields remain available during migration. New canonical fields
are additive until all consumers are updated.

## 8. Requested Phase, Module, and Budget Semantics

Requested phases and modules are applied before action execution, not merely
recorded in output metadata.

Examples:

- excluding `graphql` prevents GraphQL proof actions while retaining recon
  facts;
- requesting only `recon` produces no active proof actions;
- a workflow action budget of three starts at most three new actions;
- resumed workflows do not spend budget again on completed idempotency keys;
- confirmation follow-ups consume the declared confirmation budget.

Budget counters are event-derived and include:

- proposed actions;
- started actions;
- external handoffs;
- completed actions;
- retries;
- confirmation actions;
- elapsed wall time;
- output bytes.

## 9. Process Supervisor

`ExternalProcessRunner` evolves into a shared `ProcessSupervisor`.

### 9.1 Responsibilities

- active-process registry keyed by workflow and action;
- cancellation-token propagation from MCP call to process tree;
- workflow total deadline and per-action deadline;
- connect/start, idle-output, and cleanup deadlines;
- bounded streaming of stdout and stderr;
- verified executable identity and version;
- process heartbeat and checkpoint metadata;
- cross-platform process-tree termination;
- idempotent cleanup;
- normalized result envelopes.

### 9.2 Windows behavior

Processes are started in a Windows Job Object configured to terminate child
processes when the job closes. `taskkill /T /F` remains a fallback, not the
primary mechanism.

The supervisor records:

- root PID;
- Job Object attachment status;
- discovered or managed child count;
- termination reason;
- cleanup duration;
- remaining-process verification.

### 9.3 POSIX behavior

Processes start in a new process group. Cancellation sends a graceful signal
when allowed, waits for the cleanup deadline, then terminates the process
group.

### 9.4 Bounded output

Output is consumed incrementally to avoid pipe deadlocks and unbounded memory.
The supervisor tracks:

- total observed bytes;
- retained head and tail;
- truncation flag;
- last-output timestamp;
- optional artifact spool path;
- redaction status.

### 9.5 Deadline semantics

Each execution receives an absolute workflow deadline. Nested code derives its
remaining budget and cannot reset the total deadline.

Timeout types are explicit:

- `start_timeout`;
- `idle_timeout`;
- `action_deadline`;
- `workflow_deadline`;
- `cleanup_timeout`.

### 9.6 Cancellation

MCP cancellation marks the workflow action as cancelled, signals the
supervisor, terminates the process tree, persists bounded partial output, and
creates a checkpoint before returning.

### 9.7 Idempotency and resume

Before executing, the Tool Broker checks the action's idempotency key against
workflow events:

- completed actions are reused;
- interrupted actions may resume only if the tool declares resume support;
- non-resumable interrupted actions restart with a new attempt number;
- external handoff results are ingested once using a result digest.

## 10. Error Handling

Errors use stable categories:

- `invalid_input`;
- `scope_denied`;
- `approval_required`;
- `budget_exhausted`;
- `dependency_unavailable`;
- `tool_error`;
- `transport_error`;
- `timeout`;
- `cancelled`;
- `evidence_invalid`;
- `verdict_inconclusive`;
- `workflow_conflict`.

Every failed or deferred action contains:

- category;
- bounded human-readable summary;
- retryability;
- action and workflow IDs;
- evidence or partial-artifact references;
- recommended next action.

Exceptions do not bypass workflow event recording.

## 11. Compatibility

The implementation must not delete atomic capabilities or existing MCP names.

Compatibility requirements:

- existing function signatures continue to accept current parameters;
- existing result fields remain during the migration window;
- old entry points become adapters over the unified engine;
- `full` tool registration remains possible;
- ReverseLab tools remain callable even if their registration strategy changes
  in a later P3 design;
- existing session IDs and workflow generations can be opened or migrated;
- reports continue to accept legacy evidence while marking missing proof fields
  as incomplete rather than confirmed.

Schema reduction is explicitly out of scope for P0–P2.

### 11.1 Core and extension registry contract

The current FastMCP registry may contain both native `hunter_*` tools and
optional extension tools such as `re_*`. P0 resolves the registry-contract
failure by distinguishing these sets rather than deleting either one:

- the **core contract** contains the exact stable `hunter_*` tool set;
- the **extension inventory** contains optional namespaces and their source;
- health and capability output report core and extension counts separately;
- an extension cannot satisfy a missing core requirement;
- optional extension presence cannot make the core contract fail;
- unknown tools outside a declared core or extension namespace produce a
  contract warning or failure according to policy.

During P1, a single catalog supplies the core/extension classification used by
contract checks, capability reporting, health output, and parity tests. It
does not change which bottom-layer tools are callable in this implementation
round.

## 12. Testing Strategy

Implementation follows test-driven development. Each P0 failure receives a
failing regression before implementation changes.

### 12.1 Mandatory P0 regression tests

1. **Explicit action execution**
   - Inject an allowlisted executor.
   - Provide a reasoner action using `hunter_auto_sqli`.
   - Assert exactly one execution, one attempt, and no deferred handoff.

2. **General queue fallback**
   - Return an empty reasoner result.
   - Provide a non-empty general attack-surface queue.
   - Assert the general actions execute within module and budget filters.

3. **Memory outcome separation**
   - Return HTTP 200 with `vulnerable=false`.
   - Assert `transport_success=true`,
     `vulnerability_confirmed=false`, and no confirmed-success increment.

4. **Verdict baseline protection**
   - Supply a baseline and probe response that both contain the same SQL error.
   - Assert the result is `REFUTED` or `INCONCLUSIVE`, never `VERIFIED`.

5. **Phase, module, and budget enforcement**
   - Provide actions from multiple modules.
   - Exclude at least one module and set a small action budget.
   - Assert only eligible actions start and budget counters are event-derived.

### 12.2 P1 integration tests

- all four high-level entry points use the same engine factory;
- equivalent presets produce equivalent canonical action and verdict events;
- every action transition is persisted;
- interruption followed by resume starts at the first incomplete action;
- external handoff ingestion is idempotent;
- materialized state can be rebuilt from the event log;
- a promoted finding receives only its verdict-specific evidence IDs;
- no synthetic pattern-only evidence can create a confirmed finding;
- workflow reports are projected from promoted findings and expose their
  verdict and evidence references;
- legacy result fields remain present.

### 12.3 P2 process tests

- parent and child processes terminate on deadline;
- MCP cancellation propagates to the supervisor;
- zero orphan processes remain after cleanup;
- output retention is bounded while byte counts remain accurate;
- idle timeout differs from total action deadline;
- workflow deadline cannot be extended by nested retries;
- checkpoints contain partial output and termination metadata;
- completed idempotency keys are not executed twice;
- executable path and version are recorded;
- Windows Job Object behavior has a platform-specific test with fallback
  coverage.

## 13. Acceptance Criteria

P0–P2 are complete only when:

- explicit allowlisted reasoner action execution rate is 100% in integration
  tests;
- an empty reasoner cannot suppress the general attack queue;
- HTTP 200 with `vulnerable=false` does not count as technique success;
- a baseline SQL error cannot produce a confirmed SQLi finding by itself;
- requested phases, modules, approvals, and budgets change actual execution;
- only a `VERIFIED` verdict creates a confirmed finding;
- every confirmed finding has finding-specific evidence and no synthetic
  pattern-only proof;
- workflow reports are derived from promoted findings and the evidence graph;
- all high-level entry points use the same engine;
- the WorkflowKernel event log can reconstruct workflow state;
- cancellation and timeout leave zero managed orphan processes;
- resume does not repeat completed idempotent actions;
- bounded output and total-deadline tests pass;
- all pre-existing compatible tests pass;
- the current FastMCP registry-contract failure is resolved without deleting
  bottom-layer capability.

## 14. Non-Goals

The first implementation round does not:

- add new vulnerability classes or payload packs;
- remove existing atomic MCP tools;
- reduce default MCP Schema exposure;
- redesign ReverseLab registration;
- add a production multi-agent scheduler;
- claim superiority from test count alone;
- promote source-only hypotheses without dynamic or reproducible proof.

These belong to later P3–P4 work after the proof engine is trustworthy.

## 15. Delivery Order

### P0 — Correctness

1. Add the five mandatory regression groups.
2. Execute explicit allowlisted actions.
3. Merge general and reasoned queues.
4. Route confirmation through VerdictEngine.
5. split outcome semantics and correct memory projection.
6. resolve the current registry-contract test.

### P1 — Unified orchestration

1. Introduce one unified engine factory.
2. Make WorkflowKernel events authoritative for runner transitions.
3. Convert all high-level entry points to presets over that engine.
4. ingest action, evidence, verdict, finding, and handoff events.
5. remove the dual-path `use_runner` behavior.

### P2 — Process reliability

1. Add cancellation and deadline primitives.
2. implement ProcessSupervisor and platform adapters.
3. migrate external CLI execution paths.
4. add bounded output and identity/version recording.
5. implement checkpoint/resume and idempotency integration.
6. run focused, full-suite, contract, and process-leak verification.

## 16. Expected Result

After P0–P2, Hunter will not merely recommend or launch tools. It will provide
a single auditable path from observed fact to executed action, normalized
evidence, verified verdict, durable memory, and reproducible report, with
reliable cancellation and recovery across all high-level entry points.
