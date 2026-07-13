---
name: hunter
description: Use for authorized web/API security assessment, CTF vulnerability research, Hunter health checks, MCP orchestration, local knowledge-base lookup, evidence registration, and report generation.
---

# Hunter v8.2

Hunter is the authorized security-research framework exposed through one
FastMCP server:

- Server name: `hunter_tools`
- Entrypoint: `mcp_server.py`
- Contracted tool count: 111
- Contract: `integration-contract.json`
- Persistent workspace: `OPEN_TGTYLAB_ROOT`

`hunter_tools_mcp.py` is a compatibility launcher. It delegates to the complete
server and must not create a second Hunter registration.

## Required Startup

1. Read `cases/<slug>/state.json` and continue from `next_steps`.
2. State the concrete result sought in this session.
3. State why the selected tool is the correct tool.
4. Query the local project KB with `hunter_project_kb_search`, then read the
   selected technique with `hunter_project_kb_read`.
5. Run `hunter_healthcheck` and `hunter_capabilities` when integration state is
   relevant.
6. Use `hunter_recommend_next` or `hunter_workspace_recommend` to route from
   observed evidence.

## Safety Boundary

- Operate only on targets and artifacts within the user's authorized scope.
- Prefer targeted proof collection over broad or destructive execution.
- Do not report a vulnerability without reproducible evidence.
- High-impact exploitation and post-exploitation require an exact,
  action-bound approval descriptor.
- Treat memory and fingerprint recommendations as non-executing guidance.
- Redact secrets from logs, notes, screenshots, and persisted hook results.

## Tool Priority

- HTTP execution: Burp `send_http2_request` first, then `http_probe`.
- JavaScript source inspection: `search_in_sources`; do not download source
  merely to read it.
- PE triage: `triage_pe`, then `ghidra_headless_analyze`.
- Android dynamic work: `android_frida_run_script`.
- Packer detection: `die_scan`.
- Full suspicious-sample analysis: `sample_full_workup`.
- Hunter tools generate plans and evidence packages when an external MCP
  backend performs the actual operation.

## Capability Groups

### Diagnostics and Routing

- `hunter_healthcheck`
- `hunter_capabilities`
- `hunter_recommend_next`
- `hunter_doctor`
- `hunter_config_audit`
- `hunter_runtime_status`
- `hunter_contract_check`

### Recon and Scanning

- `hunter_scan`
- `hunter_recon`
- `hunter_vuln_scan`
- `hunter_subdomain`
- `hunter_port_scan`
- `hunter_tech_detect`
- `hunter_dir_enum`
- `hunter_js_analyze`
- `hunter_fast_scan`
- `hunter_scan_plan`
- `hunter_scan_benchmark`

### Targeted Proof Tools

- `hunter_auto_sqli`
- `hunter_auto_xss`
- `hunter_auto_ssrf`
- `hunter_auto_ssti`
- `hunter_auto_cmd`
- `hunter_auto_xxe`
- `hunter_auto_idor`
- `hunter_auto_csrf`
- `hunter_auto_cors`
- `hunter_auto_jwt`
- `hunter_auto_graphql`
- `hunter_auto_websocket`
- `hunter_auto_race`
- `hunter_auto_access_control`
- `hunter_unified_scan`

### Knowledge, Payloads, and Burp

- `hunter_kb_list`, `hunter_kb_search`, `hunter_kb_read`,
  `hunter_kb_recommend`
- `hunter_payload_list`, `hunter_payload_search`, `hunter_payload_get`,
  `hunter_payload_generate`
- `hunter_burp_bridge`, `hunter_burp_repeater`,
  `hunter_burp_proxy_search`, `hunter_burp_scanner_issues`,
  `hunter_burp_collaborator_workflow`, `hunter_burp_import`

### Workspace and Evidence

- `hunter_workspace_health`
- `hunter_case_open`, `hunter_case_status`, `hunter_case_update`,
  `hunter_case_next_steps`
- `hunter_project_kb_search`, `hunter_project_kb_read`
- `hunter_evidence_save`, `hunter_note_write`, `hunter_report_publish`
- `hunter_workspace_recommend`

### Workflow Kernel

- `hunter_workflow_create`, `hunter_workflow_open`,
  `hunter_workflow_status`
- `hunter_workflow_route`, `hunter_workflow_plan`, `hunter_workflow_run`
- `hunter_workflow_transition`, `hunter_workflow_checkpoint`,
  `hunter_workflow_resume`, `hunter_workflow_policy`
- `hunter_hypothesis_add`, `hunter_evidence_register`,
  `hunter_finding_promote`
- `hunter_backend_status`, `hunter_lane_catalog`

Workflow State v2 uses a hash-chained event log as the authority and
`workflow.json` as a derived cache. Long-running work must checkpoint after
each completed phase and resume from the first incomplete phase.

### Stateful HTTP and Attack Sessions

- `hunter_stealth_request`, `hunter_stealth_scan`
- `hunter_session_create`, `hunter_session_state`, `hunter_set_proxy_pool`
- `hunter_session_start`, `hunter_session_execute_chain`,
  `hunter_session_checkpoint`
- `hunter_post_exploit`

### Browser Bridge

- `hunter_browser_navigate`
- `hunter_browser_interact`
- `hunter_browser_capture_network`
- `hunter_browser_inject_hooks`
- `hunter_browser_get_hook_results`
- `hunter_browser_snapshot`

The browser bridge emits deferred Playwright MCP descriptors. Playwright
performs browser operations; Hunter plans, normalizes, redacts, and persists
the observations.

### JavaScript Analysis

- `hunter_js_unpack`
- `hunter_js_deobfuscate`
- `hunter_js_extract_api`
- `hunter_js_extract_signature`
- `hunter_js_full_analysis`

### Reverse Analysis

- `hunter_reverse_binary`
- `hunter_reverse_step`
- `hunter_reverse_extract_iocs`
- `hunter_reverse_generate_rules`
- `hunter_reverse_decrypt_plan`

Reverse workflows persist state and emit bounded handoffs for
`reverse_lab_tools`, Ghidra, Frida, and JSHook when those backends are
available.

### Local Memory

- `hunter_memory_query`
- `hunter_memory_record`
- `hunter_memory_recommend`
- `hunter_fingerprint_detect`
- `hunter_memory_stats`

### Unified Orchestration

- `hunter_auto_pentest`

The unified orchestrator coordinates memory, reconnaissance, attack-surface
analysis, deferred attack execution, pattern confirmation, evidence, learning,
and report generation. Repeated completed runs use explicit workflow
generations; interrupted runs resume from durable checkpoints.

## Evidence Workflow

Use this sequence for authorized assessments:

```text
case state
-> project KB search/read
-> health and capabilities
-> targeted recon
-> evidence-driven recommendation
-> targeted proof or external MCP handoff
-> evidence registration
-> finding promotion
-> checkpoint
-> note/report publication
-> case state update
```

Store project artifacts under:

- `D:\Open-tgtylab\exports\notes`
- `D:\Open-tgtylab\exports\reports`
- `D:\Open-tgtylab\exports\evidence`

Hunter-owned runtime evidence remains under the Hunter repository's
`evidence/` and `sessions/` directories.
