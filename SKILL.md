---
name: hunter
description: Use when doing authorized web/API security assessment, CTF-style vulnerability research, recon, payload selection, MCP-based pentest orchestration, Hunter health checks, Burp proof planning, Hunter KB lookup, or evidence-driven report generation with the local Hunter framework.
---

# Hunter v8.1 ? AI-driven pentest framework + `hunter_tools`

Hunter ?????? MCP server?

- server name?`hunter_tools`
- ?????`mcp_server.py`
- ??????110
- ???pipeline?recon?auto vulnerability scanners?payload?session?report?Hunter KB?Burp bridge
- `hunter_tools_mcp.py` ??????????????????? MCP server

## ??????

1. ? `cases/<slug>/state.json`?? `next_steps` ???
2. ?????`??????______`?
3. ??????????? `? hunter_healthcheck ?????? MCP ???`?
4. ????? KB?`kb_router("<??>")` -> `kb_read_file`?
5. ? `hunter_healthcheck` ? `hunter_capabilities`?
6. ???/???? `hunter_recommend_next(target, signals, finding)` ? `hunter_kb_recommend(...)`?

## ?????

- HTTP ??/????Burp `send_http2_request` > `http_probe` > ?? curl/wget?
- Hunter ???????????? Burp/http_probe ???
- Hunter KB / payload / Burp bridge ?????????
- ???????? request/response?diff?payload?????????

## 110 ??? `hunter_tools` MCP ??

### Meta / routing

- `hunter_healthcheck`
- `hunter_capabilities`
- `hunter_recommend_next`
- `hunter_agents_list`
- `hunter_phases_list`

### Hunter KB / `hunter_tools` facade

- `hunter_kb_list`??? `payloads/**/*.md` ? `payloads/*/payloads.yaml`?
- `hunter_kb_search`?????? Hunter ?? KB?
- `hunter_kb_read`????? Hunter KB ???????? `payloads/`?
- `hunter_kb_recommend`??? KB ???payload ???Hunter ??? Burp proof action?

### Burp bridge plan facade

- `hunter_burp_bridge`??? Burp MCP action descriptor builder?
- `hunter_burp_repeater`??? Repeater action plan?
- `hunter_burp_proxy_search`??? proxy history regex search action plan?
- `hunter_burp_scanner_issues`??? scanner issues retrieval action plan?
- `hunter_burp_collaborator_workflow`??? blind SSRF / XXE / CMDI Collaborator proof workflow?
- `hunter_burp_import`??? Burp ??? request/response/screenshot/evidence?

### Pipeline / recon

- `hunter_scan`
- `hunter_recon`
- `hunter_vuln_scan`
- `hunter_subdomain`
- `hunter_port_scan`
- `hunter_tech_detect`
- `hunter_dir_enum`
- `hunter_js_analyze`

### Auto proof tools

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

### Payload / session / report

- `hunter_payload_list`
- `hunter_payload_search`
- `hunter_payload_get`
- `hunter_payload_generate`
- `hunter_session_list`
- `hunter_session_status`
- `hunter_session_start`
- `hunter_session_execute_chain`
- `hunter_session_checkpoint`
- `hunter_post_exploit`
- `hunter_session_state`
- `hunter_report`

### Browser / Playwright MCP bridge

- `hunter_browser_navigate`
- `hunter_browser_interact`
- `hunter_browser_capture_network`
- `hunter_browser_inject_hooks`
- `hunter_browser_get_hook_results`
- `hunter_browser_snapshot`

The browser bridge emits deferred external Playwright MCP descriptors. It does
not control a browser directly; observations are redacted and persisted, and
Hunter follow-up actions remain confirmation-gated.

### Local memory

- `hunter_memory_query`
- `hunter_memory_record`
- `hunter_memory_recommend`
- `hunter_fingerprint_detect`
- `hunter_memory_stats`

Memory recommendations are local, explainable, and non-executing. Fingerprint
detection consumes passive observations and does not make target requests.

### Reverse analysis orchestration

- `hunter_reverse_binary`
- `hunter_reverse_step`
- `hunter_reverse_extract_iocs`
- `hunter_reverse_generate_rules`
- `hunter_reverse_decrypt_plan`

The reverse pipeline persists triage/static/identify/plan/capture/produce
state and emits external Ghidra/ReverseLabTools/Frida handoffs when those
backends are not directly available.

## ????

```text
state.json -> kb_router/kb_read_file -> hunter_healthcheck -> hunter_capabilities
-> hunter_kb_search / hunter_kb_read -> hunter_kb_recommend
-> targeted hunter_auto_* ? Burp action plan
-> Burp/http_probe ?? -> hunter_burp_import -> hunter_report -> exports/notes/reports
```

## ????

- ????????? `hunter_kb_search` ? `hunter_kb_recommend`?
- ?? token/API/IDOR/CORS ????? `hunter_kb_recommend` + `hunter_burp_repeater`?
- ?? OOB ???`hunter_burp_collaborator_workflow`?
- ??? Burp ???? API/token?`hunter_burp_proxy_search`?
- ?? payload?`hunter_payload_search/get/generate`??? `hunter_kb_recommend.payload_hits` ??

## ????

- ?????`D:\Open-tgtylab\exports\notes|reports|...`
- Hunter ?????`C:\Users\Administrator\.agents\skills\hunter\evidence\tool_output`
- case ???`D:\Open-tgtylab\cases\<slug>\state.json`


## Unified Workflow Kernel

For CTF/reverse/pentest cases, define explicit `success_conditions`, then use `hunter_workflow_create` -> `hunter_workflow_route` -> `hunter_workflow_plan` -> backend execution -> `hunter_evidence_register` / `hunter_finding_promote` -> `hunter_workflow_checkpoint`. Use `interactive` by default and bounded `autopilot` for repeatable lab automation. PE/APK/JavaScript/mixed lanes delegate to `reverse_lab_tools`, `ghidra`, and `jshook` through capability plans.
