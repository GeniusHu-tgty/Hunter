# Hunter v8 Hardening Design

## Goal
Make Hunter a stronger Codex-native security research framework by turning the MCP layer into a stable, introspectable, evidence-driven orchestrator instead of a fragile blind scanner wrapper.

## Scope
This change upgrades the local Hunter skill repo used by Codex at `C:\Users\Administrator\.agents\skills\hunter`.

## Architecture
1. **Stable MCP facade**: every MCP tool returns bounded JSON with status, elapsed time, and errors; missing or broken auto scanners are registered and mapped to their real implementation functions.
2. **Capability introspection**: `hunter_healthcheck` and `hunter_capabilities` expose runtime readiness, external tool availability, payload inventory, registered tools, and known degradation.
3. **Evidence-driven guidance**: `hunter_recommend_next` maps observed signals/findings to next tool choices and proof goals, prioritizing logic vulnerabilities and reportable impact.
4. **Windows-safe tests**: payload tests read UTF-8 explicitly and validate the actual payload inventory instead of stale expected directories.
5. **Skill synchronization**: `SKILL.md`, `README.md`, and `TOOLS.md` describe the actual available tools and recommended workflow.

## Non-goals
- No broad rewrite of scanner engines.
- No destructive target actions.
- No dependence on external network services for unit tests.

## Success Criteria
- Missing MCP tools are registered: `hunter_auto_sqli`, `hunter_auto_xss`, `hunter_auto_ssrf`, `hunter_auto_xxe`, `hunter_healthcheck`, `hunter_capabilities`, `hunter_recommend_next`.
- Existing broken MCP wrappers for `ssti`, `cmd`, and `idor` call the correct implementations.
- Health/capability tools complete locally without invoking network scans.
- Payload tests pass on Windows default locale.
- Full pytest suite passes locally.
