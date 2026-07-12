# Hunter Integration v2 P0

Hunter exposes one MCP server named `hunter_tools`. Integration v2 makes the
Hunter/OpenTgtyLab boundary machine-verifiable and portable.

## Contract

`integration-contract.json` is the compatibility contract. It declares:

- contract version;
- required MCP server name;
- minimum callable tool count;
- required tools;
- OpenTgtyLab workspace schema version.

Run the same validation used by CI:

```bash
python scripts/check_integration_contract.py
```

## Diagnostic MCP tools

- `hunter_contract_check`: validates the contract against the live registry.
- `hunter_config_audit`: discovers user/project Codex configs and rejects the
  legacy `hunter` registration. Missing configs are reported without assuming a
  Windows drive or username.
- `hunter_runtime_status`: reports interpreter, OS, process, workspace and tool
  count without executing platform-specific process commands.
- `hunter_doctor`: aggregates contract, configuration and runtime checks.

`hunter_healthcheck` embeds these Integration v2 checks and
`hunter_capabilities` advertises all diagnostic tools.

## Portable workspace discovery

Workspace lookup order is:

1. explicit adapter argument;
2. `OPEN_TGTYLAB_ROOT`, `OPEN_TGTYLAB_WORKSPACE`, or `TGTYLAB_ROOT`;
3. current directory and its parents;
4. `~/Open-tgtylab` (case-compatible alternative included);
5. current directory as an unavailable fallback.

No fixed drive, username, or installation directory is required.

## CI

`.github/workflows/integration-contract.yml` runs contract validation and the
full pytest suite on Windows and Linux using supported Python versions.
