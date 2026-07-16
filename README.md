# Hunter

Hunter is an MCP-first framework for authorized security assessment. It separates
candidate discovery from reproducible verification, keeps HTTP execution behind a
single RequestBroker boundary, and records proof state through the Event Kernel.

The project is designed for controlled assessments, CTF environments, local labs,
and software or infrastructure you are authorized to test.

## What Changed

The current architecture is evidence-oriented rather than scanner-oriented:

```text
discover -> low-cost candidate discovery and proxy audit
probe    -> baseline / probe / post-baseline through RequestBroker
verify   -> Experiment + Oracle + Event Kernel attestation
race     -> health precheck + RaceCoordinator + state oracle
```

`discover` does not create a full evidence chain. Verified findings require the
appropriate control path, durable artifacts, and a verdict recorded by the Event
Kernel.

## Core Architecture

### RequestBroker

All legacy auto tools use a requests-compatible
`LegacyRequestsAdapter(RequestBroker(...))`. The adapter preserves `get`, `post`,
and `request` call patterns while the broker owns:

- response projections for HTML and JSON;
- WAF, CAPTCHA, rate-limit, login redirect, and soft-ban classification;
- per-origin and identity-scoped cooldown state in SQLite/WAL;
- compact, content-addressed artifacts with retention and quota rules;
- baseline/probe/post-baseline control groups;
- isolated `IdentityPool` credentials and BrowserPool handoff data.

Runtime defaults live in [`config.yaml`](config.yaml). The broker reads its
`request_broker` section for cooldown, blocking, and artifact quota settings.

### Evidence And Workflows

The Event Kernel is the source of truth for workflow state, action attempts,
evidence manifests, attestations, verdicts, and recovery checkpoints. Raw network
bodies stay in Broker artifacts; the Event Kernel records canonical identifiers
and digests instead of copying unbounded response data.

Response-driven verification, OAST, authorization proof, and race experiments
all converge on the same evidence and verdict path. A WAF page, CAPTCHA, timeout,
or missing cleanup plan is inconclusive, not a vulnerability finding.

### Browser, MITM, And External Tools

Browser integration is optional (`hunter[browser]`). When a Playwright backend is
not available, browser workflows return a structured
`missing_inputs=["browser_pool_available"]` result without disabling other tools.

The MITM controller is fail-closed for protected external CLI work. Tool trust is
measured with a local HTTPS probe; untrusted tools remain `candidate_only` and do
not silently fall back to direct protected scanning.

## MCP Server

Hunter exposes one FastMCP server:

```text
server: hunter_tools
entrypoint: mcp_server.py
contract: integration-contract.json
```

`hunter_tools_mcp.py` is a compatibility launcher only. ReverseLab tools are
loaded internally when `REVERSELAB_MCP_PATH` points to a valid extension, then
registered with the `re_` namespace. Existing Hunter MCP tool names and legacy
workflow files remain compatible.

Useful diagnostics:

- `hunter_healthcheck`
- `hunter_capabilities`
- `hunter_contract_check`
- `hunter_config_audit`
- `hunter_runtime_status`
- `hunter_doctor`
- `hunter_broker_benchmark`

## Install

```bash
git clone https://github.com/GeniusHu-tgty/Hunter.git
cd Hunter
python -m pip install -e .
```

Install optional transports only when needed:

```bash
python -m pip install -e ".[stealth,browser]"
```

The browser extra provides Playwright support. Install browser binaries separately
when running a local Playwright backend:

```bash
python -m playwright install
```

## MCP Configuration

Register only `hunter_tools`; do not register a second standalone ReverseLab
server for the same Hunter process.

```toml
[mcp_servers.hunter_tools]
type = "stdio"
command = "python"
args = ["/absolute/path/to/Hunter/mcp_server.py"]

[mcp_servers.hunter_tools.env]
OPEN_TGTYLAB_ROOT = "/absolute/path/to/Open-tgtylab"
REVERSELAB_MCP_PATH = "/absolute/path/to/ReverseLabToolsMCP/reverse_lab_tools_mcp.py"
```

`REVERSELAB_MCP_PATH` is optional. If it is absent or invalid, Hunter continues
with the core tool contract and reports the missing extension through diagnostics.

## Typical Assessment Flow

1. Open or resume a case and read its next steps.
2. Run `hunter_healthcheck` and `hunter_capabilities`.
3. Query the project knowledge base for the target technology or test class.
4. Use reconnaissance or passive discovery to produce candidates.
5. Route a candidate to `probe`, then a bounded verification workflow when
   controls and an oracle are available.
6. Register evidence, record a verdict, checkpoint the workflow, and publish a
   report or note.

For HTTP execution, the project preference remains:

```text
Burp send_http2_request -> http_probe -> documented local fallback
```

## Development

Run the complete suite:

```bash
python -m pytest -q
```

Run the Broker-focused checks:

```bash
python -m pytest -q \
  tests/test_request_broker.py \
  tests/test_request_broker_boundary.py \
  tests/test_mitm_controller.py \
  tests/test_broker_benchmark.py \
  tests/test_oast_verifier.py
```

The request-boundary test rejects direct `requests`, `httpx`, or `aiohttp` use in
legacy auto scanners. The pre-commit hook runs the same guard.

## Repository Layout

```text
core/request_broker/          Request policy, projections, artifacts, OAST, MITM
core/workflow/event_kernel/   Event-sourced workflow and evidence authority
core/browser/                 Browser MCP planning and encrypted session store
core/evidence/                Normalization and verdict integration
tests/                        Unit, integration, and Event Kernel acceptance tests
config.yaml                   Broker runtime defaults
integration-contract.json     MCP compatibility contract
```

## Disclaimer

本项目仅用于教育和授权安全研究目的。用户必须确保在合法授权范围内操作。使用本项目产生的任何后果由用户自行承担。

See [DISCLAIMER.md](DISCLAIMER.md) for the full disclaimer.

## Related Projects

- [Open-tgtylab](https://github.com/GeniusHu-tgty/Open-tgtylab) — 安全研究工作台，集成逆向工程、CTF、移动安全、Web安全于一体
