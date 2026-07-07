# Hunter Architecture

## Overview
Hunter is an AI-driven penetration testing framework that combines automated tools with intelligent analysis.

## Architecture Components

### 1. Core Engine (`core/`)
- **auto_sqli.py** — SQL injection detection
- **auto_xss.py** — XSS detection
- **auto_ssti.py** — SSTI detection
- **auto_ssrf.py** — SSRF detection
- **auto_xxe.py** — XXE detection
- **auto_cmd.py** — Command injection detection
- **auto_idor.py** — IDOR detection
- **unified_scanner.py** — Unified scan orchestrator
- **burp_bridge.py** — Burp Suite MCP integration

### 2. MCP Server (`mcp_server.py`)
- Exposes Hunter tools as MCP tools
- Integrates with Claude Code
- Provides unified interface

### 3. Payloads (`payloads/`)
- SQLi payloads
- XSS payloads
- SSTI payloads
- XXE payloads
- Command injection payloads
- SSRF payloads
- Access control payloads
- File upload payloads
- Auth payloads
- Business logic payloads
- NoSQL payloads
- Race condition payloads
- Info disclosure payloads
- JWT payloads
- LFI payloads
- CORS payloads
- GraphQL payloads
- OAuth payloads
- Prototype pollution payloads
- Smuggling payloads
- WAF bypass payloads
- CTF payloads
- WebSocket payloads
- DOM XSS payloads
- Cache poisoning payloads
- Clickjacking payloads

### 4. Documentation (`docs/`)
- Burp MCP workflow
- Quick reference
- Common errors
- Verified lab techniques
- Verified solutions
- Burp optimal config
- Capability matrix
- Progress tracker
- Timing attack techniques
- Automated workflow
- FAQ
- Test cases
- Usage guide

## Data Flow

```
User Request
    ↓
Claude Code (MCP Client)
    ↓
Hunter MCP Server
    ↓
Core Engine (auto_* tools)
    ↓
Target Application
    ↓
Burp MCP Bridge
    ↓
Burp Suite
    ↓
Findings & Reports
```

## Integration Points

### 1. Claude Code Integration
- Hunter MCP server exposes tools
- Claude Code calls Hunter tools
- Results returned to Claude Code

### 2. Burp Suite Integration
- Burp MCP bridge sends requests
- Burp Scanner finds vulnerabilities
- Burp Collaborator for OOB testing

### 3. Playwright Integration
- Lab launching
- Form filling
- Exploit delivery
- Result verification

## Key Design Principles

### 1. Modularity
- Each tool is independent
- Tools can be used standalone
- Easy to add new tools

### 2. Automation
- Unified scanner orchestrates all tools
- Auto-detection of vulnerabilities
- Minimal manual intervention

### 3. Integration
- Burp MCP for HTTP requests
- Playwright for browser automation
- Knowledge base for techniques

### 4. Extensibility
- Easy to add new payload categories
- Easy to add new detection tools
- Easy to add new documentation
