# Hunter Usage Guide

## Quick Start

### 1. Start Hunter MCP Server
```bash
cd /path/to/hunter
python mcp_server.py
```

### 2. Use Hunter Tools in Claude Code
```
# Unified scan (recommended)
unified_scan(target="https://target.com")

# Individual tools
auto_sqli(target="https://target.com/filter?category=Gifts")
auto_xss(target="https://target.com/search?q=")
auto_ssti(target="https://target.com/?message=")
auto_ssrf(target="https://target.com/stock?url=")
```

### 3. Use with Burp MCP
```
# Send request via Burp
burp(action="send", url="https://target.com/")

# Check Scanner findings
burp(action="scanner_issues")

# Generate OOB payload
burp(action="collaborator_generate")
```

## Advanced Usage

### Custom Scan Phases
```python
from core.unified_scanner import UnifiedScanner

scanner = UnifiedScanner("https://target.com")
result = scanner.run_full_scan(phases=["recon", "sqli", "xss"])
```

### Cookie Injection (PortSwigger Labs)
```python
from core.auto_sqli import AutoSQLi

sqli = AutoSQLi(
    base_url="https://lab.web-security-academy.net/filter?category=Gifts",
    param="category",
    cookie_param="TrackingId",
    cookie_value="original_value"
)
result = sqli.run_full_scan()
```

### Blind SQLi with Collaborator
```python
# Generate Collaborator domain
collab = burp(action="collaborator_generate")

# Use in blind SQLi
sqli = AutoSQLi(base_url=target, oob_domain=collab["domain"])
result = sqli.test_blind_oob()
```

## Best Practices

### 1. Always Recon First
```
unified_scan(target="https://target.com", phases=["recon"])
# Get: forms, params, endpoints, CSRF tokens
```

### 2. Use Appropriate Tools
- SQLi → auto_sqli
- XSS → auto_xss
- SSTI → auto_ssti
- SSRF → auto_ssrf
- XXE → auto_xxe
- CMDi → auto_cmd
- IDOR → auto_idor

### 3. Check Burp Scanner Results
```
burp(action="scanner_issues", severity_filter="high,critical")
```

### 4. Record Findings
```python
scanner.ctx.add_finding("sqli", payload, evidence, "high")
```

### 5. Get Recommendations
```python
recommendations = scanner.get_recommendations()
# Returns: next steps based on findings
```
