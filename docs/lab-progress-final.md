# Hunter Lab Progress - Final Status (2026-07-06)

## Solved Labs (36 total)

### SQL Injection (14)
1. Oracle DB Version - UNION SELECT BANNER
2. Oracle DB Contents - all_tables + all_tab_columns
3. Single Column Multi-value - || concatenation
4. MySQL DB Version - @@version
5. UNION determine columns - ORDER BY
6. UNION find text column - string replacement
7. UNION retrieve from tables - users table
8. Blind Conditional Response - TrackingId cookie
9. Blind Conditional Error - TO_CHAR(1/0)
10. Visible Error-based - CAST type conversion
11. Blind Time Delay - pg_sleep
12. Blind Time Delay + Extract - CASE WHEN
13. Blind OOB Interaction - UTL_INADDR
14. Blind OOB Data Exfil - xp_dirtree

### XSS (3)
15. DOM XSS jQuery hashchange - iframe.src + hash
16. Stored XSS href attribute - javascript:alert(1)
17. Reflected XSS JS string - '-alert(1)-'

### SSTI (1)
18. Basic SSTI ERB - <%= 7*7 %>

### SSRF (3)
19. SSRF blacklist bypass - 127.1 + %2561dmin
20. SSRF filter bypass via open redirect - chain
21. SSRF basic against local server

### XXE (2)
22. Basic XXE file read - file:///etc/passwd
23. XXE SSRF - 169.254.169.254

### Command Injection (1)
24. Command injection simple - |whoami

### Access Control (1)
25. User role controlled by request parameter - Admin=true

### Authentication (7)
26. Username enumeration via different responses
27. Username enumeration via subtly different responses
28. Username enumeration via response timing
29. Broken brute-force protection, IP block
30. 2FA simple bypass - direct /my-account
31. Password reset broken logic - token not bound to user
32. Password brute-force via password change

### Information Disclosure (2)
33. Error messages - Apache Struts version
34. Backup files disclosure

### Path Traversal (1)
35. Simple case - ../../../etc/passwd

### Other (1)
36. HTTP Request Smuggling CL.TE - raw socket

## Hunter Improvements Made

### Tools Deep Optimized (7)
- auto_sqli: Cookie injection, CSRF extraction, OOB, conditional response
- auto_xss: CSRF extraction, exploit HTML generation, DOM/Stored/Reflected
- auto_ssrf: 127.1 bypass, double URL encoding, redirect chain
- auto_ssti: Jinja2/Twig disambiguation, 5 engine RCE payloads
- auto_xxe: SVG upload, error-based DTD, PHP wrapper
- auto_cmd: OOB DNS, Windows support
- auto_idor: Cookie role tampering, hidden params

### Unified Scanner
- 8 phases: recon/sqli/xss/ssti/ssrf/xxe/cmd/idor
- Burp Scanner aggregation
- Smart recommendations

### Burp Integration
- 30+ MCP actions
- Collaborator for blind vulns
- Scanner issues aggregation
- Proxy history analysis

### Payload Categories (30)
sqli, xss, ssti, xxe, cmd, ssrf, access-control, file-upload, auth,
business-logic, nosql, race-condition, info_leak, jwt, lfi, cors,
graphql, oauth, prototype-pollution, smuggling, waf-bypass, ctf,
websocket, dom-xss, cache-poisoning, clickjacking

### Documentation (10+)
- burp-mcp-workflow.md
- quick-reference.md
- common-errors.md
- verified-lab-techniques.md
- verified-solutions.md
- burp-optimal-config.md
- capability-matrix.md
- progress-tracker.md
- timing-attack-techniques.md

### GraphQL (1)
37. Accidental exposure of private GraphQL fields
    - Endpoint: /graphql/v1 (found via JS source)
    - Introspection enabled, User type exposed password field
    - getUser(id) query returned plaintext passwords for all accounts
    - Extracted administrator credentials, logged in, deleted carlos

### Business Logic (2)
38. Excessive trust in client-side controls
    - Hidden price field in cart form: price=133700 (cents)
    - Modified to price=1 ($0.01) in POST request
    - Server had no server-side price validation
    - $1337 jacket purchased for $0.01

### Access Control (2)
39. Unprotected admin functionality
    - robots.txt leaked: Disallow: /administrator-panel
    - Admin panel accessible without authentication
    - Deleted carlos via /administrator-panel/delete?username=carlos

### XXE (3)
40. Exploiting XXE via image file upload
    - Uploaded malicious SVG as avatar
    - SVG contained XXE: <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
    - Server parsed SVG, expanded XXE, converted to PNG
    - Used OCR (easyocr) to read hostname from PNG: 154846213d25
    - Submitted answer to /submitSolution

### Race Condition (2)
41. Bypassing rate limits via race conditions
    - Rate limiter: 2 attempts per 120s lockout
    - Used HTTP/2 single-packet attack (httpx http2=True)
    - asyncio.gather() sent 30 requests simultaneously on single TCP connection
    - All 30 passed the rate limit check before counter incremented
    - Found carlos password: 123123
    - Key: HTTP/2 multiplexing = requests arrive simultaneously

### CORS (2)
42. CORS vulnerability with trusted insecure protocols
    - CORS trusted all subdomains regardless of HTTP/HTTPS
    - stock subdomain had reflected XSS in productId param
    - Chain: XSS on http://stock.SUB → CORS request to /accountDetails
    - Exfiltrated admin API key via exploit server
    - Key: HTTP subdomain + CORS trust = credential theft

### XXE (4)
43. Blind XXE with out-of-band interaction
    - POST /product/stock accepts XML
    - Injected: <!ENTITY xxe SYSTEM "http://COLLABORATOR">
    - Burp Collaborator recorded DNS + HTTP callbacks
    - file:// protocol confirmed working
    - oastify.com domain reached successfully

### XSS (4)
44. Stored XSS into onclick event handler
    - Website field reflected in onclick: tracker.track('VALUE')
    - Server escaped ' to \' but not &apos; HTML entity
    - Payload: http://x.com&apos;-alert(document.domain)-&apos;
    - Browser decodes &apos; to ' at render time, bypassing server filter
