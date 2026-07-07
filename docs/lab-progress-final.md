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

### Web Cache Poisoning (1)
45. Web cache poisoning with an unkeyed header
    - X-Forwarded-Host header not included in cache key
    - Server uses it to generate script src: //evil.com/resources/js/tracking.js
    - Hosted alert(document.cookie) on exploit server
    - Cached response served malicious script to all users
    - http_probe worked when Burp timed out

### Web Cache Poisoning (2)
46. [PENDING] HTTP request smuggling CL.TE

### NoSQL Injection (1)
46. Exploiting NoSQL operator injection to bypass authentication
    - MongoDB operator injection in JSON login body
    - Admin username had random suffix (admin510uqku8)
    - Payload: {"username":{"$regex":"^administrator"},"password":{"$ne":"invalid"}}
    - $regex matched partial username, $ne bypassed password check

### Prototype Pollution (1)
47. DOM XSS via client-side prototype pollution
    - deparam.js vulnerable to __proto__ bracket notation
    - searchLogger.js reads config.transport_url (inherited from polluted prototype)
    - Sink: document.createElement('script').src = config.transport_url
    - Payload: ?__proto__[transport_url]=data:,alert(document.cookie)//
    - data: URL embeds JS directly, // comments out suffix

### HTTP Request Smuggling (2)
48. HTTP request smuggling, basic CL.TE
    - Front-end: Content-Length (90 bytes)
    - Back-end: Transfer-Encoding: chunked
    - "0\r\n\r\n" = chunk end for back-end, but CL reads more
    - Residual "GPOST /" pollutes next request
    - Must use raw TCP socket (Python socket), HTTP libs normalize headers

### SSRF (4)
49. Blind SSRF with out-of-band detection
    - Referer header triggers server-side fetch
    - Set Referer to Collaborator URL: http://COLLABORATOR
    - Analytics software fetches Referer, triggers DNS interaction
    - Lab auto-detects OOB interaction

### Insecure Deserialization (1)
50. Modifying serialized data types (PHP type juggling)
    - PHP session cookie contains serialized User object
    - Original: O:4:"User":2:{...s:12:"access_token";s:32:"TOKEN";}
    - Modified: O:4:"User":2:{...s:12:"access_token";b:1;}
    - PHP loose comparison: true == "any_string" → true
    - Bypassed access_token validation, accessed admin panel
    - Deleted carlos via /admin/delete?username=carlos

### OAuth (1)
51. OAuth authentication bypass via implicit grant
    - /authenticate endpoint trusts client-provided email
    - No verification that email matches OAuth token
    - Enumerate admin email by trying different formats (302=success)
    - Set email to admin's email in callback, bypass token verification
    - Python requests can run full OAuth flow (authorize→login→consent→callback)

### JWT (1)
52. JWT authentication bypass via unverified signature
    - JWT uses RS256 but server doesn't verify signature at all
    - Changed "sub": "wiener" → "sub": "administrator"
    - Cleared signature (empty string)
    - Modified JWT accepted by server, accessed /admin
    - Deleted carlos via /admin/delete?username=carlos

### WebSocket (1)
53. Manipulating WebSocket messages to exploit vulnerabilities
    - Chat application uses WebSocket for messaging
    - Payload: <img src=x onerror=alert(document.cookie)>
    - Server echoes message to agent without sanitization
    - Agent's browser renders HTML, onerror fires, executes XSS

### Clickjacking (1)
54. Basic clickjacking with CSRF token protection
    - Target: /my-account page with Delete account button
    - Exploit: transparent iframe (opacity:0.0001) + decoy button
    - Button at (479, 16) inside iframe, iframe offset (8, 8)
    - Decoy positioned at top:487px, left:24px to align
    - Key: account for iframe body margin (8px default)

### GraphQL (2)
55. Bypassing GraphQL brute force protections
    - Rate limiter counts HTTP requests, not GraphQL operations
    - GraphQL aliases: a0:login(...), a1:login(...), ... in single request
    - 119 password attempts in 1 HTTP request
    - mutation{a0:login(input:{username:"carlos",password:"123456"}){token} a1:login(...) ...}
    - Found carlos password: 123456
    - Key: GraphQL aliases = unlimited operations per request

### SQLi (15)
56. SQL injection with filter bypass via XML encoding
    - WAF blocks raw SQL keywords (UNION, SELECT, --)
    - XML parser decodes numeric char references BEFORE SQL query
    - Encode: &#49; = '1', &#32; = space, &#85; = 'U', etc.
    - Full payload: &#49;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84; = "1 UNION SELECT"
    - Extracted admin password: qfq7k4hac92rkhi73ywo
    - Helper: ''.join(f'&#{ord(c)};' for c in payload)

### CORS (3)
57. CORS vulnerability with trusted null origin
    - Server trusts Origin: null
    - Sandboxed iframe without allow-same-origin sends Origin: null
    - /accountDetails returns admin API key with credentials
    - Exploit: srcdoc iframe + XMLHttpRequest with withCredentials=true
    - Admin API key: pGaVOclyKuQeEY6CTr7zYGrse6NnsE3G

### SQLi (16)
58. Blind SQL injection with conditional errors (Oracle)
    - TrackingId cookie injectable, Oracle DB
    - Error trigger: ' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'--
    - Extract: SUBSTR(password,{i},1) = '{c}' with TO_CHAR(1/0) for true condition
    - Must use FROM dual for standalone SELECT in Oracle
    - Extracted: administrator / zfc6opka8uiwb7fnp2ll
    - ~20 requests/second extraction speed

### XSS (5)
59. DOM XSS in document.write sink using source location.search
    - Source: location.search (URL query parameter)
    - Sink: document.write() - no HTML encoding
    - Payload: /?search="><img src=x onerror=alert(document.cookie)>
    - Closes existing input tag, injects new img tag with onerror

### GraphQL (3)
60. Finding a hidden GraphQL endpoint
    - Hidden endpoint at /api (not /graphql)
    - GET + query={__typename} confirmed GraphQL
    - Introspection blocked: "GraphQL introspection is not allowed"
    - Bypass: Insert comment after __schema: %23 (hash) + %0a (newline)
    - Regex matches __schema{ but parser ignores comments
    - Discovered: getUser(id), deleteOrganizationUser(input)
    - Deleted carlos via mutation{deleteOrganizationUser(input:{id:3})}
    - Key bypass: __schema#\n{ bypasses __schema{ regex

### SSTI (2)
61. Basic server-side template injection (code context)
    - Tornado template engine
    - Injection point: "Preferred name" dropdown value
    - Value placed inside {{user_input}} template expression
    - RCE payload: __import__('os').popen('rm /home/carlos/morale.txt').read()
    - No delimiter breakout needed - direct code context
    - Triggered by posting blog comment
