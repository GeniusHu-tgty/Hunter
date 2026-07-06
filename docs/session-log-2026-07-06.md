# Hunter Session Log - 2026-07-06

## Labs Solved Today: 34 total

### SQLi (14 labs)
1. Oracle DB Version - UNION SELECT BANNER
2. Oracle DB Contents - all_tables + all_tab_columns
3. Single Column Multi-value - || concatenation
4. MySQL DB Version - SELECT @@version
5. UNION determine columns - ORDER BY / NULL count
6. UNION find text column - Replace NULL with 'a'
7. UNION retrieve data - SELECT username,password
8. Blind Conditional Response - TrackingId cookie
9. Blind Conditional Error - Oracle TO_CHAR(1/0)
10. Visible Error-based - PostgreSQL CAST
11. Blind Time Delay - pg_sleep
12. Blind Time Delay + Extract - CASE WHEN + pg_sleep
13. Blind OOB Interaction - Oracle UTL_INADDR
14. Blind OOB Data Exfiltration - MSSQL xp_dirtree

### XSS (3 labs)
15. DOM XSS jQuery hashchange - iframe.src + hash
16. Stored XSS href attribute - javascript:alert(1)
17. Reflected XSS JS string - '-alert(1)-'

### SSTI (1 lab)
18. Basic SSTI ERB - <%= system('rm...') %>

### SSRF (3 labs)
19. SSRF blacklist bypass - 127.1 + %2561dmin
20. SSRF open redirect bypass - /product/nextProduct?path=http://internal
21. SSRF filter bypass via open redirect - chain attack

### XXE (2 labs)
22. Basic XXE file read - <!ENTITY xxe SYSTEM "file:///etc/passwd">
23. XXE SSRF - SYSTEM "http://169.254.169.254"

### Command Injection (1 lab)
24. Command injection simple - 1|whoami

### Access Control (1 lab)
25. User role controlled by request parameter - Admin=false→true

### Authentication (7 labs)
26. Username enumeration (responses) - apollo:superman
27. Username enumeration (subtle) - azureuser:159753
28. Username enumeration (timing) - root:1.4s vs 0.8s
29. Broken brute-force protection - correct/incorrect alternation
30. Password brute-force via password change - carlos:joshua
31. 2FA simple bypass - direct /my-account access
32. Password reset broken logic - change hidden username

### Business Logic (1 lab)
33. High-level logic vulnerability - quantity=-235

### NoSQL (1 lab)
34. NoSQL injection detection - '||1||'

### Race Condition (1 lab)
35. Limit overrun - parallel coupon application

### Info Disclosure (1 lab)
36. Error messages - Apache Struts 2 2.3.31

### Path Traversal (1 lab)
37. Simple case - ../../../etc/passwd

### CORS (1 lab)
38. Basic origin reflection - Origin: evil.com

## Hunter Improvements Today

### Tools Fixed
- 21 files standalone import fallback
- 7 auto_* tools: 7/7 tests passing

### Knowledge Base Added (25+ categories)
- SQLi (blind + advanced)
- XSS (reflected + stored + DOM + WebSocket)
- SSTI + XXE advanced
- SSRF (blacklist bypass + chain)
- Auth (brute force + 2FA + password reset)
- Business logic + Race condition
- NoSQL injection
- CORS + Clickjacking
- HTTP Smuggling
- GraphQL + Web Cache Poisoning
- OAuth + Open Redirect
- Prototype Pollution

### Documentation
- burp-mcp-workflow.md
- quick-reference.md
- common-errors.md
- burp-automation-config.md
- verified-lab-techniques.md
- progress-tracker.md

### GitHub
- Repository: https://github.com/GeniusHu-tgty/Hunter
- All commits pushed successfully
- CI workflow fixed
- DISCLAIMER.md added
