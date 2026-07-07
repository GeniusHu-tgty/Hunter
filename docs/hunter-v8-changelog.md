# Hunter v8 Changelog (2026-07-07)

## New Tools Added

### Core Auto-* Tools
1. **auto_csrf.py** - CSRF vulnerability detection
   - Form analysis with CSRF token extraction
   - Token-session binding testing
   - SameSite cookie checking
   - GET-based state change detection
   - Auto-generate exploit HTML

2. **auto_graphql.py** - GraphQL vulnerability scanner
   - Endpoint discovery (10+ common paths)
   - Full introspection query
   - Private data access testing
   - Query batching test
   - Depth limit bypass test
   - Field suggestion leak detection

3. **auto_websocket.py** - WebSocket vulnerability scanner
   - WebSocket endpoint discovery (HTML + JS analysis)
   - Origin policy bypass testing
   - XSS injection via WebSocket
   - Cross-Site WebSocket Hijacking (CSWSH)
   - Message manipulation testing

### MCP Server Tools (7 new)
- `hunter_auto_csrf` - CSRF scan
- `hunter_auto_graphql` - GraphQL scan
- `hunter_auto_websocket` - WebSocket scan
- `hunter_auto_ssti` - SSTI scan (exposed)
- `hunter_auto_cmd` - Command injection scan (exposed)
- `hunter_auto_idor` - IDOR scan (exposed)
- `hunter_unified_scan` - All 11 phases unified

### Unified Scanner Phases (11 total)
1. recon - Attack surface discovery
2. sqli - SQL injection
3. xss - Cross-site scripting
4. ssti - Server-side template injection
5. ssrf - Server-side request forgery
6. xxe - XML external entity
7. cmd - Command injection
8. idor - Insecure direct object reference
9. csrf - Cross-site request forgery (NEW)
10. graphql - GraphQL vulnerabilities (NEW)
11. websocket - WebSocket vulnerabilities (NEW)

### Payload Files Added
- `payloads/dom-xss/dom-xss-techniques.md` - Complete DOM XSS reference
- `payloads/auth/csrf-techniques.md` - CSRF attack techniques
- `payloads/graphql/graphql-attacks.md` - GraphQL attack payloads

## Tool Count
- **Before**: 7 auto_* tools, 5 MCP tools
- **After**: 10 auto_* tools, 12 MCP tools
