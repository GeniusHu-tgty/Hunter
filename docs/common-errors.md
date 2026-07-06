# Hunter Common Errors & Solutions

## Burp MCP Issues

### Error: Request timeout (30s)
**Cause:** Burp MCP has 30s timeout per request
**Solution:** Use Python http.client as fallback for slow targets

### Error: Connection reset
**Cause:** Target WAF or Burp proxy issue
**Solution:** 
- Try HTTP/1.1 instead of HTTP/2
- Add User-Agent header
- Try without Burp proxy (direct Python request)

### Error: Missing parameter 'csrf'
**Cause:** Login form requires CSRF token
**Solution:** GET the login page first, extract csrf from `<input name="csrf" value="xxx">`, then POST

## Lab Solving Issues

### Lab not showing "Solved"
**Cause:** Using Burp POST instead of browser login
**Solution:** Use Playwright to fill and submit login form

### Rate limited (PortSwigger)
**Cause:** Too many failed attempts
**Solution:** Wait 30 minutes, or use fresh session with 5s+ delays

### Lab instance expired
**Cause:** Lab timeout (usually 30-60 minutes)
**Solution:** Click ACCESS THE LAB again to get new instance

## Hunter Tool Issues

### ModuleNotFoundError: 'core'
**Cause:** Tool depends on core.config module
**Solution:** Already fixed with fallback imports (2026-07-06)

### Git push fails (Connection reset)
**Cause:** Git TLS handshake issue
**Solution:** Try `git push` from terminal, or use GitHub API

### GitHub API 401
**Cause:** Expired or missing token
**Solution:** Generate new Personal Access Token at github.com/settings/tokens
