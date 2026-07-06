# Security Configuration Checklist

## Authentication Security

### Password Policy
- [ ] Minimum 12 characters
- [ ] Require uppercase + lowercase + digit + special
- [ ] Block common passwords (top 10000 list)
- [ ] Block passwords containing username
- [ ] Password history (prevent reuse of last 5)
- [ ] Account lockout after 5 failed attempts

### Session Management
- [ ] Session tokens are random (≥128 bits entropy)
- [ ] Session expires after 15 minutes inactivity
- [ ] Session invalidated on logout
- [ ] New session on login (prevent fixation)
- [ ] HttpOnly + Secure + SameSite cookies

### 2FA
- [ ] TOTP or hardware key (not SMS)
- [ ] Backup codes available
- [ ] Rate limit on 2FA attempts
- [ ] 2FA enforced on all sensitive operations

## Input Validation

### SQL Injection Prevention
- [ ] Parameterized queries everywhere
- [ ] No string concatenation in SQL
- [ ] ORM used consistently
- [ ] WAF as defense-in-depth

### XSS Prevention
- [ ] Output encoding for all contexts (HTML/JS/URL/CSS)
- [ ] Content-Security-Policy header
- [ ] HttpOnly cookies
- [ ] No inline scripts

### SSRF Prevention
- [ ] Whitelist allowed URLs/IPs
- [ ] Block private IP ranges (10.x, 172.16.x, 192.168.x)
- [ ] Validate URL after following redirects
- [ ] No user-controlled URLs in server-side requests

### File Upload
- [ ] Whitelist allowed extensions
- [ ] Validate MIME type server-side
- [ ] Rename uploaded files
- [ ] Store outside web root
- [ ] Scan for malware

## HTTP Security Headers

```
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

## API Security

### Authentication
- [ ] API keys rotated regularly
- [ ] OAuth2 with PKCE for public clients
- [ ] JWT with strong signing algorithm (RS256)
- [ ] Token expiry ≤ 15 minutes

### Authorization
- [ ] RBAC enforced server-side
- [ ] No client-side role checks
- [ ] IDOR prevention (use UUIDs, not sequential IDs)
- [ ] Rate limiting per user/IP

### Input Validation
- [ ] JSON schema validation
- [ ] Request size limits
- [ ] Content-Type validation
- [ ] No raw SQL in resolvers
