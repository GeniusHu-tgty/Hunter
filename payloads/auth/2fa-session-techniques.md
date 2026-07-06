# 2FA & Session Management - Verified Techniques

## 2FA Bypass Techniques

### Direct Access Bypass (Verified)
```
# After entering correct password, app shows 2FA code page
# Try accessing protected page directly:
GET /my-account
# If returns 200 with user data = 2FA bypassed
```

### Response Manipulation
```
# App returns: {"success": false}
# Change to: {"success": true}
# Or change status code from 403 to 200
```

### Brute Force 2FA Code
```
# If 4-digit code: 0000-9999
# If no rate limit on 2FA = brute forceable
# If rate limit exists: use timing differences
```

### Session Fixation + 2FA Bypass
```
# If app accepts session ID from URL:
# 1. Get valid session with 2FA completed
# 2. Fix session ID in victim's browser
# 3. Victim uses pre-authenticated session
```

## Session Management

### Session Fixation
```
# If app accepts session ID from cookie/URL:
1. Attacker gets session ID: /?session=attacker_id
2. Sends to victim: https://target.com/?session=attacker_id
3. Victim logs in → session now authenticated
4. Attacker uses same session ID → authenticated
```

### Cookie Manipulation
```
# Client-side role storage
Cookie: role=user → role=admin
Cookie: isAdmin=false → isAdmin=true
Cookie: admin=0 → admin=1
```

### Session Token Prediction
```
# If tokens are time-based or sequential:
# 1. Get multiple session tokens
# 2. Analyze pattern
# 3. Predict next valid token
```

## PortSwigger Lab Approach

### 2FA Simple Bypass
1. Login with valid credentials (wiener:peter)
2. App shows 2FA code page
3. Navigate directly to /my-account
4. If accessible = 2FA bypassed

### Password Reset Broken Logic
1. Request password reset for carlos
2. Get reset email (in exploit server)
3. Extract temp token from URL
4. Try submitting new password with the token
5. If token can be reused without the full flow = broken logic
