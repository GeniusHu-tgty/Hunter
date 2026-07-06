# Brute Force & Password Attack - Verified Techniques

## Password Change Brute Force (Verified)

### Lab Approach
1. Find password change form (POST /change-password)
2. Parameters: current_password, new_password, confirm_password
3. Brute force current_password with wordlist
4. Set new_password to known value

### Detection
```
# Invalid current password
POST /change-password
current=wrong&new=secret&confirm=secret
→ 400 "Current password is incorrect"

# Valid current password
POST /change-password
current=correct&new=secret&confirm=secret
→ 302 redirect or 200 OK
```

### CSRF Token Handling
```
1. GET /change-password → Extract CSRF token
2. POST /change-password with CSRF + credentials
3. Repeat for each password attempt
```

## Common Password Lists

### Top 10 (PortSwigger labs)
```
123456
password
admin
letmein
welcome
monkey
dragon
master
qwerty
abc123
```

### Extended (100+)
```
# See wordlists/common.txt and wordlists/raft-small.txt
```

## Rate Limit Bypass

### IP Rotation
```
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Client-IP: 1.2.3.4
```

### Correct/Incorrect Alternation
```
# Login with correct password → reset counter
# Login with wrong password → test candidate
# Repeat
```

### Session Rotation
```
# Get fresh session for each attempt
# Avoids session-based rate limiting
```

## Timing-Based Enumeration

### Detection
```
# Valid username: ~1.4s (bcrypt hash comparison)
# Invalid username: ~0.8s (no password check)
# Delta: ~0.6s = reliable signal
```

### Important Rules
1. NEVER fire parallel requests for timing attacks
2. One request per fresh session
3. 5+ second delay between attempts
4. Burp MCP doesn't expose timing - use Python time.time()
5. PortSwigger rate limit: ~3 attempts per 30min per IP
