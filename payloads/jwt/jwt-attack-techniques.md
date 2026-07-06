# OAuth & Authentication Token Attacks

## OAuth Vulnerabilities

### Missing State Parameter
```
# If OAuth flow doesn't validate state parameter:
# 1. Attacker initiates OAuth flow
# 2. Gets authorization code
# 3. Victim clicks link with attacker's code
# 4. Code gets linked to victim's account
# 5. Attacker accesses victim's account
```

### Token Leakage via Referrer
```
# If OAuth tokens in URL:
# 1. Attacker posts image on forum: <img src="https://target.com/callback?token=xxx">
# 2. When victim views post, token sent in Referer header
# 3. Attacker captures token from server logs
```

### Implicit Flow Token Theft
```
# Implicit flow returns token in URL fragment (#)
# If JavaScript on page reads fragment and sends to server:
# Attacker can inject JS to steal token
```

## JWT Attack Reference

### alg:none
```
# Change header: {"alg": "none", "typ": "JWT"}
# Remove signature
# Modify payload (role: admin)
# Token: header.payload. (empty signature)
```

### Key Confusion (RS256 → HS256)
```
# If server uses RS256 (asymmetric) but accepts HS256 (symmetric):
# 1. Get server's public key
# 2. Sign token with public key as HMAC secret
# 3. Server verifies with public key = valid
```

### Kid Injection
```
# If kid parameter is user-controllable:
# {"kid": "/dev/null", "alg": "HS256"}
# Sign with empty key (since /dev/null is empty)
```

### JKU/X5U Injection
```
# If jku/x5u parameter points to attacker's server:
# Host malicious JWKS on attacker server
# Point jku to attacker's URL
```
