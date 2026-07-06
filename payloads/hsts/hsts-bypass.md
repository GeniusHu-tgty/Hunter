# HSTS Bypass - Attack Techniques

## HSTS (HTTP Strict Transport Security)

### What HSTS Does
```
# Server sends header:
Strict-Transport-Security: max-age=31536000; includeSubDomains

# Browser remembers to use HTTPS for this domain
# Prevents SSL stripping attacks
```

### Bypass Techniques

#### 1. First Visit Attack
```
# If user has never visited the site before:
# No HSTS header cached → SSL stripping possible
# Solution: HSTS Preload List
```

#### 2. Subdomain Bypass
```
# If includeSubDomains not set:
# Attack subdomain without HSTS
# http://sub.target.com → SSL strip
```

#### 3. Header Injection
```
# If attacker can inject HTTP headers:
# Remove or modify Strict-Transport-Security header
```

#### 4. Mixed Content
```
# If page loads HTTP resources:
# Some content loaded over HTTP → mixed content
# Can inject into HTTP resources
```

## PortSwigger Lab Approach
1. Check if HSTS header is present
2. Check if includeSubDomains is set
3. Test subdomain access over HTTP
4. Check for mixed content issues
5. Test first-visit attack
