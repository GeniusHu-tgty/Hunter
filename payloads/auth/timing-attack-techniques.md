# Race Condition & Timing Attack - Verified Payloads

## Username Enumeration via Timing (Verified)

### Technique
- Valid username: server checks password before responding → longer response time
- Invalid username: server responds immediately → shorter response time
- Binary search on timing differences for efficiency

### Detection
```python
import time
import http.client

def measure_login_time(host, username, password):
    start = time.time()
    # POST /login with credentials
    # Measure time difference
    end = time.time()
    return end - start

# Valid username takes ~100ms longer due to password hash comparison
```

### PortSwigger Lab Approach
1. Get login page, extract CSRF token
2. Try common usernames: admin, administrator, carlos, wiener, root, test
3. Measure response time for each (use time.time())
4. Username with consistently longer response time = valid
5. Brute force password for that username

## Race Condition - Coupon Abuse (Verified)

### Technique
```
# Apply same coupon multiple times concurrently
# Each request checks "has coupon been used?" before marking it used
# If 20 requests arrive simultaneously, all pass the check
# Result: 20x discount applied
```

### PortSwigger Lab Approach
1. Login, add item to cart
2. Get CSRF token from cart page
3. Send 20 concurrent POST /cart/coupon requests
4. Each applies 30% discount
5. Total discount exceeds 100% → free item
