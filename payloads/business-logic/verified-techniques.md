# Business Logic & Race Condition - Verified Techniques

## Business Logic: Negative Quantity (Verified)

### Attack
```
POST /cart
productId=12&quantity=-235
```

### How It Works
1. Add expensive item (e.g., leather jacket $1337)
2. Add cheap item with negative quantity (-235)
3. Total becomes negative or very small
4. Checkout with store credit

### Root Cause
Server doesn't validate that quantity > 0

### Fix
```python
if quantity <= 0:
    return error("Invalid quantity")
```

## NoSQL Injection: String Concatenation (Verified)

### Attack
```
GET /filter?category=Gifts'||1||'
```

### How It Works
1. Server builds MongoDB query via string concatenation
2. Single quote breaks out of string context
3. `||1||` injects boolean OR that always evaluates true
4. All products returned (including unreleased)

### Root Cause
```javascript
// Vulnerable
db.products.find({category: "'" + userInput + "'"})

// Fixed
db.products.find({category: userInput})  // parameterized
```

## Race Condition: Coupon Overuse (Verified)

### Attack
1. Add item to cart
2. Get CSRF token
3. Send 20 concurrent POST /cart/coupon requests
4. Each applies 20% discount
5. ~16 slip through before flag is set
6. Total: 20% × 16 = 320% discount → item costs $47

### How It Works
- TOCTOU window: check "is coupon used?" → "mark as used"
- Parallel requests all pass the check before any marks the flag
- Classic time-of-check-time-of-use vulnerability

### Fix
```sql
-- Atomic operation
UPDATE cart SET discount = discount + 20 
WHERE coupon = 'PROMO20' AND NOT used
-- Single SQL statement, no race window
```

## Key Lessons

1. **Business logic**: Always validate inputs server-side (positive numbers, valid ranges)
2. **NoSQL**: Use parameterized queries, never string concatenation
3. **Race conditions**: Use atomic database operations, not check-then-set patterns
