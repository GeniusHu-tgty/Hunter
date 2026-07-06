# Crypto Attacks - Payload Reference

## Hash Cracking
```
# MD5 - weak, collision-prone
# SHA1 - deprecated
# SHA256 - strong
# bcrypt - slow, good for passwords
# Argon2 - modern, recommended

# Tools: hashcat, john
hashcat -m 0 hash.txt wordlist.txt  # MD5
hashcat -m 100 hash.txt wordlist.txt  # SHA1
hashcat -m 1400 hash.txt wordlist.txt  # SHA256
```

## JWT Attacks

### alg:none
```
Header: {"alg":"none","typ":"JWT"}
Payload: {"sub":"admin","role":"admin"}
Signature: (empty)
Token: header.payload.
```

### Weak Secret
```
# Common secrets: secret, password, key, 123456, admin
# Use jwt_tool or hashcat for brute force
```

### Key Confusion (RS256 → HS256)
```
# If server uses RS256 but accepts HS256:
# Sign with public key as HMAC secret
```

## Padding Oracle
```
# If CBC mode with padding validation:
# 1. Send modified ciphertext
# 2. Check for padding error vs other error
# 3. Use padding oracle to decrypt
```

## ECB Mode
```
# ECB encrypts identical blocks identically
# Can detect patterns in ciphertext
# Use CBC or GCM instead
```
