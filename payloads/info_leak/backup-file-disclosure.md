# Info Disclosure via Backup Files - Verified

## Attack
```
GET /backup/ProductTemplate.java.bak
```

## What Was Found
- Full Java source code leaked
- Hardcoded PostgreSQL password in ConnectionBuilder
- SQL injection vulnerability: `String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id)`

## Common Backup Extensions
```
.bak, .old, .orig, ~, .copy, .swp, .save
.java.bak, .php.bak, .py.bak, .config.bak
```

## Common Backup Paths
```
/backup/
/src/
/WEB-INF/
/.git/
/.svn/
```

## Lesson
Backup files in web-accessible directories leak source code and credentials. Always probe for backup extensions on discovered application paths.
