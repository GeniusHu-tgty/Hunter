# HUNTER v3 渗透报告

**目标:** model.qiaojiai.com
**IP:** 121.41.95.160
**日期:** 2026-05-30 18:41-19:07
**模式:** aggressive
**状态:** IP 被防火墙封禁（扫描触发）

---

## 侦察结果

### 基础设施
| 项目 | 值 |
|------|-----|
| IP | 121.41.95.160 |
| Server | nginx |
| 前端 | React SPA |
| WAF | 未检测到 |

### 开放端口（封禁前）
| 端口 | 服务 | 风险 |
|------|------|------|
| 22/tcp | SSH | 暴力破解 |
| 80/tcp | HTTP | 重定向到 HTTPS |
| 443/tcp | HTTPS | 主服务 |
| 3306/tcp | MySQL | 数据库暴露（高危） |
| 5432/tcp | PostgreSQL | 数据库暴露（高危） |

### 子域名
- 1 个子域名发现

---

## 漏洞发现

### 🔴 CRITICAL
- 无确认 CRITICAL（信息泄露路径均为 SPA fallback）

### 🟠 HIGH
1. **CORS 通配符 + Credentials**
   - `Access-Control-Allow-Origin: *` 配合 `Access-Control-Allow-Credentials: true`
   - 攻击者可跨域读取用户数据
   - 修复：限制 Allow-Origin 为特定域名

2. **MySQL 端口暴露 (3306)**
   - 公网可访问 MySQL
   - 暴力破解/未授权访问风险
   - 修复：防火墙限制访问来源

3. **PostgreSQL 端口暴露 (5432)**
   - 公网可访问 PostgreSQL
   - 暴力破解/未授权访问风险
   - 修复：防火墙限制访问来源

### 🟡 MEDIUM
1. **缺少 HSTS 头**
   - 未设置 `Strict-Transport-Security`
   - 降级攻击风险

2. **缺少 CSP 头**
   - 未设置 `Content-Security-Policy`
   - XSS 攻击面增大

3. **缺少 X-Frame-Options 头**
   - 点击劫持风险

### 🔵 LOW
1. **缺少 X-Content-Type-Options 头**
2. **缺少 Referrer-Policy 头**
3. **缺少 Permissions-Policy 头**

---

## JS 分析

### API 端点发现（5 个）
- `api/pricing` — 定价接口
- `api/user/models` — 用户模型列表
- `api/user/self/groups` — 用户分组
- `api/oauth/state` — OAuth 状态
- `api/user/logout` — 登出

### JS Secrets
- 255 个潜在 secrets（需人工验证具体类型）

---

## 目录扫描

扫描了 29 个常见路径，所有路径返回 1612 bytes（React SPA fallback）：
- `.git/HEAD`, `.env`, `.env.local`, `.env.production`
- `.svn/entries`, `.DS_Store`
- `wp-config.php.bak`, `config.php.bak`
- `backup.sql`, `dump.sql`, `db.sql`
- `swagger.json`, `swagger-ui.html`, `openapi.json`
- `graphql`, `graphiql`
- `phpinfo.php`, `info.php`, `test.php`
- `robots.txt` (67 bytes, 空内容)
- `server-status`, `elmah.axd`, `trace.axd`

**结论：** 均为 SPA fallback 路由，非真正信息泄露。

---

## 防火墙行为

- 初始扫描：端口开放，HTTP 可访问
- 触发速率限制后：HTTP 429 响应
- 持续扫描后：IP 被完全封禁（所有端口 filtered）
- 防火墙有动态规则：先限速，后封 IP

---

## 攻击链评估

### 潜在攻击链
1. **CORS + API → 数据窃取**
   - 利用 CORS 通配符 + credentials
   - 跨域调用 `api/user/models` 等接口
   - 窃取用户模型数据

2. **MySQL/PostgreSQL 暴力破解**
   - 端口暴露 + 无 WAF
   - hydra 爆破 root/postgres 密码
   - 数据库完全控制

3. **SSH 暴力破解**
   - 端口暴露
   - hydra 爆破
   - 服务器控制

### 阻碍
- IP 已被封禁，无法继续测试
- 需要换 IP 或等待解封

---

## 修复建议

### 立即修复（P0）
1. 防火墙禁止公网访问 3306/5432
2. 修复 CORS 配置（限制 Allow-Origin）
3. 防火墙禁止公网访问 22（改用 VPN/堡垒机）

### 短期修复（P1）
1. 添加 HSTS 头
2. 添加 CSP 头
3. 添加 X-Frame-Options 头

### 长期优化（P2）
1. WAF 部署
2. API 速率限制优化
3. JS secrets 清理

---

## 工具使用
- HUNTER v3 aggressive 模式
- nmap 端口扫描
- curl 手动验证

## 后续步骤
1. 换 IP 后继续 API 端点测试
2. 深入分析 255 个 JS secrets
3. MySQL/PostgreSQL 爆破（需解封后）
