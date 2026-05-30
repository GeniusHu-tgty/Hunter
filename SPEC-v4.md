# Hunter v4 — AI-Driven Pentest Agent 设计规格

> 日期: 2026-05-30
> 状态: 待实现
> 作者: Claude + 用户协作设计

---

## 1. 核心理念

### 问题诊断

Hunter v3 本质上是一个 Python 脚本，Claude 只当 CLI wrapper：

```
v3: Claude → 调 hunt.py → 等脚本跑完 → 读文本报告 → 给结论
                              ↑
                      Claude 在这期间什么都没做
```

13,000 行 Python，但 Claude 的推理能力完全浪费。脚本跑完才能看结果，不能中途调整策略。

### 设计目标

**v4: Claude 是攻击者大脑，MCP 工具是手脚。**

```
v4: Claude 思考 → 调工具 → 分析结果 → 链式推理 → 动态调整
                    ↑
              每一步 Claude 都在思考
```

### 核心原则

1. **Claude 做决策，工具做执行** — 工具不判断"是否漏洞"，只发送 payload 返回响应
2. **工具返回完整数据** — 1M 上下文允许保留完整响应，Claude 分析更准确
3. **知识图谱自动积累** — 每次工具调用自动更新，Claude 不需要手动记录
4. **12 个原子工具** — 每个工具语义清晰、职责单一、可组合

---

## 2. 架构

```
┌──────────────────────────────────────────┐
│          Claude 大脑 (1M 上下文)          │
│                                          │
│  读完整源码 · 分析完整响应 · 理解业务逻辑   │
│  写自定义 exploit · 跨大量信息推理          │
│  动态调整策略 · 链式攻击                   │
└──────────────┬───────────────────────────┘
               │ tool_use (JSON in/out)
               ▼
┌──────────────────────────────────────────┐
│         Hunter MCP Server                │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │         12 个核心工具               │  │
│  │                                    │  │
│  │  探测: probe · port_scan · dns     │  │
│  │        dir_enum · subdomain        │  │
│  │  分析: tech · js_analyze · src_read│  │
│  │  验证: inject                      │  │
│  │  执行: shell · exec                │  │
│  │  管理: session                     │  │
│  └────────────────────────────────────┘  │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │  知识图谱 (JSON 文件持久化)         │  │
│  │  findings[] · attempts[] · shells[]│  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

---

## 3. 工具定义

### 3.1 探测层（5 个）

#### `probe` — HTTP 万能探测器

所有 HTTP 操作的入口。支持自定义方法、headers、body、重定向控制。

**输入：**
```json
{
  "url": "http://target/path",
  "method": "GET",
  "headers": {"Cookie": "session=abc"},
  "body": "username=admin&password=test",
  "follow_redirects": true,
  "timeout": 10
}
```

**输出：**
```json
{
  "url": "http://target/path",
  "status": 200,
  "headers": {"Server": "nginx", "X-Powered-By": "PHP/7.2"},
  "body": "完整响应体（1M 上下文下不截断）",
  "body_length": 4523,
  "cookies": {"session": "xyz789"},
  "timing_ms": 234,
  "redirect_chain": [],
  "interesting": [
    "form_login with hidden csrf_token",
    "comment: <!-- debug mode -->",
    "header leak: X-Powered-By reveals PHP/7.2"
  ],
  "tags": ["form", "csrf", "debug_comment", "header_leak"]
}
```

**关键设计：**
- `interesting` 字段：工具自动标记值得关注的内容（表单、注释、泄露信息）
- `tags` 字段：结构化标签，Claude 可快速过滤
- `body` 完整返回，不截断（1M 上下文支持）
- 内置 TLS 指纹伪装、UA 轮换、WAF 检测（复用 v3 StealthSession）

---

#### `port_scan` — 端口扫描

支持 top100/top1000/custom 端口列表。

**输入：**
```json
{
  "host": "10.10.90.2",
  "ports": "top100",
  "timeout": 3
}
```

**输出：**
```json
{
  "host": "10.10.90.2",
  "open": [
    {"port": 22, "service": "ssh", "version": "OpenSSH 7.4"},
    {"port": 80, "service": "http", "version": "nginx 1.16"},
    {"port": 161, "service": "snmp", "version": ""},
    {"port": 3306, "service": "mysql", "version": "5.1.73"}
  ],
  "closed_count": 96,
  "filtered_count": 0,
  "scan_time_ms": 12340
}
```

**关键设计：**
- 只返回开放端口，不浪费 context 在 closed/filtered 上
- 尝试服务版本检测（nmap -sV 或 banner grabbing）
- `ports` 支持：`"top100"`, `"top1000"`, `"22,80,443,3306"`, `"1-65535"`

---

#### `dns` — DNS 查询

**输入：**
```json
{
  "domain": "gnnu.edu.cn",
  "type": "ANY"
}
```

**输出：**
```json
{
  "domain": "gnnu.edu.cn",
  "records": [
    {"type": "A", "value": "10.10.90.2", "ttl": 3600},
    {"type": "MX", "value": "mail.gnnu.edu.cn", "priority": 10},
    {"type": "TXT", "value": "v=spf1 include:...", "ttl": 3600},
    {"type": "NS", "value": "ns1.gnnu.edu.cn", "ttl": 86400}
  ]
}
```

**关键设计：**
- 支持 A/AAAA/MX/TXT/NS/CNAME/SOA/SRV/ANY
- 返回所有记录类型，Claude 分析哪些有价值

---

#### `dir_enum` — 目录枚举

**输入：**
```json
{
  "url": "http://target",
  "wordlist": "default",
  "extensions": ["php", "bak", "sql", "zip"],
  "max_results": 50,
  "recursion_depth": 2
}
```

**输出：**
```json
{
  "url": "http://target",
  "found": [
    {"path": "/admin", "status": 302, "size": 0, "redirect": "/login", "interesting": true},
    {"path": "/api/online_list", "status": 200, "size": 15234, "interesting": true},
    {"path": "/backup.sql", "status": 200, "size": 234567, "interesting": true},
    {"path": "/robots.txt", "status": 200, "size": 234, "interesting": false}
  ],
  "total_checked": 159,
  "interesting_count": 3
}
```

**关键设计：**
- `interesting` 标记：非标准大小、非 404、敏感路径
- 支持递归扫描（发现 /admin/ 后继续扫描 /admin/ 下的路径）
- 内置 159 个常用路径 + 敏感文件（.git/config, .env, backup.sql 等）

---

#### `subdomain` — 子域名发现

**输入：**
```json
{
  "domain": "gnnu.edu.cn",
  "methods": ["crtsh", "dns_brute"]
}
```

**输出：**
```json
{
  "domain": "gnnu.edu.cn",
  "subdomains": [
    {"subdomain": "cas.gnnu.edu.cn", "source": "crtsh", "ip": "10.10.90.5"},
    {"subdomain": "mail.gnnu.edu.cn", "source": "dns_brute", "ip": "10.10.90.10"},
    {"subdomain": "vpn.gnnu.edu.cn", "source": "crtsh", "ip": "10.10.90.3"}
  ],
  "total_found": 15
}
```

**关键设计：**
- `methods` 支持：`crtsh`（证书透明度）、`dns_brute`（DNS 暴力）、`subfinder`（如果安装）
- 去重 + IP 解析
- 后续可以用 `port_scan` 扫描发现的子域名

---

### 3.2 分析层（3 个）

#### `tech` — 技术栈识别

**输入：**
```json
{
  "url": "http://target"
}
```

**输出：**
```json
{
  "url": "http://target",
  "technologies": {
    "server": "nginx 1.16",
    "language": "PHP 7.2",
    "framework": "ThinkPHP 5.1.37",
    "cms": null,
    "waf": null,
    "os_hint": "Linux"
  },
  "evidence": {
    "header:X-Powered-By": "PHP/7.2",
    "header:Server": "nginx",
    "cookie:thinkphp_show_page_trace": "ThinkPHP",
    "body:generator": "ThinkPHP 5.1"
  },
  "known_vulns": [
    "ThinkPHP 5.1.x RCE (CVE-2018-20062) — 需要确认补丁状态",
    "ThinkPHP 5.1.x SQLi (CVE-2019-9082)"
  ]
}
```

**关键设计：**
- `evidence` 字段：Claude 可以验证指纹依据是否可靠
- `known_vulns` 字段：工具提供已知漏洞提示，Claude 决定是否测试
- 复用 v3 的 14 种框架指纹 + cookie 语言检测

---

#### `js_analyze` — JavaScript 分析

**输入：**
```json
{
  "url": "http://target/static/js/app.js"
}
```

**输出：**
```json
{
  "url": "http://target/static/js/app.js",
  "size": 234567,
  "endpoints": ["/api/users", "/api/admin/config", "/api/auth/login"],
  "secrets": [
    {"type": "aws_key", "value": "AKIA...", "line": 1234},
    {"type": "api_key", "value": "sk-abc...", "line": 5678}
  ],
  "internal_urls": ["http://192.168.1.100:8080", "http://admin.internal.corp"],
  "interesting_patterns": [
    {"pattern": "hardcoded_password", "context": "const DB_PASS = 'admin123'", "line": 890},
    {"pattern": "debug_flag", "context": "DEBUG = true", "line": 12}
  ],
  "source_preview": "前 5000 字符的 JS 源码..."
}
```

**关键设计：**
- `source_preview`：1M 上下文下可以返回更长甚至完整的 JS 源码
- `secrets` 自动检测 AWS Key、API Key、JWT、内部 URL
- `interesting_patterns`：硬编码密码、调试标志、注释中的信息

---

#### `src_read` — 读目标文件

**杀手工具。** 如果目标有 LFI/目录遍历/源码泄露，Claude 直接读源码理解逻辑。

**输入：**
```json
{
  "url": "http://target/index.php",
  "param": "page",
  "technique": "lfi",
  "paths": ["/etc/passwd", "/var/www/html/config.php", "/proc/self/environ"]
}
```

**输出：**
```json
{
  "technique": "lfi",
  "results": [
    {
      "path": "/etc/passwd",
      "success": true,
      "content": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:...",
      "size": 1234
    },
    {
      "path": "/var/www/html/config.php",
      "success": true,
      "content": "<?php\n$db_host = 'localhost';\n$db_user = 'root';\n$db_pass = 'P@ssw0rd123';\n...",
      "size": 567
    },
    {
      "path": "/proc/self/environ",
      "success": false,
      "error": "403 Forbidden"
    }
  ]
}
```

**关键设计：**
- 支持多种读取技术：LFI、目录遍历、路径遍历、源码泄露（.git/source）
- `content` 返回完整文件内容（1M 上下文支持）
- Claude 读源码后可以理解业务逻辑、找到数据库凭据、发现隐藏功能

---

### 3.3 验证层（1 个）

#### `inject` — 注入测试

Claude 构造 payload，工具负责发送和响应对比。

**输入：**
```json
{
  "url": "http://target/login",
  "method": "POST",
  "param": "username",
  "payloads": [
    "' OR 1=1--",
    "' AND 1=1--",
    "' AND 1=2--",
    "admin'--"
  ],
  "base_payload": "admin",
  "compare_field": "body_length"
}
```

**输出：**
```json
{
  "url": "http://target/login",
  "param": "username",
  "base_response": {"status": 200, "body_length": 1234, "body_preview": "Login failed"},
  "results": [
    {
      "payload": "' OR 1=1--",
      "status": 200,
      "body_length": 4567,
      "body_preview": "Welcome, admin!",
      "redirect": "/dashboard",
      "diff_from_base": "+3333 bytes",
      "interesting": true
    },
    {
      "payload": "' AND 1=1--",
      "status": 200,
      "body_length": 1234,
      "body_preview": "Login failed",
      "redirect": null,
      "diff_from_base": "0 bytes",
      "interesting": false
    },
    {
      "payload": "' AND 1=2--",
      "status": 200,
      "body_length": 890,
      "body_preview": "Login failed",
      "redirect": null,
      "diff_from_base": "-344 bytes",
      "interesting": true
    }
  ],
  "analysis": {
    "likely_vuln": true,
    "type": "boolean-based blind SQLi",
    "confidence": 0.85,
    "evidence": "OR payload returns different response, AND 1=2 returns shorter response"
  }
}
```

**关键设计：**
- `base_response`：正常请求的响应，作为对比基准
- `diff_from_base`：每个 payload 与基准的差异
- `analysis`：工具的初步判断，Claude 可以接受或推翻
- `compare_field` 支持：`body_length`、`body_hash`、`status_code`、`redirect`
- Claude 可以传任意 payload，不局限于预定义列表

---

### 3.4 执行层（2 个）

#### `shell` — Shell 管理

**输入：**
```json
{
  "action": "start",
  "type": "reverse",
  "lhost": "10.10.90.100",
  "lport": 4444,
  "shell_type": "bash"
}
```

**输出：**
```json
{
  "session_id": "shell_001",
  "status": "listening",
  "type": "reverse",
  "lhost": "10.10.90.100",
  "lport": 4444,
  "shell_type": "bash"
}
```

**其他 action：**
- `{"action": "list"}` → 返回所有 shell session
- `{"action": "exec", "session_id": "shell_001", "command": "id"}` → 执行命令
- `{"action": "close", "session_id": "shell_001"}` → 关闭 session

**关键设计：**
- 支持 20+ 种 reverse shell（bash/python/php/perl/ruby/java/powershell 等）
- 支持 webshell 部署和交互
- 命令执行返回 stdout + stderr + exit_code
- 复用 v3 ShellManager 的 payload 库

---

#### `exec` — 执行 Python 代码

安全阀。当预定义工具不够用时，Claude 直接写代码执行。

**输入：**
```json
{
  "code": "import requests\nr = requests.get('http://target/api/users')\nprint(r.status_code, r.json())",
  "timeout": 30
}
```

**输出：**
```json
{
  "stdout": "200 [{'id': 1, 'name': 'admin'}, {'id': 2, 'name': 'test'}]",
  "stderr": "",
  "exit_code": 0,
  "execution_time_ms": 1234
}
```

**关键设计：**
- 沙箱执行：超时 30s（可调）、不能监听端口、限制文件系统访问
- 预装常见库：requests, socket, subprocess, json, re, base64 等
- Claude 可以写自定义 exploit、调外部工具（nmap/sqlmap/nuclei/hydra）
- 返回 stdout + stderr，Claude 分析输出

**典型用例：**
- 调 sqlmap 跑 SQLi
- 调 nuclei 跑 CVE 模板
- 写自定义 payload 发送
- 解析复杂响应格式
- SNMP/Redis 等协议操作

---

### 3.5 管理层（1 个）

#### `session` — 会话/知识图谱

**输入：**
```json
{
  "action": "summary"
}
```

**输出：**
```json
{
  "target": "10.10.90.2",
  "session_id": "sess_20260530_001",
  "started_at": "2026-05-30T10:00:00Z",
  "duration_minutes": 45,
  "findings_count": 12,
  "findings_summary": {
    "critical": 1,
    "high": 2,
    "medium": 4,
    "low": 5
  },
  "top_findings": [
    {"type": "info_leak", "url": "/api/online_list", "severity": "critical"},
    {"type": "sqli", "param": "username", "severity": "high"}
  ],
  "shells_active": 1,
  "attack_paths": [
    "info_leak → user list → credential stuffing",
    "sqli → db dump → admin access → RCE"
  ]
}
```

**其他 action：**
- `{"action": "findings"}` → 返回所有发现
- `{"action": "findings", "filter": {"type": "sqli"}}` → 按类型过滤
- `{"action": "attempts"}` → 返回所有尝试（成功/失败）
- `{"action": "save"}` → 持久化到磁盘
- `{"action": "load", "session_id": "sess_xxx"}` → 恢复之前的 session
- `{"action": "export"}` → 导出为 Markdown 报告

---

## 4. 知识图谱数据结构

```python
session = {
    "target": "10.10.90.2",
    "session_id": "sess_20260530_001",
    "started_at": "2026-05-30T10:00:00Z",

    # 所有发现，按时间排序
    "findings": [
        {
            "id": "f001",
            "timestamp": "2026-05-30T10:05:00Z",
            "type": "info_leak",
            "severity": "critical",
            "title": "API 无认证信息泄露",
            "detail": "/api/online_list 返回所有在线用户数据",
            "evidence": {"url": "http://target/api/online_list", "status": 200},
            "tool": "dir_enum"
        }
    ],

    # 所有尝试，记录成功/失败
    "attempts": [
        {
            "timestamp": "2026-05-30T10:10:00Z",
            "action": "sqli_union",
            "target": "/login",
            "payload": "' UNION SELECT 1,2,3--",
            "result": "blocked by WAF",
            "waf_rule": "UNION keyword detection",
            "success": false
        },
        {
            "timestamp": "2026-05-30T10:12:00Z",
            "action": "sqli_comment",
            "target": "/login",
            "payload": "UN/**/ION SEL/**/ECT 1,2,3--",
            "result": "success, columns reflected",
            "success": true
        }
    ],

    # Shell sessions
    "shells": [
        {
            "session_id": "shell_001",
            "type": "reverse",
            "created_at": "2026-05-30T10:30:00Z",
            "status": "active",
            "info": "bash on CentOS 6.8"
        }
    ],

    # Claude 生成的攻击路径
    "attack_paths": [
        "SNMP private → sysDescr → OS version → kernel exploit",
        "info_leak → user list → credential stuffing → admin"
    ]
}
```

**持久化：** JSON 文件存储在 `~/.claude/skills/hunter/sessions/` 目录。

---

## 5. MCP Server 实现

### 技术栈

- **框架：** FastMCP（Python MCP SDK）
- **依赖：** requests, socket, subprocess, json
- **可选依赖：** nmap, ffuf, subfinder, nuclei, hydra, sqlmap（自动检测，缺失时降级）

### 文件结构

```
hunter/
├── SPEC-v4.md              # 本文档
├── SKILL.md                # Claude skill 定义（更新）
├── mcp_server.py           # MCP server 入口
├── tools/
│   ├── __init__.py
│   ├── probe.py            # HTTP 探测（复用 v3 stealth.py）
│   ├── port_scan.py        # 端口扫描
│   ├── dns_tool.py         # DNS 查询
│   ├── dir_enum.py         # 目录枚举
│   ├── subdomain.py        # 子域名发现
│   ├── tech.py             # 技术栈识别
│   ├── js_analyze.py       # JS 分析
│   ├── src_read.py         # 读目标文件
│   ├── inject.py           # 注入测试
│   ├── shell_tool.py       # Shell 管理（复用 v3 shell_manager.py）
│   ├── exec_tool.py        # Python 代码执行
│   └── session_tool.py     # 会话/知识图谱
├── core/
│   ├── __init__.py
│   ├── knowledge.py        # 知识图谱数据结构 + 持久化
│   ├── stealth.py          # TLS 指纹 + WAF 绕过（复用 v3）
│   └── config.py           # 配置（复用 v3）
├── sessions/               # 持久化的 session 文件
└── reports/                # 生成的报告（复用 v3）
```

### 复用 v3 模块

| v4 工具 | 复用 v3 模块 | 复用内容 |
|---------|-------------|---------|
| `probe` | `core/stealth.py` | StealthSession（TLS 指纹、UA 轮换、WAF 绕过） |
| `tech` | `core/config.py` | 框架指纹库 |
| `inject` | `exploits/web/sqli_exploit.py` | SQLi 检测逻辑 |
| `shell` | `shells/shell_manager.py` | Shell payload 库、listener |
| `session` | `core/report_gen.py` | 报告生成 |
| `exec` | `exploits/web/*.py` | 各种 exploit 模块（通过 exec 调用） |

---

## 6. Claude 使用流程

### 典型渗透会话

```
1. Claude: "先看 DNS 和端口"
   → dns("target.com") + port_scan("target.com", "top100") [并行]

2. Claude: "80 端口是 HTTP，看看什么技术栈"
   → tech("http://target.com")

3. Claude: "ThinkPHP 5.1，试试目录枚举"
   → dir_enum("http://target.com")

4. Claude: "发现 /api/online_list，无认证！"
   → probe("http://target.com/api/online_list")

5. Claude: "分析 JS 文件找更多端点"
   → js_analyze("http://target.com/static/js/app.js")

6. Claude: "试 SQLi 注入登录表单"
   → inject("http://target.com/login", "username", ["' OR 1=1--", "' AND 1=1--", "' AND 1=2--"])

7. Claude: "确认 SQLi，写自定义 UNION 查询提取数据"
   → exec("import requests; ...自定义 SQLi exploit...")

8. Claude: "拿到数据库凭据，试 SSH 登录"
   → exec("import paramiko; ...SSH 登录...")

9. Claude: "拿到 shell，收集系统信息"
   → shell("exec", "shell_001", "uname -a && id && cat /etc/passwd")

10. Claude: "生成渗透报告"
    → session("export")
```

### SKILL.md 方法论指导

```
渗透顺序：
1. 被动侦察（DNS、子域名）— 不触碰目标
2. 主动侦察（端口、目录、技术栈）— 最小化请求
3. 漏洞发现（注入、配置错误）— 有针对性测试
4. 漏洞利用（提取数据、RCE）— 确认漏洞可利用
5. 后渗透（提权、横移、持久化）— 扩大战果
6. 报告（总结发现、攻击路径、修复建议）

每一步：
- 先观察，再假设，再行动
- 失败了分析原因，换策略
- 记录所有尝试（成功和失败）
- 低危发现可能拼成高危攻击链
```

---

## 7. 实现计划

### Phase 1 — 骨架 + 核心侦察（1-2 天）

**目标：** Claude 能侦察目标并自动积累知识

**任务：**
- [ ] MCP server 框架（FastMCP）
- [ ] 知识图谱数据结构 + 持久化
- [ ] `probe` 工具（复用 StealthSession）
- [ ] `port_scan` 工具
- [ ] `dns` 工具
- [ ] `dir_enum` 工具
- [ ] `tech` 工具
- [ ] `session` 工具（基础版：summary + findings）
- [ ] 更新 SKILL.md

**验证：** 在本地目标（Dr.COM 网关）上跑通完整侦察流程

### Phase 2 — 分析 + 利用（2-3 天）

**目标：** Claude 能发现漏洞并利用

**任务：**
- [ ] `js_analyze` 工具
- [ ] `src_read` 工具
- [ ] `inject` 工具
- [ ] `exec` 工具（沙箱 + 超时）
- [ ] `shell` 工具（复用 ShellManager）
- [ ] 知识图谱：attempts 追踪
- [ ] 集成 v3 exploit 模块（通过 exec 调用）

**验证：** 在测试环境上跑通 "发现漏洞 → 确认 → 利用 → 拿 shell"

### Phase 3 — 完善 + 扩展（1-2 天）

**目标：** 生产可用

**任务：**
- [ ] `subdomain` 工具
- [ ] Shell 完善（webshell 部署、多 session）
- [ ] 报告生成（Markdown + HackerOne 格式）
- [ ] 多 session 管理
- [ ] 错误处理完善
- [ ] 文档

**验证：** 在真实 bug bounty 目标上测试

---

## 8. 与 v3 的对比

| 维度 | v3 | v4 |
|------|-----|-----|
| 决策者 | Python 脚本硬编码 | Claude 实时推理 |
| 输出格式 | 文本报告 | 结构化 JSON |
| 漏洞确认 | 模式匹配（正则） | Claude 理解语义 |
| 攻击链 | 硬编码 8 条 | Claude 动态推理 |
| Payload | 固定列表 50-100 个 | Claude 根据目标动态构造 |
| 被封后 | 停止 | Claude 换策略 |
| 源码分析 | 无 | src_read + Claude 理解 |
| 误报 | 正则过滤 | Claude 语义分析 |
| 信息管理 | 无 | 知识图谱 |
| 上下文 | 无状态 | 1M 上下文 + 知识图谱 |

---

## 9. 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| MCP server 崩溃 | 丢失内存中的状态 | 知识图谱定期持久化到磁盘 |
| 工具超时 | Claude 等待 | 每个工具有 timeout 参数 |
| 1M 上下文信息过载 | Claude 迷失重点 | 工具标记 interesting + tags |
| 模型推理错误 | 错误判断 | knowledge.attempts 记录失败，避免重复 |
| 第三方 API 限速 | 降低渗透速度 | 工具内置自适应延迟 |
| 工具可靠性 | 网络错误 | 结构化错误返回，Claude 可以重试 |

---

## 10. 未来扩展（不在 MVP 范围）

- [ ] OOB 回调（Interactsh 集成）— 盲注 XXE/SSRF
- [ ] JS 渲染（Playwright 集成）— SPA 应用
- [ ] Nuclei 深度集成 — 10000+ CVE 模板
- [ ] Burp Suite 集成 — 导入/导出
- [ ] 多目标管理 — 同时渗透多个目标
- [ ] 团队协作 — 共享知识图谱
- [ ] AI 辅助报告 — 自动生成 HackerOne 提交格式
