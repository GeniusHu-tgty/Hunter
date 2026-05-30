---
name: hunter
description: |
  AI-driven pentest agent v4. Claude 是大脑，MCP 工具是手脚。
  不是扫描器——是让 Claude 思考的渗透框架。
  12 个原子工具 + 知识图谱 + 1M 上下文支持。
  Use when: "渗透", "扫描", "找漏洞", "爆破", "pentest", "scan", "hack", "bug bounty", "漏洞利用", "提权"
triggers:
  - 渗透
  - 扫描
  - 找漏洞
  - 爆破
  - pentest
  - scan for vulnerabilities
  - hack
  - bug bounty
  - vulnerability scan
  - security test
  - 漏洞利用
  - 提权
  - shell
  - 反弹shell
---

# HUNTER v4 — AI-Driven Pentest Agent

Claude 是攻击者大脑，MCP 工具是手脚。每一步都由 Claude 思考决策。

## 核心理念

- **Claude 做决策，工具做执行** — 工具不判断"是否漏洞"，只发送 payload 返回响应
- **工具返回完整数据** — 1M 上下文允许保留完整响应，Claude 分析更准确
- **知识图谱自动积累** — 每次工具调用自动更新，Claude 不需要手动记录

## 12 个 MCP 工具

### 探测层
| 工具 | 用途 |
|------|------|
| `probe` | HTTP 万能探测器（所有 HTTP 操作入口） |
| `port_scan` | 端口扫描（支持 top100/top1000/custom） |
| `dns` | DNS 查询（A/AAAA/MX/TXT/NS/CNAME/SOA） |
| `dir_enum` | 目录枚举（只返回 interesting 结果） |
| `subdomain` | 子域名发现（crt.sh + DNS 暴力） |

### 分析层
| 工具 | 用途 |
|------|------|
| `tech` | 技术栈识别（框架/语言/服务器/WAF/CMS） |
| `js_analyze` | JavaScript 静态分析（端点/密钥/内部 URL） |
| `src_read` | 读目标文件（LFI/目录遍历/源码泄露） |

### 验证层
| 工具 | 用途 |
|------|------|
| `inject` | 注入测试（Claude 传 payload，工具发请求+对比） |

### 执行层
| 工具 | 用途 |
|------|------|
| `shell` | Shell 管理（reverse/bind/webshell） |
| `exec` | 执行 Python 代码（自定义 exploit 安全阀） |

### 管理层
| 工具 | 用途 |
|------|------|
| `session` | 会话/知识图谱（查询/持久化/报告导出） |

## 渗透方法论

### 顺序
1. **被动侦察** — DNS、子域名（不触碰目标）
2. **主动侦察** — 端口、目录、技术栈（最小化请求）
3. **漏洞发现** — 注入测试、配置错误（有针对性测试）
4. **漏洞利用** — 提取数据、RCE（确认漏洞可利用）
5. **后渗透** — 提权、横移、持久化（扩大战果）
6. **报告** — 总结发现、攻击路径、修复建议

### 每一步
- 先观察，再假设，再行动
- 失败了分析原因，换策略
- 记录所有尝试（成功和失败）— knowledge graph 自动记录
- 低危发现可能拼成高危攻击链

### Claude 独特优势
- **读源码找逻辑漏洞** — src_read 读配置文件、源码
- **理解错误语义** — 从错误信息推断后端结构
- **写自定义 exploit** — exec 执行自定义 Python 代码
- **跨信息推理** — 结合 JS 端点 + 错误信息 + 版本号
- **动态调整策略** — 被 WAF 挡了 → 分析 → 换绕过方式

## 启动方式

MCP server 自动在 Claude Code 中注册。直接说"渗透目标 X"即可开始。

## v3 能力保留

以下 v3 模块仍可通过 `exec` 工具调用：
- SQLi (sqlmap 集成 + UNION/布尔/时间盲注)
- SSTI (Jinja2/Mako/Twig/Freemarker RCE)
- XXE (文件读取/SSRF/Blind/SVG)
- 文件上传 → webshell
- 认证绕过 (50+ 默认凭据 + JWT)
- SSRF (云元数据 + gopher/dict 协议)
- 反序列化 (Java/Python/PHP/.NET)
- 多协议攻击 (SSH/FTP/Redis/MySQL/SMB/SNMP/Docker/K8s)
- 后渗透 (凭据提取/提权/横移/持久化)

## 文件结构

```
hunter/
├── mcp_server.py       # MCP server 入口
├── core/               # 核心模块
│   ├── knowledge.py    # 知识图谱
│   ├── stealth.py      # TLS 指纹 + WAF 绕过
│   └── config.py       # 配置
├── tools/              # 12 个 MCP 工具
├── sessions/           # 持久化的 session
└── reports/            # 生成的报告
```
