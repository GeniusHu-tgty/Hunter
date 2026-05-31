# Hunter

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-Protocol-FF6B35?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-00B8D4?style=for-the-badge)

**AI-Driven Penetration Testing Framework v4**

不是扫描器 — 是让 Claude 思考的渗透框架。

*12 原子工具 + 知识图谱 + 1M 上下文支持。*

</div>

---

## 设计哲学

传统渗透工具：人写规则 → 工具执行 → 人看结果。

Hunter：**Claude 是大脑，MCP 工具是手脚。**

```
你（下达目标）
    ↓
Claude（分析、决策、推理攻击链）
    ↓
12 个原子 MCP 工具（侦察、扫描、漏洞利用、后渗透）
    ↓
知识图谱（记录发现，构建攻击拓扑）
    ↓
自动生成报告 + CVSS 评级
```

Claude 不是在执行脚本 — 它在**思考**下一步该做什么。

## 12 原子工具

### 侦察阶段

| 工具 | 能力 |
|------|------|
| `probe` | HTTP 探测 + 自动 Body 分析 + 技术栈识别 |
| `dns_tool` | DNS 解析 + 子域枚举 + 记录类型全支持 |
| `subdomain` | 子域名爆破 + 字典攻击 + DNS 验证 |
| `tech` | Web 技术栈指纹识别（CMS/框架/服务器/语言） |
| `port_scan` | TCP 端口扫描 + 服务识别 + Banner 抓取 |

### 扫描阶段

| 工具 | 能力 |
|------|------|
| `dir_enum` | 目录/路径枚举 + 字典爆破 + 状态码分析 |
| `js_analyze` | JavaScript 静态分析 + API 端点提取 + Secret 扫描 |
| `src_read` | 源码读取 + 敏感信息提取 + 配置文件发现 |

### 漏洞利用阶段

| 工具 | 能力 |
|------|------|
| `inject` | SQL 注入检测 + WAF 绕过 + 数据提取 |
| `exec` | 命令执行 + Shell 交互 + 输出捕获 |
| `shell` | 反弹 Shell + 交互式终端 |

### 后渗透阶段

| 工具 | 能力 |
|------|------|
| `inject` | 横向移动 + 权限提升 + 持久化 |

## 架构

```
hunter/
├── core/                    # 核心引擎
│   ├── hunter.py            #   主控制器
│   ├── knowledge.py         #   知识图谱（发现存储 + 关系推理）
│   ├── config.py            #   配置管理
│   ├── severity.py          #   CVSS 严重性评级
│   ├── stealth.py           #   隐蔽模式（限速/代理/指纹伪装）
│   └── report_gen.py        #   报告生成
├── engines/                 # 扫描引擎
│   ├── recon.py             #   侦察引擎
│   ├── scan.py              #   扫描引擎
│   ├── discover.py          #   发现引擎
│   └── brute.py             #   爆破引擎
├── tools/                   # 12 个原子 MCP 工具
│   ├── probe.py             #   HTTP 探测
│   ├── dns_tool.py          #   DNS 工具
│   ├── subdomain.py         #   子域名枚举
│   ├── tech.py              #   技术栈识别
│   ├── port_scan.py         #   端口扫描
│   ├── dir_enum.py          #   目录枚举
│   ├── js_analyze.py        #   JS 分析
│   ├── src_read.py          #   源码读取
│   ├── inject.py            #   注入检测
│   ├── exec_tool.py         #   命令执行
│   └── shell_tool.py        #   Shell 交互
├── mcp_server.py            # MCP 服务器入口
├── hunt.py                  # CLI 入口
└── tests/                   # 单元测试
```

## 工作流程

### 侦察模式

```bash
# 目标侦察
python hunt.py recon https://target.com

# 输出：子域名、开放端口、技术栈、API端点、敏感文件
```

### 渗透模式

```bash
# 完整渗透测试
python hunt.py pentest https://target.com --mode standard

# 快速扫描（5分钟）
python hunt.py pentest https://target.com --mode quick

# 深度扫描（60分钟+）
python hunt.py pentest https://target.com --mode aggressive
```

### MCP 集成

Hunter 作为 MCP 服务器运行，Claude 直接调用工具：

```python
# Claude 决策 → 调用工具 → 分析结果 → 决定下一步
probe("https://target.com")  # → 发现 PHP 后端
tech("https://target.com")   # → ThinkPHP 5.1.37
inject("https://target.com/login", payload="' OR 1=1--")  # → SQL 注入确认
```

## 知识图谱

每次发现自动存入知识图谱，构建攻击拓扑：

```
target.com
├── 子域名: api.target.com, admin.target.com
├── 端口: 80(nginx), 443(nginx), 3306(mysql)
├── 技术栈: PHP 7.4, ThinkPHP 5.1.37, MySQL 5.7
├── 漏洞:
│   ├── SQL注入 (login endpoint) - CVSS 9.8
│   ├── 目录遍历 (/upload/) - CVSS 7.5
│   └── 信息泄露 (/api/debug) - CVSS 5.3
└── 攻击链: SQL注入 → 数据库访问 → 凭据提取 → 后台登录
```

## 三种模式

| 模式 | 时间 | 深度 | 适用场景 |
|------|------|------|---------|
| Quick | 5 分钟 | 表面 | 快速评估攻击面 |
| Standard | 30 分钟 | 中等 | 常规渗透测试 |
| Aggressive | 60 分钟+ | 深度 | 全面安全审计 |

## 隐蔽模式

内置反检测机制：

- **请求限速** — 可配置 QPS，避免触发 WAF
- **代理支持** — SOCKS5/HTTP 代理链
- **指纹伪装** — 随机 User-Agent + 请求头
- **Tor 集成** — 自动路由流量

## 快速开始

```bash
# 克隆
git clone https://github.com/GeniusHu-666/Hunter.git
cd Hunter

# 安装依赖
pip install -r requirements.txt

# 运行侦察
python hunt.py recon https://target.com

# 运行渗透
python hunt.py pentest https://target.com --mode standard
```

## MCP 配置

在 Claude Desktop 或 Claude Code 中配置：

```json
{
  "mcpServers": {
    "hunter": {
      "command": "python",
      "args": ["/path/to/hunter/mcp_server.py"]
    }
  }
}
```

## 技术栈

```
Python 3.10+  ·  MCP Protocol  ·  知识图谱  ·  CVSS 评分
DNS解析  ·  TCP扫描  ·  HTTP指纹  ·  JS静态分析  ·  SQL注入检测
```

## 免责声明

本工具仅供**授权安全测试和教育目的**使用。未经授权对他人系统进行渗透测试是违法行为。使用者需自行承担法律责任。

## License

MIT
