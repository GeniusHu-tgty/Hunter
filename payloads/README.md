# Hunter Payload 知识库

## 概述

Hunter Payload 知识库是一个系统化的 Web 漏洞 Payload 集合，从 Des-CTF-Knowledge 等优质安全资源中提取并整合，用于自动化渗透测试。

## 目录结构

```
payloads/
├── README.md           # 本文件
├── loader.py           # Payload 加载器
├── sqli/              # SQL 注入
│   └── payloads.yaml
├── rce/               # 命令执行/RCE
│   └── payloads.yaml
├── ssrf/              # SSRF
│   └── payloads.yaml
├── ssti/              # 服务端模板注入
│   └── payloads.yaml
├── xss/               # XSS
│   └── payloads.yaml
├── lfi/               # 本地文件包含
│   └── payloads.yaml
├── jwt/               # JWT 攻击
│   └── payloads.yaml
├── upload/            # 文件上传绕过
│   └── payloads.yaml
├── deser/             # 反序列化
│   └── payloads.yaml
├── info_leak/         # 信息泄露
│   └── payloads.yaml
└── xxe/               # XXE
    └── payloads.yaml
```

## 使用方法

### 1. Python 加载器

```python
from payloads.loader import PayloadLoader

loader = PayloadLoader()

# 获取 SQL 注入 payload
sqli_payloads = loader.get_payloads('sqli')
print(sqli_payloads['union_injection']['exploit']['database'])

# 获取特定类型的 payload
rce_payloads = loader.get_payloads('rce')
print(rce_payloads['reverse_shell']['bash'])

# 获取 SSRF payload
ssrf_payloads = loader.get_payloads('ssrf')
print(ssrf_payloads['cloud_metadata']['aws'])
```

### 2. 命令行使用

```bash
# 列出所有 payload 类型
python loader.py --list

# 获取特定类型的 payload
python loader.py --type sqli --section union_injection

# 搜索 payload
python loader.py --search "反弹 shell"
```

### 3. 集成到 Hunter 工具

```python
# 在 fuzz 工具中使用
from payloads.loader import PayloadLoader

def fuzz_sqli(target_url, param):
    loader = PayloadLoader()
    payloads = loader.get_payloads('sqli')

    for category in payloads.values():
        for payload in category.get('exploit', {}).values():
            if isinstance(payload, list):
                for p in payload:
                    test_url = f"{target_url}?{param}={p}"
                    response = requests.get(test_url)
                    if is_vulnerable(response):
                        return True
    return False
```

## Payload 来源

- **Des-CTF-Knowledge**: CTF 知识库，12 篇核心文章
- **Hunter 实战经验**: 阶跃星辰、旷视科技等 SRC 测试
- **OWASP**: Web 安全标准
- **PortSwigger**: Web 安全研究

## 更新记录

- **2026-06-02**: 初始版本，从 Des-CTF-Knowledge 提取
  - SQL 注入 (联合注入/报错注入/堆叠注入/盲注/WAF绕过)
  - 命令执行 (反弹shell/无字母数字webshell)
  - SSRF (gopher攻击Redis/FastCGI/云元数据)
  - SSTI (Jinja2/Flask/Spring/Freemarker)
  - XSS (基础/事件处理器/编码绕过/DOM XSS)
  - LFI (路径遍历/PHP伪协议/日志包含)
  - JWT (算法攻击/KID注入/密钥爆破)
  - 文件上传 (后缀绕过/.htaccess/图片马)
  - 反序列化 (PHP/Java/Python/.NET)
  - 信息泄露 (配置文件/Git/备份/监控)
  - XXE (基础/OOB/SVG/XInclude)
