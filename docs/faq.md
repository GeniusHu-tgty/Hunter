# Hunter FAQ

## Q: Hunter 工具跑不了怎么办？
**A:** 检查 import 链：
```python
import sys; sys.path.insert(0, '.')
from core.auto_sqli import AutoSQLi  # 应该能导入
```
如果失败，检查 `core/probe.py` 是否存在 fallback import。

## Q: Burp MCP 超时怎么办？
**A:** Burp MCP 有 30 秒超时。对于慢目标，用 Python requests 直接发：
```python
import requests
resp = requests.get(target, verify=False, timeout=30)
```

## Q: 统一扫描引擎找不到参数怎么办？
**A:** 检查目标 URL 是否有表单。如果没有表单，扫描器会返回 0 forms。可以手动指定参数：
```python
scanner.ctx.params = ["category", "search", "id"]
```

## Q: Hunter MCP 连不上怎么办？
**A:** 检查：
1. MCP server 是否在运行
2. 端口是否被占用
3. 依赖是否安装（mcp, requests）

## Q: GitHub push 失败怎么办？
**A:** 检查网络连接。如果被墙，用代理：
```bash
git config http.proxy http://127.0.0.1:7890
git config https.proxy http://127.0.0.1:7890
```

## Q: Lab 实例过期怎么办？
**A:** PortSwigger lab 实例通常 30-60 分钟过期。重新访问 lab 页面，点击 ACCESS THE LAB 获取新实例。

## Q: 找不到漏洞怎么办？
**A:** 
1. 先用 `probe` 做侦察
2. 检查所有参数（GET/POST/Cookie/Header）
3. 用 Burp Scanner 辅助
4. 查看 Proxy History 找隐藏参数

## Q: 找到漏洞但 lab 没有 solved 怎么办？
**A:** PortSwigger lab 需要通过浏览器触发。用 Playwright 填表单并提交，不要用 Burp 直接发 POST。
