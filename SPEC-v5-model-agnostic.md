# Hunter — 模型无关的渗透攻击平台

## 设计哲学

> 不依赖模型聪明，依赖架构硬。
> 任何 LLM 接入都能打出一样的效果。

### 核心原则

1. **模型只是调度员** — 不做判断、不写 payload、不分析响应。只做：下一步调哪个工具
2. **工具链可被任何模型调用** — 所有能力通过 MCP 暴露，结构化的输入输出，不靠 prompt 技巧
3. **确定性下放到代码** — WAF 识别、漏洞验证、假阳性过滤这些逻辑写死在 Python 里，不是靠模型"觉得"
4. **记忆持久化到磁盘** — 不靠对话上下文，每个目标的攻击面/假设/证据写 JSON 文件

---

## 一、RequestBroker — 统一请求出口（P0）

所有 HTTP 请求必须经过此层。

### 核心功能

```python
class RequestBroker:
    def execute(template: RequestTemplate) -> ResponseEnvelope: ...
    def classify(response) -> ResponseClass: ...
    def adapt_strategy(target: str, history: SessionHistory): ...
```

### ResponseClass 枚举

```
ALLOWED_APP        → 正常应用响应
LOGIN_REDIRECT     → 被踢回登录页
WAF_BLOCK          → WAF 拦截页/空壳200
CAPTCHA            → 验证码拦截
RATE_LIMITED       → 限流/429
SOFT_BAN           → 软封禁（返回假数据但不报错）
NETWORK_ERROR      → 连接超时/拒绝
PROXY_FAIL         → 代理失效
```

### ResponseEnvelope 格式

```json
{
  "request_id": "uuid",
  "template": {"method": "GET", "url": "...", "headers": {...}, "body": null},
  "response": {"status": 200, "headers": {...}, "body_preview": "...", "body_hash": "sha256"},
  "classification": "WAF_BLOCK",
  "baseline_diff": {"similarity": 0.12, "diff_keys": ["body_length", "title"]},
  "timing_ms": 342,
  "evidence_path": "sessions/<target>/request_<uuid>.json",
  "next_action": "cool_down_30s | proxy_rotate | retry_bypass | ignore"
}
```

### WAF 识别策略（硬编码规则，不依赖模型）

```
优先级规则（命中任意一条即分类为 WAF_BLOCK）：

1. 状态码 403/405/406/501  +  body 含 "waf"|"安全"|"拦截"|"denied"|"blocked"
2. 状态码 200 + body 长度 < 500 + 不含预期关键词
3. 状态码 200 + body 含验证码/captcha
4. 响应 header 含 X-WAF/Server: AISECURE/Server: SENSE 等
5. 连续 3 个不同 payload 返回完全相同的 body_hash
6. 状态码 429 + Retry-After header
7. 连接正常但 body 是空壳（纯 HTML 骨架无内容）
8. 正常基线请求返回正常，带 payload 的请求返回完全不同的 UI（被重定向到安全页）
```

### 自适应策略存储

```json
{
  "target": "edu-example.edu.cn",
  "session_id": "sess_xxx",
  "rate": {"max_rps": 2, "current_rps": 0.5, "cooldown_until": null},
  "waf_profile": {
    "detected": true,
    "type": "sangfor|nsfocus|aliyun|cloudflare|custom",
    "triggers": ["union_select", "etc_passwd", "single_quote"],
    "bypass_methods_tried": ["encoding", "case_mix", "comment_embed"],
    "cool_down_seconds": 120
  },
  "proxy_pool": {"active": "proxy_7", "banned_count": 3, "last_rotation": "iso8601"},
  "failure_reasons": ["WAF_BLOCK_x3", "RATE_LIMITED_x1"],
  "success_fingerprint": {"title": "教务管理系统", "body_hash_prefix": "a3f2"}
}
```

---

## 二、认证与会话层（P1）

### 架构

```
AuthManager
  ├── SessionStore (JSON 文件)
  ├── LoginFlow (模板化登录)
  ├── TokenRefresh
  └── MultiIdentity (多账号切换)
```

### Session 数据结构

```json
{
  "identity": "admin_low",
  "auth_type": "cookie|bearer|basic|csrf",
  "cookies": {"PHPSESSID": "abc123", "laravel_session": "xyz"},
  "headers": {"Authorization": "Bearer eyJ..."},
  "csrf_token": {"name": "_token", "from": "meta|input|header", "value": "xxx"},
  "created_at": "iso8601",
  "last_refresh": "iso8601",
  "expires_at": "iso8601",
  "validated": true
}
```

### 多主体实验模式

```
场景：
  - Session A（普通用户）执行操作 X
  - Session B（管理员）读取结果
  - 检测是否越权访问到 Session A 的资源

实现：
  IdentityPool.switch("admin") → 发请求 → IdentityPool.switch("user")
  每次切换自动注入对应凭证
```

---

## 三、发现层 — 被动攻击面提取（P1）

不主动发包，只从已有流量提取信息。

### 数据源

| 源 | 提取内容 |
|----|---------|
| Burp HTTP History | 所有请求/响应、参数、路径、cookie |
| Browser Snapshot | DOM、JS 注入点、Storage、WebSocket 消息 |
| JS Source | API 端点、路由、参数名、注释泄露 |
| HTML | 表单、action URL、隐藏字段、CSRF token |
| Error Response | 路径泄露、堆栈跟踪、DB 类型 |
| OpenAPI/GraphQL Schema | 完整 API 定义 |

### 输出：请求语料库

```json
{
  "endpoints": [
    {
      "path": "/api/user/{id}",
      "methods": ["GET", "PUT", "DELETE"],
      "parameters": [
        {"name": "id", "in": "path", "semantic": "user_id|uuid|numeric"},
        {"name": "page", "in": "query", "semantic": "pagination"}
      ],
      "auth_required": true,
      "responses": {"200": {"schema": {...}}, "403": "unauthorized"}
    }
  ],
  "auth_flows": [
    {"type": "login_form", "url": "/login", "fields": ["username", "password", "_token"]},
    {"type": "oauth", "provider": "CAS", "callback": "/cas/callback"}
  ],
  "object_flow": [
    {"id_param": "user_id", "appears_in": ["/api/user/create", "/api/user/{id}", "/api/user/{id}/delete"]}
  ]
}
```

### 自动生成假设

基于语料库生成可测试假设，规则硬编码：

```
规则1：参数名含 id/uid/user_id + DELETE 方法 → 测试 IDOR
规则2：存在文件上传端点 → 测试任意文件上传
规则3：参数含 url/redirect/next → 测试 SSRF/开放重定向
规则4：响应含 version/debug/stack → 测试信息泄露
规则5：GraphQL 端点 → 测试 introspection 未关闭
规则6：API 返回 403 → 测试 401/403 绕过（换 method/加 header/加后缀）
规则7：参数含 page/limit/offset → 测试批量越权
```

---

## 四、实验引擎 — 漏洞验证（P2）

### Hypothesis → Experiment 结构

```json
{
  "hypothesis": {
    "id": "hyp_001",
    "category": "idor",
    "target_endpoint": "/api/user/{id}",
    "risk": "critical",
    "prerequisites": [
      {"type": "auth", "identity": "user_a"},
      {"type": "auth", "identity": "user_b"},
      {"type": "resource", "id": "已知用户B的资源ID"}
    ],
    "readonly": true
  },
  "experiment": {
    "id": "exp_001",
    "plan": [
      {"step": "baseline", "identity": "user_a", "request": "GET /api/user/{user_a_id}"},
      {"step": "probe", "identity": "user_a", "request": "GET /api/user/{user_b_id}"},
      {"step": "negative_control", "identity": "anonymous", "request": "GET /api/user/{user_a_id}"}
    ],
    "oracle": {
      "type": "json_pointer",
      "path": "$.data.username",
      "baseline_value": "user_a_username",
      "expected_if_vulnerable": "user_b_username"
    }
  }
}
```

### Oracle 类型（验证锚点）

| 类型 | 说明 | 示例 |
|------|------|------|
| json_pointer | JSON响应指定路径的值 | $.data.username |
| status_diff | 状态码不一致 | 200 vs 403 |
| body_length | 响应体长度突变 | 基线200B → 漏洞响应12KB |
| resource_exists | 资源可达性 | 能读到不属于自己的文件 |
| callback | OAST 回调 | DNS/HTTP 请求到达 collaborator |
| state_change | 状态机跳转 | 未支付订单变成已支付 |

### 验证流程（确定性代码，不是模型判断）

```
1. 发基线请求（正常用户 A 访问自己的资源）
2. 记录 Oracle 值
3. 发探测请求（用户 A 访问用户 B 的资源）
4. 记录 Oracle 值
5. 发送阴性对照（匿名访问同一资源）
6. 比较三组结果：
   - 基线 = 正常访问 = Oracle 含 user_a 的数据
   - 探测 = Oracle 含 user_b 的数据 → 越权 CONFIRMED
   - 阴性对照 = 403/空响应 → 认证有效
   - 如果探测和阴性返回相同结果 → 可能是认证整体缺失，不是 IDOR
7. 输出 Verdict
```

### Verdict 分级

```
VERIFIED     → 阳性对照通过 + Oracle 命中 + 阴性对照符合预期
LIKELY       → Oracle 命中但阴性对照不可用
INCONCLUSIVE → Oracle 部分命中或有干扰
REFUTED      → 阴性对照也命中相同值（假阳性）
BROKEN       → 前置条件不满足（缺少 session/资源 ID）
```

---

## 五、证据链与报告（P2）

### Evidence 存储

```
sessions/<target>/
├── requests/           # 原始请求+响应 JSON
│   ├── req_uuid_1.json
│   └── req_uuid_2.json
├── experiments/        # 实验记录
│   └── exp_idor_001.json
├── evidence/           # 已证实证据
│   ├── VERIFIED_idor_user_profile.json
│   └── LIKELY_ssrf_internal.json
└── report.md           # 最终报告
```

### 证据 JSON

```json
{
  "evidence_id": "ev_001",
  "finding": "IDOR — 普通用户可以越权查看其他用户个人信息",
  "severity": "high",
  "verdict": "VERIFIED",
  "experiment_id": "exp_001",
  "endpoint": "GET /api/user/{id}",
  "poC_curl": "curl -X GET 'https://target.edu.cn/api/user/10086' -H 'Cookie: PHPSESSID=xxx' -H 'User-Agent: Mozilla/5.0'",
  "poC_python": "requests.get('https://target.edu.cn/api/user/10086', cookies={'PHPSESSID': 'xxx'}).text",
  "timeline": [
    {"time": "iso8601", "action": "baseline_request", "response_preview": "200 OK {username: 'user_a'}"},
    {"time": "iso8601", "action": "probe_request", "response_preview": "200 OK {username: 'user_b'}"},
    {"time": "iso8601", "action": "negative_control", "response_preview": "403 Forbidden"}
  ],
  "evidence_files": ["requests/req_baseline.json", "requests/req_probe.json", "requests/req_control.json"],
  "impact": "可遍历用户ID获取全部用户个人信息（姓名/手机/邮箱/学号）"
}
```

### 报告生成（E 级可读）

报告包含：
1. 目标摘要
2. 发现的漏洞列表（按严重度排序）
3. 每个漏洞：复现步骤 + PoC（curl/Python 双格式）+ 截图引用
4. 已排除的假阳性列表（REFUTED hypotheses）
5. 缺失的测试条件（如"需要两个有效 session 才能测越权"）

---

## 六、工具接口规范

### 所有 MCP 工具必须遵守

```json
{
  "mode": "discover | probe | verify",
  "classification": "verified | likely | inconclusive | refuted",
  "confidence": 0.0,
  "evidence_ids": [],
  "controls": [
    {"type": "baseline", "request_id": "..."},
    {"type": "negative", "request_id": "..."}
  ],
  "missing_inputs": ["需要第二个账号session", "需要OAST地址"],
  "next_actions": ["实验IDOR越权", "实验SSRF内网探测"],
  "errors": []
}
```

### 模型不需要自己做的事

```
❌ 判断响应是不是 WAF 页面         → RequestBroker.classify() 做
❌ 判断请求结果是不是漏洞           → Experiment.Oracle 做
❌ 构造 payload                    → payload 库取
❌ 决定这个请求用什么速度发         → RequestBroker 自适应策略做
❌ 记忆目标之前的扫描结果           → 文件持久化做
❌ 写 PoC                          → 模板引擎自动生成
✅ 决定下一步测什么                 → 模型唯一职责
```

---

## 七、实施顺序

| 阶段 | 内容 | 时间 |
|------|------|------|
| P0 | RequestBroker + 响应分类 + WAF识别 | 2周 |
| P0.5 | 所有现有工具接入 RequestBroker | 1周 |
| P1 | 认证管理器 + 会话存储 | 1周 |
| P1.5 | 被动发现层 + 请求语料库 | 2周 |
| P2 | 实验引擎 + Oracle + 前8个插件 | 3周 |
| P2.5 | 证据链 + 报告生成 | 1周 |
| P3 | 多模型适配层 + HunterBench | 2周 |

### 前8个实验插件（按价值排序）

1. **IDOR/BOLA** — 替换参数 ID 遍历
2. **SSRF** — 参数注入 collaborator URL → 检测回调
3. **SQL 注入** — 时间盲注 + OAST 双验证
4. **认证绕过** — 找回密码/Session 固定/MFA 跳过
5. **文件上传** — 扩展名/MIME/内容三重检测绕过
6. **SSTI** — 通用 payload 检测 + 引擎识别
7. **XXE** — OOB + 参数实体
8. **批量越权** — 分页参数篡改

---

## 八、配置结构

```yaml
# config.yaml
request_broker:
  default_rate: 2  # 每秒请求数
  waf_detection: true
  proxy_pool:
    enabled: true
    providers: ["file://proxies.txt"]
    rotation: "on_block|round_robin"
  cooldown:
    initial: 30  # 秒
    max: 600

session:
  auth_profiles: "sessions/auth_profiles.json"
  default_experiment_identity: "anonymous"

discovery:
  sources: ["burp", "browser", "js", "html"]
  hypothesis_rules: "config/hypothesis_rules.json"

experiment:
  plugins_dir: "experiment_plugins/"
  max_concurrent: 3
  oast_server: "burp_collaborator"
  require_negative_control: true

reporting:
  output: "sessions/<target>/report.md"
  include_poc: true
  include_refuted: true
