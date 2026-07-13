# curl_cffi Stealth HTTP 传输设计

## 目标

将 `StealthHTTPClient` 的默认真实 HTTP transport 从 Python `requests` 切换到
`curl_cffi.requests.Session`，为每个持久化 stealth 会话应用与浏览器头部指纹
对应的 TLS impersonation，同时保留缺包回退和现有 mock transport 契约。

## 后端选择

- 模块导入时优先执行 `from curl_cffi import requests`。
- `ImportError` 时导入原生 `requests`，并将后端标记为 fallback。
- 无论 curl 后端是否可用，都保留原生 `requests` 模块引用，用于：
  - fallback Cookie jar；
  - 识别现有 `requests.Session` chunked 测试 transport。
- fallback 警告只在第一次创建默认真实 transport 时记录一次：
  `curl_cffi not installed, falling back to requests (TLS fingerprint WILL be detected)`
- 自定义 `transport_factory` 不触发 fallback 警告，也不改变调用签名。

## 指纹映射

`FingerprintManager` 为每条指纹增加 `impersonate` 字段。基于
`curl_cffi>=0.6.0` 的可用目标定义以下基线：

- Chrome 110 -> `chrome110`
- Chrome 120 及以上 -> `chrome120`
- Edge 99 -> `edge99`
- Edge 101 及以上 -> `edge101`
- Safari 15/16 -> `safari15_3`
- Safari 17 及以上 -> `safari17_0`

Firefox 在 0.6 基线没有受支持目标，因此保留 `impersonate=None`。默认 curl
会话只从有 impersonate 的指纹中选择；header-only API 仍保留 Firefox 指纹。

## 会话生命周期

- `StealthHTTPClient` 构造方法新增可选 `impersonate` 全局覆盖。
- `session_create` 新增可选 `impersonate` 单会话覆盖。
- 新会话保存 `fingerprint_id` 和 `impersonate`。
- 恢复旧会话时：
  - 显式覆盖优先；
  - 其次使用持久化值；
  - 再使用指纹映射；
  - curl 后端遇到无映射旧指纹时，轮换到可 impersonate 指纹。
- 默认 transport 使用 `requests.Session(impersonate=value)` 创建。
- fallback transport 使用无额外参数的原生 `requests.Session()`。
- timeline 增加 `impersonate`，便于审计实际 transport 指纹。

## Cookie 与兼容

- curl 后端使用 `curl_cffi.requests.Cookies`。
- fallback 使用 `requests.cookies.cookiejar_from_dict`。
- 注入的 mock transport 保持无参数 factory 和原有请求 kwargs。
- chunked 生成器只对原生 `requests.Session` 使用，保持现有测试语义。

## 依赖

仓库当前没有 `pyproject.toml`，新增最小 PEP 621 元数据：

```toml
[project.optional-dependencies]
stealth = ["curl_cffi>=0.6.0"]
```

## 测试

- curl_cffi 可导入时选择 curl 后端。
- 阻断 curl_cffi 导入时选择 requests fallback。
- fallback 警告严格一次。
- 至少六组 impersonate 基线映射。
- 默认 Session 收到持久化 impersonate。
- 构造级与会话级显式覆盖。
- mock transport factory 不接收新参数。
- 旧 stealth、策略执行、Cookie 与 chunked 测试保持不变。

