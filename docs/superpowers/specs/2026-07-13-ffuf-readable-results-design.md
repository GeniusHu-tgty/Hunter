# FFUF 可读目录枚举结果设计

## 目标

修复 `hunter_dir_enum` 对 ffuf JSON 行输出的处理，使 Base64 编码的目录路径
自动恢复为可读 URL，同时保留原始 URL 供审计，并增加按 HTTP 状态码分组的摘要。

## 兼容策略

- `stdout_preview` 保持现有截断和内容，不做任何改写。
- 现有 `results` 保持原始 ffuf 记录，避免改变下游消费者对原始字段的假设。
- 新增 `parsed_results`，其中每条记录是原记录的副本：
  - `raw_url` 保存原始 `url`。
  - Base64 解码成功时，`url` 替换为可读 URL。
  - 解码失败、UTF-8 失败或结果含不可打印字符时，`url` 保持不变。
- 新增 `human_readable`，按 HTTP 状态码升序分组展示 `parsed_results`。

## 解码规则

1. 优先检查 ffuf 记录 `input` 字典中的字符串值，并在 URL 路径中定位对应值。
2. 如果没有可靠的 `input` 候选，则逐个检查 URL 路径段。
3. 同时接受标准 Base64 和 URL-safe Base64，自动补齐缺失的 `=` padding。
4. 解码后必须满足：
   - 严格 UTF-8；
   - 非空；
   - 不含控制字符或其他不可打印字符；
   - 重新编码后与原候选的标准或 URL-safe 形式一致。
5. 只替换 URL 路径，保留 scheme、host、query 和 fragment。

## 摘要规则

- 结果总数少于 20 时展示全部状态码，包括 404。
- 结果总数大于等于 20 时过滤 404。
- 每组格式为 `HTTP <status> (<count>个):`。
- 有 `redirectlocation` 或 `location` 时显示 `URL -> 目标 URL`，相对跳转通过
  `urljoin` 转换为绝对 URL。
- 为避免 MCP 响应失控，结构化结果和摘要最多展示 200 条；`count` 仍表示原始总数。

## 测试

- 标准 Base64 示例 `.well-known/browserid`。
- URL-safe Base64 和缺失 padding。
- 普通路径、无效 Base64、二进制内容保持不变。
- query 与 fragment 保持。
- 301/302 跳转摘要。
- 404 在 `<20` 和 `>=20` 两种规模下的展示行为。
- `stdout_preview` 与旧 `results` 保持原样。

