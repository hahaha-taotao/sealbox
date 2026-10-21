# 凭据经纪人 MCP 与 GitHub 只读补齐 — 设计

日期：2026-09-24  
状态：已确认（规划）  
产品名：Sealbox（印盒）

## 1. 目标

让模型用金库里的凭据去办事，而看不到明文；并补齐 GitHub PR / Release / Actions 的只读上下文，避免 Agent 在 commit/push 之后两眼一抹黑。

一句话：Cursor / Claude Code 可以按标题选用 Token、看 PR 和 CI，必要时对已登记 origin 发 GET；Token、密码、私钥永不进入工具结果。

## 2. 已确认决策

| # | 决策点 | 结论 |
|---|---|---|
| 1 | GitHub 只读 | 按现有 `github_mcp` 模式加 P0 GET 工具，共用 `GithubMcpPolicy.enabled` |
| 2 | 通用经纪人 | 独立开关 `BrokerMcpPolicy.enabled`，默认关；不并进 GitHub / ZoomKey 开关 |
| 3 | HTTP 形态 | 只允许 GET；目标 origin 必须等于所选 `ApiToken` 条目的 `url`；路径相对且封闭 |
| 4 | 助手 | 低风险只读 GitHub 新工具可进内置助手；`credential_http_get` 标 `risk: medium`，助手不自动调用 |
| 5 | 明确不做 | 任意 URL/方法/请求头/原始 body；把 Token 回给模型；workflow logs / artifacts；合并 PR；Contents 写 API |

## 3. GitHub P0 只读工具

已有：`github_get_pull_request`、`github_list_workflow_runs`。本期新增（全部 `readOnly: true`、`risk: low`，固定 `https://api.github.com:443` GET）：

| 工具 | GitHub 路径 |
|---|---|
| `github_list_pull_request_files` | `/repos/{repo}/pulls/{number}/files` |
| `github_list_pull_request_commits` | `/repos/{repo}/pulls/{number}/commits` |
| `github_list_pull_request_reviews` | `/repos/{repo}/pulls/{number}/reviews` |
| `github_list_pull_request_comments` | `/repos/{repo}/pulls/{number}/comments` |
| `github_get_pull_request_status` | `/repos/{repo}/commits/{ref}/status`（`ref` 默认可省略：先 GET PR 取 head.sha） |
| `github_list_releases` | `/repos/{repo}/releases` |
| `github_get_release` | `/repos/{repo}/releases/{id}` 或 `/releases/tags/{tag}` |
| `github_list_release_assets` | `/repos/{repo}/releases/{id}/assets` |
| `github_list_tags` | `/repos/{repo}/tags` |
| `github_compare_commits` | `/repos/{repo}/compare/{base}...{head}` |
| `github_list_workflows` | `/repos/{repo}/actions/workflows` |
| `github_get_workflow_run` | `/repos/{repo}/actions/runs/{run_id}` |
| `github_list_workflow_jobs` | `/repos/{repo}/actions/runs/{run_id}/jobs` |

DTO 规则与现网一致：截断 body、去掉 token 字段、`redact_text`、分页上限 50、无重定向、`PublicResolver`。

`github_get_pull_request_status` 的 `ref` 只允许 SHA 或引用名字符集 `[A-Za-z0-9._/-]`，最长 200，禁止 `..`。

不实现：`/actions/jobs/{id}/logs`、artifacts 下载。

## 4. 凭据经纪人

新模块 `src-tauri/src/broker.rs`，工具挂进现有 `127.0.0.1:17891` MCP。

### 4.1 策略

金库 secret setting 键 `broker_mcp_policy`：

```json
{ "enabled": false }
```

损坏或缺失视为关闭。启用时 MCP 页二次确认：「将允许模型列出凭据元数据，并对已填写网址的自定义 Token 发 HTTPS GET。明文不会返回给模型。」

### 4.2 `vault_list_credentials`

- 参数：`kind`（可选，单种 `EntryKind`）、`query`（可选，搜标题/账号/网址，最长 100）
- 返回：`{ credentials: [{ id, kind, title, account, url, has_totp, fingerprint }], count }`
- 不含 notes、密码、Token、私钥、证书 PEM
- `fingerprint` 仅 SSH / 客户端证书已有明文指纹
- `readOnly: true`，`risk: low`

### 4.3 `credential_http_get`

- 参数：`credential` 或 `credential_id`（与 GitHub 相同的标题/账号/ID 解析，但只匹配 `ApiToken`）、`path`（必填，必须以 `/` 开头）
- 解析条目：`service` 为 `github` / `gitee` / `gitlab` / `zoomkey-jira` / `zoomkey-crm` 时拒绝，提示改用专用工具
- 条目必须有 `url`，取其 origin（scheme+host+port）
- 只允许 `https`
- `path` 禁止 `://`、`\\`、`..`、`@`、换行；最长 500；query 可含在 path 中但 host 不得出现
- 最终 URL = origin + path，再走 `http_guard::assert_public_target`
- 请求头由 Rust 写死：`Authorization: Bearer <token>`、`Accept: application/json`、固定 UA；模型不能加头
- 超时 15s，无重定向，响应 ≤ 64 KiB，非 JSON 则当文本截断
- 返回给模型前 `redact_text` Token
- `readOnly: true`，`risk: medium`（助手过滤器会丢掉）
- 审计：`mcp_broker`，detail 含 credential 指纹、origin、path、status，不含 Token 与 body

## 5. 界面与文档

MCP 页在 GitHub / ZoomKey 卡片旁增加「凭据经纪人」开关与说明。`tools/list` 随开关变化。README 与 `2026-09-20-github-mcp-roadmap.md` 的「当前能力 / P0」同步。

## 6. 成功标准

1. GitHub MCP 开启后，模型能列出某 PR 的 files/commits/reviews，以及 workflow run 的 jobs；结果里没有 Token。
2. 经纪人关闭时 `tools/list` 没有 `vault_list_credentials` / `credential_http_get`，直接调用被拒绝。
3. `credential_http_get` 不能把请求打到条目 origin 以外，不能打到内网，不能改方法或请求头。
4. 内置助手能发现新的 GitHub 只读工具，不能发现 `credential_http_get`。
5. 现有 GitHub / git / ZoomKey 测试全绿。
