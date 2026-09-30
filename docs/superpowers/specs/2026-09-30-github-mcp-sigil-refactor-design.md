# GitHub MCP 按 Sigil 重构 — 设计

日期：2026-09-30
状态：已确认
产品名：Sealbox（印盒）

## 1. 目标

现有 GitHub MCP 能看仓库、PR 和 CI 运行，但发版和排障仍然要离开工具：不能搜仓库、不能改文件、不能发布 Release、不能下载失败日志、不能重跑 CI。按 Sigil 的 GitHub 工具面补齐这些操作，同时把 HTTP、确认和脱敏收进一个小客户端，避免继续把逻辑堆进 `github_mcp.rs`。

一句话：模型用金库里的 GitHub Token 完成发版和 CI，Token 不出现在工具结果里，请求也打不到 `api.github.com` 以外。

## 2. 已确认决策

| # | 决策点 | 结论 |
|---|---|---|
| 1 | 范围 | 发版 + CI。对齐 Sigil 的仓库、文件、Issue、PR、Release、ref、Actions、变量和 secret |
| 2 | 不做 | 删仓库、分支保护、协作者、deploy key、Actions 总开关、workflow 默认权限 |
| 3 | 模块 | 新增内部客户端 `Github`。分发器仍按工具名调用 `get` / `send` / `download` / `upload` |
| 4 | 名字 | 保留现有工具名，同时注册 Sigil 同义名。同义名走同一实现 |
| 5 | 本地 git | `github_git_*` 留在 `git_workspace.rs`，不改行为 |
| 6 | 开关 | 继续用 `GithubMcpPolicy.enabled` 与 `api_write_enabled`，默认都关 |
| 7 | 确认 | 每个写操作逐次桌面确认。确认框不含 Token、secret 明文或文件正文 |
| 8 | 落盘 | 日志、artifact、release asset 只写到调用方给出的绝对路径，结果只含路径、字节数和 sha256 |

## 3. 模块

对外接缝不变：`tool_definitions_for_policy`、`call_tool`、`call_tool_detailed`、`load_policy`、`resolve_github_credential`。MCP 和 Tauri 命令继续调这些函数。

新增 `src-tauri/src/github_api.rs`，只负责一次已经过策略检查的 GitHub 调用。

```rust
pub struct Github { /* token, label; Drop 时清零 token；不实现 Debug */ }

pub struct Call {
    pub method: Method,                 // 默认 Get
    pub path: String,                   // 以 / 开头，无 scheme、无 host
    pub query: Vec<(String, String)>,
    pub body: Option<Body>,             // Json 或 Octet
    pub ok: &'static [u16],             // 默认 &[200]
}

pub struct Saved { pub path: PathBuf, pub bytes: u64, pub sha256: String }

impl Github {
    pub fn open(resolved: ResolvedGithubCredential) -> Self;
    pub fn get(&self, path: impl AsRef<str>, query: &[(&str, &str)]) -> Result<Value, String>;
    pub fn send(&self, call: Call, confirm: Option<Confirm>) -> Result<(u16, Value), String>;
    pub fn download(&self, call: Call, dest: &Path, cap: u64) -> Result<Saved, String>;
    pub fn upload(&self, call: Call, file: &Path, confirm: Confirm) -> Result<(u16, Value), String>;
}
```

`get` 是 `send` 的只读形式：`Method::Get`、`ok: &[200]`、无确认。非 GET 必须走 `send` 或 `upload`。`confirm == None` 只允许 `github_release_generate_notes` 这一条生成文本的 POST；其他非 GET 漏掉确认时，客户端直接拒绝，不发请求。

客户端隐藏这些事实：

- 主机只允许 `https://api.github.com:443`；`upload` 只允许 `https://uploads.github.com:443`
- 无重定向、`PublicResolver`、固定 `Authorization`、`Accept`、`X-GitHub-Api-Version: 2022-11-28`、User-Agent
- 超时 15 秒，JSON 请求体不超过 128 KiB，JSON 响应不超过 512 KiB
- 非期望状态码变成带截断正文的错误，再经过 `redact_text`
- 确认发生在打开连接之前；用户拒绝则不发请求
- 下载先写入临时文件，校验大小后再改名；失败删除临时文件

不把 HTTP 客户端或确认函数做成调用方要传入的接口。生产环境只有一套 `ureq` 和桌面确认，测试继续用 `confirm::with_auto`。DTO 裁剪留在工具模块，客户端返回的是已经脱敏的 JSON。

`github_mcp.rs` 变成适配器：校验参数、解析仓库和凭据、构造 `Call`、把响应收成小 DTO。同义名在进 match 之前收成规范名，避免每个工具写两个分支。

## 4. 工具

规范名采用 Sigil 的名字。括号里是继续可用的旧名。

### 4.1 只读，`risk: low`

这些工具在 GitHub MCP 开启后就出现，不需要写开关。

| 工具 | GitHub 路径 | 说明 |
|---|---|---|
| `github_user_info`（`github_get_authenticated_user`） | `GET /user` | 只返回 id、login、name、html_url、public_repos、private_repos。不返回 email、bio、公司或其他字段 |
| `github_repo_list`（`github_list_repositories`） | `GET /user/repos` | 增加 `type`、`visibility`、`affiliation`、`sort`、`direction`、`name_contains` |
| `github_repo_search` | `GET /search/repositories` | `q` 必填，最长 256；服务端搜索 |
| `github_repo_get`（`github_get_repository`） | `GET /repos/{repo}` | 现有 DTO |
| `github_file_get`（`github_get_file`） | `GET /repos/{repo}/contents/{path}` | 现有行为；目录返回条目，文件返回截断正文 |
| `github_issues_list`（`github_list_issues`） | `GET /repos/{repo}/issues` | 增加 `labels`、`assignee`、`creator`、`since`、`sort`、`direction` |
| `github_pulls_list`（`github_list_pull_requests`） | `GET /repos/{repo}/pulls` | 现有行为 |
| `github_commits_list` | `GET /repos/{repo}/commits` | `sha` 可选，分页 |
| `github_branches_list` | `GET /repos/{repo}/branches` | 分页；只返回 name、sha、protected |
| `github_tags_list`（`github_list_tags`） | `GET /repos/{repo}/tags` | 现有行为 |
| `github_release_list`（`github_list_releases`） | `GET /repos/{repo}/releases` | 含 draft |
| `github_release_get`（`github_get_release`） | 按 id 或 tag | 按 tag 查不到 draft 时，错误里说明改用 list 取 id |
| `github_release_generate_notes` | `POST /repos/{repo}/releases/generate-notes` | 只生成文本，不创建 Release。GitHub 这条是 POST，但仍标只读，不弹确认 |
| `github_workflow_list`（`github_list_workflows`） | `GET /repos/{repo}/actions/workflows` | 现有行为 |
| `github_runs_list`（`github_list_workflow_runs`） | `GET /repos/{repo}/actions/runs` | 现有行为 |
| `github_run_get`（`github_get_workflow_run`） | `GET /repos/{repo}/actions/runs/{id}` | 现有行为 |
| `github_run_jobs`（`github_list_workflow_jobs`） | `GET /repos/{repo}/actions/runs/{id}/jobs` | 失败 job 带上失败 step 的 name 和 conclusion。全部 job 失败且没有失败 step 时，结果加 `quota_exhausted_suspect: true` |
| `github_run_artifacts` | `GET /repos/{repo}/actions/runs/{id}/artifacts` | id、name、size、expired |
| `github_repo_variable_list` | `GET /repos/{repo}/actions/variables` | 变量是明文配置，原样返回 |
| `github_repo_secret_list` | `GET /repos/{repo}/actions/secrets` | 只返回 name 和 updated_at |
| `github_billing_actions` | `GET /users/{account}/settings/billing/actions` 或组织等价路径 | `year` 与 `month` 必须同时给；缺省时结果注明「这是本年至今，不是当月」。接口无剩余额度字段 |
| `github_ref_get` | `GET /repos/{repo}/git/ref/{ref}` | `git_ref` 接受 `heads/x`、`tags/x` 或带 `refs/` 前缀 |

保留现有 PR 上下文工具，不改名也不改参数：`github_get_pull_request`、`github_list_pull_request_files`、`github_list_pull_request_commits`、`github_list_pull_request_reviews`、`github_list_pull_request_comments`、`github_get_pull_request_status`、`github_compare_commits`、`github_list_release_assets`。

`github_list_credentials` 继续只返回 id、标题、账号和是否默认，不含 Token。

分页统一：`page` 从 1 起，`per_page` 默认 30、最大 50。列表响应保留 `truncated: true` 当 GitHub 返回被大小上限截断时。

### 4.2 写入，`risk: high`

这些工具只在 `enabled` 和 `api_write_enabled` 都打开时出现。每次调用弹确认。

| 工具 | 方法与路径 | 确认框展示 |
|---|---|---|
| `github_issue_create`（`github_create_issue`） | `POST /repos/{repo}/issues` | 仓库、标题 |
| `github_issue_comment`（`github_create_issue_comment`） | `POST /repos/{repo}/issues/{number}/comments` | 仓库与编号 |
| `github_issue_update` | `PATCH /repos/{repo}/issues/{number}` | 仓库、编号、要改的 state/title |
| `github_pr_create`（`github_create_pull_request`） | `POST /repos/{repo}/pulls` | 仓库、head、base、是否草稿。默认 `draft=true` |
| `github_pr_merge` | `PUT /repos/{repo}/pulls/{number}/merge` | 仓库、编号、merge/squash/rebase。默认 merge |
| `github_repo_create` | `POST /user/repos` | 仓库名。`private` 固定为 true，不接受公开 |
| `github_repo_update` | `PATCH /repos/{repo}` | 仓库和实际改动的字段。`private=false` 直接拒绝 |
| `github_file_put` | `PUT /repos/{repo}/contents/{path}` | 仓库、路径、分支、是新建还是更新。更新必须带 `sha` |
| `github_file_delete` | `DELETE /repos/{repo}/contents/{path}` | 仓库、路径、分支、sha |
| `github_release_create`（`github_create_release`） | `POST /repos/{repo}/releases` | 仓库、tag、是否草稿。默认 `draft=true` |
| `github_release_publish` | `PATCH /repos/{repo}/releases/{id}` | 仓库、release id。把 draft 设为 false |
| `github_release_delete` | `DELETE /repos/{repo}/releases/{id}` | 仓库、release id。不删 tag |
| `github_release_asset_upload` | `POST https://uploads.github.com/repos/{repo}/releases/{id}/assets` | 仓库、release id、本地文件名和大小 |
| `github_ref_create` | `POST /repos/{repo}/git/refs` | 仓库、ref、sha 前 12 位 |
| `github_ref_delete` | `DELETE /repos/{repo}/git/refs/{ref}` | 仓库、ref。说明删 tag 不会删 Release |
| `github_workflow_dispatch` | `POST /repos/{repo}/actions/workflows/{id}/dispatches` | 仓库、workflow、ref |
| `github_repository_dispatch` | `POST /repos/{repo}/dispatches` | 仓库、event_type |
| `github_run_rerun` | `POST /repos/{repo}/actions/runs/{id}/rerun` | 仓库、run id |
| `github_rerun_failed_jobs` | `POST /repos/{repo}/actions/runs/{id}/rerun-failed-jobs` | 仓库、run id |
| `github_run_cancel` | `POST /repos/{repo}/actions/runs/{id}/cancel` | 仓库、run id |
| `github_repo_variable_set` | `POST` 或 `PATCH /repos/{repo}/actions/variables` | 仓库、变量名。不展示变量值 |
| `github_repo_variable_delete` | `DELETE /repos/{repo}/actions/variables/{name}` | 仓库、变量名 |
| `github_repo_secret_set` | `PUT /repos/{repo}/actions/secrets/{name}` | 仓库、secret 名、值的来源（凭据标题或文件名） |

`github_file_put` 的 `content` 最长 48 KiB 明文，客户端自己做 base64。路径禁止 `..`、反斜杠和绝对路径。

`github_repo_secret_set` 的值只能给一个来源：`value_credential_name`、`value_from_file` 或 `value`。给了两个或三个就拒绝。凭据只接受 `ApiToken` 或 `Password` 的秘密字段；文件必须是绝对路径、普通文件、不超过 64 KiB。明文只用来按 GitHub 文档做 libsodium sealed box（`crypto_box_seal`，匿名公钥加密），请求体只有 `encrypted_value` 和 `key_id`。公钥来自 `GET /repos/{repo}/actions/secrets/public-key`。明文不进入确认框、审计、日志和返回值。`value` 明文参数保留是为了和 Sigil 同形，描述里标明不推荐。

仓库里现有的 `aes-gcm` 不能用，GitHub 只接受 sealed box。实现时新增一个维护中的 `crypto_box` crate（当前可选 `crypto_box` 0.9，底层是 `crypto_box::seal`），不手写 X25519 或 XSalsa20。这个依赖只服务 `github_repo_secret_set`。

### 4.3 落盘，`risk: medium`

这些工具在写开关打开时才出现。内置助手不自动调用。它们是 GET，但仍弹确认，因为会把可能含构建信息的内容写到磁盘。

| 工具 | 来源 | 上限 |
|---|---|---|
| `github_download_release_asset` | release asset | 256 MiB |
| `github_download_artifact` | Actions artifact zip | 256 MiB |
| `github_download_run_logs` | Actions run 日志 zip | 64 MiB |

`dest_path` 必须是绝对路径，父目录必须已存在，目标不能是目录，也不能覆盖已有文件。返回 `{ "path", "bytes", "sha256" }`。不返回文件字节、日志正文或下载 URL 中的 token。

## 5. 错误与审计

参数错误在发请求前返回，说明缺哪个字段或哪条规则。GitHub 的 4xx/5xx 保留状态码，正文截断到 240 字节并脱敏。

审计沿用现有 `GithubCallResult`：仓库、路径或 ref、状态码、凭据指纹、结果条数。不记录 Token、secret、请求体和响应体。下载多记目标路径和字节数，不记内容。

同义名在审计里记规范名。

## 6. 界面与文档

MCP 页不新增开关。写开关的说明改为「允许创建和修改 Issue、PR、Release、文件、ref、Actions 变量和 secret，并下载 CI 产物。每次操作都会确认。」

更新 `docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md` 的当前能力，把本规格已实现的项目从「未承诺」挪走。README 的 GitHub MCP 小节同步工具数量和仍不做的边界。

## 7. 测试

客户端测试用本地 HTTP 桩，不访问 GitHub：

- 只读 GET 不弹确认，非 200 不把响应体原样返回
- 写操作在确认拒绝时零请求；确认通过后才发，且只发到声明的主机
- `upload` 打到 uploads 主机；普通 `send` 即使路径写成 uploads 也被拒绝
- 下载超过上限时删除临时文件，目标路径不存在
- secret 请求体是加密后的 `encrypted_value`，确认记录和返回 JSON 都不含明文

工具测试覆盖：旧名和新名命中同一规范名；写开关关闭时写工具不在 `tools/list`；`private=false`、缺 sha 的文件更新、相对 `dest_path`、secret 来源冲突都被拒绝。

现有 GitHub、git workspace、MCP 测试保持通过。

## 8. 成功标准

1. 开启 GitHub MCP 后，模型能搜索仓库、列出分支和提交、查看失败 job 的 step。
2. 打开写开关后，模型能创建或更新 Issue、合并 PR、发布草稿 Release、上传一个本地文件作为 asset、重跑失败 job。
3. 每一次写操作都能被桌面确认取消，取消后 GitHub 收不到请求。
4. 下载日志和 artifact 后，模型只看到路径、大小和 sha256。
5. 设置 Actions secret 时，模型看不到明文，确认框只显示来源。
6. 删仓库、分支保护、协作者、deploy key 没有对应工具。
7. 现有工具名和 `github_git_*` 行为不变。
