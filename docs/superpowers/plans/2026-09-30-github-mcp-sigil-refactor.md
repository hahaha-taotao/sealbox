# GitHub MCP Sigil 重构 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 GitHub MCP 覆盖 Sigil 的发版和 CI 操作，Token 不出现在工具结果里，请求打不到 `api.github.com` 以外。

**Architecture:** 新增 `github_api::Github` 隐藏主机、确认、大小限制和脱敏。`github_mcp.rs` 只做参数校验、同义名和 DTO。本地 `github_git_*` 不动。测试传输只在 `cfg(test)` 下替换，生产路径只用 `ureq` + `PublicResolver`，因为公网解析会拒绝 `127.0.0.1`。

**Tech Stack:** Rust 2021、ureq 2、serde_json、`crypto_box` 0.9、现有 `confirm::ask_payload`。

**Spec:** `docs/superpowers/specs/2026-09-30-github-mcp-sigil-refactor-design.md`

## File structure

- Create `src-tauri/src/github_api.rs` — 一次 GitHub 调用：`get` / `send` / `download` / `upload`
- Modify `src-tauri/src/lib.rs` — `pub mod github_api;`
- Modify `src-tauri/src/github_mcp.rs` — 别名、新工具、改走 `Github`
- Modify `src-tauri/Cargo.toml` — `crypto_box = "0.9"`
- Modify `src/App.vue` — 写开关文案
- Modify `README.md` 与 `docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md`
- Tests live in each module's `mod tests`

不要访问真实 GitHub。不要实现删仓库、分支保护、协作者、deploy key、Actions 总开关。

---

### Task 1: GitHub 客户端

**Files:**
- Create: `src-tauri/src/github_api.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/Cargo.toml`（此任务先不加 crypto_box）

- [ ] **Step 1: 写失败测试**

在 `src-tauri/src/github_api.rs` 底部放测试模块。测试通过 `install_transport_for_test` 捕获请求，不打开 socket。

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_api() -> Github {
        Github::open_for_test("ghp_testtoken", "work")
    }

    #[test]
    fn get_does_not_confirm_and_returns_json() {
        let _guard = crate::confirm::with_auto(Some(false), || {
            install_transport_for_test(|req| {
                assert_eq!(req.method, "GET");
                assert_eq!(req.url, "https://api.github.com/user");
                assert!(req.authorization.ends_with("ghp_testtoken"));
                Ok(HttpReply { status: 200, body: br#"{"login":"octo","token":"ghp_testtoken"}"#.to_vec() })
            });
            let value = test_api().get("/user", &[]).unwrap();
            assert_eq!(value["login"], "octo");
            assert!(!value.to_string().contains("ghp_testtoken"));
        });
    }

    #[test]
    fn write_without_confirm_makes_no_request() {
        let probe = TransportProbe::install(|_| unreachable!("缺少确认时不能发请求"));
        let error = test_api().send(Call {
            method: Method::Post,
            path: "/repos/a/b/issues".into(),
            query: vec![],
            body: Some(Body::Json(json!({"title":"x"}))),
            ok: &[201],
            allow_missing_confirm: false,
        }, None).unwrap_err();
        assert!(error.contains("缺少确认"));
        assert!(probe.calls().is_empty());
    }

    #[test]
    fn denied_confirm_makes_no_request() {
        let probe = TransportProbe::install(|_| unreachable!("确认拒绝后不能发请求"));
        let error = crate::confirm::with_auto(Some(false), || {
            test_api().send(sample_post(), Some(Confirm {
                title: "创建 Issue".into(),
                prompt: "允许？".into(),
                fields: vec![("仓库".into(), "a/b".into())],
            }))
        }).unwrap_err();
        assert!(error.contains("用户拒绝"));
        assert!(probe.calls().is_empty());
    }

    #[test]
    fn send_cannot_select_uploads_host() {
        let probe = TransportProbe::install(|_| Ok(HttpReply { status: 201, body: b"{}".to_vec() }));
        let error = test_api().send(Call {
            method: Method::Post,
            path: "/repos/a/b/releases/1/assets?name=a".into(),
            query: vec![],
            body: None,
            ok: &[201],
            allow_missing_confirm: false,
        }, Some(sample_confirm())).unwrap_err();
        assert!(error.contains("不合法"));
        assert!(probe.calls().is_empty());
    }

    #[test]
    fn upload_targets_uploads_host() {
        let probe = TransportProbe::install(|req| {
            assert!(req.url.starts_with("https://uploads.github.com/"));
            Ok(HttpReply { status: 201, body: br#"{"id":1}"#.to_vec() })
        });
        let value = crate::confirm::with_auto(Some(true), || {
            test_api().upload_bytes(
                "/repos/a/b/releases/1/assets?name=a",
                b"hi",
                "application/octet-stream",
                sample_confirm(),
            )
        }).unwrap();
        assert_eq!(value.0, 201);
        assert_eq!(probe.calls().len(), 1);
    }
}
```

`upload_bytes` 是 `upload` 的测试入口，避免每个测试都写临时文件。生产的 `upload` 读文件后调用它。

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p sealbox --lib github_api::tests -- --test-threads=1`

Expected: FAIL，`github_api` 模块不存在。

- [ ] **Step 3: 实现客户端**

`src-tauri/src/lib.rs` 在 `pub mod github_mcp;` 下加 `pub mod github_api;`。

`github_api.rs` 实现这些类型。行为必须与测试和下面的不变量一致。

```rust
use crate::confirm::{self, ConfirmPayload, ConfirmField};
use crate::http_guard::{assert_public_target, parse_http_url, sha256_hex, PublicResolver};
use crate::redact::redact_text;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

const API: &str = "https://api.github.com";
const UPLOADS: &str = "https://uploads.github.com";
const MAX_JSON: usize = 512 * 1024;
const MAX_REQUEST: usize = 128 * 1024;

#[derive(Clone, Copy)]
pub enum Method { Get, Post, Put, Patch, Delete }

pub enum Body { Json(Value), Octet { content_type: String, bytes: Vec<u8> } }

pub struct Call {
    pub method: Method,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<Body>,
    pub ok: &'static [u16],
    pub allow_missing_confirm: bool,
}

pub struct Confirm { pub title: String, pub prompt: String, pub fields: Vec<(String, String)> }
pub struct Saved { pub path: PathBuf, pub bytes: u64, pub sha256: String }
pub struct HttpReply { pub status: u16, pub body: Vec<u8> }
pub struct Captured { pub method: String, pub url: String, pub authorization: String, pub body: Vec<u8> }

pub struct Github { token: String, label: String }
```

不变量：

1. `path` 必须以 `/` 开头，不能含 `://`、`..`、`\`、`@`。
2. `send` 的最终 URL 主机必须是 `api.github.com:443`。`upload_bytes` 的主机必须是 `uploads.github.com:443`。用 `parse_http_url` + `assert_public_target`。
3. `Method::Get` 以外，`allow_missing_confirm == false` 且 `confirm == None` 时返回 `缺少确认`，传输函数不被调用。
4. 有 `confirm` 时先 `confirm::ask_payload`。拒绝返回 `用户拒绝了这次 GitHub 写操作`。
5. 期望状态以外：`GitHub HTTP {status}: {message}`，message 截断 240 字节，再 `redact_text(..., &[token])`。JSON 响应里的 token 同样替换成 `***`。
6. 204 或空 body 返回 `Value::Null`。
7. 下载写入 `dest.with_extension("part")`，超过 `cap` 删除临时文件并返回错误，成功后 `rename` 到 `dest`。`dest` 已存在则拒绝。

测试传输用 `TransportProbe`，因为闭包要记录调用次数，不能是函数指针。`install` 把回复闭包按测试线程存进 thread local，`calls()` 返回已经发出的请求。`exchange` 先看这个 thread local。没有时走 `ureq`：`redirects(0)`、超时 15/8 秒、`PublicResolver`、头 `Authorization: Bearer {token}`、`Accept: application/vnd.github+json`、`X-GitHub-Api-Version: 2022-11-28`、User-Agent `Sealbox/{version}`。`install_transport_for_test` 用 `#[cfg(test)]` 包起来。

`get` 调用 `send`，`allow_missing_confirm: true`，`confirm: None`，`ok: &[200]`。

`upload` 检查 `file` 是绝对路径的普通文件，读入后调用 `upload_bytes`。上传的 `Content-Type` 由调用方传入，查询串里的 `name` 由调用方放进 path。

- [ ] **Step 4: 补上拒绝路径的测试并跑通**

再加三个测试：

- `path` 为 `https://evil.example/user` 时 `get` 失败且传输未被调用
- 状态 404 的 body `{"message":"nope ghp_testtoken"}` 返回字符串里没有 `ghp_testtoken`
- `download` 到已存在文件失败；超过 cap 时目标文件不存在

Run: `cargo test -p sealbox --lib github_api::tests -- --test-threads=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/lib.rs src-tauri/src/github_api.rs
git commit -m "feat(github): add a pinned GitHub API client"
```

---

### Task 2: 同义名与现有调用改走客户端

**Files:**
- Modify: `src-tauri/src/github_mcp.rs`

- [ ] **Step 1: 写失败测试**

在 `github_mcp.rs` 的 `mod tests` 增加：

```rust
#[test]
fn alias_collapses_to_canonical_name() {
    assert_eq!(canonical_tool_name("github_list_repositories"), "github_repo_list");
    assert_eq!(canonical_tool_name("github_repo_list"), "github_repo_list");
    assert_eq!(canonical_tool_name("github_create_issue"), "github_issue_create");
    assert_eq!(canonical_tool_name("github_get_file"), "github_file_get");
    assert_eq!(canonical_tool_name("github_git_status"), "github_git_status");
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p sealbox --lib github_mcp::tests::alias_collapses_to_canonical_name -- --test-threads=1`

Expected: FAIL，`canonical_tool_name` 不存在。

- [ ] **Step 3: 实现别名表**

```rust
pub fn canonical_tool_name(name: &str) -> &str {
    match name {
        "github_get_authenticated_user" => "github_user_info",
        "github_list_repositories" => "github_repo_list",
        "github_get_repository" => "github_repo_get",
        "github_get_file" => "github_file_get",
        "github_list_issues" => "github_issues_list",
        "github_list_pull_requests" => "github_pulls_list",
        "github_create_issue" => "github_issue_create",
        "github_create_issue_comment" => "github_issue_comment",
        "github_create_pull_request" => "github_pr_create",
        "github_create_release" => "github_release_create",
        "github_list_releases" => "github_release_list",
        "github_get_release" => "github_release_get",
        "github_list_tags" => "github_tags_list",
        "github_list_workflows" => "github_workflow_list",
        "github_list_workflow_runs" => "github_runs_list",
        "github_get_workflow_run" => "github_run_get",
        "github_list_workflow_jobs" => "github_run_jobs",
        other => other,
    }
}
```

`call_tool_text` 开头对非 `github_git_*` 的名字做 `let name = canonical_tool_name(name);`。match 改用规范名。`tool_definitions` 对每个规范名再发一条旧名，schema 和描述相同，这样 `tools/list` 里新旧名都在。

把 `github_get_authenticated_user` 的 match 臂改成调用 `Github::open(resolved).get("/user", &[])`，再映射成现有 `GithubUserDto`。删除这条路径上的 `request_json` 调用。其他旧工具先保持原 helper，后续任务逐个迁。

- [ ] **Step 4: 跑现有 GitHub 测试**

Run: `cargo test -p sealbox --lib github_mcp::tests -- --test-threads=1`

Expected: PASS，包括新别名测试和原来的只读/写开关测试。

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/github_mcp.rs
git commit -m "refactor(github): collapse MCP tool aliases"
```

---

### Task 3: 只读仓库、Issue、分支和计费

**Files:**
- Modify: `src-tauri/src/github_mcp.rs`

这些工具 `readOnly: true`，`risk: low`。参数都带现有 `credential` / `credential_id`。仓库参数继续走 `repository_args`。

| 规范名 | 方法与路径 | 额外参数 | 返回字段 |
|---|---|---|---|
| `github_repo_search` | `GET /search/repositories` | `q` 必填 1–256，`sort`，`order`，`page`，`per_page` | `total_count`，`items[]` 用现有 repository DTO |
| `github_commits_list` | `GET /repos/{repo}/commits` | `sha` 可选，分页 | sha、commit.message 截断 200、author.login、html_url |
| `github_branches_list` | `GET /repos/{repo}/branches` | 分页 | name、commit.sha、protected |
| `github_ref_get` | `GET /repos/{repo}/git/ref/{ref}` | `git_ref` 必填 | ref、object.sha |
| `github_billing_actions` | `GET /users/{account}/settings/billing/actions` 或 `/orgs/{account}/settings/billing/actions` | `account` 可空，`is_org`，`year`，`month` 必须同时有或同时无 | 原样保留 `total_minutes_used`、`total_paid_minutes_used`、`included_minutes`；缺 month 时加 `period: "year_to_date"` |

`github_repo_list` 在现有查询上接受 `type`、`visibility`、`affiliation`、`sort`、`direction`、`name_contains`。`name_contains` 在 DTO 之后按 `full_name` 子串过滤当前页，不额外请求。

`github_issues_list` 接受 `labels`、`assignee`、`creator`、`since`、`sort`、`direction`，原样放进 query。

`github_ref_get` 把 `refs/` 前缀去掉后再拼路径，拒绝包含 `..` 的 ref。

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn repo_search_requires_q_and_is_low_risk() {
    let def = api_tool_definitions().into_iter().find(|t| t["name"] == "github_repo_search").unwrap();
    assert_eq!(def["readOnly"], true);
    assert_eq!(def["risk"], "low");
    let error = validate_tool_arguments(&def["inputSchema"], &json!({})).unwrap_err();
    assert!(error.contains("q"));
}

#[test]
fn billing_rejects_month_without_year() {
    let error = billing_query(&json!({"month": 9})).unwrap_err();
    assert!(error.contains("year"));
}

#[test]
fn ref_get_strips_refs_prefix() {
    assert_eq!(normalize_git_ref("refs/heads/main").unwrap(), "heads/main");
    assert!(normalize_git_ref("heads/../main").is_err());
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p sealbox --lib github_mcp::tests::repo_search_requires_q_and_is_low_risk -- --test-threads=1`

Expected: FAIL，工具尚未定义。

- [ ] **Step 3: 实现**

每个工具用 `tool(...)` 注册。分发臂只解析参数、拼 query、调用 `Github::get`、映射 DTO。`github_billing_actions` 的 account 为空时先 `get("/user")` 取 `login`。`is_org: true` 走 `/orgs/{account}/...`。

`normalize_git_ref` 与 `billing_query` 做成 `pub(crate)`，方便测试。

- [ ] **Step 4: 跑测试**

Run: `cargo test -p sealbox --lib github_mcp::tests -- --test-threads=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/github_mcp.rs
git commit -m "feat(github): add repository search, refs, and billing reads"
```

---

### Task 4: Issue、PR、仓库写入

**Files:**
- Modify: `src-tauri/src/github_mcp.rs`

全部 `write_tool`，`risk: high`。写开关关闭时不出现在 `tool_definitions_for_policy`。

| 规范名 | 调用 | 确认字段 | 拒绝条件 |
|---|---|---|---|
| `github_issue_update` | `PATCH /repos/{repo}/issues/{number}`，body 只含给出的 state/title/body/labels | 仓库、编号、state 或标题 | state 不是 open/closed；四个字段都缺 |
| `github_pr_merge` | `PUT /repos/{repo}/pulls/{number}/merge`，`merge_method` 默认 merge | 仓库、编号、方式 | 方式不是 merge/squash/rebase |
| `github_repo_create` | `POST /user/repos`，body 强制 `private: true` | 仓库名 | 调用方传 `private: false` |
| `github_repo_update` | `PATCH /repos/{repo}`，只发送给出的字段 | 仓库和变更字段名 | `private: false`；没有任何字段 |

现有 create issue / comment / PR 改为 `Github::send`，确认文案保持现在的中文。PR 默认 `draft=true`。

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn repo_create_refuses_public() {
    let error = repo_create_body(&json!({"name":"box","private":false})).unwrap_err();
    assert!(error.contains("私有"));
}

#[test]
fn issue_update_hidden_until_api_write() {
    let names = tool_names(&GithubMcpPolicy { enabled: true, api_write_enabled: false, ..Default::default() });
    assert!(!names.contains(&"github_issue_update"));
    let names = tool_names(&GithubMcpPolicy { enabled: true, api_write_enabled: true, ..Default::default() });
    assert!(names.contains(&"github_issue_update"));
    assert!(names.contains(&"github_pr_merge"));
}
```

`tool_names` 是测试里对 `tool_definitions_for_policy` 取 name 的辅助函数。文件里已有类似断言，照它写。

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p sealbox --lib github_mcp::tests::repo_create_refuses_public -- --test-threads=1`

Expected: FAIL

- [ ] **Step 3: 实现四个工具和迁移**

`send` 的 `ok`：创建用 `&[201]`，更新和合并用 `&[200]`。确认通过 `Confirm` 传入。用户拒绝时 match 臂不会自己发请求，因为客户端已经挡住。

- [ ] **Step 4: 跑测试**

Run: `cargo test -p sealbox --lib github_mcp::tests github_api::tests -- --test-threads=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/github_mcp.rs
git commit -m "feat(github): add issue, pull request, and repository writes"
```

---

### Task 5: 文件与 ref 写入

**Files:**
- Modify: `src-tauri/src/github_mcp.rs`

| 规范名 | 调用 | 确认字段 | 规则 |
|---|---|---|---|
| `github_file_put` | `PUT /repos/{repo}/contents/{path}` | 仓库、路径、分支、新建或更新 | `content` 最长 48 KiB；更新时 `sha` 必填；body 的 `content` 由实现做标准 base64 |
| `github_file_delete` | `DELETE /repos/{repo}/contents/{path}` | 仓库、路径、分支 | `message` 与 `sha` 必填 |
| `github_ref_create` | `POST /repos/{repo}/git/refs` | 仓库、ref、sha 前 12 位 | sha 必须是 40 位十六进制；ref 规范成 `refs/heads/...` 或 `refs/tags/...` |
| `github_ref_delete` | `DELETE /repos/{repo}/git/refs/{ref}` | 仓库、ref | 204 视为成功，返回 `{ "deleted": true, "ref": "..." }` |

路径复用现有 `path_arg`，它已经拒绝 `..`。

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn file_put_requires_sha_when_updating() {
    let error = file_put_body(&json!({"path":"README.md","content":"hi","sha":""})).unwrap_err();
    assert!(error.contains("sha"));
}

#[test]
fn ref_create_rejects_short_sha() {
    assert!(normalize_full_sha("abc").is_err());
    assert_eq!(normalize_full_sha(&"a".repeat(40)).unwrap().len(), 40);
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p sealbox --lib github_mcp::tests::file_put_requires_sha_when_updating -- --test-threads=1`

Expected: FAIL

- [ ] **Step 3: 实现**

`file_put_body`：`sha` 缺省或空表示新建，不放进 JSON；非空必须是 40 位 hex。`content` 用 `base64::engine::general_purpose::STANDARD.encode`。确认框不包含 content。

- [ ] **Step 4: 跑测试**

Run: `cargo test -p sealbox --lib github_mcp::tests -- --test-threads=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/github_mcp.rs
git commit -m "feat(github): add file and ref writes"
```

---

### Task 6: Release 与 Actions 控制

**Files:**
- Modify: `src-tauri/src/github_mcp.rs`

| 规范名 | 调用 | 风险 | 确认 |
|---|---|---|---|
| `github_release_generate_notes` | `POST /repos/{repo}/releases/generate-notes` | low，只读 | 不确认。`allow_missing_confirm: true`。这是唯一例外 |
| `github_release_publish` | `PATCH /repos/{repo}/releases/{id}` body `{"draft":false}` 加可选 name/body/prerelease | high | 仓库、release id |
| `github_release_delete` | `DELETE /repos/{repo}/releases/{id}` | high | 仓库、release id。返回 `{ "deleted": true }`，不删 tag |
| `github_release_asset_upload` | `upload` 到 `/repos/{repo}/releases/{id}/assets?name=` | high | 仓库、release id、文件名、字节数 |
| `github_workflow_dispatch` | `POST .../actions/workflows/{workflow}/dispatches` | high | 仓库、workflow、ref |
| `github_repository_dispatch` | `POST /repos/{repo}/dispatches` | high | 仓库、event_type |
| `github_run_rerun` | `POST .../actions/runs/{id}/rerun` | high | 仓库、run id |
| `github_rerun_failed_jobs` | `POST .../actions/runs/{id}/rerun-failed-jobs` | high | 仓库、run id |
| `github_run_cancel` | `POST .../actions/runs/{id}/cancel` | high | 仓库、run id |
| `github_run_artifacts` | `GET .../actions/runs/{id}/artifacts` | low | 无 |
| `github_repo_variable_list` | `GET .../actions/variables` | low | 无 |
| `github_repo_variable_set` | 先 GET 同名；没有则 POST，有则 PATCH | high | 仓库、变量名。不放变量值 |
| `github_repo_variable_delete` | `DELETE .../actions/variables/{name}` | high | 仓库、变量名 |

`github_run_jobs` 在现有 DTO 上增加：失败 job 的 `steps` 里只保留 `conclusion != success` 的 name 和 conclusion。如果每个 job 的 conclusion 都是 failure 且没有任何 step，结果加 `quota_exhausted_suspect: true`。

`github_release_get` 按 tag 收到 404 时，错误文案追加「draft 请用 github_release_list 取 id」。

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn generate_notes_is_read_only_post() {
    let def = find_tool("github_release_generate_notes");
    assert_eq!(def["readOnly"], true);
    assert_eq!(def["risk"], "low");
}

#[test]
fn failed_jobs_without_steps_mark_quota() {
    let jobs = json!({"jobs":[{"conclusion":"failure","steps":[]}]});
    let dto = workflow_jobs_dto(&jobs).unwrap();
    assert_eq!(dto["quota_exhausted_suspect"], true);
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p sealbox --lib github_mcp::tests::generate_notes_is_read_only_post -- --test-threads=1`

Expected: FAIL

- [ ] **Step 3: 实现上表**

dispatch 的 204 用 `ok: &[204]`。`github_release_asset_upload` 的文件名只允许 `A-Za-z0-9._-`，最长 120，用 `percent_encode` 放进 query。`content_type` 默认 `application/octet-stream`。

- [ ] **Step 4: 跑测试**

Run: `cargo test -p sealbox --lib github_mcp::tests github_api::tests -- --test-threads=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/github_mcp.rs
git commit -m "feat(github): add release publishing and actions controls"
```

---

### Task 7: 下载与 Actions secret

**Files:**
- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/src/github_mcp.rs`

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn download_rejects_relative_dest() {
    let error = check_dest_path("logs.zip").unwrap_err();
    assert!(error.contains("绝对路径"));
}

#[test]
fn secret_set_rejects_two_sources() {
    let error = secret_source(&json!({
        "value": "plain",
        "value_from_file": "C:/keys/app.key"
    })).unwrap_err();
    assert!(error.contains("一个来源"));
}

#[test]
fn sealed_box_round_trip_hides_plaintext() {
    let secret = b"super-secret";
    let encrypted = seal_secret(secret, &test_public_key()).unwrap();
    assert!(!encrypted.contains("super-secret"));
    let opened = open_seal_for_test(&encrypted, &test_secret_key()).unwrap();
    assert_eq!(opened, secret);
}
```

`test_public_key` / `test_secret_key` 在测试里用 `crypto_box::SecretKey::generate` 生成一次。

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test -p sealbox --lib github_mcp::tests::download_rejects_relative_dest -- --test-threads=1`

Expected: FAIL

- [ ] **Step 3: 加依赖并实现**

`Cargo.toml` 的 `[dependencies]` 加 `crypto_box = "0.9"`。

下载工具都是 `risk: medium`、`readOnly: false`，因此只有写开关打开才出现。调用 `Github::download`。

| 工具 | URL | cap |
|---|---|---|
| `github_download_release_asset` | `GET /repos/{repo}/releases/assets/{asset_id}`，Accept 改成 `application/octet-stream` | 256 MiB |
| `github_download_artifact` | `GET /repos/{repo}/actions/artifacts/{artifact_id}/zip` | 256 MiB |
| `github_download_run_logs` | `GET /repos/{repo}/actions/runs/{run_id}/logs` | 64 MiB |

`check_dest_path`：`Path::is_absolute()`，父目录 `is_dir()`，目标 `!exists()`。确认框展示仓库、资源 id、目标路径。返回 JSON 只有 `path`、`bytes`、`sha256`。

`github_repo_secret_list` 是 low 只读，字段只有 `name` 和 `updated_at`。

`github_repo_secret_set`：

1. `secret_source` 要求三个字段恰好一个有值。
2. `value_credential_name` 走 `resolve_github_credential` 以外的金库查找，只接受 `ApiToken` 或 `Password`。不要把取到的明文放进 `Confirm`。
3. `value_from_file` 必须是绝对路径、普通文件、不超过 64 KiB。
4. `GET /repos/{repo}/actions/secrets/public-key` 得到 `key` 和 `key_id`。
5. `seal_secret` 用 `crypto_box::seal`，输出标准 base64。请求体只有 `encrypted_value` 和 `key_id`。
6. `PUT /repos/{repo}/actions/secrets/{name}`，成功状态 201 或 204。返回 `{ "name": "...", "updated": true }`。

若 `crypto_box` 0.9 的函数名不是 `seal`，用该 crate 文档中的匿名 sealed box API。测试的往返必须成立，不能改成「只断言非空」。

- [ ] **Step 4: 跑测试**

Run: `cargo test -p sealbox --lib github_mcp::tests github_api::tests -- --test-threads=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/github_mcp.rs
git commit -m "feat(github): download actions artifacts and set secrets"
```

---

### Task 8: 文档、界面和全量回归

**Files:**
- Modify: `src/App.vue` 约 2188 和 2235 行
- Modify: `README.md` 的 GitHub MCP 小节
- Modify: `docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md`

- [ ] **Step 1: 改文案**

`App.vue` 启用说明改为：「启用后开放 GitHub 只读 API、本地 git，以及可单独打开的 Issue、PR、Release、文件、Actions 和 secret 写入。」

写开关说明改为：「GitHub API 写入包含 Issue、PR、Release、文件、ref、Actions 变量和 secret，以及 CI 产物下载。每次仍需桌面确认。不提供删仓库、分支保护、协作者和 deploy key。」

- [ ] **Step 2: 更新路线图**

`2026-09-20-github-mcp-roadmap.md` 的「当前能力」加上本规格已实现的工具名。把已实现项从「高风险写入 / 未承诺」删除。保留仍未做的：删仓库、分支保护、协作者、deploy key、Actions 总开关、workflow 权限。把状态行改成指向 `2026-09-30-github-mcp-sigil-refactor-design.md`。

README 的工具列表与路线图一致，不新增没有实现的工具。

- [ ] **Step 3: 全量后端测试**

Run: `cargo test -p sealbox --lib -- --test-threads=1`

Expected: PASS。失败就停，不把失败解释成既有问题，除非能指出同名测试在本计划之前的提交就失败。

- [ ] **Step 4: Commit**

```bash
git add src/App.vue README.md docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md docs/superpowers/specs/2026-09-30-github-mcp-sigil-refactor-design.md
git commit -m "docs: describe the Sigil-shaped GitHub MCP"
```

---

## Self-review

- 规格第 4 节每个工具都落在 Task 3–7 的表里。PR 上下文旧工具明确不改。
- `github_release_generate_notes` 是唯一不确认的 POST，Task 1 的 `allow_missing_confirm` 和 Task 6 的测试对应。
- 下载不返回正文，secret 不回显明文，与规格第 4.3 和 secret 段一致。
- 没有删仓库、分支保护、协作者、deploy key 的任务。
- 类型名前后一致：`Github`、`Call`、`Confirm`、`canonical_tool_name`、`allow_missing_confirm`。
