# GitHub Read-Only Context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给已启用的 GitHub MCP 补上 PR、Release、tag、commit 对比和 Actions 的只读 GET，让模型在 commit/push 之后能看 diff 范围、review、CI 和发布状态，而拿不到日志、artifact 或 Token。

**Architecture:** 13 个新工具全部注册进现有 `api_tool_definitions()`，用现成的 `tool()`（`readOnly: true`、`risk: low`）。调用走现有 `call_tool_text` → `prepare` → `request_json`。响应只经新的 DTO 映射，字段截断后由现有 `redact_text` 再滤一遍。不新增模块，不改策略开关，不改助手过滤器：`assistant_tool_allowed` 已经放行所有 `github_` 前缀，再由 `risk == "low"` 且 `readOnlyHint` 把写入工具挡在外面。

**Tech Stack:** 现有 `src-tauri/src/github_mcp.rs`、`ureq` GET、`http_guard::assert_public_target`、`redact_text`。测试用 `cargo test`，不访问网络。

**Spec:** `docs/superpowers/specs/2026-09-24-credential-broker-mcp-design.md` 第 3 节，以及 `docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md` 的 P0 列表。本计划不实现该设计第 4 节的凭据经纪人。

---

## 范围

做这 13 个工具，全部固定 `GET https://api.github.com:443`，无重定向，分页上限沿用 `MAX_PAGE_SIZE = 50`：

| 工具 | 路径 |
|---|---|
| `github_list_pull_request_files` | `/repos/{repo}/pulls/{number}/files` |
| `github_list_pull_request_commits` | `/repos/{repo}/pulls/{number}/commits` |
| `github_list_pull_request_reviews` | `/repos/{repo}/pulls/{number}/reviews` |
| `github_list_pull_request_comments` | `/repos/{repo}/pulls/{number}/comments` |
| `github_get_pull_request_status` | `/repos/{repo}/commits/{ref}/status`，省略 `ref` 时先 GET PR 取 `head.sha` |
| `github_list_releases` | `/repos/{repo}/releases` |
| `github_get_release` | `/repos/{repo}/releases/{id}` 或 `/repos/{repo}/releases/tags/{tag}` |
| `github_list_release_assets` | `/repos/{repo}/releases/{id}/assets` |
| `github_list_tags` | `/repos/{repo}/tags` |
| `github_compare_commits` | `/repos/{repo}/compare/{base}...{head}` |
| `github_list_workflows` | `/repos/{repo}/actions/workflows` |
| `github_get_workflow_run` | `/repos/{repo}/actions/runs/{run_id}` |
| `github_list_workflow_jobs` | `/repos/{repo}/actions/runs/{run_id}/jobs` |

明确不做：

- `/actions/jobs/{id}/logs`、`/actions/runs/{id}/logs`、artifacts 下载
- `uploads.github.com`
- 凭据经纪人、`vault_list_credentials`、`credential_http_get`
- 新的写入工具（PR 评论、更新 Issue、合并、发正式 Release）
- 拆分 `github_mcp.rs`。本计划只在现有函数里加分支；文件拆分是另一项优化

## 文件

| 文件 | 责任 |
|---|---|
| Modify `src-tauri/src/github_mcp.rs` | 工具 schema、DTO、路径拼装、`call_tool_text` 分支、单测 |
| Modify `README.md` | 只读工具列表补上新名字 |
| Modify `docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md` | 把已实现的 P0 项标成完成 |

不要改 `assistant.rs`、`mcp.rs`、`commands.rs`、`App.vue`。新工具自动出现在 `tools/list`，也自动进入助手的低风险只读集合。

## 现有锚点

实现时对着这些现有符号，不要新造一套请求栈：

- `api_tool_definitions()` 在 `github_list_workflow_runs` 之后、第一个 `write_tool(` 之前插入。`tool()` 已设置 `readOnly/risk/annotations`。
- `call_tool_text` 的 match 在 `"github_list_workflow_runs"` 分支之后、`_ =>` 之前插入。
- `request_json` 只接受拼进 `https://api.github.com` 的 path，并强制 host `api.github.com`、端口 443。
- `repository_args`、`issue_number`、`page_args`、`page_args_with_default`、`optional_ref`、`percent_encode`、`limited_string`、`list_dto` 直接复用。
- `read_only_tools_have_closed_schemas` 现在列了 9 个名字。`tool_schemas_are_closed` 断言 `read_only == 9`。
- 只读工具总数改为 **22**（现有 9 个 + 本计划 13 个）。不要把 `github_git_*` 算进这个 22，那些不在 `api_tool_definitions()` 里。

---

### Task 1: 注册 13 个只读工具

**Files:**
- Modify: `src-tauri/src/github_mcp.rs`（`api_tool_definitions`，约 371–387 行之后）
- Test: `src-tauri/src/github_mcp.rs` 内 `read_only_tools_have_closed_schemas` 与 `tool_schemas_are_closed`

- [ ] **Step 1: 先改测试，让它失败**

在 `read_only_tools_have_closed_schemas` 的 `expected` 数组末尾、`"github_list_workflow_runs"` 之后追加：

```rust
            "github_list_pull_request_files",
            "github_list_pull_request_commits",
            "github_list_pull_request_reviews",
            "github_list_pull_request_comments",
            "github_get_pull_request_status",
            "github_list_releases",
            "github_get_release",
            "github_list_release_assets",
            "github_list_tags",
            "github_compare_commits",
            "github_list_workflows",
            "github_get_workflow_run",
            "github_list_workflow_jobs",
```

把 `tool_schemas_are_closed` 里的 `assert_eq!(read_only, 9);` 改成：

```rust
        assert_eq!(read_only, 22);
```

- [ ] **Step 2: 跑测试，确认失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp::tests::read_only_tools_have_closed_schemas --offline
```

Expected: FAIL，`tool must be registered`。

- [ ] **Step 3: 插入工具定义**

在 `api_tool_definitions()` 里，`github_list_workflow_runs` 的 `tool(...)` 结束之后、`write_tool("github_create_issue"` 之前，插入下面 13 个 `tool(...)`。schema 全部 `additionalProperties: false`，因为走的是现有 `schema()`。

```rust
        tool(
            "github_list_pull_request_files",
            "列出某个 PR 改了哪些文件：filename、status、增删行数、blob SHA。看 diff 范围时调用。不含 patch 全文。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo", "number"],
            ),
        ),
        tool(
            "github_list_pull_request_commits",
            "列出某个 PR 的 commit SHA、标题和作者。需要把 PR 和本地提交对上时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo", "number"],
            ),
        ),
        tool(
            "github_list_pull_request_reviews",
            "列出某个 PR 的 review：state、提交者、提交时间。判断谁批准或要求修改时调用。不含 review 正文全文。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo", "number"],
            ),
        ),
        tool(
            "github_list_pull_request_comments",
            "列出某个 PR 的行内评论：path、line、用户、截断后的正文。看 review 讨论时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo", "number"],
            ),
        ),
        tool(
            "github_get_pull_request_status",
            "读取 PR head 或指定 ref 的 combined status：state 与各 context。判断 CI 是否通过时调用。不返回日志。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("ref", string_schema(1, 200)),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_list_releases",
            "列出仓库 Release：tag、名称、是否草稿、是否预发布、html_url。不含 body 全文，也不含资产文件。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_get_release",
            "读取单个 Release 的元数据。传 id 或 tag_name 之一。body 截断，不含资产二进制。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("id", json!({"type":"integer","minimum":1,"maximum":9007199254740991})),
                    ("tag_name", string_schema(1, 200)),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_list_release_assets",
            "列出某个 Release 的资产名、大小、content_type 和下载次数。不下载文件。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("id", json!({"type":"integer","minimum":1,"maximum":9007199254740991})),
                ],
                &["repo", "id"],
            ),
        ),
        tool(
            "github_list_tags",
            "列出仓库 tag 名和对应 commit SHA。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_compare_commits",
            "比较 base 与 head：ahead/behind、提交数和文件名列表。不含 patch 全文。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("base", string_schema(1, 200)),
                    ("head", string_schema(1, 200)),
                ],
                &["repo", "base", "head"],
            ),
        ),
        tool(
            "github_list_workflows",
            "列出仓库 Actions workflow：id、name、path、state。不含 workflow 文件内容。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_get_workflow_run",
            "读取单次 workflow run：status、conclusion、head_sha、head_branch、html_url。不含日志。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("run_id", json!({"type":"integer","minimum":1,"maximum":9007199254740991})),
                ],
                &["repo", "run_id"],
            ),
        ),
        tool(
            "github_list_workflow_jobs",
            "列出某次 run 的 jobs：name、status、conclusion，以及各 step 的名称和结论。不含日志。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("run_id", json!({"type":"integer","minimum":1,"maximum":9007199254740991})),
                ],
                &["repo", "run_id"],
            ),
        ),
```

`github_get_pull_request_status` 的 `repo` 必填，`number` 和 `ref` 都可选：省略 `ref` 时必须有 `number`，这条约束放在 Task 3 的参数函数里，不放进 JSON Schema 的 `required`（JSON Schema 表达「二选一」会把 `schema()` 辅助函数改复杂）。

- [ ] **Step 4: 再跑测试**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp::tests::read_only_tools_have_closed_schemas github_mcp::tests::tool_schemas_are_closed --offline
```

Expected: PASS。`tool_schemas_are_closed` 的只读计数是 22。

- [ ] **Step 5: 提交**

```bash
git add src-tauri/src/github_mcp.rs
git commit -m "feat(github-mcp): register read-only PR, release, and Actions tools"
```

---

### Task 2: DTO 映射丢掉 patch、日志和下载地址

**Files:**
- Modify: `src-tauri/src/github_mcp.rs`（`GithubFileDto` 之后、`api_tool_definitions` 之前；以及 `list_dto` 附近）
- Test: 同文件 `tests` 模块

- [ ] **Step 1: 写失败测试**

在 `mod tests` 里、`file_dto_filters_and_marks_binary_content` 之后追加：

```rust
    #[test]
    fn readonly_dtos_drop_patches_logs_and_download_urls() {
        let file = pull_file_dto(&json!({
            "filename": "src/main.rs",
            "status": "modified",
            "additions": 3,
            "deletions": 1,
            "changes": 4,
            "sha": "abc",
            "patch": "@@ secret patch",
            "contents_url": "https://api.github.com/repos/a/b/contents/src/main.rs"
        }))
        .unwrap();
        assert_eq!(file["filename"], "src/main.rs");
        assert_eq!(file["additions"], 3);
        assert!(file.get("patch").is_none());
        assert!(file.get("contents_url").is_none());

        let asset = release_asset_dto(&json!({
            "id": 9,
            "name": "Sealbox_setup.exe",
            "size": 100,
            "content_type": "application/octet-stream",
            "download_count": 2,
            "browser_download_url": "https://github.com/a/b/releases/download/v1/Sealbox_setup.exe",
            "url": "https://api.github.com/repos/a/b/releases/assets/9"
        }))
        .unwrap();
        assert_eq!(asset["name"], "Sealbox_setup.exe");
        assert!(asset.get("browser_download_url").is_none());
        assert!(asset.get("url").is_none());

        let job = workflow_job_dto(&json!({
            "id": 7,
            "name": "build",
            "status": "completed",
            "conclusion": "success",
            "html_url": "https://github.com/a/b/actions/runs/1/job/7",
            "logs_url": "https://api.github.com/repos/a/b/actions/jobs/7/logs",
            "steps": [
                {"name": "checkout", "status": "completed", "conclusion": "success", "number": 1},
                {"name": "secret-step", "status": "completed", "conclusion": "failure", "number": 2}
            ]
        }))
        .unwrap();
        assert_eq!(job["name"], "build");
        assert!(job.get("logs_url").is_none());
        assert_eq!(job["steps"][1]["conclusion"], "failure");
        assert!(job["steps"][0].get("log").is_none());

        let compare = compare_dto(&json!({
            "status": "ahead",
            "ahead_by": 1,
            "behind_by": 0,
            "total_commits": 1,
            "files": [{"filename": "README.md", "status": "modified", "additions": 1, "deletions": 0, "patch": "leak"}],
            "commits": [{"sha": "deadbeef", "commit": {"message": "docs"}}]
        }))
        .unwrap();
        assert_eq!(compare["ahead_by"], 1);
        assert_eq!(compare["files"][0]["filename"], "README.md");
        assert!(compare["files"][0].get("patch").is_none());
        assert_eq!(compare["commits"].as_array().unwrap().len(), 1);
    }
```

- [ ] **Step 2: 跑测试，确认失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp::tests::readonly_dtos_drop_patches_logs_and_download_urls --offline
```

Expected: FAIL，`pull_file_dto` 未定义。

- [ ] **Step 3: 加 DTO 和映射函数**

在 `GithubFileDto` 结构体之后增加这些结构体。它们只用于序列化给模型，不派生 `Deserialize`。

```rust
#[derive(Clone, Debug, Serialize)]
struct GithubPullFileDto {
    filename: Option<String>,
    status: Option<String>,
    additions: Option<i64>,
    deletions: Option<i64>,
    changes: Option<i64>,
    sha: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubCommitDto {
    sha: Option<String>,
    message: Option<String>,
    author: Option<String>,
    html_url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubReviewDto {
    id: Option<i64>,
    user: Option<String>,
    state: Option<String>,
    submitted_at: Option<String>,
    body: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubReviewCommentDto {
    id: Option<i64>,
    user: Option<String>,
    path: Option<String>,
    line: Option<i64>,
    side: Option<String>,
    body: Option<String>,
    html_url: Option<String>,
    created_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubStatusContextDto {
    context: Option<String>,
    state: Option<String>,
    description: Option<String>,
    target_url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubTagDto {
    name: Option<String>,
    sha: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubReleaseAssetDto {
    id: Option<i64>,
    name: Option<String>,
    size: Option<i64>,
    content_type: Option<String>,
    download_count: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubWorkflowDto {
    id: Option<i64>,
    name: Option<String>,
    path: Option<String>,
    state: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubWorkflowStepDto {
    name: Option<String>,
    status: Option<String>,
    conclusion: Option<String>,
    number: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubWorkflowJobDto {
    id: Option<i64>,
    name: Option<String>,
    status: Option<String>,
    conclusion: Option<String>,
    html_url: Option<String>,
    steps: Vec<GithubWorkflowStepDto>,
}
```

在 `workflow_run_dto` 之后增加映射。`patch`、`contents_url`、`browser_download_url`、`url`、`logs_url` 都不要读出来。

```rust
fn pull_file_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubPullFileDto {
        filename: limited_string(value.get("filename")),
        status: limited_string(value.get("status")),
        additions: value.get("additions").and_then(Value::as_i64),
        deletions: value.get("deletions").and_then(Value::as_i64),
        changes: value.get("changes").and_then(Value::as_i64),
        sha: limited_string(value.get("sha")),
    })
    .ok()
}

fn commit_dto(value: &Value) -> Option<Value> {
    let commit = value.get("commit");
    serde_json::to_value(GithubCommitDto {
        sha: limited_string(value.get("sha")),
        message: limited_string_with_cap(
            commit.and_then(|item| item.get("message")),
            MAX_DESCRIPTION_BYTES,
        ),
        author: limited_string(
            commit
                .and_then(|item| item.get("author"))
                .and_then(|item| item.get("name"))
                .or_else(|| value.get("author").and_then(|item| item.get("login"))),
        ),
        html_url: limited_string(value.get("html_url")),
    })
    .ok()
}

fn review_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubReviewDto {
        id: value.get("id").and_then(Value::as_i64),
        user: limited_string(value.get("user").and_then(|item| item.get("login"))),
        state: limited_string(value.get("state")),
        submitted_at: limited_string(value.get("submitted_at")),
        body: limited_string_with_cap(value.get("body"), MAX_DESCRIPTION_BYTES),
    })
    .ok()
}

fn review_comment_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubReviewCommentDto {
        id: value.get("id").and_then(Value::as_i64),
        user: limited_string(value.get("user").and_then(|item| item.get("login"))),
        path: limited_string(value.get("path")),
        line: value.get("line").and_then(Value::as_i64),
        side: limited_string(value.get("side")),
        body: limited_string_with_cap(value.get("body"), MAX_DESCRIPTION_BYTES),
        html_url: limited_string(value.get("html_url")),
        created_at: limited_string(value.get("created_at")),
    })
    .ok()
}

fn status_context_dto(value: &Value) -> Option<GithubStatusContextDto> {
    Some(GithubStatusContextDto {
        context: limited_string(value.get("context")),
        state: limited_string(value.get("state")),
        description: limited_string(value.get("description")),
        target_url: limited_string(value.get("target_url")),
    })
}

fn tag_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubTagDto {
        name: limited_string(value.get("name")),
        sha: limited_string(value.get("commit").and_then(|item| item.get("sha"))),
    })
    .ok()
}

fn release_asset_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubReleaseAssetDto {
        id: value.get("id").and_then(Value::as_i64),
        name: limited_string(value.get("name")),
        size: value.get("size").and_then(Value::as_i64),
        content_type: limited_string(value.get("content_type")),
        download_count: value.get("download_count").and_then(Value::as_i64),
    })
    .ok()
}

fn workflow_summary_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubWorkflowDto {
        id: value.get("id").and_then(Value::as_i64),
        name: limited_string(value.get("name")),
        path: limited_string(value.get("path")),
        state: limited_string(value.get("state")),
    })
    .ok()
}

fn workflow_job_dto(value: &Value) -> Option<Value> {
    let steps = value
        .get("steps")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .take(50)
                .map(|step| GithubWorkflowStepDto {
                    name: limited_string(step.get("name")),
                    status: limited_string(step.get("status")),
                    conclusion: limited_string(step.get("conclusion")),
                    number: step.get("number").and_then(Value::as_i64),
                })
                .collect()
        })
        .unwrap_or_default();
    serde_json::to_value(GithubWorkflowJobDto {
        id: value.get("id").and_then(Value::as_i64),
        name: limited_string(value.get("name")),
        status: limited_string(value.get("status")),
        conclusion: limited_string(value.get("conclusion")),
        html_url: limited_string(value.get("html_url")),
        steps,
    })
    .ok()
}

fn compare_dto(value: &Value) -> Result<Value, String> {
    let files = value
        .get("files")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(pull_file_dto)
                .take(MAX_PAGE_SIZE as usize)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let commits = value
        .get("commits")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(commit_dto)
                .take(MAX_PAGE_SIZE as usize)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(json!({
        "status": limited_string(value.get("status")),
        "ahead_by": value.get("ahead_by").and_then(Value::as_i64),
        "behind_by": value.get("behind_by").and_then(Value::as_i64),
        "total_commits": value.get("total_commits").and_then(Value::as_i64),
        "files": files,
        "commits": commits
    }))
}

fn combined_status_dto(value: &Value) -> Result<Value, String> {
    let statuses = value
        .get("statuses")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(status_context_dto)
                .take(MAX_PAGE_SIZE as usize)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(json!({
        "state": limited_string(value.get("state")),
        "sha": limited_string(value.get("sha")),
        "total_count": value.get("total_count").and_then(Value::as_i64),
        "statuses": statuses
    }))
}

fn object_list_dto(
    value: &Value,
    key: &str,
    per_page: u64,
    mapper: fn(&Value) -> Option<Value>,
) -> Result<Value, String> {
    let items = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| "GitHub 响应格式不正确".to_string())?
        .iter()
        .filter_map(mapper)
        .take(per_page as usize)
        .collect::<Vec<_>>();
    let count = items.len();
    Ok(json!({ key: items, "count": count }))
}
```

`GithubReleaseDto` 已经存在，列表和单条 Release 继续用它。它没有 `body` 字段，正好满足「列表不含 body 全文」。单条 `github_get_release` 也不把 body 加回去：Release 说明可能很长，也不是判断发布状态所必需的。如果以后要看说明，再单开一个截断字段，不在本计划里加。

- [ ] **Step 4: 跑测试**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp::tests::readonly_dtos_drop_patches_logs_and_download_urls --offline
```

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add src-tauri/src/github_mcp.rs
git commit -m "feat(github-mcp): map read-only DTOs without patches or logs"
```

---

### Task 3: 参数校验与路径拼装

**Files:**
- Modify: `src-tauri/src/github_mcp.rs`（`issue_number` 附近，以及 `call_tool_text`）
- Test: 同文件 `tests` 模块

- [ ] **Step 1: 写失败测试**

```rust
    #[test]
    fn readonly_paths_reject_bad_refs_and_encode_compare() {
        assert!(positive_id(&json!({"id": 0}), "id").is_err());
        assert_eq!(positive_id(&json!({"run_id": 42}), "run_id").unwrap(), 42);
        assert!(compare_ref_arg(&json!({"base": "refs/../main"}), "base").is_err());
        assert!(compare_ref_arg(&json!({"head": "feature%2Fx"}), "head").is_err());
        assert_eq!(
            compare_endpoint("octocat/hello-world", "main", "feature/ui").unwrap(),
            "/repos/octocat/hello-world/compare/main...feature%2Fui"
        );
        assert!(compare_endpoint("octocat/hello-world", "a...b", "main").is_err());
        let missing = pull_status_selector(&json!({"repo": "octocat/hello-world"})).unwrap_err();
        assert!(missing.contains("number"), "{missing}");
        assert_eq!(
            pull_status_selector(&json!({"repo": "octocat/hello-world", "ref": "abc123"})).unwrap(),
            PullStatusSelector::Ref("abc123".into())
        );
    }
```

`PullStatusSelector` 在下一步定义。测试先失败是预期的。

- [ ] **Step 2: 跑测试，确认失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp::tests::readonly_paths_reject_bad_refs_and_encode_compare --offline
```

Expected: FAIL，`positive_id` 未定义。

- [ ] **Step 3: 实现参数函数**

放在 `issue_number` 后面。`compare_ref_arg` 复用 `optional_ref` 的字符规则，但字段名是 `base` / `head`，而且必填。禁止 `...`，因为 compare 路径自己要用 `base...head` 分隔。

```rust
fn positive_id(args: &Value, name: &str) -> Result<u64, String> {
    args.get(name)
        .and_then(Value::as_u64)
        .filter(|value| *value >= 1)
        .ok_or_else(|| format!("缺少参数 {name}"))
}

fn compare_ref_arg(args: &Value, name: &str) -> Result<String, String> {
    let wrapped = json!({ "ref": args.get(name).cloned().unwrap_or(Value::Null) });
    optional_ref(&wrapped)?
        .filter(|value| !value.contains("..."))
        .ok_or_else(|| format!("参数 {name} 格式不合法"))
}

fn compare_endpoint(repository: &str, base: &str, head: &str) -> Result<String, String> {
    if base.contains("...") || head.contains("...") {
        return Err("比较引用不能包含 ...".into());
    }
    Ok(format!("/repos/{repository}/compare/{base}...{head}"))
}

enum PullStatusSelector {
    Ref(String),
    Pull(u64),
}

fn pull_status_selector(args: &Value) -> Result<PullStatusSelector, String> {
    if let Some(reference) = optional_ref(args)? {
        if reference.contains("...") {
            return Err("ref 格式不合法".into());
        }
        return Ok(PullStatusSelector::Ref(reference));
    }
    if args.get("number").is_some() {
        return Ok(PullStatusSelector::Pull(issue_number(args)?));
    }
    Err("缺少参数 number".into())
}
```

`optional_ref` 已经拒绝空段、`..`、`%`、反斜杠和控制字符，并做百分号编码。这里不要再写一套 ref 校验。

- [ ] **Step 4: 跑测试**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp::tests::readonly_paths_reject_bad_refs_and_encode_compare --offline
```

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add src-tauri/src/github_mcp.rs
git commit -m "feat(github-mcp): validate read-only PR and compare arguments"
```

---

### Task 4: 把 13 个工具接到 `call_tool_text`

**Files:**
- Modify: `src-tauri/src/github_mcp.rs` 的 `call_tool_text` match
- Test: 同文件。这一任务不发网络请求；断言「策略关闭时拒绝」以及「写入开关关闭时这些工具仍出现」

- [ ] **Step 1: 扩展关闭策略测试**

`all_github_tools_reject_when_policy_is_disabled` 的 `cases` 数组在 `github_list_pull_requests` 之后追加。这些调用在 `prepare` 里就会因为策略关闭返回「未启用」，不会打到 GitHub。

```rust
            (
                "github_list_pull_request_files",
                json!({"repo":"octocat/hello-world","number":1}),
            ),
            (
                "github_get_pull_request_status",
                json!({"repo":"octocat/hello-world","number":1}),
            ),
            (
                "github_list_releases",
                json!({"repo":"octocat/hello-world"}),
            ),
            (
                "github_get_release",
                json!({"repo":"octocat/hello-world","tag_name":"v1.0.0"}),
            ),
            (
                "github_compare_commits",
                json!({"repo":"octocat/hello-world","base":"main","head":"feature"}),
            ),
            (
                "github_get_workflow_run",
                json!({"repo":"octocat/hello-world","run_id":1}),
            ),
            (
                "github_list_workflow_jobs",
                json!({"repo":"octocat/hello-world","run_id":1}),
            ),
```

再加一个测试，确认只开总开关、不开 API 写入时，新工具仍然可见：

```rust
    #[test]
    fn new_readonly_tools_stay_visible_without_api_write() {
        let definitions = tool_definitions_for_policy(&GithubMcpPolicy {
            enabled: true,
            api_write_enabled: false,
            ..Default::default()
        });
        for name in [
            "github_list_pull_request_files",
            "github_get_pull_request_status",
            "github_list_releases",
            "github_get_release",
            "github_list_release_assets",
            "github_compare_commits",
            "github_list_workflow_jobs",
        ] {
            assert!(
                definitions.iter().any(|definition| definition["name"] == name),
                "{name} missing"
            );
        }
    }
```

- [ ] **Step 2: 跑测试，确认后一个失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp::tests::new_readonly_tools_stay_visible_without_api_write --offline
```

Expected: 在 Task 1 已提交的前提下，这个测试应已经 PASS。如果 FAIL，说明工具没有放进 `api_tool_definitions()`，回到 Task 1，不要在 `tool_definitions_for_policy` 里开特例。

`all_github_tools_reject_when_policy_is_disabled` 在分支接上之前，未知工具会返回「未知 GitHub 工具」而不是「未启用」。先跑一次确认它失败：

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp::tests::all_github_tools_reject_when_policy_is_disabled --offline
```

Expected: FAIL，错误文本是「未知 GitHub 工具」。

- [ ] **Step 3: 插入 match 分支**

在 `"github_list_workflow_runs" => { ... }` 之后、`_ => return Err("未知 GitHub 工具".into())` 之前插入。每个分支都用已经准备好的 `token` 和 `request_json`。

```rust
        "github_list_pull_request_files" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint = format!(
                "/repos/{repository}/pulls/{number}/files?page={page}&per_page={per_page}"
            );
            request_json(&token, &endpoint, |value| list_dto(value, per_page, pull_file_dto))
        }
        "github_list_pull_request_commits" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint = format!(
                "/repos/{repository}/pulls/{number}/commits?page={page}&per_page={per_page}"
            );
            request_json(&token, &endpoint, |value| list_dto(value, per_page, commit_dto))
        }
        "github_list_pull_request_reviews" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint = format!(
                "/repos/{repository}/pulls/{number}/reviews?page={page}&per_page={per_page}"
            );
            request_json(&token, &endpoint, |value| list_dto(value, per_page, review_dto))
        }
        "github_list_pull_request_comments" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint = format!(
                "/repos/{repository}/pulls/{number}/comments?page={page}&per_page={per_page}"
            );
            request_json(&token, &endpoint, |value| {
                list_dto(value, per_page, review_comment_dto)
            })
        }
        "github_get_pull_request_status" => {
            let repository = repository_args(&args)?;
            let reference = match pull_status_selector(&args)? {
                PullStatusSelector::Ref(reference) => reference,
                PullStatusSelector::Pull(number) => {
                    let (_, pull) = request_json(
                        &token,
                        &format!("/repos/{repository}/pulls/{number}"),
                        |value| pull_dto(value).ok_or_else(|| "GitHub 响应格式不正确".to_string()),
                    )?;
                    pull.get("head")
                        .and_then(|item| item.get("sha"))
                        .and_then(Value::as_str)
                        .filter(|sha| {
                            !sha.is_empty()
                                && sha.len() <= 200
                                && sha.chars().all(|c| c.is_ascii_hexdigit())
                        })
                        .ok_or_else(|| "PR head SHA 不可用".to_string())?
                        .to_string()
                }
            };
            request_json(
                &token,
                &format!("/repos/{repository}/commits/{reference}/status"),
                combined_status_dto,
            )
        }
        "github_list_releases" => {
            let repository = repository_args(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint =
                format!("/repos/{repository}/releases?page={page}&per_page={per_page}");
            request_json(&token, &endpoint, |value| {
                list_dto(value, per_page, release_list_dto)
            })
        }
        "github_get_release" => {
            let repository = repository_args(&args)?;
            let endpoint = if args.get("id").is_some() {
                let id = positive_id(&args, "id")?;
                format!("/repos/{repository}/releases/{id}")
            } else if args.get("tag_name").is_some() {
                let tag = compare_ref_arg(&args, "tag_name")?;
                format!("/repos/{repository}/releases/tags/{tag}")
            } else {
                return Err("缺少参数 id".into());
            };
            request_json(&token, &endpoint, |value| {
                release_list_dto(value).ok_or_else(|| "GitHub 响应格式不正确".to_string())
            })
        }
        "github_list_release_assets" => {
            let repository = repository_args(&args)?;
            let id = positive_id(&args, "id")?;
            request_json(&token, &format!("/repos/{repository}/releases/{id}/assets"), |value| {
                list_dto(value, MAX_PAGE_SIZE, release_asset_dto)
            })
        }
        "github_list_tags" => {
            let repository = repository_args(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint = format!("/repos/{repository}/tags?page={page}&per_page={per_page}");
            request_json(&token, &endpoint, |value| list_dto(value, per_page, tag_dto))
        }
        "github_compare_commits" => {
            let repository = repository_args(&args)?;
            let base = compare_ref_arg(&args, "base")?;
            let head = compare_ref_arg(&args, "head")?;
            let endpoint = compare_endpoint(&repository, &base, &head)?;
            request_json(&token, &endpoint, compare_dto)
        }
        "github_list_workflows" => {
            let repository = repository_args(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint =
                format!("/repos/{repository}/actions/workflows?page={page}&per_page={per_page}");
            request_json(&token, &endpoint, |value| {
                object_list_dto(value, "workflows", per_page, workflow_summary_dto)
            })
        }
        "github_get_workflow_run" => {
            let repository = repository_args(&args)?;
            let run_id = positive_id(&args, "run_id")?;
            request_json(
                &token,
                &format!("/repos/{repository}/actions/runs/{run_id}"),
                |value| workflow_run_dto(value).ok_or_else(|| "GitHub 响应格式不正确".to_string()),
            )
        }
        "github_list_workflow_jobs" => {
            let repository = repository_args(&args)?;
            let run_id = positive_id(&args, "run_id")?;
            request_json(
                &token,
                &format!("/repos/{repository}/actions/runs/{run_id}/jobs"),
                |value| object_list_dto(value, "jobs", MAX_PAGE_SIZE, workflow_job_dto),
            )
        }
```

`release_list_dto` 复用已有的 `GithubReleaseDto`，不要新造一个带 `body` 的结构：

```rust
fn release_list_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubReleaseDto {
        id: value.get("id").and_then(Value::as_i64),
        tag_name: limited_string(value.get("tag_name")),
        name: limited_string(value.get("name")),
        target_commitish: limited_string(value.get("target_commitish")),
        draft: value.get("draft").and_then(Value::as_bool),
        prerelease: value.get("prerelease").and_then(Value::as_bool),
        html_url: limited_string(value.get("html_url")),
        created_at: limited_string(value.get("created_at")),
        published_at: limited_string(value.get("published_at")),
    })
    .ok()
}
```

`github_get_workflow_run` 继续用现有 `workflow_run_dto`。那个 DTO 没有 `logs_url`、`jobs_url`、`artifacts_url`。不要给它加这些字段。

- [ ] **Step 4: 跑 github_mcp 测试**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp:: --offline
```

Expected: PASS。没有新增的网络调用。策略关闭的用例返回「未启用」。

- [ ] **Step 5: 提交**

```bash
git add src-tauri/src/github_mcp.rs
git commit -m "feat(github-mcp): serve read-only PR, release, and Actions queries"
```

---

### Task 5: 文档与路线图

**Files:**
- Modify: `README.md` 约 125–126 行
- Modify: `docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md` 的「当前能力」和 P0 列表

- [ ] **Step 1: 改 README 工具列表**

把这两行：

```markdown
- `github_list_issues` / `github_list_pull_requests` / `github_get_pull_request` — Issue / PR，含 head/base、draft、mergeable、assignees
- `github_list_workflow_runs` — 轮询 Actions 状态
```

换成：

```markdown
- `github_list_issues` / `github_list_pull_requests` / `github_get_pull_request` — Issue / PR，含 head/base、draft、mergeable、assignees
- `github_list_pull_request_files` / `github_list_pull_request_commits` / `github_list_pull_request_reviews` / `github_list_pull_request_comments` / `github_get_pull_request_status` — PR 文件、提交、review、行内评论和 combined status；不含 patch 全文和日志
- `github_list_releases` / `github_get_release` / `github_list_release_assets` / `github_list_tags` / `github_compare_commits` — Release 元数据、资产清单、tag 和 commit 对比；不下载资产
- `github_list_workflows` / `github_list_workflow_runs` / `github_get_workflow_run` / `github_list_workflow_jobs` — Actions workflow、运行、单次 run 和 jobs；不含日志和 artifacts
```

不要改下面「GitHub API 写入」那段。写入开关的行为没变。

- [ ] **Step 2: 更新路线图**

在 `docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md` 的「当前能力」只读 API 那一条后面补一句：PR 文件/提交/review/评论/状态、Release、Release assets、tags、compare、workflow 定义、单次 run 和 jobs 已实现，全部 `risk: low`。

把 P0 列表里对应的 13 项改成删除线或移到「已实现」。保留这两句，不要改成可做：

```markdown
Workflow 日志和 Artifacts 即使是 GET，也可能包含部署信息或意外泄露的 Secret，建议标为 `risk: "medium"`，不要自动提供给内置助手。
```

以及「明确不做」里的日志/artifact 含义：本计划没有新增日志工具。

- [ ] **Step 3: 提交**

```bash
git add README.md docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md
git commit -m "docs: list the new GitHub read-only MCP tools"
```

---

## 做完后的检查

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp:: assistant:: --offline
```

Expected: 两个模块都 PASS。`assistant::` 不用改代码；跑它是为了确认新工具没有被误标成 `risk: high`，也没有把写入工具放进只读集合。助手过滤器看的是 `annotations.readOnlyHint`、`risk == "low"` 和 `github_` 前缀，本计划的 `tool()` 满足这三条。

再人工看一眼 `api_tool_definitions()`，确认没有出现这些字符串：

- `jobs/{id}/logs`
- `actions/artifacts`
- `uploads.github.com`
- `browser_download_url`

## 自检

- 设计第 3 节的 13 个路径都有 Task 4 的分支。
- `github_get_pull_request_status` 省略 `ref` 时先取 PR `head.sha`，并且只接受十六进制 SHA，避免把 PR JSON 里的任意字符串拼进路径。
- patch、日志 URL、资产下载 URL 在 Task 2 被测试锁住。
- 凭据经纪人没有任务。那是下一份计划。
- 没有「类似 Task N」或「自行处理边界」这种空步骤。
