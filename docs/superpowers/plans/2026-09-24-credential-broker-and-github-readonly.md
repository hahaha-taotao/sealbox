# Credential Broker MCP and GitHub Read-Only Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 补齐 GitHub PR / Release / Actions 只读工具，并增加默认关闭的凭据经纪人：列出元数据、对自定义 Token 的登记 origin 发 GET，永不把明文回给模型。

**Architecture:** 新 GitHub GET 全部走现有 `request_json` + DTO + `redact_text`。经纪人是新模块 `broker.rs`，独立 `broker_mcp_policy`，挂进 `mcp.rs` 的 `tools/list` 与 `call_tool`。助手过滤器已按 `risk != low` 丢弃，`credential_http_get` 标 `medium` 即可。

**Tech Stack:** 现有 `github_mcp` / `http_guard` / `ureq` / MCP HTTP loopback。

**Spec:** `docs/superpowers/specs/2026-09-24-credential-broker-mcp-design.md`

---

## File map

| File | Responsibility |
|---|---|
| Modify `src-tauri/src/github_mcp.rs` | 注册 13 个只读工具、DTO、`call_tool_text` 分支 |
| Create `src-tauri/src/broker.rs` | 策略、list credentials、HTTP GET |
| Modify `src-tauri/src/lib.rs` | `pub mod broker`；MCP 策略 command |
| Modify `src-tauri/src/mcp.rs` | tools/list 与 call_tool 接入 broker |
| Modify `src-tauri/src/commands.rs` | `broker_policy_get` / `broker_policy_set` |
| Modify `src-tauri/src/assistant.rs` | 只测：http_get 不进助手；GitHub 新工具进助手 |
| Modify `src/lib/tauri.ts` | Broker 策略类型 |
| Modify `src/App.vue` | MCP 页经纪人卡片 |
| Modify `README.md` | 工具列表 |
| Modify `docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md` | P0 标为已实现 |

不要实现 workflow logs、artifacts、任意 HTTP、POST。

---

### Task 1: GitHub 只读工具注册与 schema

**Files:**
- Modify: `src-tauri/src/github_mcp.rs`

- [ ] **Step 1: 改现有计数测试，让它先红**

把 `read_only_tools_have_closed_schemas` 的 `expected` 数组和 `tool_schemas_are_closed` 的 `assert_eq!(read_only, 9)` 改成包含：

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

只读总数改为 `22`（原 9 + 13）。

- [ ] **Step 2: 跑测试确认失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp::tests::read_only_tools_have_closed_schemas --offline
```

Expected: FAIL，`tool must be registered`。

- [ ] **Step 3: 在 `api_tool_definitions` 的 `github_list_workflow_runs` 之后、第一个 `write_tool` 之前插入定义**

共用 `credential` / `credential_id` / `repo` / `owner`。各工具 schema：

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
            "列出某个 PR 的 commit SHA、标题、作者。需要把 PR 和本地提交对上时调用。",
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
            "列出某个 PR 的 review：state、提交者、提交时间。判断谁批准/要求修改时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
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
            "读取 PR head 或指定 ref 的 combined status：state 与各 context。判断 CI 是否绿时调用。",
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
            "列出仓库 Release：tag、草稿、预发布、html_url。不含 body 全文。",
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
            "读取单个 Release 元数据。传 id 或 tag_name 之一。body 截断，不含资产二进制。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("id", json!({"type":"integer","minimum":1})),
                    ("tag_name", string_schema(1, 200)),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_list_release_assets",
            "列出某个 Release 的资产名、大小、content_type、下载次数。不下载文件。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("id", json!({"type":"integer","minimum":1})),
                ],
                &["repo", "id"],
            ),
        ),
        tool(
            "github_list_tags",
            "列出仓库 tag 名与 commit SHA。",
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
            "比较 base 与 head：ahead/behind、文件列表（不含 patch）。",
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
            "列出仓库 Actions workflow：id、name、path、state。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_get_workflow_run",
            "读取单次 workflow run：status、conclusion、head_sha、html_url。不含日志。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("run_id", json!({"type":"integer","minimum":1})),
                ],
                &["repo", "run_id"],
            ),
        ),
        tool(
            "github_list_workflow_jobs",
            "列出某次 run 的 jobs：name、status、conclusion、各 step 名称与结论。不含日志。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("run_id", json!({"type":"integer","minimum":1})),
                ],
                &["repo", "run_id"],
            ),
        ),
```

- [ ] **Step 4: 再跑 schema 测试**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp::tests::read_only_tools_have_closed_schemas github_mcp::tests::tool_schemas_are_closed --offline
```

Expected: PASS。`call_tool_text` 对这些名字仍返回「未知 GitHub 工具」，下一任务再接。

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/github_mcp.rs
git commit -m "$(cat <<'EOF'
feat(github-mcp): register PR release and Actions read tools

EOF
)"
```

---

### Task 2: GitHub 只读调用与 DTO

**Files:**
- Modify: `src-tauri/src/github_mcp.rs`

- [ ] **Step 1: 给 DTO 映射写单测**

在 `github_mcp.rs` tests 中追加：

```rust
    #[test]
    fn pr_file_and_status_dtos_drop_patches_and_tokens() {
        let file = pr_file_dto(&json!({
            "filename":"src/lib.rs",
            "status":"modified",
            "additions":1,
            "deletions":1,
            "changes":2,
            "sha":"abc",
            "patch":"@@ leaked ghp_test_token_value",
            "blob_url":"https://github.com/x"
        }))
        .unwrap();
        assert_eq!(file["filename"], "src/lib.rs");
        assert!(file.get("patch").is_none());
        let status = combined_status_dto(&json!({
            "state":"success",
            "sha":"deadbeef",
            "total_count":1,
            "statuses":[{"context":"ci","state":"success","description":"ok","target_url":"https://example.com"}]
        }))
        .unwrap();
        assert_eq!(status["state"], "success");
        assert_eq!(status["statuses"][0]["context"], "ci");
        assert!(git_ref_arg("abc/def").is_ok());
        assert!(git_ref_arg("main..other").is_err());
        assert!(git_ref_arg("http://evil").is_err());
    }
```

- [ ] **Step 2: 跑测试确认失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp::tests::pr_file_and_status_dtos_drop_patches_and_tokens --offline
```

Expected: FAIL，函数不存在。

- [ ] **Step 3: 实现 DTO、参数、match 分支**

辅助函数：

```rust
fn git_ref_arg(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() || value.len() > 200 || value.contains("..") {
        return Err("ref 不合法".into());
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
    {
        return Err("ref 不合法".into());
    }
    Ok(value.to_string())
}

fn optional_git_ref(args: &Value) -> Result<Option<String>, String> {
    match args.get("ref").and_then(Value::as_str) {
        None => Ok(None),
        Some(value) => Ok(Some(git_ref_arg(value)?)),
    }
}

fn run_id(args: &Value) -> Result<u64, String> {
    args.get("run_id")
        .and_then(Value::as_u64)
        .filter(|value| *value >= 1)
        .ok_or_else(|| "缺少参数 run_id".into())
}

fn release_id(args: &Value) -> Result<u64, String> {
    args.get("id")
        .and_then(Value::as_u64)
        .filter(|value| *value >= 1)
        .ok_or_else(|| "缺少参数 id".into())
}
```

DTO（字段均 `Option`/`Vec`，body 用 `limited_string_with_cap(..., MAX_DESCRIPTION_BYTES)`）：

- `pr_file_dto`：filename, status, additions, deletions, changes, sha。不要 patch。
- `commit_dto`：sha, message（截断 200）, author_login, html_url。
- `review_dto`：id, state, user, submitted_at, body（截断）。
- `pull_comment_dto`：id, path, line, user, body（截断）, html_url。
- `combined_status_dto`：state, sha, total_count, statuses[{context,state,description,target_url}] 最多 20。
- `tag_dto`：name, sha（从 `commit.sha`）。
- `compare_dto`：status, ahead_by, behind_by, total_commits, files 用 `pr_file_dto` 最多 50。
- `workflow_dto`：id, name, path, state。
- `workflow_job_dto`：id, name, status, conclusion, steps[{name,status,conclusion}] 最多 30，无 log。
- `release_asset_dto`：id, name, content_type, size, download_count。无 url 里的 token query 则只返回 name/size。

在 `call_tool_text` 的 `github_list_workflow_runs` 分支后、`_ =>` 前插入对应 `request_json`。

`github_get_pull_request_status`：

```rust
        "github_get_pull_request_status" => {
            let repository = repository_args(&args)?;
            let reference = if let Some(value) = optional_git_ref(&args)? {
                value
            } else {
                let number = issue_number(&args)?;
                let (_, pr) = request_json(&token, &format!("/repos/{repository}/pulls/{number}"), |value| {
                    pull_dto(value).ok_or_else(|| "GitHub 响应格式不正确".into())
                })?;
                let sha = pr
                    .get("head")
                    .and_then(|head| head.get("sha"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| "无法读取 PR head SHA".to_string())?;
                git_ref_arg(sha)?
            };
            let encoded = percent_encode(&reference, false);
            request_json(
                &token,
                &format!("/repos/{repository}/commits/{encoded}/status"),
                |value| combined_status_dto(value).ok_or_else(|| "GitHub 响应格式不正确".into()),
            )
        }
```

注意：内层 `request_json` 会再消耗一次网络；单测 DTO 即可，不必在单元测试里打真实 GitHub。`github_get_release`：有 `id` 走 `/releases/{id}`，否则要 `tag_name` 走 `/releases/tags/{tag}`，两者都缺则报错。

`github_compare_commits` path：`/repos/{repo}/compare/{base}...{head}`，base/head 都经 `git_ref_arg` 再 `percent_encode`。

- [ ] **Step 4: 跑 github_mcp 测试**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml github_mcp::tests --offline
```

Expected: PASS。未知工具应变少；disabled policy 测试若枚举工具名，把新只读名字加进「未启用」循环的抽样（至少 `github_list_tags`）。

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/github_mcp.rs
git commit -m "$(cat <<'EOF'
feat(github-mcp): fetch PR reviews releases and workflow jobs

EOF
)"
```

---

### Task 3: 经纪人 list credentials

**Files:**
- Create: `src-tauri/src/broker.rs`
- Modify: `src-tauri/src/lib.rs`

- [ ] **Step 1: 模块 + 失败测试**

`lib.rs` 在 `pub mod backup;` 后加 `pub mod broker;`。

`broker.rs` 测试：

```rust
    #[test]
    fn list_credentials_omits_secrets_and_respects_kind() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .upsert_entry(
                &dek,
                crate::vault::UpsertEntry {
                    id: None,
                    kind: crate::vault::EntryKind::ApiToken,
                    title: "agentos".into(),
                    account: Some("octocat".into()),
                    url: Some("https://api.github.com".into()),
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: Some("do-not-leak".into()),
                    secret: crate::vault::SecretPayload::ApiToken {
                        service: "custom".into(),
                        account: Some("octocat".into()),
                        token: "ghp_test_token_value".into(),
                    },
                },
            )
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        save_policy(
            session.vault().unwrap(),
            session.dek().unwrap(),
            &BrokerMcpPolicy { enabled: true },
        )
        .unwrap();
        let text = call_tool(
            &mut session,
            "vault_list_credentials",
            json!({"kind":"api_token","query":"agent"}),
        )
        .unwrap();
        assert!(text.contains("agentos"));
        assert!(!text.contains("ghp_test_token_value"));
        assert!(!text.contains("do-not-leak"));
        save_policy(
            session.vault().unwrap(),
            session.dek().unwrap(),
            &BrokerMcpPolicy { enabled: false },
        )
        .unwrap();
        let err = call_tool(&mut session, "vault_list_credentials", json!({})).unwrap_err();
        assert!(err.contains("未启用"));
    }
```

- [ ] **Step 2: 跑测试确认失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml broker::tests::list_credentials_omits_secrets_and_respects_kind --offline
```

Expected: 编译失败。

- [ ] **Step 3: 实现策略与 list**

```rust
pub const POLICY_KEY: &str = "broker_mcp_policy";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct BrokerMcpPolicy {
    pub enabled: bool,
}

impl Default for BrokerMcpPolicy {
    fn default() -> Self {
        Self { enabled: false }
    }
}

pub fn load_policy(vault: &Vault, dek: &[u8; 32]) -> BrokerMcpPolicy {
    let Some(raw) = vault.get_secret_setting(dek, POLICY_KEY).ok().flatten() else {
        return BrokerMcpPolicy::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save_policy(vault: &Vault, dek: &[u8; 32], policy: &BrokerMcpPolicy) -> Result<(), String> {
    vault
        .set_secret_setting(dek, POLICY_KEY, &serde_json::to_string(policy).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

pub fn tool_definitions(policy: &BrokerMcpPolicy) -> Vec<Value> {
    if !policy.enabled {
        return Vec::new();
    }
    vec![
        tool_low(
            "vault_list_credentials",
            "列出金库条目的标题、类型、账号和网址。不含密码、Token、私钥或备注。按标题选用凭据前可调用。",
            schema(&[
                ("kind", json!({"type":"string","enum":["website","api_token","ssh","mailbox","mail_auth","server","database","client_cert"]})),
                ("query", json!({"type":"string","minLength":1,"maxLength":100})),
            ], &[]),
        ),
        json!({
            "name": "credential_http_get",
            "description": "用金库里已填写网址的自定义 API Token 对同一 origin 发 HTTPS GET。永不返回 Token。仅限已登记的 https 地址。",
            "inputSchema": schema(&[
                ("credential", json!({"type":"string","minLength":1,"maxLength":100})),
                ("credential_id", json!({"type":"string","minLength":1,"maxLength":100})),
                ("path", json!({"type":"string","minLength":1,"maxLength":500,"description":"相对路径，必须以 / 开头"})),
            ], &["path"]),
            "readOnly": true,
            "risk": "medium",
            "annotations": crate::github_mcp::annotations(true, false)
        }),
    ]
}

pub fn is_broker_tool(name: &str) -> bool {
    matches!(name, "vault_list_credentials" | "credential_http_get")
}
```

`call_tool`：未启用返回「凭据经纪人未启用」。list 用 `ListFilter { query, kind }`，映射 `EntryDto` 到 `{id,kind,title,account,url,has_totp,fingerprint}`，最多 100 条。

`tool_low` 与 github 的 `tool()` 相同结构（`risk: low`）。不要从 github_mcp 把 `tool` 改成 pub，经纪人自己写一个小 json! 即可。

- [ ] **Step 4: 跑测试**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml broker::tests::list_credentials_omits_secrets_and_respects_kind --offline
```

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/broker.rs src-tauri/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(mcp): list vault credential metadata without secrets

EOF
)"
```

---

### Task 4: credential_http_get 安全边界

**Files:**
- Modify: `src-tauri/src/broker.rs`

- [ ] **Step 1: 写失败测试**

```rust
    #[test]
    fn http_get_rejects_reserved_services_and_path_escape() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let github = vault
            .upsert_entry(
                &dek,
                crate::vault::UpsertEntry {
                    id: None,
                    kind: crate::vault::EntryKind::ApiToken,
                    title: "github".into(),
                    account: None,
                    url: None,
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: crate::vault::SecretPayload::ApiToken {
                        service: "github".into(),
                        account: None,
                        token: "ghp_test_token_value".into(),
                    },
                },
            )
            .unwrap();
        let custom = vault
            .upsert_entry(
                &dek,
                crate::vault::UpsertEntry {
                    id: None,
                    kind: crate::vault::EntryKind::ApiToken,
                    title: "widgets".into(),
                    account: None,
                    url: Some("https://api.example.com/v1".into()),
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: crate::vault::SecretPayload::ApiToken {
                        service: "custom".into(),
                        account: None,
                        token: "secret-token-value".into(),
                    },
                },
            )
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        save_policy(session.vault().unwrap(), session.dek().unwrap(), &BrokerMcpPolicy { enabled: true }).unwrap();
        let err = call_tool(
            &mut session,
            "credential_http_get",
            json!({"credential_id": github.id, "path": "/user"}),
        )
        .unwrap_err();
        assert!(err.contains("专用"), "{err}");
        for path in ["/../secret", "http://evil.test/", "/foo@bar", "foo"] {
            let err = call_tool(
                &mut session,
                "credential_http_get",
                json!({"credential_id": custom.id, "path": path}),
            )
            .unwrap_err();
            assert!(err.contains("path") || err.contains("路径"), "{path}: {err}");
        }
        let built = build_request_url("https://api.example.com/v1", "/widgets?limit=1").unwrap();
        assert_eq!(built, "https://api.example.com/widgets?limit=1");
        assert!(build_request_url("https://api.example.com/v1", "/widgets#x").is_err());
        assert!(build_request_url("http://api.example.com", "/x").is_err());
    }
```

- [ ] **Step 2: 跑测试确认失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml broker::tests::http_get_rejects_reserved_services_and_path_escape --offline
```

Expected: FAIL。

- [ ] **Step 3: 实现 URL 拼接与调用**

`build_request_url(entry_url, path)`：

1. `http_guard::parse_http_url(entry_url, true)`
2. scheme 必须 https
3. path 必须以 `/` 开头，不得含 `://` `\\` `..` `@` `#` `\r` `\n` `\0`
4. 最终 URL = `https://{host}:{port}{path}`（默认 443 可省略端口）
5. 再 `parse_http_url` + `assert_public_target`

解析凭据：列出 `ApiToken`，匹配 id / title / account，逻辑对齐 `github_mcp::resolve_github_credential` 但不过滤 service==github。若 service ∈ `{github,gitee,gitlab,zoomkey-jira,zoomkey-crm}` 拒绝。url 空拒绝。

真实 GET 用 ureq，复制 `github_mcp::request_json` 的 builder 模式，但 host 来自条目 origin，Authorization Bearer token，Accept application/json，redirects(0)，响应 64KiB，`redact_text(&body, &[token])`。单元测试只覆盖 build_request_url 与拒绝分支，不监听端口。

- [ ] **Step 4: 跑 broker 测试**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml broker::tests --offline
```

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/broker.rs
git commit -m "$(cat <<'EOF'
feat(mcp): GET allowlisted credential origins without leaking tokens

EOF
)"
```

---

### Task 5: 接入 MCP 路由、助手过滤、设置页

**Files:**
- Modify: `src-tauri/src/mcp.rs`
- Modify: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/assistant.rs`
- Modify: `src/lib/tauri.ts`
- Modify: `src/App.vue`
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md`

- [ ] **Step 1: 在 mcp.rs 测试里断言开关**

现有 `disabled_github_tools_are_not_exposed` 附近追加：

```rust
    #[test]
    fn broker_tools_follow_independent_switch() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let mutex = Mutex::new(session);
        let names = super::tools_list(&mutex)["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_string))
            .collect::<Vec<_>>();
        assert!(!names.contains(&"vault_list_credentials".into()));
        {
            let mut s = mutex.lock().unwrap();
            let vault = s.vault().unwrap();
            let dek = s.dek().unwrap();
            crate::broker::save_policy(vault, dek, &crate::broker::BrokerMcpPolicy { enabled: true }).unwrap();
        }
        let names = super::tools_list(&mutex)["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_string))
            .collect::<Vec<_>>();
        assert!(names.contains(&"vault_list_credentials".into()));
        assert!(names.contains(&"credential_http_get".into()));
        let def = super::tools_list(&mutex)["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "credential_http_get")
            .cloned()
            .unwrap();
        assert_eq!(def["risk"], "medium");
        assert_eq!(def["readOnly"], true);
    }
```

助手测试（`assistant.rs` 已有 `safe_tool_definitions` 的测试则追加，否则在 assistant tests 加）：构造假 `tools/list` JSON，含 `github_list_tags` risk low 与 `credential_http_get` risk medium，断言只有前者进入 `safe_tool_definitions`。

- [ ] **Step 2: 跑测试确认失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml mcp::tests::broker_tools_follow_independent_switch --offline
```

Expected: FAIL。

- [ ] **Step 3: 接线**

`tools_list`：在 github/zoomkey 之后：

```rust
    if let Some(policy) = locked.vault().ok().and_then(|vault| {
        locked.dek().ok().map(|dek| crate::broker::load_policy(vault, dek))
    }) {
        tools.extend(crate::broker::tool_definitions(&policy));
    }
```

`call_tool` 在 zoomkey 之后：

```rust
    if crate::broker::is_broker_tool(name) {
        let mut s = lock_session(session);
        return crate::broker::call_tool(&mut s, name, args);
    }
```

在 broker `call_tool` 成功/失败时写审计 `mcp_broker` / `mcp_broker_denied`（可在 mcp.rs 包一层，与 github 相同）。最小做法：broker 内部 `vault.audit`。

`commands.rs`：

```rust
#[tauri::command]
pub fn broker_policy_get(state: State<AppState>) -> Result<crate::broker::BrokerMcpPolicy, String> {
    let session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let dek = session.dek().map_err(map_err)?;
    Ok(crate::broker::load_policy(vault, dek))
}

#[tauri::command]
pub fn broker_policy_set(
    state: State<AppState>,
    policy: crate::broker::BrokerMcpPolicy,
) -> Result<crate::broker::BrokerMcpPolicy, String> {
    let session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let dek = session.dek().map_err(map_err)?;
    crate::broker::save_policy(vault, dek, &policy).map_err(map_err)?;
    Ok(crate::broker::load_policy(vault, dek))
}
```

`lib.rs` handler 注册这两个命令。

`tauri.ts`：`BrokerMcpPolicy { enabled: boolean }`，`brokerPolicyGet` / `brokerPolicySet`。

`App.vue` MCP 页：GitHub 卡片后加「凭据经纪人」，开关默认关，打开时 `window.confirm` 使用 spec 里的那句说明。展示两行工具名。

README MCP 工具列表补 GitHub P0 名字和两条经纪人工具，写明默认关、GET-only、不回 Token。

roadmap：把本期工具从 P0 移到「当前能力」。

- [ ] **Step 4: 全量测试**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml --offline
```

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/mcp.rs src-tauri/src/commands.rs src-tauri/src/lib.rs src-tauri/src/assistant.rs src-tauri/src/broker.rs src/lib/tauri.ts src/App.vue README.md docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md
git commit -m "$(cat <<'EOF'
feat(mcp): expose credential broker behind its own switch

EOF
)"
```

---

## 验收

- GitHub MCP 开、经纪人关：`tools/list` 有新的 PR/CI 工具，没有 `vault_list_credentials`。
- 经纪人开：可列出标题；对 github service 的 Token 调 `credential_http_get` 被拒绝。
- 助手探测：能看到 `github_list_tags`，看不到 `credential_http_get`。
- 现有 git 写入确认框与 ZoomKey 行为不变。
