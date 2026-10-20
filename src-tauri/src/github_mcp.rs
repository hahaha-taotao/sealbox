use crate::http_guard::{assert_public_target, parse_http_url, sha256_hex, PublicResolver};
use crate::redact::redact_text;
use crate::session::Session;
use crate::vault::SecretPayload;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::io::Read;
use std::time::Duration;

const API_BASE: &str = "https://api.github.com";
const API_VERSION: &str = "2022-11-28";
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_DESCRIPTION_BYTES: usize = 2 * 1024;
const MAX_RELEASE_BODY_BYTES: usize = 64 * 1024;
const MAX_RELEASE_TAG_CHARS: usize = 200;
const MAX_PAGE_SIZE: u64 = 50;
const ELLIPSIS: &str = "…";

#[derive(Clone, Debug, Default)]
pub struct GithubAuditContext {
    pub repository: Option<String>,
    pub path: Option<String>,
    pub reference: Option<String>,
}

#[derive(Clone, Debug)]
pub struct GithubCallResult {
    pub text: String,
    pub status: u16,
    pub result_count: Option<usize>,
    pub credential_fingerprint: String,
    pub context: GithubAuditContext,
}

#[derive(Clone, Debug)]
pub struct GithubCallError {
    pub message: String,
    pub status: Option<u16>,
    pub reason: &'static str,
    pub credential_fingerprint: Option<String>,
    pub context: GithubAuditContext,
}

impl GithubCallError {
    fn validation(message: impl Into<String>, context: GithubAuditContext) -> Self {
        Self {
            message: message.into(),
            status: None,
            reason: "validation",
            credential_fingerprint: None,
            context,
        }
    }
}

impl From<String> for GithubCallError {
    fn from(message: String) -> Self {
        Self::validation(message, GithubAuditContext::default())
    }
}

impl From<&str> for GithubCallError {
    fn from(message: &str) -> Self {
        Self::validation(message, GithubAuditContext::default())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubCredentialMeta {
    pub id: String,
    pub title: String,
    pub account: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ResolvedGithubCredential {
    pub id: String,
    pub title: String,
    pub token: String,
}

fn credential_prop() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 100,
        "description": "GitHub Token 的标题、账号或 ID。金库里只有一个 GitHub Token 时可省略。"
    })
}

fn credential_id_prop() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 100,
        "description": "兼容旧参数，等同于 credential。"
    })
}

fn repo_prop() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 201,
        "description": "仓库，推荐 owner/repo，例如 hahaha-taotao/sealbox。也兼容 https://github.com/owner/repo，或与 owner 字段拆开填写。"
    })
}

#[derive(Clone, Debug, Serialize)]
struct GithubUserDto {
    id: Option<i64>,
    login: Option<String>,
    name: Option<String>,
    company: Option<String>,
    blog: Option<String>,
    html_url: Option<String>,
    public_repos: Option<i64>,
    private_repos: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubOwnerDto {
    login: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubRepositoryDto {
    id: Option<i64>,
    full_name: Option<String>,
    name: Option<String>,
    owner: GithubOwnerDto,
    private: Option<bool>,
    fork: Option<bool>,
    default_branch: Option<String>,
    html_url: Option<String>,
    description: Option<String>,
    updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubIssueDto {
    number: Option<i64>,
    title: Option<String>,
    state: Option<String>,
    html_url: Option<String>,
    user: GithubOwnerDto,
    labels: Vec<String>,
    assignees: Vec<String>,
    comments: Option<i64>,
    created_at: Option<String>,
    updated_at: Option<String>,
    closed_at: Option<String>,
    body: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubRefDto {
    #[serde(rename = "ref")]
    git_ref: Option<String>,
    sha: Option<String>,
    repo: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubPullDto {
    number: Option<i64>,
    title: Option<String>,
    state: Option<String>,
    html_url: Option<String>,
    user: GithubOwnerDto,
    labels: Vec<String>,
    assignees: Vec<String>,
    requested_reviewers: Vec<String>,
    draft: Option<bool>,
    mergeable: Option<bool>,
    mergeable_state: Option<String>,
    head: GithubRefDto,
    base: GithubRefDto,
    created_at: Option<String>,
    updated_at: Option<String>,
    body: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubReleaseDto {
    id: Option<i64>,
    tag_name: Option<String>,
    name: Option<String>,
    target_commitish: Option<String>,
    draft: Option<bool>,
    prerelease: Option<bool>,
    html_url: Option<String>,
    created_at: Option<String>,
    published_at: Option<String>,
}

/// 旧工具名不再单独注册。已经接到旧名的客户端仍落到同一实现。
pub fn canonical_tool_name(name: &str) -> &str {
    match name {
        "github_get_authenticated_user" => "github_user_info",
        "github_list_repositories" => "github_repo_list",
        "github_get_repository" => "github_repo_get",
        "github_list_issues" => "github_issues_list",
        "github_list_pull_requests" => "github_pulls_list",
        "github_create_issue" => "github_issue_create",
        "github_create_issue_comment" => "github_issue_comment",
        "github_create_pull_request" => "github_pr_create",
        "github_create_release" => "github_release_create",
        "github_list_releases" => "github_release_list",
        "github_get_release" => "github_release_get",
        other => other,
    }
}

/// 常用任务工具按 action 落到已有实现。未知名原样返回。
fn task_dispatch_name(name: &str, args: &Value) -> Result<String, String> {
    let canonical = canonical_tool_name(name);
    let action = args.get("action").and_then(Value::as_str).unwrap_or("");
    let mapped = match canonical {
        "github_release" => match action {
            "list" => "github_release_list",
            "get" => "github_release_get",
            "notes" => "github_release_generate_notes",
            "create" => "github_release_create",
            "publish" => "github_release_publish",
            "" => return Err("github_release 需要 action：list、get、notes、create、publish".into()),
            other => {
                return Err(format!(
                    "github_release 不支持 action={other}。可用 list、get、notes、create、publish"
                ))
            }
        },
        "github_pr" => match action {
            "list" => "github_pulls_list",
            "get" => "github_get_pull_request",
            "create" => "github_pr_create",
            "merge" => "github_pr_merge",
            "" => return Err("github_pr 需要 action：list、get、create、merge".into()),
            other => {
                return Err(format!(
                    "github_pr 不支持 action={other}。可用 list、get、create、merge"
                ))
            }
        },
        "github_issue" => match action {
            "list" => "github_issues_list",
            "get" => "github_issues_get",
            "create" => "github_issue_create",
            "comment" => "github_issue_comment",
            "close" => "github_issue_close",
            "" => return Err("github_issue 需要 action：list、get、create、comment、close".into()),
            other => {
                return Err(format!(
                    "github_issue 不支持 action={other}。可用 list、get、create、comment、close"
                ))
            }
        },
        _ => canonical,
    };
    Ok(mapped.to_string())
}

pub fn api_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "github_list_credentials",
            "列出本地活动 GitHub Token 的标题和账号。回答「我有哪些 GitHub Token / 该用哪条凭据」时调用。金库里只有一条时可省略 credential。永不返回 Token 明文。",
            schema(&[], &[]),
        ),
        tool(
            "github_user_info",
            "读取当前 GitHub 账号的 login、姓名、公开/私有仓库数。回答「我是谁 / 这个 Token 属于哪个账号」时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                ],
                &[],
            ),
        ),
        tool(
            "github_repo_list",
            "列出当前 Token 可见的仓库（full_name、默认分支、私有与否）。回答「我有多少 GitHub 仓库 / 列出我的仓库」时调用。默认只看自己拥有的仓库。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("type", json!({"type":"string","enum":["all","owner","public","private","member"],"description":"仓库范围，原样传给 GitHub type 参数"})),
                    ("visibility", json!({"type":"string","enum":["all","public","private"],"default":"all"})),
                    ("affiliation", json!({"type":"string","enum":["owner","collaborator","organization_member"],"default":"owner"})),
                    ("sort", json!({"type":"string","enum":["created","updated","pushed","full_name"]})),
                    ("direction", json!({"type":"string","enum":["asc","desc"]})),
                    ("name_contains", string_schema(1, 200)),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &[],
            ),
        ),
        tool(
            "github_repo_get",
            "读取单个仓库的元数据：默认分支、是否私有、描述、更新时间。需要确认某个 owner/repo 是否存在或默认分支是什么时调用。",
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
            "github_issues_list",
            "列出仓库 Issue（不含 PR）：编号、标题、状态、标签、指派人、评论数。回答「这个仓库有哪些未关闭 Issue」时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("state", json!({"type":"string","enum":["open","closed","all"],"default":"open"})),
                    ("labels", string_schema(1, 400)),
                    ("assignee", string_schema(1, 100)),
                    ("creator", string_schema(1, 100)),
                    ("since", string_schema(1, 40)),
                    ("sort", json!({"type":"string","enum":["created","updated","comments"]})),
                    ("direction", json!({"type":"string","enum":["asc","desc"]})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_pulls_list",
            "列出仓库 Pull Request：编号、标题、draft、head/base、mergeable、指派人和 requested reviewers。回答「有哪些未合并 PR / 这个 PR 能不能合」时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("state", json!({"type":"string","enum":["open","closed","all"],"default":"open"})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_get_pull_request",
            "读取单个 PR 的完整协作状态：draft、head/base SHA、mergeable、reviewers。需要判断某个 PR 能否合并或当前基于哪条分支时调用。",
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
            "github_release_list",
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
            "github_release_get",
            "读取单个 Release 的元数据。传 id 或 tag_name 之一。不含 body，不含资产二进制。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                    ("tag_name", string_schema(1, 200)),
                ],
                &["repo"],
            ),
        ),
        write_tool(
            "github_issue_create",
            "在仓库创建 Issue。用户说「帮我开一个 bug / 功能单」时调用。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("title", string_schema(1, 256)),
                    ("body", string_schema(0, MAX_RELEASE_BODY_BYTES as u64)),
                    ("labels", json!({"type":"string","minLength":1,"maxLength":400,"description":"逗号分隔的标签名"})),
                ],
                &["repo", "title"],
            ),
        ),
        write_tool(
            "github_issue_comment",
            "在已有 Issue 或 PR 下追加一条评论。需要回复 Issue/PR 时调用。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("body", string_schema(1, MAX_RELEASE_BODY_BYTES as u64)),
                ],
                &["repo", "number", "body"],
            ),
        ),
        write_tool(
            "github_pr_create",
            "从 head 分支向 base 开 PR。用户说「帮我提 PR」时调用。默认 draft=true。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("title", string_schema(1, 256)),
                    ("head", string_schema(1, 200)),
                    ("base", string_schema(1, 200)),
                    ("body", string_schema(0, MAX_RELEASE_BODY_BYTES as u64)),
                    ("draft", json!({"type":"boolean","default":true})),
                ],
                &["repo", "title", "head", "base"],
            ),
        ),
        write_tool(
            "github_pr_merge",
            "合并一个 Pull Request。merge_method 只能是 merge、squash 或 rebase，默认 merge。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("merge_method", json!({"type":"string","enum":["merge","squash","rebase"],"default":"merge"})),
                ],
                &["repo", "number"],
            ),
        ),
        tool(
            "github_release_generate_notes",
            "根据 tag 生成建议的 Release 标题和正文，不会创建 Release。body 最多返回 64 KiB。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("tag_name", string_schema(1, MAX_RELEASE_TAG_CHARS as u64)),
                    ("previous_tag_name", string_schema(1, MAX_RELEASE_TAG_CHARS as u64)),
                    ("target_commitish", string_schema(1, 200)),
                ],
                &["repo", "tag_name"],
            ),
        ),
        write_tool(
            "github_release_publish",
            "把草稿 Release 正式发布（draft=false）。可同时改名称、正文或 prerelease。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                    ("name", string_schema(1, 200)),
                    ("body", string_schema(0, MAX_RELEASE_BODY_BYTES as u64)),
                    ("prerelease", json!({"type":"boolean"})),
                ],
                &["repo", "id"],
            ),
        ),
        write_tool(
            "github_release_create",
            "在仓库创建 Release。用户说「打一个 GitHub Release」时调用。默认 draft=true。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("tag_name", string_schema(1, MAX_RELEASE_TAG_CHARS as u64)),
                    ("target_commitish", string_schema(1, 200)),
                    ("name", string_schema(1, 200)),
                    ("body", string_schema(0, MAX_RELEASE_BODY_BYTES as u64)),
                    ("draft", json!({"type":"boolean","default":true})),
                    ("prerelease", json!({"type":"boolean","default":false})),
                    ("generate_release_notes", json!({"type":"boolean","default":false})),
                    ("make_latest", json!({"type":"string","enum":["true","false","legacy"],"default":"legacy"})),
                ],
                &["repo", "tag_name"],
            ),
        ),
    ]
}

fn task_tool(name: &str, description: &str, actions: &[&str], properties: &[(&str, Value)], required: &[&str]) -> Value {
    let mut props = Map::new();
    props.insert(
        "action".into(),
        json!({
            "type": "string",
            "enum": actions,
            "description": "要执行的动作。只读动作不弹确认，写入动作弹出一次桌面确认。"
        }),
    );
    for (key, value) in properties {
        props.insert((*key).to_string(), value.clone());
    }
    let mut required_fields = vec![Value::String("action".into())];
    required_fields.extend(required.iter().map(|item| Value::String((*item).to_string())));
    json!({
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": Value::Object(props),
            "required": required_fields,
            "additionalProperties": false
        },
        "readOnly": false,
        "risk": "high",
        "annotations": annotations(false, true)
    })
}

fn task_tool_definitions() -> Vec<Value> {
    let credential = ("credential", credential_prop());
    let credential_id = ("credential_id", credential_id_prop());
    let repo = ("repo", repo_prop());
    let owner = ("owner", string_schema(1, 100));
    let number = (
        "number",
        json!({"type":"integer","minimum":1,"maximum":1000000000}),
    );
    vec![
        task_tool(
            "github_release",
            "版本管理。list 列 Release，get 读一个（id 或 tag_name），notes 只生成说明不创建，create 建草稿，publish 把草稿发布。",
            &["list", "get", "notes", "create", "publish"],
            &[
                credential.clone(),
                credential_id.clone(),
                repo.clone(),
                owner.clone(),
                ("id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                ("tag_name", string_schema(1, 200)),
                ("previous_tag_name", string_schema(1, 200)),
                ("target_commitish", string_schema(1, 200)),
                ("name", string_schema(1, 200)),
                ("body", string_schema(0, MAX_RELEASE_BODY_BYTES as u64)),
                ("draft", json!({"type":"boolean","default":true})),
                ("prerelease", json!({"type":"boolean"})),
                ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
            ],
            &["repo"],
        ),
        task_tool(
            "github_pr",
            "Pull Request。list 与 get 只读；create 默认草稿；merge 必须带编号，方式为 merge、squash 或 rebase。",
            &["list", "get", "create", "merge"],
            &[
                credential.clone(),
                credential_id.clone(),
                repo.clone(),
                owner.clone(),
                ("state", json!({"type":"string","enum":["open","closed","all"],"default":"open"})),
                number.clone(),
                ("title", string_schema(1, 256)),
                ("head", string_schema(1, 200)),
                ("base", string_schema(1, 200)),
                ("body", string_schema(0, MAX_RELEASE_BODY_BYTES as u64)),
                ("draft", json!({"type":"boolean","default":true})),
                ("merge_method", json!({"type":"string","enum":["merge","squash","rebase"],"default":"merge"})),
                ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
            ],
            &["repo"],
        ),
        task_tool(
            "github_issue",
            "Issue。list 与 get 只读；create 开新单；comment 追加评论；close 关闭，不改标题和正文。",
            &["list", "get", "create", "comment", "close"],
            &[
                credential,
                credential_id,
                repo,
                owner,
                ("state", json!({"type":"string","enum":["open","closed","all"],"default":"open"})),
                number,
                ("title", string_schema(1, 256)),
                ("body", string_schema(0, MAX_RELEASE_BODY_BYTES as u64)),
                ("labels", string_schema(1, 400)),
                ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
            ],
            &["repo"],
        ),
    ]
}

pub fn tool_definitions() -> Vec<Value> {
    let mut tools = api_tool_definitions();
    tools.extend(task_tool_definitions());
    tools.extend(crate::git_workspace::tool_definitions());
    tools
}

pub fn tool_definitions_for_mcp() -> Vec<Value> {
    tool_definitions()
}

fn string_schema(minimum: u64, maximum: u64) -> Value {
    json!({"type":"string","minLength":minimum,"maxLength":maximum})
}

fn schema(properties: &[(&str, Value)], required: &[&str]) -> Value {
    let mut props = Map::new();
    for (name, value) in properties {
        props.insert((*name).to_string(), value.clone());
    }
    json!({
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": false
    })
}

pub(crate) fn annotations(read_only: bool, destructive: bool) -> Value {
    json!({
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": read_only,
        "openWorldHint": true
    })
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "readOnly": true,
        "risk": "low",
        "annotations": annotations(true, false)
    })
}

fn write_tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "readOnly": false,
        "risk": "high",
        "annotations": annotations(false, true)
    })
}

pub fn is_github_api_tool(name: &str) -> bool {
    let canonical = canonical_tool_name(name);
    api_tool_definitions()
        .iter()
        .any(|definition| definition.get("name").and_then(Value::as_str) == Some(canonical))
}

pub fn is_github_tool(name: &str) -> bool {
    is_github_api_tool(name) || crate::git_workspace::is_git_tool(name)
}

pub fn list_credentials(session: &Session) -> Result<Vec<GithubCredentialMeta>, String> {
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    let entries = vault
        .list_entries(&crate::vault::ListFilter {
            kind: Some(crate::vault::EntryKind::ApiToken),
            ..Default::default()
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for entry in entries {
        let Ok(SecretPayload::ApiToken {
            service, account, ..
        }) = vault.get_active_secret(dek, &entry.id)
        else {
            continue;
        };
        if service.trim().eq_ignore_ascii_case("github") {
            out.push(GithubCredentialMeta {
                id: entry.id,
                title: entry.title,
                account,
            });
        }
    }
    Ok(out)
}

pub fn resolve_github_credential(
    session: &Session,
    args: &Value,
) -> Result<ResolvedGithubCredential, String> {
    let requested = args
        .get("credential")
        .or_else(|| args.get("credential_id"))
        .or_else(|| args.get("credential_name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let credentials = list_credentials(session)?;
    if credentials.is_empty() {
        return Err(
            "金库里没有活动的 GitHub API Token。请先在保险库新建一条服务为 github 的 API Token。"
                .into(),
        );
    }
    let selected = if let Some(requested) = requested {
        match_credential(&credentials, requested)?
    } else if credentials.len() == 1 {
        &credentials[0]
    } else {
        let titles = credentials
            .iter()
            .map(|item| {
                if item.account.as_deref().unwrap_or("").is_empty() {
                    item.title.clone()
                } else {
                    format!("{} ({})", item.title, item.account.as_deref().unwrap_or(""))
                }
            })
            .collect::<Vec<_>>()
            .join("、");
        return Err(format!(
            "有多条 GitHub Token，请传 credential=标题。可选：{titles}"
        ));
    };
    token_from_id(session, &selected.id).map(|token| ResolvedGithubCredential {
        id: selected.id.clone(),
        title: selected.title.clone(),
        token,
    })
}

fn match_credential<'a>(
    credentials: &'a [GithubCredentialMeta],
    requested: &str,
) -> Result<&'a GithubCredentialMeta, String> {
    if let Some(exact_id) = credentials.iter().find(|item| item.id == requested) {
        return Ok(exact_id);
    }
    let lowered = requested.to_ascii_lowercase();
    let mut matches = credentials
        .iter()
        .filter(|item| {
            item.title.eq_ignore_ascii_case(requested)
                || item
                    .account
                    .as_deref()
                    .is_some_and(|account| account.eq_ignore_ascii_case(requested))
        })
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        return Ok(matches[0]);
    }
    if matches.is_empty() {
        matches = credentials
            .iter()
            .filter(|item| {
                item.title.to_ascii_lowercase().contains(&lowered)
                    || item
                        .account
                        .as_deref()
                        .is_some_and(|account| account.to_ascii_lowercase().contains(&lowered))
            })
            .collect();
    }
    match matches.as_slice() {
        [only] => Ok(*only),
        [] => Err(format!(
            "找不到 GitHub Token「{requested}」。先调 github_list_credentials 看标题。"
        )),
        many => {
            let titles = many
                .iter()
                .map(|item| item.title.as_str())
                .collect::<Vec<_>>()
                .join("、");
            Err(format!("有多条 GitHub Token 匹配「{requested}」：{titles}。请改用更精确的标题或 ID。"))
        }
    }
}

pub fn token_from_id(session: &Session, credential_id: &str) -> Result<String, String> {
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    let payload = vault
        .get_active_secret(dek, credential_id)
        .map_err(|_| "GitHub Token 不存在或已在回收站".to_string())?;
    let SecretPayload::ApiToken { service, token, .. } = payload else {
        return Err("凭据必须是 GitHub API Token".into());
    };
    if !service.trim().eq_ignore_ascii_case("github") {
        return Err("凭据不是 GitHub API Token".into());
    }
    if token.trim().is_empty() {
        return Err("GitHub Token 不能为空".into());
    }
    Ok(token)
}

pub fn call_tool(session: &mut Session, name: &str, args: Value) -> Result<String, String> {
    call_tool_detailed(session, name, args)
        .map(|result| result.text)
        .map_err(|error| error.message)
}

pub fn call_tool_detailed(
    session: &mut Session,
    name: &str,
    args: Value,
) -> Result<GithubCallResult, GithubCallError> {
    let context = audit_context(&args);
    let fingerprint = github_credential_fingerprint(session, &args);
    match call_tool_text(session, name, args) {
        Ok((status, text)) => {
            let result_count = serde_json::from_str::<Value>(&text).ok().and_then(|value| {
                value
                    .get("items")
                    .or_else(|| value.get("repositories"))
                    .or_else(|| value.get("workflow_runs"))
                    .and_then(Value::as_array)
                    .map(Vec::len)
            });
            Ok(GithubCallResult {
                text,
                status,
                result_count,
                credential_fingerprint: fingerprint.unwrap_or_default(),
                context,
            })
        }
        Err(raw) => {
            let (status, parsed_reason, message) = parse_call_error(&raw);
            let reason = if raw == "MCP 未启用。请先在 Sealbox 的 MCP 页面打开。" {
                "disabled"
            } else if raw.contains("用户拒绝") {
                "denied"
            } else {
                parsed_reason
            };
            Err(GithubCallError {
                message,
                status,
                reason,
                credential_fingerprint: fingerprint,
                context,
            })
        }
    }
}

fn call_tool_text(session: &mut Session, name: &str, args: Value) -> Result<(u16, String), String> {
    if crate::git_workspace::is_git_tool(name) {
        return crate::git_workspace::call_tool_text(session, name, args).map(|text| (200, text));
    }
    if name == "github_list_credentials" {
        let definition = tool_definitions()
            .into_iter()
            .find(|definition| definition.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| "未知 GitHub 工具".to_string())?;
        validate_arguments(&definition["inputSchema"], &args)?;
        let vault = session.vault().map_err(|e| e.to_string())?;
        let dek = session.dek().map_err(|e| e.to_string())?;
        if !crate::zoomkey::mcp_enabled(vault, dek) {
            return Err("MCP 未启用。请先在 Sealbox 的 MCP 页面打开。".into());
        }
        let credentials = list_credentials(session)?;
        session.touch();
        return serde_json::to_string_pretty(&credentials)
            .map(|text| (200, text))
            .map_err(|e| e.to_string());
    }
    let dispatched = if name.starts_with("github_git_") {
        name.to_string()
    } else {
        task_dispatch_name(name, &args)?
    };
    let name = dispatched.as_str();
    let (token, credential_label) = prepare(session, name, &args)?;
    let (status, result) = match name {
        "github_release_generate_notes" => {
            let repository = repository_args(&args)?;
            let tag_name = release_tag_arg(&args)?;
            let previous = optional_release_tag(&args, "previous_tag_name")?;
            let target = optional_release_string(&args, "target_commitish", 200)?;
            if let Some(value) = target.as_deref() {
                reject_dot_dot(value, "target_commitish")?;
            }
            let mut request = Map::new();
            request.insert("tag_name".into(), Value::String(tag_name));
            if let Some(value) = previous {
                request.insert("previous_tag_name".into(), Value::String(value));
            }
            if let Some(value) = target {
                request.insert("target_commitish".into(), Value::String(value));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path: format!("/repos/{repository}/releases/generate-notes"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(Value::Object(request))),
                    ok: &[200],
                    allow_missing_confirm: true,
                },
                None,
            )?;
            Ok((status, generate_notes_dto(&value)))
        }
        "github_release_publish" => {
            let repository = repository_args(&args)?;
            let id = positive_id(&args, "id")?;
            let name = optional_release_string(&args, "name", 200)?;
            let body = optional_release_body(&args)?;
            let mut request = Map::new();
            request.insert("draft".into(), Value::Bool(false));
            if let Some(value) = name {
                request.insert("name".into(), Value::String(value));
            }
            if let Some(value) = body {
                request.insert("body".into(), Value::String(value));
            }
            if args.get("prerelease").is_some() {
                request.insert("prerelease".into(), Value::Bool(bool_arg(&args, "prerelease", false)?));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Patch,
                    path: format!("/repos/{repository}/releases/{id}"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(Value::Object(request))),
                    ok: &[200],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "发布 GitHub Release".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("release id".into(), id.to_string()),
                    ],
                }),
            )?;
            let dto = release_dto(&value).ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
            Ok((status, dto))
        }
        "github_release_create" => {
            let repository = repository_args(&args)?;
            let tag_name = release_tag_arg(&args)?;
            let target_commitish = optional_release_string(&args, "target_commitish", 200)?;
            let name = optional_release_string(&args, "name", 200)?;
            let body = optional_release_body(&args)?;
            let draft = bool_arg(&args, "draft", true)?;
            let prerelease = bool_arg(&args, "prerelease", false)?;
            let generate_release_notes = bool_arg(&args, "generate_release_notes", false)?;
            let make_latest =
                enum_arg(&args, "make_latest", &["true", "false", "legacy"], "legacy")?;
            let mut request = Map::new();
            request.insert("tag_name".into(), Value::String(tag_name.clone()));
            if let Some(value) = target_commitish {
                request.insert("target_commitish".into(), Value::String(value));
            }
            if let Some(value) = name {
                request.insert("name".into(), Value::String(value));
            }
            if let Some(value) = body {
                request.insert("body".into(), Value::String(value));
            }
            request.insert("draft".into(), Value::Bool(draft));
            request.insert("prerelease".into(), Value::Bool(prerelease));
            request.insert(
                "generate_release_notes".into(),
                Value::Bool(generate_release_notes),
            );
            request.insert("make_latest".into(), Value::String(make_latest));
            let path = format!("/repos/{repository}/releases");
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path,
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(Value::Object(request))),
                    ok: &[201],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "创建 GitHub Release".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("标签".into(), tag_name),
                        ("草稿".into(), if draft { "是".into() } else { "否".into() }),
                        ("凭据".into(), credential_label),
                    ],
                }),
            )?;
            let dto = release_dto(&value).ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
            Ok((status, dto))
        }
        "github_issue_create" => {
            let repository = repository_args(&args)?;
            let title = required_text(&args, "title", 256)?;
            let body = optional_release_body(&args)?;
            let labels = optional_csv(&args, "labels")?;
            let mut request = Map::new();
            request.insert("title".into(), Value::String(title.clone()));
            if let Some(value) = body {
                request.insert("body".into(), Value::String(value));
            }
            if !labels.is_empty() {
                request.insert(
                    "labels".into(),
                    Value::Array(labels.into_iter().map(Value::String).collect()),
                );
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path: format!("/repos/{repository}/issues"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(Value::Object(request))),
                    ok: &[201],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "创建 GitHub Issue".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("标题".into(), title),
                        ("凭据".into(), credential_label.clone()),
                    ],
                }),
            )?;
            let dto = issue_dto(&value).ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
            Ok((status, dto))
        }
        "github_issue_comment" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let body = required_text(&args, "body", MAX_RELEASE_BODY_BYTES)?;
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path: format!("/repos/{repository}/issues/{number}/comments"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(json!({"body": body}))),
                    ok: &[201],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "评论 GitHub Issue/PR".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), format!("{repository}#{number}")),
                        ("凭据".into(), credential_label.clone()),
                    ],
                }),
            )?;
            Ok((
                status,
                json!({
                    "id": value.get("id").and_then(Value::as_i64),
                    "html_url": limited_string(value.get("html_url")),
                    "user": limited_string(value.get("user").and_then(|item| item.get("login"))),
                }),
            ))
        }
        "github_pr_create" => {
            let repository = repository_args(&args)?;
            let title = required_text(&args, "title", 256)?;
            let head = required_text(&args, "head", 200)?;
            let base = required_text(&args, "base", 200)?;
            let body = optional_release_body(&args)?;
            let draft = bool_arg(&args, "draft", true)?;
            let mut request = Map::new();
            request.insert("title".into(), Value::String(title.clone()));
            request.insert("head".into(), Value::String(head.clone()));
            request.insert("base".into(), Value::String(base.clone()));
            request.insert("draft".into(), Value::Bool(draft));
            if let Some(value) = body {
                request.insert("body".into(), Value::String(value));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path: format!("/repos/{repository}/pulls"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(Value::Object(request))),
                    ok: &[201],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "创建 GitHub Pull Request".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("分支".into(), format!("{head} → {base}")),
                        ("标题".into(), title),
                        (
                            "草稿".into(),
                            if draft { "是".into() } else { "否".into() },
                        ),
                        ("凭据".into(), credential_label.clone()),
                    ],
                }),
            )?;
            let dto = pull_dto(&value).ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
            Ok((status, dto))
        }
        "github_pr_merge" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let merge_method = merge_method_arg(&args)?;
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Put,
                    path: format!("/repos/{repository}/pulls/{number}/merge"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(
                        json!({"merge_method": merge_method}),
                    )),
                    ok: &[200],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "合并 GitHub Pull Request".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("编号".into(), number.to_string()),
                        ("方式".into(), merge_method),
                    ],
                }),
            )?;
            Ok((status, merge_dto(&value)?))
        }
        "github_user_info" => {
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone())
                .get("/user", Vec::new())?;
            let dto = serde_json::to_value(GithubUserDto {
                id: value.get("id").and_then(Value::as_i64),
                login: limited_string(value.get("login")),
                name: limited_string(value.get("name")),
                company: limited_string(value.get("company")),
                blog: limited_string(value.get("blog")),
                html_url: limited_string(value.get("html_url")),
                public_repos: value.get("public_repos").and_then(Value::as_i64),
                private_repos: value.get("total_private_repos").and_then(Value::as_i64),
            })
            .map_err(|e| e.to_string())?;
            Ok((status, dto))
        }
        "github_repo_list" => {
            let visibility = enum_arg(&args, "visibility", &["all", "public", "private"], "all")?;
            let affiliation = enum_arg(
                &args,
                "affiliation",
                &["owner", "collaborator", "organization_member"],
                "owner",
            )?;
            let (page, per_page) = page_args(&args)?;
            let name_contains = optional_query_text(&args, "name_contains", 200)?;
            let mut query = vec![
                ("visibility".to_string(), visibility),
                ("affiliation".to_string(), affiliation),
                ("page".to_string(), page.to_string()),
                ("per_page".to_string(), per_page.to_string()),
            ];
            if let Some(kind) = optional_enum(
                &args,
                "type",
                &["all", "owner", "public", "private", "member"],
            )? {
                query.push(("type".to_string(), kind));
            }
            if let Some(sort) =
                optional_enum(&args, "sort", &["created", "updated", "pushed", "full_name"])?
            {
                query.push(("sort".to_string(), sort));
            }
            if let Some(direction) = optional_enum(&args, "direction", &["asc", "desc"])? {
                query.push(("direction".to_string(), direction));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone())
                .get("/user/repos", query)?;
            let repos = value
                .as_array()
                .ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
            let items: Vec<Value> = repos
                .iter()
                .filter_map(repository_dto)
                .filter(|item| match name_contains.as_deref() {
                    Some(needle) => item
                        .get("full_name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| name.contains(needle)),
                    None => true,
                })
                .take(per_page as usize)
                .collect();
            let count = items.len();
            Ok((status, json!({"repositories": items, "count": count})))
        }
        "github_repo_get" => {
            let repository = repository_args(&args)?;
            request_json(&token, &format!("/repos/{repository}"), |value| {
                repository_dto(value).ok_or_else(|| "GitHub 响应格式不正确".into())
            })
        }
        "github_issues_list" => {
            let repository = repository_args(&args)?;
            let state = enum_arg(&args, "state", &["open", "closed", "all"], "open")?;
            let (page, per_page) = page_args(&args)?;
            let mut query = vec![
                ("state".to_string(), state),
                ("page".to_string(), page.to_string()),
                ("per_page".to_string(), per_page.to_string()),
            ];
            for name in ["labels", "assignee", "creator", "since"] {
                let max = match name {
                    "labels" => 400,
                    "since" => 40,
                    _ => 100,
                };
                if let Some(value) = optional_query_text(&args, name, max)? {
                    query.push((name.to_string(), value));
                }
            }
            if let Some(sort) = optional_enum(&args, "sort", &["created", "updated", "comments"])? {
                query.push(("sort".to_string(), sort));
            }
            if let Some(direction) = optional_enum(&args, "direction", &["asc", "desc"])? {
                query.push(("direction".to_string(), direction));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone())
                .get(&format!("/repos/{repository}/issues"), query)?;
            Ok((status, list_dto(&value, per_page, issue_dto)?))
        }
        "github_pulls_list" => {
            let repository = repository_args(&args)?;
            let state = enum_arg(&args, "state", &["open", "closed", "all"], "open")?;
            let (page, per_page) = page_args(&args)?;
            let endpoint =
                format!("/repos/{repository}/pulls?state={state}&page={page}&per_page={per_page}");
            request_json(&token, &endpoint, |value| {
                list_dto(value, per_page, pull_dto)
            })
        }
        "github_get_pull_request" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            request_json(
                &token,
                &format!("/repos/{repository}/pulls/{number}"),
                |value| pull_dto(value).ok_or_else(|| "GitHub 响应格式不正确".into()),
            )
        }
        "github_release_list" => {
            let repository = repository_args(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint = format!("/repos/{repository}/releases?page={page}&per_page={per_page}");
            request_json(&token, &endpoint, |value| {
                list_dto(value, per_page, release_list_dto)
            })
        }
        "github_release_get" => {
            let repository = repository_args(&args)?;
            let by_tag = args.get("id").is_none() && args.get("tag_name").is_some();
            let endpoint = if args.get("id").is_some() {
                let id = positive_id(&args, "id")?;
                format!("/repos/{repository}/releases/{id}")
            } else if by_tag {
                let tag = compare_ref_arg(&args, "tag_name")?;
                format!("/repos/{repository}/releases/tags/{tag}")
            } else {
                return Err("缺少参数 id".into());
            };
            match request_json(&token, &endpoint, |value| {
                release_list_dto(value).ok_or_else(|| "GitHub 响应格式不正确".to_string())
            }) {
                Ok(result) => Ok(result),
                Err(error) if by_tag && error.contains("HTTP 404") => {
                    Err(format!("{error}；draft 请用 github_release_list 取 id"))
                }
                Err(error) => Err(error),
            }
        }
        _ => return Err("未知 GitHub 工具".into()),
    }?;
    session.touch();
    let serialized = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
    Ok((status, redact_text(&serialized, &[token.as_str()])))
}

fn prepare(session: &Session, name: &str, args: &Value) -> Result<(String, String), String> {
    let definition = tool_definitions()
        .into_iter()
        .find(|definition| definition.get("name").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| "未知 GitHub 工具".to_string())?;
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    if !crate::zoomkey::mcp_enabled(vault, dek) {
        return Err("MCP 未启用。请先在 Sealbox 的 MCP 页面打开。".into());
    }
    validate_arguments(&definition["inputSchema"], args)?;
    let resolved = resolve_github_credential(session, args)?;
    Ok((resolved.token, resolved.title))
}

fn audit_context(args: &Value) -> GithubAuditContext {
    let repository = repository_args(args).ok().or_else(|| {
        args.get("repo")
            .and_then(Value::as_str)
            .map(|value| truncate(value, 201))
    });
    GithubAuditContext {
        repository,
        path: args.get("path").and_then(Value::as_str).map(str::to_string),
        reference: args
            .get("ref")
            .or_else(|| args.get("tag_name"))
            .or_else(|| args.get("head"))
            .and_then(Value::as_str)
            .map(|value| truncate(value, MAX_RELEASE_TAG_CHARS).replace(['\r', '\n'], " ")),
    }
}

fn github_credential_fingerprint(session: &Session, args: &Value) -> Option<String> {
    let resolved = resolve_github_credential(session, args).ok()?;
    Some(sha256_hex(resolved.id.as_bytes())[..12].to_string())
}

fn parse_call_error(raw: &str) -> (Option<u16>, &'static str, String) {
    if let Some(rest) = raw.strip_prefix("GitHub HTTP ") {
        let status = rest
            .split(':')
            .next()
            .and_then(|value| value.parse::<u16>().ok());
        return (status, "github_http", raw.to_string());
    }
    if raw == "GitHub 网络请求失败" {
        return (None, "network", raw.to_string());
    }
    (None, "validation", raw.to_string())
}

pub(crate) fn validate_tool_arguments(schema: &Value, args: &Value) -> Result<(), String> {
    validate_arguments(schema, args)
}

fn validate_arguments(schema: &Value, args: &Value) -> Result<(), String> {
    let object = args
        .as_object()
        .ok_or_else(|| "工具参数必须是对象".to_string())?;
    let schema = schema
        .as_object()
        .ok_or_else(|| "工具 schema 无效".to_string())?;
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for key in required.iter().filter_map(Value::as_str) {
            if !object.contains_key(key) {
                return Err(format!("缺少参数 {key}"));
            }
        }
    }
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| "工具 schema 缺少 properties".to_string())?;
    for (key, value) in object {
        let definition = properties
            .get(key)
            .ok_or_else(|| format!("不支持的参数 {key}"))?;
        validate_value(key, value, definition)?;
    }
    Ok(())
}

fn validate_value(name: &str, value: &Value, definition: &Value) -> Result<(), String> {
    if definition.get("type") == Some(&Value::String("string".into())) {
        let value = value
            .as_str()
            .ok_or_else(|| format!("参数 {name} 必须是字符串"))?;
        let min = definition
            .get("minLength")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let max = definition
            .get("maxLength")
            .and_then(Value::as_u64)
            .unwrap_or(usize::MAX as u64) as usize;
        if value.chars().count() < min || value.chars().count() > max {
            return Err(format!("参数 {name} 长度不合法"));
        }
        if let Some(values) = definition.get("enum").and_then(Value::as_array) {
            if !values.iter().any(|item| item.as_str() == Some(value)) {
                return Err(format!("参数 {name} 取值不合法"));
            }
        }
    } else if definition.get("type") == Some(&Value::String("integer".into())) {
        let value = value
            .as_u64()
            .ok_or_else(|| format!("参数 {name} 必须是正整数"))?;
        let min = definition
            .get("minimum")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let max = definition
            .get("maximum")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        if value < min || value > max {
            return Err(format!("参数 {name} 超出范围"));
        }
    } else if definition.get("type") == Some(&Value::String("boolean".into()))
        && !value.is_boolean()
    {
        return Err(format!("参数 {name} 必须是布尔值"));
    }
    Ok(())
}

fn repository_args(args: &Value) -> Result<String, String> {
    if let Some(repo) = args.get("repo").and_then(Value::as_str) {
        let trimmed = repo.trim();
        if trimmed.contains('/') || looks_like_github_url(trimmed) {
            return normalize_repository(trimmed);
        }
        if let Some(owner) = args.get("owner").and_then(Value::as_str) {
            return normalize_repository(&format!("{}/{}", owner.trim(), trimmed));
        }
        return Err("请传 repo=\"owner/repo\"，例如 hahaha-taotao/sealbox".into());
    }
    if let (Some(owner), Some(name)) = (
        args.get("owner").and_then(Value::as_str),
        args.get("name").and_then(Value::as_str),
    ) {
        return normalize_repository(&format!("{}/{}", owner.trim(), name.trim()));
    }
    Err("缺少仓库。请传 repo=\"owner/repo\"".into())
}

fn looks_like_github_url(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.contains("github.com/") || lower.starts_with("https://") || lower.starts_with("http://")
}

pub fn normalize_repository(raw: &str) -> Result<String, String> {
    let mut value = raw.trim().trim_end_matches('/').to_string();
    if value.ends_with(".git") {
        value.truncate(value.len() - 4);
    }
    for prefix in [
        "https://github.com/",
        "http://github.com/",
        "https://www.github.com/",
        "git@github.com:",
    ] {
        if let Some(stripped) = value
            .strip_prefix(prefix)
            .or_else(|| value.strip_prefix(&prefix.to_ascii_uppercase()))
        {
            value = stripped.to_string();
            break;
        }
        let lower = value.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix(prefix) {
            value = value[value.len() - rest.len()..].to_string();
            break;
        }
    }
    if value.len() > 201
        || value.is_empty()
        || value.contains('%')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err("仓库名格式不合法。请使用 owner/repo，例如 hahaha-taotao/sealbox".into());
    }
    let mut parts = value.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    if parts.next().is_some() || !valid_segment(owner) || !valid_segment(repo) {
        return Err("仓库名格式不合法。请使用 owner/repo，例如 hahaha-taotao/sealbox".into());
    }
    Ok(format!("{owner}/{repo}"))
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value != "."
        && value != ".."
        && value
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn optional_ref(args: &Value) -> Result<Option<String>, String> {
    let Some(value) = args.get("ref") else {
        return Ok(None);
    };
    let reference = value.as_str().ok_or("参数 ref 必须是字符串")?;
    if reference.is_empty()
        || reference.len() > 200
        || reference.contains('%')
        || reference.contains('\\')
        || reference.chars().any(char::is_control)
        || reference
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err("ref 格式不合法".into());
    }
    Ok(Some(percent_encode(reference, false)))
}

fn optional_enum(args: &Value, name: &str, allowed: &[&str]) -> Result<Option<String>, String> {
    if args.get(name).is_none() {
        return Ok(None);
    }
    enum_arg(args, name, allowed, "").map(Some)
}

fn optional_query_text(args: &Value, name: &str, max: usize) -> Result<Option<String>, String> {
    let Some(value) = args.get(name) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| format!("参数 {name} 必须是字符串"))?;
    if value.is_empty()
        || value.chars().count() > max
        || value.chars().any(|character| character == '\n' || character == '\r' || character == '\0')
    {
        return Err(format!("参数 {name} 长度或格式不合法"));
    }
    Ok(Some(value.to_string()))
}

fn percent_encode(value: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let safe = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && *byte == b'/');
        if safe {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", byte));
        }
    }
    out
}

fn enum_arg(args: &Value, name: &str, allowed: &[&str], default: &str) -> Result<String, String> {
    let value = args.get(name).and_then(Value::as_str).unwrap_or(default);
    if allowed.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(format!("参数 {name} 取值不合法"))
    }
}

fn page_args(args: &Value) -> Result<(u64, u64), String> {
    page_args_with_default(args, 30)
}

fn page_args_with_default(args: &Value, default_per_page: u64) -> Result<(u64, u64), String> {
    let page = args.get("page").and_then(Value::as_u64).unwrap_or(1);
    let per_page = args
        .get("per_page")
        .and_then(Value::as_u64)
        .unwrap_or(default_per_page);
    if !(1..=100).contains(&page) || !(1..=MAX_PAGE_SIZE).contains(&per_page) {
        return Err("分页参数超出范围".into());
    }
    Ok((page, per_page))
}

fn issue_number(args: &Value) -> Result<u64, String> {
    args.get("number")
        .and_then(Value::as_u64)
        .filter(|value| *value >= 1)
        .ok_or_else(|| "缺少参数 number".to_string())
}

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

fn required_text(args: &Value, name: &str, max: usize) -> Result<String, String> {
    let value = args
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("缺少参数 {name}"))?;
    if value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(format!("参数 {name} 长度或格式不合法"));
    }
    Ok(value.to_string())
}

fn optional_csv(args: &Value, name: &str) -> Result<Vec<String>, String> {
    let Some(raw) = args.get(name).and_then(Value::as_str) else {
        return Ok(Vec::new());
    };
    let labels = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    if labels.len() > 20 || labels.iter().any(|value| value.chars().count() > 50) {
        return Err(format!("参数 {name} 不合法"));
    }
    Ok(labels)
}

fn bool_arg(args: &Value, name: &str, default: bool) -> Result<bool, String> {
    let Some(value) = args.get(name) else {
        return Ok(default);
    };
    value
        .as_bool()
        .ok_or_else(|| format!("参数 {name} 必须是布尔值"))
}

fn optional_release_tag(args: &Value, name: &str) -> Result<Option<String>, String> {
    if args.get(name).is_none() {
        return Ok(None);
    }
    let wrapped = json!({ "tag_name": args.get(name).cloned().unwrap_or(Value::Null) });
    release_tag_arg(&wrapped).map(Some)
}

fn reject_dot_dot(value: &str, name: &str) -> Result<(), String> {
    if value.contains("..") {
        Err(format!("参数 {name} 格式不合法"))
    } else {
        Ok(())
    }
}

fn generate_notes_dto(value: &Value) -> Value {
    json!({
        "name": limited_string(value.get("name")),
        "body": limited_string_with_cap(value.get("body"), MAX_RELEASE_BODY_BYTES)
    })
}

fn release_tag_arg(args: &Value) -> Result<String, String> {
    let tag = args
        .get("tag_name")
        .and_then(Value::as_str)
        .ok_or("缺少参数 tag_name")?;
    if tag.is_empty()
        || tag.chars().count() > MAX_RELEASE_TAG_CHARS
        || tag.chars().any(char::is_control)
        || tag.contains('%')
        || tag.contains('\\')
        || tag
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err("tag_name 格式不合法".into());
    }
    Ok(tag.to_string())
}

fn optional_release_string(args: &Value, name: &str, max: usize) -> Result<Option<String>, String> {
    let Some(value) = args.get(name) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| format!("参数 {name} 必须是字符串"))?;
    if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(format!("参数 {name} 长度或格式不合法"));
    }
    Ok(Some(value.to_string()))
}

pub(crate) fn merge_method_arg(args: &Value) -> Result<String, String> {
    let method = args
        .get("merge_method")
        .and_then(Value::as_str)
        .unwrap_or("merge");
    if !matches!(method, "merge" | "squash" | "rebase") {
        return Err("参数 merge_method 取值不合法".into());
    }
    Ok(method.to_string())
}

fn merge_dto(value: &Value) -> Result<Value, String> {
    Ok(json!({
        "sha": limited_string(value.get("sha")),
        "merged": value.get("merged").and_then(Value::as_bool),
        "message": limited_string(value.get("message")),
    }))
}

fn optional_release_body(args: &Value) -> Result<Option<String>, String> {
    let Some(value) = args.get("body") else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| "参数 body 必须是字符串".to_string())?;
    if value.chars().count() > MAX_RELEASE_BODY_BYTES
        || value
            .chars()
            .any(|character| matches!(character, '\0' | '\u{000b}' | '\u{000c}'))
    {
        return Err("参数 body 长度或格式不合法".into());
    }
    Ok(Some(value.to_string()))
}

fn request_json<T>(
    token: &str,
    path: &str,
    map: impl FnOnce(&Value) -> Result<T, String>,
) -> Result<(u16, T), String> {
    let target = parse_http_url(&format!("{API_BASE}{path}"), true)?;
    if target.scheme != "https" || target.host != "api.github.com" || target.port != 443 {
        return Err("GitHub API 目标不合法".into());
    }
    assert_public_target(&target)?;
    let agent = ureq::builder()
        .redirects(0)
        .timeout(Duration::from_secs(15))
        .timeout_connect(Duration::from_secs(8))
        .resolver(PublicResolver)
        .user_agent(concat!("Sealbox/", env!("CARGO_PKG_VERSION")))
        .build();
    let response = agent
        .get(&format!("{API_BASE}{path}"))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", API_VERSION)
        .call();
    let (status, body, truncated) = match response {
        Ok(response) => {
            let (status, body, truncated) = read_response(response);
            (status, body, truncated)
        }
        Err(ureq::Error::Status(status, response)) => {
            let (_, body, truncated) = read_response(response);
            return Err(redact_text(
                &github_error(status, &body, truncated),
                &[token],
            ));
        }
        Err(_) => return Err("GitHub 网络请求失败".into()),
    };
    if truncated {
        return Err("GitHub 响应超过安全大小限制".into());
    }
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| "GitHub 响应不是有效 JSON".to_string())?;
    map(&value)
        .map(|value| (status, value))
        .map_err(|error| format!("GitHub 响应处理失败: {error}"))
}

fn read_response(response: ureq::Response) -> (u16, Vec<u8>, bool) {
    let status = response.status();
    let mut reader = response.into_reader();
    let mut body = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                let remaining = MAX_RESPONSE_BYTES.saturating_sub(body.len());
                if remaining == 0 {
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&buffer[..n.min(remaining)]);
                if n > remaining {
                    truncated = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (status, body, truncated)
}

fn github_error(status: u16, body: &[u8], truncated: bool) -> String {
    if truncated {
        return format!("GitHub 返回 HTTP {status}，响应过大");
    }
    let message = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .map(|value| truncate(&value, 240))
        .unwrap_or_else(|| "GitHub 请求失败".into());
    format!("GitHub HTTP {status}: {message}")
}

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

fn release_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubReleaseDto {
        id: value.get("id").and_then(Value::as_i64),
        tag_name: limited_string_with_cap(value.get("tag_name"), MAX_RELEASE_TAG_CHARS),
        name: limited_string_with_cap(value.get("name"), 200),
        target_commitish: limited_string_with_cap(value.get("target_commitish"), 200),
        draft: value.get("draft").and_then(Value::as_bool),
        prerelease: value.get("prerelease").and_then(Value::as_bool),
        html_url: limited_string(value.get("html_url")),
        created_at: limited_string(value.get("created_at")),
        published_at: limited_string(value.get("published_at")),
    })
    .ok()
}

fn repository_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubRepositoryDto {
        id: value.get("id").and_then(Value::as_i64),
        full_name: limited_string(value.get("full_name")),
        name: limited_string(value.get("name")),
        owner: GithubOwnerDto {
            login: limited_string(value.get("owner").and_then(|v| v.get("login"))),
        },
        private: value.get("private").and_then(Value::as_bool),
        fork: value.get("fork").and_then(Value::as_bool),
        default_branch: limited_string(value.get("default_branch")),
        html_url: limited_string(value.get("html_url")),
        description: limited_string(value.get("description")),
        updated_at: limited_string(value.get("updated_at")),
    })
    .ok()
}

fn login_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .take(20)
                .filter_map(|item| limited_string(item.get("login").or_else(|| item.get("name"))))
                .collect()
        })
        .unwrap_or_default()
}

fn label_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .take(20)
                .filter_map(|item| limited_string(item.get("name")))
                .collect()
        })
        .unwrap_or_default()
}

fn git_ref_dto(value: Option<&Value>) -> GithubRefDto {
    GithubRefDto {
        git_ref: limited_string(value.and_then(|item| item.get("ref"))),
        sha: limited_string(value.and_then(|item| item.get("sha"))),
        repo: limited_string(
            value
                .and_then(|item| item.get("repo"))
                .and_then(|item| item.get("full_name")),
        ),
    }
}

fn issue_dto(value: &Value) -> Option<Value> {
    if value.get("pull_request").is_some() {
        return None;
    }
    serde_json::to_value(GithubIssueDto {
        number: value.get("number").and_then(Value::as_i64),
        title: limited_string(value.get("title")),
        state: limited_string(value.get("state")),
        html_url: limited_string(value.get("html_url")),
        user: GithubOwnerDto {
            login: limited_string(value.get("user").and_then(|v| v.get("login"))),
        },
        labels: label_list(value.get("labels")),
        assignees: login_list(value.get("assignees")),
        comments: value.get("comments").and_then(Value::as_i64),
        created_at: limited_string(value.get("created_at")),
        updated_at: limited_string(value.get("updated_at")),
        closed_at: limited_string(value.get("closed_at")),
        body: limited_string_with_cap(value.get("body"), MAX_DESCRIPTION_BYTES),
    })
    .ok()
}

fn pull_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubPullDto {
        number: value.get("number").and_then(Value::as_i64),
        title: limited_string(value.get("title")),
        state: limited_string(value.get("state")),
        html_url: limited_string(value.get("html_url")),
        user: GithubOwnerDto {
            login: limited_string(value.get("user").and_then(|v| v.get("login"))),
        },
        labels: label_list(value.get("labels")),
        assignees: login_list(value.get("assignees")),
        requested_reviewers: login_list(value.get("requested_reviewers")),
        draft: value.get("draft").and_then(Value::as_bool),
        mergeable: value.get("mergeable").and_then(Value::as_bool),
        mergeable_state: limited_string(value.get("mergeable_state")),
        head: git_ref_dto(value.get("head")),
        base: git_ref_dto(value.get("base")),
        created_at: limited_string(value.get("created_at")),
        updated_at: limited_string(value.get("updated_at")),
        body: limited_string_with_cap(value.get("body"), MAX_DESCRIPTION_BYTES),
    })
    .ok()
}

fn list_dto(
    value: &Value,
    per_page: u64,
    mapper: fn(&Value) -> Option<Value>,
) -> Result<Value, String> {
    let items = value
        .as_array()
        .ok_or_else(|| "GitHub 响应格式不正确".to_string())?
        .iter()
        .filter_map(mapper)
        .take(per_page as usize)
        .collect::<Vec<_>>();
    let count = items.len();
    Ok(json!({"items": items, "count": count}))
}

fn limited_string(value: Option<&Value>) -> Option<String> {
    limited_string_with_cap(value, MAX_DESCRIPTION_BYTES)
}

fn limited_string_with_cap(value: Option<&Value>, cap: usize) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(|value| truncate(value, cap))
}

fn truncate(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let suffix_bytes = ELLIPSIS.len();
    let mut end = max_bytes.saturating_sub(suffix_bytes).min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &value[..end], ELLIPSIS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;
    use crate::vault::Vault;

    fn find_tool(name: &str) -> Value {
        tool_definitions()
            .into_iter()
            .find(|definition| definition["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing"))
    }






    #[test]
    fn generate_notes_is_read_only_post() {
        let def = find_tool("github_release_generate_notes");
        assert_eq!(def["readOnly"], true);
        assert_eq!(def["risk"], "low");
    }




    #[test]
    fn all_write_tools_are_registered_for_shared_mcp() {
        let definitions = tool_definitions_for_mcp();
        for name in [
            "github_release",
            "github_pr",
            "github_issue",
            "github_git",
            "github_release_create",
        ] {
            assert!(definitions.iter().any(|definition| definition["name"] == name), "{name} missing");
        }
    }

    #[test]
    fn repo_list_rejects_missing_shape() {
        let def = api_tool_definitions()
            .into_iter()
            .find(|t| t["name"] == "github_repo_list")
            .unwrap();
        assert_eq!(def["readOnly"], true);
        assert_eq!(def["risk"], "low");
        let error = validate_tool_arguments(&def["inputSchema"], &json!({"page": 0})).unwrap_err();
        assert!(error.contains("page"), "{error}");
    }







    #[test]
    fn file_and_ref_tools_are_registered_for_shared_mcp() {
        let definitions = tool_definitions_for_mcp();
        for name in ["github_release", "github_pr", "github_issue", "github_git"] {
            assert!(definitions.iter().any(|definition| definition["name"] == name), "{name} missing");
        }
    }

    #[test]
    fn new_read_tools_are_registered_for_shared_mcp() {
        let definitions = tool_definitions_for_mcp();
        for name in ["github_repo_list", "github_repo_get", "github_issues_list", "github_pulls_list", "github_release_list"] {
            assert!(definitions.iter().any(|definition| definition["name"] == name), "{name} missing");
        }
    }





    #[test]
    fn issue_update_tool_is_registered_for_shared_mcp() {
        let definitions = tool_definitions_for_mcp();
        for name in ["github_issue", "github_pr", "github_release"] {
            assert!(definitions.iter().any(|definition| definition["name"] == name), "{name} missing");
        }
    }

    #[test]
    fn task_tools_are_high_risk() {
        for name in ["github_release", "github_pr", "github_issue", "github_git"] {
            let def = find_tool(name);
            assert_eq!(def["readOnly"], false);
            assert_eq!(def["risk"], "high");
            assert_eq!(def["annotations"]["destructiveHint"], true);
        }
    }

    #[test]
    fn credential_list_is_low_risk() {
        let def = find_tool("github_list_credentials");
        assert_eq!(def["readOnly"], true);
        assert_eq!(def["risk"], "low");
    }

    #[test]
    fn alias_collapses_to_canonical_name() {
        assert_eq!(canonical_tool_name("github_repo_list"), "github_repo_list");
        assert_eq!(canonical_tool_name("github_repo_list"), "github_repo_list");
        assert_eq!(canonical_tool_name("github_issue_create"), "github_issue_create");
        assert_eq!(canonical_tool_name("github_release_create"), "github_release_create");
        assert_eq!(canonical_tool_name("github_git"), "github_git");
    }

    #[test]
    fn canonical_names_are_used_for_dispatch() {
        assert_eq!(canonical_tool_name("github_get_authenticated_user"), "github_user_info");
        assert_eq!(canonical_tool_name("github_create_release"), "github_release_create");
        assert!(is_github_api_tool("github_user_info"));
        assert!(is_github_api_tool("github_get_authenticated_user"));
    }





    #[test]
    fn release_tool_is_high_risk_and_closed() {
        let definition = api_tool_definitions()
            .into_iter()
            .find(|definition| definition["name"] == "github_release_create")
            .expect("release tool must be registered");
        assert_eq!(definition["readOnly"], false);
        assert_eq!(definition["risk"], "high");
        assert_eq!(definition["annotations"]["readOnlyHint"], false);
        assert_eq!(definition["annotations"]["destructiveHint"], true);
        assert_eq!(definition["inputSchema"]["additionalProperties"], false);
        assert!(definition["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "tag_name"));
    }

    #[test]
    fn all_write_tools_are_visible_without_a_github_policy() {
        let definitions = tool_definitions_for_mcp();
        assert!(definitions.iter().any(|definition| definition["name"] == "github_release_create"));
        assert!(definitions.iter().any(|definition| definition["name"] == "github_issue_create"));
    }

    #[test]
    fn read_only_tools_have_closed_schemas() {
        let expected = [
            "github_list_credentials",
            "github_user_info",
            "github_repo_list",
            "github_repo_get",
            "github_issues_list",
            "github_pulls_list",
            "github_get_pull_request",
            "github_release_list",
            "github_release_get",
            "github_release_generate_notes",
        ];
        let definitions = tool_definitions();
        for name in expected {
            let definition = definitions
                .iter()
                .find(|definition| definition["name"] == name)
                .expect("tool must be registered");
            assert_eq!(definition["readOnly"], true);
            assert_eq!(definition["risk"], "low");
            assert_eq!(definition["annotations"]["readOnlyHint"], true);
            assert_eq!(definition["annotations"]["destructiveHint"], false);
            assert_eq!(definition["inputSchema"]["additionalProperties"], false);
            assert!(is_github_api_tool(name));
            assert!(is_github_tool(name));
        }
        assert!(is_github_tool("github_git"));
        assert!(!is_github_api_tool("github_git"));
    }

    #[test]
    fn all_github_tools_reject_when_policy_is_disabled() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let cases = [
            ("github_list_credentials", json!({})),
            (
                "github_user_info",
                json!({"credential_id":"id"}),
            ),
            ("github_repo_list", json!({"credential_id":"id"})),
            (
                "github_repo_get",
                json!({"credential_id":"id","owner":"octocat","repo":"hello-world"}),
            ),
            (
                "github_issues_list",
                json!({"credential_id":"id","owner":"octocat","repo":"hello-world"}),
            ),
            (
                "github_pulls_list",
                json!({"credential_id":"id","owner":"octocat","repo":"hello-world"}),
            ),
            (
                "github_release_list",
                json!({"repo":"octocat/hello-world"}),
            ),
            (
                "github_release_get",
                json!({"repo":"octocat/hello-world","tag_name":"v1.0.0"}),
            ),
        ];
        for (name, args) in cases {
            let error = call_tool(&mut session, name, args).unwrap_err();
            assert!(error.contains("未启用"), "{name}: {error}");
        }
        let release_error = call_tool(
            &mut session,
            "github_release_create",
            json!({
                "credential_id":"id",
                "owner":"octocat",
                "repo":"hello-world",
                "tag_name":"v1.0.0"
            }),
        )
        .unwrap_err();
        assert!(release_error.contains("未启用"), "{release_error}");
        let git_error = call_tool(
            &mut session,
            "github_git",
            json!({"action":"status","path":"E:\\\\repo"}),
        )
        .unwrap_err();
        assert!(git_error.contains("未启用"), "{git_error}");
    }

    #[test]
    fn new_readonly_tools_stay_visible_for_shared_mcp() {
        let definitions = tool_definitions_for_mcp();
        for name in [
            "github_issues_list",
            "github_pulls_list",
            "github_release_list",
            "github_release_get",
            "github_release_generate_notes",
            "github_pr",
            "github_issue",
        ] {
            assert!(
                definitions
                    .iter()
                    .any(|definition| definition["name"] == name),
                "{name} missing"
            );
        }
    }

    #[test]
    fn tool_schemas_are_closed() {
        for definition in api_tool_definitions() {
            assert_eq!(definition["inputSchema"]["additionalProperties"], false);
        }
        let read_only = api_tool_definitions()
            .into_iter()
            .filter(|definition| definition["readOnly"] == true)
            .count();
        // Credentials, account, repos, issues, pull requests, and releases.
        assert_eq!(read_only, 10);
    }

    #[test]
    fn canonical_user_tool_is_registered_once() {
        let definitions = api_tool_definitions();
        let count = definitions.iter().filter(|definition| definition["name"] == "github_user_info").count();
        assert_eq!(count, 1);
        assert!(!definitions.iter().any(|definition| definition["name"] == "github_get_authenticated_user"));
    }

    #[test]
    fn release_arguments_reject_unsafe_values_and_wrong_boolean_types() {
        assert!(release_tag_arg(&json!({"tag_name":"refs/../main"})).is_err());
        assert!(release_tag_arg(&json!({"tag_name":"release%2F1"})).is_err());
        assert!(optional_release_string(&json!({"name": 1}), "name", 200).is_err());
        assert!(optional_release_body(&json!({"body": "bad\u{000b}"})).is_err());
        assert!(bool_arg(&json!({"draft":"true"}), "draft", true).is_err());
        assert_eq!(bool_arg(&json!({}), "draft", true).unwrap(), true);
    }






    fn enable_mcp(vault: &Vault, dek: &[u8; 32]) {
        crate::zoomkey::save_policy(
            vault,
            dek,
            &crate::zoomkey::ZoomkeyMcpPolicy {
                enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
    }

    fn token_entry(service: &str) -> (Vault, [u8; 32], String) {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let entry = vault
            .upsert_entry(
                &dek,
                crate::vault::UpsertEntry {
                    id: None,
                    kind: crate::vault::EntryKind::ApiToken,
                    title: service.into(),
                    account: Some("octocat".into()),
                    url: None,
                    folder_id: None,
                    tags: Vec::new(),
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::ApiToken {
                        service: service.into(),
                        account: Some("octocat".into()),
                        token: "ghp_test_token_value".into(),
                    },
                },
            )
            .unwrap();
        (vault, dek, entry.id)
    }

    #[test]
    fn active_token_is_selected_by_tool_argument() {
        let (vault, dek, id) = token_entry("github");
        enable_mcp(&vault, &dek);
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let (token, _) = prepare(
            &session,
            "github_repo_get",
            &json!({"credential_id":id,"owner":"octocat","repo":"other"}),
        )
        .unwrap();
        assert_eq!(token, "ghp_test_token_value");
    }

    #[test]
    fn credential_can_be_matched_by_title_or_omitted_when_unique() {
        let (vault, dek, _) = token_entry("github");
        enable_mcp(&vault, &dek);
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let by_title = prepare(
            &session,
            "github_user_info",
            &json!({"credential":"github"}),
        )
        .unwrap();
        assert_eq!(by_title.0, "ghp_test_token_value");
        let implicit = prepare(&session, "github_user_info", &json!({})).unwrap();
        assert_eq!(implicit.0, "ghp_test_token_value");
    }

    #[test]
    fn repository_accepts_owner_slash_repo() {
        assert_eq!(
            repository_args(&json!({"repo":"hahaha-taotao/sealbox"})).unwrap(),
            "hahaha-taotao/sealbox"
        );
        assert_eq!(
            repository_args(&json!({"repo":"https://github.com/octocat/hello-world.git"})).unwrap(),
            "octocat/hello-world"
        );
        assert_eq!(
            repository_args(&json!({"owner":"octocat","repo":"hello-world"})).unwrap(),
            "octocat/hello-world"
        );
    }

    #[test]
    fn credential_discovery_returns_metadata_without_token() {
        let (vault, dek, _) = token_entry("github");
        enable_mcp(&vault, &dek);
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let text = call_tool(&mut session, "github_list_credentials", json!({})).unwrap();
        assert!(text.contains("github"));
        assert!(!text.contains("ghp_test_token_value"));
    }

    #[test]
    fn write_is_denied_when_desktop_confirm_rejects() {
        let (vault, dek, id) = token_entry("github");
        enable_mcp(&vault, &dek);
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let error = crate::confirm::with_auto(Some(false), || {
            call_tool(
                &mut session,
                "github_issue_create",
                json!({
                    "credential_id": id,
                    "repo": "octocat/hello-world",
                    "title": "bug"
                }),
            )
        })
        .unwrap_err();
        assert!(error.contains("拒绝"), "{error}");
    }
}
