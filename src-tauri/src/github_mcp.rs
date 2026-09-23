use crate::http_guard::{assert_public_target, parse_http_url, sha256_hex, PublicResolver};
use crate::redact::redact_text;
use crate::session::Session;
use crate::vault::{SecretPayload, Vault};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::io::Read;
use std::time::Duration;

const POLICY_KEY: &str = "github_mcp_policy";
const API_BASE: &str = "https://api.github.com";
const API_VERSION: &str = "2022-11-28";
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_CONTENT_BYTES: usize = 64 * 1024;
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GithubWorkspace {
    pub name: String,
    pub path: String,
    pub default_credential_id: Option<String>,
}

impl Default for GithubWorkspace {
    fn default() -> Self {
        Self {
            name: String::new(),
            path: String::new(),
            default_credential_id: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GithubMcpPolicy {
    pub enabled: bool,
    pub api_write_enabled: bool,
    pub default_credential_id: Option<String>,
    pub workspaces: Vec<GithubWorkspace>,
}

impl Default for GithubMcpPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            api_write_enabled: false,
            default_credential_id: None,
            workspaces: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubCredentialMeta {
    pub id: String,
    pub title: String,
    pub account: Option<String>,
    pub is_default: bool,
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
        "description": "GitHub Token 的标题、账号或 ID。可省略：使用 MCP 页的默认 Token；若金库里只有一个 GitHub Token 则自动选用。"
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
struct GithubWorkflowRunDto {
    id: Option<i64>,
    name: Option<String>,
    display_title: Option<String>,
    status: Option<String>,
    conclusion: Option<String>,
    event: Option<String>,
    head_branch: Option<String>,
    html_url: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubFileDto {
    path: Option<String>,
    sha: Option<String>,
    size: Option<u64>,
    content: Option<String>,
    is_binary: bool,
    truncated: bool,
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

pub fn api_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "github_list_credentials",
            "列出本地活动 GitHub Token 的标题、账号和是否为默认凭据。回答「我有哪些 GitHub Token / 该用哪条凭据」时调用。日常读写不必先调这个：可直接传标题，或省略后使用默认 Token。永不返回 Token 明文。",
            schema(&[], &[]),
        ),
        tool(
            "github_get_authenticated_user",
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
            "github_list_repositories",
            "列出当前 Token 可见的仓库（full_name、默认分支、私有与否）。回答「我有多少 GitHub 仓库 / 列出我的仓库」时调用。默认只看自己拥有的仓库。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("visibility", json!({"type":"string","enum":["all","public","private"],"default":"all"})),
                    ("affiliation", json!({"type":"string","enum":["owner","collaborator","organization_member"],"default":"owner"})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &[],
            ),
        ),
        tool(
            "github_get_repository",
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
            "github_get_file",
            "读取 GitHub 仓库里的单个文本文件（README、工作流 YAML 等）。需要看远端文件内容而不是本地工作区时调用。目录会报错。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("path", string_schema(1, 500)),
                    ("ref", string_schema(1, 200)),
                ],
                &["repo", "path"],
            ),
        ),
        tool(
            "github_list_issues",
            "列出仓库 Issue（不含 PR）：编号、标题、状态、标签、指派人、评论数。回答「这个仓库有哪些未关闭 Issue」时调用。",
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
            "github_list_pull_requests",
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
            "github_list_workflow_runs",
            "列出仓库最近的 GitHub Actions 运行：status、conclusion、head_branch、html_url。轮询 CI / 发布流水线状态时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("branch", string_schema(1, 200)),
                    ("status", json!({"type":"string","enum":["queued","in_progress","completed"]})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":20})),
                ],
                &["repo"],
            ),
        ),
        write_tool(
            "github_create_issue",
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
            "github_create_issue_comment",
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
            "github_create_pull_request",
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
            "github_create_release",
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

pub fn tool_definitions() -> Vec<Value> {
    let mut tools = api_tool_definitions();
    tools.extend(crate::git_workspace::tool_definitions());
    tools
}

pub fn tool_definitions_for_policy(policy: &GithubMcpPolicy) -> Vec<Value> {
    let mut tools = crate::git_workspace::tool_definitions();
    tools.extend(
        api_tool_definitions()
            .into_iter()
            .filter(|definition| {
                definition["readOnly"].as_bool().unwrap_or(false) || policy.api_write_enabled
            }),
    );
    tools
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
    api_tool_definitions()
        .iter()
        .any(|definition| definition.get("name").and_then(Value::as_str) == Some(name))
}

pub fn is_github_tool(name: &str) -> bool {
    is_github_api_tool(name) || crate::git_workspace::is_git_tool(name)
}

pub fn load_policy(vault: &Vault, dek: &[u8; 32]) -> GithubMcpPolicy {
    let Some(raw) = vault.get_secret_setting(dek, POLICY_KEY).ok().flatten() else {
        return GithubMcpPolicy::default();
    };
    let Ok(value) = serde_json::from_str::<Value>(&raw) else {
        return GithubMcpPolicy::default();
    };
    if value.get("scopes").is_some() || value.get("allowed_repositories").is_some() {
        return GithubMcpPolicy::default();
    }
    let mut value = value;
    if value.get("default_credential_id").is_none() {
        if let Some(legacy) = value.get("credential_id").cloned() {
            if let Some(object) = value.as_object_mut() {
                object.insert("default_credential_id".into(), legacy);
            }
        }
    }
    normalize_policy(serde_json::from_value(value).unwrap_or_default()).unwrap_or_default()
}

pub fn save_policy(vault: &Vault, dek: &[u8; 32], policy: &GithubMcpPolicy) -> Result<(), String> {
    let normalized = normalize_policy(policy.clone())?;
    let raw = serde_json::to_string(&normalized).map_err(|e| e.to_string())?;
    vault
        .set_secret_setting(dek, POLICY_KEY, &raw)
        .map_err(|e| e.to_string())
}

pub fn normalize_policy(policy: GithubMcpPolicy) -> Result<GithubMcpPolicy, String> {
    let mut names = std::collections::HashSet::new();
    let mut workspaces = Vec::new();
    for workspace in policy.workspaces {
        let name = normalize_workspace_name(&workspace.name)?;
        if !names.insert(name.clone()) {
            return Err(format!("工作区短名重复：{name}"));
        }
        let path = workspace.path.trim().to_string();
        if path.is_empty() {
            return Err(format!("工作区 {name} 缺少绝对路径"));
        }
        let path_buf = std::path::PathBuf::from(&path);
        if !path_buf.is_absolute() {
            return Err(format!("工作区 {name} 的 path 必须是绝对路径"));
        }
        let default_credential_id = workspace
            .default_credential_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        workspaces.push(GithubWorkspace {
            name,
            path,
            default_credential_id,
        });
    }
    let default_credential_id = policy
        .default_credential_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    Ok(GithubMcpPolicy {
        enabled: policy.enabled,
        api_write_enabled: policy.enabled && policy.api_write_enabled,
        default_credential_id,
        workspaces,
    })
}

pub fn normalize_workspace_name(raw: &str) -> Result<String, String> {
    let name = raw.trim();
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return Err("工作区短名只能是字母、数字、下划线或连字符".into());
    }
    Ok(name.to_string())
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
                is_default: false,
            });
        }
    }
    if let Ok(policy) = session
        .vault()
        .and_then(|vault| session.dek().map(|dek| load_policy(vault, dek)))
    {
        if let Some(default_id) = policy.default_credential_id.as_deref() {
            for item in &mut out {
                item.is_default = item.id == default_id;
            }
        } else if out.len() == 1 {
            out[0].is_default = true;
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
        return Err("金库里没有活动的 GitHub API Token。请先在保险库新建一条服务为 github 的 API Token。".into());
    }
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    let policy = load_policy(vault, dek);
    let selected = if let Some(requested) = requested {
        match_credential(&credentials, requested)?
    } else if let Some(default_id) = policy.default_credential_id.as_deref() {
        credentials
            .iter()
            .find(|item| item.id == default_id)
            .ok_or_else(|| "MCP 页选择的默认 GitHub Token 已不存在，请重新选择".to_string())?
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
            "有多条 GitHub Token，请传 credential=标题，或在 Sealbox MCP 页选定默认 Token。可选：{titles}"
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
            "找不到 GitHub Token「{requested}」。先调 github_list_credentials，或在 MCP 页选定默认 Token。"
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
            let reason = if raw == "GitHub MCP 能力未启用" {
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
        return crate::git_workspace::call_tool_text(session, name, args)
            .map(|text| (200, text));
    }
    if name == "github_list_credentials" {
        let definition = tool_definitions()
            .into_iter()
            .find(|definition| definition.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| "未知 GitHub 工具".to_string())?;
        validate_arguments(&definition["inputSchema"], &args)?;
        let vault = session.vault().map_err(|e| e.to_string())?;
        let dek = session.dek().map_err(|e| e.to_string())?;
        if !load_policy(vault, dek).enabled {
            return Err("GitHub MCP 能力未启用".into());
        }
        let credentials = list_credentials(session)?;
        session.touch();
        return serde_json::to_string_pretty(&credentials)
            .map(|text| (200, text))
            .map_err(|e| e.to_string());
    }
    let (token, credential_label) = prepare(session, name, &args)?;
    let (status, result) = match name {
        "github_create_release" => {
            let repository = repository_args(&args)?;
            let tag_name = release_tag_arg(&args)?;
            let target_commitish = optional_release_string(&args, "target_commitish", 200)?;
            let name = optional_release_string(&args, "name", 200)?;
            let body = optional_release_body(&args)?;
            let draft = bool_arg(&args, "draft", true)?;
            let prerelease = bool_arg(&args, "prerelease", false)?;
            let generate_release_notes = bool_arg(&args, "generate_release_notes", false)?;
            let make_latest = enum_arg(&args, "make_latest", &["true", "false", "legacy"], "legacy")?;
            confirm_github_write(
                "创建 GitHub Release",
                &format!(
                    "仓库 {repository}\n标签 {tag_name}\n草稿 {}\n凭据 {}",
                    if draft { "是" } else { "否" },
                    credential_label
                ),
            )?;
            let mut request = Map::new();
            request.insert("tag_name".into(), Value::String(tag_name));
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
            let request = Value::Object(request);
            post_json(&token, &format!("/repos/{repository}/releases"), &request, |value| {
                release_dto(value).ok_or_else(|| "GitHub 响应格式不正确".into())
            })
        }
        "github_create_issue" => {
            let repository = repository_args(&args)?;
            let title = required_text(&args, "title", 256)?;
            let body = optional_release_body(&args)?;
            let labels = optional_csv(&args, "labels")?;
            confirm_github_write(
                "创建 GitHub Issue",
                &format!("仓库 {repository}\n标题 {title}\n凭据 {credential_label}"),
            )?;
            let mut request = Map::new();
            request.insert("title".into(), Value::String(title));
            if let Some(value) = body {
                request.insert("body".into(), Value::String(value));
            }
            if !labels.is_empty() {
                request.insert(
                    "labels".into(),
                    Value::Array(labels.into_iter().map(Value::String).collect()),
                );
            }
            post_json(&token, &format!("/repos/{repository}/issues"), &Value::Object(request), |value| {
                issue_dto(value).ok_or_else(|| "GitHub 响应格式不正确".into())
            })
        }
        "github_create_issue_comment" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let body = required_text(&args, "body", MAX_RELEASE_BODY_BYTES)?;
            confirm_github_write(
                "评论 GitHub Issue/PR",
                &format!("仓库 {repository}#{number}\n凭据 {credential_label}"),
            )?;
            post_json(
                &token,
                &format!("/repos/{repository}/issues/{number}/comments"),
                &json!({"body": body}),
                |value| {
                    Ok(json!({
                        "id": value.get("id").and_then(Value::as_i64),
                        "html_url": limited_string(value.get("html_url")),
                        "user": limited_string(value.get("user").and_then(|item| item.get("login"))),
                    }))
                },
            )
        }
        "github_create_pull_request" => {
            let repository = repository_args(&args)?;
            let title = required_text(&args, "title", 256)?;
            let head = required_text(&args, "head", 200)?;
            let base = required_text(&args, "base", 200)?;
            let body = optional_release_body(&args)?;
            let draft = bool_arg(&args, "draft", true)?;
            confirm_github_write(
                "创建 GitHub Pull Request",
                &format!(
                    "仓库 {repository}\n{head} → {base}\n标题 {title}\n草稿 {}\n凭据 {credential_label}",
                    if draft { "是" } else { "否" }
                ),
            )?;
            let mut request = Map::new();
            request.insert("title".into(), Value::String(title));
            request.insert("head".into(), Value::String(head));
            request.insert("base".into(), Value::String(base));
            request.insert("draft".into(), Value::Bool(draft));
            if let Some(value) = body {
                request.insert("body".into(), Value::String(value));
            }
            post_json(&token, &format!("/repos/{repository}/pulls"), &Value::Object(request), |value| {
                pull_dto(value).ok_or_else(|| "GitHub 响应格式不正确".into())
            })
        }
        "github_get_authenticated_user" => request_json(&token, "/user", |value| {
            serde_json::to_value(GithubUserDto {
                id: value.get("id").and_then(Value::as_i64),
                login: limited_string(value.get("login")),
                name: limited_string(value.get("name")),
                company: limited_string(value.get("company")),
                blog: limited_string(value.get("blog")),
                html_url: limited_string(value.get("html_url")),
                public_repos: value.get("public_repos").and_then(Value::as_i64),
                private_repos: value.get("total_private_repos").and_then(Value::as_i64),
            })
            .map_err(|e| e.to_string())
        }),
        "github_list_repositories" => {
            let visibility = enum_arg(&args, "visibility", &["all", "public", "private"], "all")?;
            let affiliation = enum_arg(
                &args,
                "affiliation",
                &["owner", "collaborator", "organization_member"],
                "owner",
            )?;
            let (page, per_page) = page_args(&args)?;
            let path = format!(
                "/user/repos?visibility={visibility}&affiliation={affiliation}&page={page}&per_page={per_page}"
            );
            request_json(&token, &path, |value| {
                let repos = value
                    .as_array()
                    .ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
                let items: Vec<Value> = repos
                    .iter()
                    .filter_map(repository_dto)
                    .take(per_page as usize)
                    .collect();
                let count = items.len();
                Ok(json!({"repositories": items, "count": count}))
            })
        }
        "github_get_repository" => {
            let repository = repository_args(&args)?;
            request_json(&token, &format!("/repos/{repository}"), |value| {
                repository_dto(value).ok_or_else(|| "GitHub 响应格式不正确".into())
            })
        }
        "github_get_file" => {
            let repository = repository_args(&args)?;
            let path = path_arg(&args, "path")?;
            let reference = optional_ref(&args)?;
            let endpoint = if let Some(reference) = reference {
                format!("/repos/{repository}/contents/{path}?ref={reference}")
            } else {
                format!("/repos/{repository}/contents/{path}")
            };
            request_json(&token, &endpoint, file_dto)
        }
        "github_list_issues" => {
            let repository = repository_args(&args)?;
            let state = enum_arg(&args, "state", &["open", "closed", "all"], "open")?;
            let (page, per_page) = page_args(&args)?;
            let endpoint =
                format!("/repos/{repository}/issues?state={state}&page={page}&per_page={per_page}");
            request_json(&token, &endpoint, |value| {
                list_dto(value, per_page, issue_dto)
            })
        }
        "github_list_pull_requests" => {
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
            request_json(&token, &format!("/repos/{repository}/pulls/{number}"), |value| {
                pull_dto(value).ok_or_else(|| "GitHub 响应格式不正确".into())
            })
        }
        "github_list_workflow_runs" => {
            let repository = repository_args(&args)?;
            let (page, per_page) = page_args_with_default(&args, 20)?;
            let mut endpoint = format!(
                "/repos/{repository}/actions/runs?page={page}&per_page={per_page}"
            );
            if let Some(branch) = optional_release_string(&args, "branch", 200)? {
                endpoint.push_str("&branch=");
                endpoint.push_str(&percent_encode(&branch, false));
            }
            if let Some(status) = args.get("status").and_then(Value::as_str) {
                let status = enum_arg(
                    &json!({"status": status}),
                    "status",
                    &["queued", "in_progress", "completed"],
                    "completed",
                )?;
                endpoint.push_str("&status=");
                endpoint.push_str(&status);
            }
            request_json(&token, &endpoint, |value| {
                let runs = value
                    .get("workflow_runs")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
                let items: Vec<Value> = runs
                    .iter()
                    .filter_map(workflow_run_dto)
                    .take(per_page as usize)
                    .collect();
                let count = items.len();
                Ok(json!({"workflow_runs": items, "count": count}))
            })
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
    let policy = load_policy(vault, dek);
    if !policy.enabled {
        return Err("GitHub MCP 能力未启用".into());
    }
    if !definition["readOnly"].as_bool().unwrap_or(false) && !policy.api_write_enabled {
        return Err("GitHub API 写入能力未启用".into());
    }
    validate_arguments(&definition["inputSchema"], args)?;
    let resolved = resolve_github_credential(session, args)?;
    Ok((resolved.token, resolved.title))
}

fn confirm_github_write(title: &str, detail: &str) -> Result<(), String> {
    if crate::confirm::ask(title, &format!("{detail}\n\n允许这次 GitHub 写操作？")) {
        Ok(())
    } else {
        Err("用户拒绝了这次 GitHub 写操作".into())
    }
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

fn path_arg(args: &Value, name: &str) -> Result<String, String> {
    let path = args
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("缺少参数 {name}"))?;
    if path.is_empty()
        || path.len() > 500
        || path.contains('%')
        || path.contains('\\')
        || path.contains('\0')
        || path.chars().any(char::is_control)
    {
        return Err("文件路径格式不合法".into());
    }
    let segments: Vec<&str> = path.split('/').collect();
    if segments
        .iter()
        .any(|segment| segment.is_empty() || *segment == "." || *segment == "..")
    {
        return Err("文件路径格式不合法".into());
    }
    Ok(percent_encode(path, true))
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
        || tag.split('/').any(|segment| segment.is_empty() || segment == "." || segment == "..")
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

fn post_json<T>(
    token: &str,
    path: &str,
    request: &Value,
    map: impl FnOnce(&Value) -> Result<T, String>,
) -> Result<(u16, T), String> {
    let target = parse_http_url(&format!("{API_BASE}{path}"), true)?;
    if target.scheme != "https" || target.host != "api.github.com" || target.port != 443 {
        return Err("GitHub API 目标不合法".into());
    }
    assert_public_target(&target)?;
    let body = serde_json::to_vec(request).map_err(|_| "GitHub 请求体无效".to_string())?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err("GitHub 请求体超过安全大小限制".into());
    }
    let agent = ureq::builder()
        .redirects(0)
        .timeout(Duration::from_secs(15))
        .timeout_connect(Duration::from_secs(8))
        .resolver(PublicResolver)
        .user_agent(concat!("Sealbox/", env!("CARGO_PKG_VERSION")))
        .build();
    let response = agent
        .post(&format!("{API_BASE}{path}"))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.github+json")
        .set("Content-Type", "application/json")
        .set("X-GitHub-Api-Version", API_VERSION)
        .send_bytes(&body);
    let (status, body, truncated) = match response {
        Ok(response) => read_response(response),
        Err(ureq::Error::Status(status, response)) => {
            let (_, body, truncated) = read_response(response);
            return Err(redact_text(&github_error(status, &body, truncated), &[token]));
        }
        Err(_) => return Err("GitHub 网络请求失败".into()),
    };
    if status != 201 {
        return Err(format!("GitHub 写入返回异常状态 {status}"));
    }
    if truncated {
        return Err("GitHub 响应超过安全大小限制".into());
    }
    let value: Value = serde_json::from_slice(&body)
        .map_err(|_| "GitHub 响应不是有效 JSON".to_string())?;
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

fn workflow_run_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubWorkflowRunDto {
        id: value.get("id").and_then(Value::as_i64),
        name: limited_string(value.get("name")),
        display_title: limited_string(value.get("display_title")),
        status: limited_string(value.get("status")),
        conclusion: limited_string(value.get("conclusion")),
        event: limited_string(value.get("event")),
        head_branch: limited_string(value.get("head_branch")),
        html_url: limited_string(value.get("html_url")),
        created_at: limited_string(value.get("created_at")),
        updated_at: limited_string(value.get("updated_at")),
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

fn file_dto(value: &Value) -> Result<Value, String> {
    if value.get("type").and_then(Value::as_str) == Some("dir") || value.get("content").is_none() {
        return Err("GitHub 路径不是可读取的单个文件".into());
    }
    let encoded = value
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.replace('\n', "").as_bytes())
        .map_err(|_| "文件内容不是有效 Base64".to_string())?;
    let is_binary = std::str::from_utf8(&decoded).is_err() || decoded.contains(&0);
    let content = if is_binary {
        None
    } else {
        Some(truncate(
            std::str::from_utf8(&decoded).unwrap_or_default(),
            MAX_CONTENT_BYTES,
        ))
    };
    serde_json::to_value(GithubFileDto {
        path: limited_string(value.get("path")),
        sha: limited_string(value.get("sha")),
        size: value.get("size").and_then(Value::as_u64),
        content,
        is_binary,
        truncated: decoded.len() > MAX_CONTENT_BYTES,
    })
    .map_err(|e| e.to_string())
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

    #[test]
    fn default_policy_is_disabled() {
        let policy = GithubMcpPolicy::default();
        assert!(!policy.enabled);
        assert!(!policy.api_write_enabled);
    }

    #[test]
    fn legacy_policy_fields_migrate_to_disabled() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .set_secret_setting(
                &dek,
                "github_mcp_policy",
                r#"{"enabled":true,"scopes":["user"],"allowed_repositories":["octocat/repo"]}"#,
            )
            .unwrap();
        assert!(!load_policy(&vault, &dek).enabled);
    }

    #[test]
    fn repository_and_path_reject_traversal() {
        assert!(normalize_repository("octocat/hello-world/extra").is_err());
        assert!(normalize_repository("octocat/%2e%2e").is_err());
        assert!(path_arg(&json!({"path":"src/../secret"}), "path").is_err());
        assert!(path_arg(&json!({"path":"src/%2e%2e/secret"}), "path").is_err());
        assert_eq!(
            path_arg(&json!({"path":"docs/my file@2.txt"}), "path").unwrap(),
            "docs/my%20file%402.txt"
        );
        assert!(optional_ref(&json!({"ref":"refs/../main"})).is_err());
    }

    #[test]
    fn release_tool_is_high_risk_and_closed() {
        let definition = api_tool_definitions()
            .into_iter()
            .find(|definition| definition["name"] == "github_create_release")
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
    fn write_tools_require_the_separate_policy_switch() {
        let read_only = tool_definitions_for_policy(&GithubMcpPolicy {
            enabled: true,
            api_write_enabled: false,
            ..Default::default()
        });
        assert!(!read_only
            .iter()
            .any(|definition| definition["name"] == "github_create_release"));
        let with_write = tool_definitions_for_policy(&GithubMcpPolicy {
            enabled: true,
            api_write_enabled: true,
            ..Default::default()
        });
        assert!(with_write
            .iter()
            .any(|definition| definition["name"] == "github_create_release"));
        assert!(with_write
            .iter()
            .any(|definition| definition["name"] == "github_create_pull_request"));
        assert!(with_write
            .iter()
            .any(|definition| definition["name"] == "github_create_issue"));
    }

    #[test]
    fn read_only_tools_have_closed_schemas() {
        let expected = [
            "github_list_credentials",
            "github_get_authenticated_user",
            "github_list_repositories",
            "github_get_repository",
            "github_get_file",
            "github_list_issues",
            "github_list_pull_requests",
            "github_get_pull_request",
            "github_list_workflow_runs",
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
        assert!(is_github_tool("github_git_status"));
        assert!(!is_github_api_tool("github_git_status"));
    }

    #[test]
    fn all_github_tools_reject_when_policy_is_disabled() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let cases = [
            ("github_list_credentials", json!({})),
            (
                "github_get_authenticated_user",
                json!({"credential_id":"id"}),
            ),
            ("github_list_repositories", json!({"credential_id":"id"})),
            (
                "github_get_repository",
                json!({"credential_id":"id","owner":"octocat","repo":"hello-world"}),
            ),
            (
                "github_get_file",
                json!({"credential_id":"id","owner":"octocat","repo":"hello-world","path":"README.md"}),
            ),
            (
                "github_list_issues",
                json!({"credential_id":"id","owner":"octocat","repo":"hello-world"}),
            ),
            (
                "github_list_pull_requests",
                json!({"credential_id":"id","owner":"octocat","repo":"hello-world"}),
            ),
        ];
        for (name, args) in cases {
            let error = call_tool(&mut session, name, args).unwrap_err();
            assert!(error.contains("未启用"), "{name}: {error}");
        }
        let release_error = call_tool(
            &mut session,
            "github_create_release",
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
            "github_git_status",
            json!({"path":"E:\\\\repo"}),
        )
        .unwrap_err();
        assert!(git_error.contains("未启用"), "{git_error}");
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
        assert_eq!(read_only, 9);
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

    #[test]
    fn policy_disables_api_writes_without_disabling_git() {
        let policy = normalize_policy(GithubMcpPolicy {
            enabled: false,
            api_write_enabled: true,
            ..Default::default()
        })
        .unwrap();
        assert!(!policy.enabled);
        assert!(!policy.api_write_enabled);
    }

    #[test]
    fn file_dto_filters_and_marks_binary_content() {
        let value = json!({
            "type":"file",
            "path":"README.md",
            "sha":"abc",
            "size":3,
            "content":base64::engine::general_purpose::STANDARD.encode("abc")
        });
        let dto = file_dto(&value).unwrap();
        assert_eq!(dto["content"], "abc");
        assert_eq!(dto["is_binary"], false);
        assert_eq!(dto["truncated"], false);
        assert!(dto.get("token").is_none());
        assert!(file_dto(&json!({"type":"dir"})).is_err());
        let leaked = serde_json::to_string(&json!({"body": "ghp_test_token_value"})).unwrap();
        let redacted = redact_text(&leaked, &["ghp_test_token_value"]);
        assert!(!redacted.contains("ghp_test_token_value"));
        assert!(redacted.contains("[REDACTED]"));
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
    fn enabled_policy_requires_no_preselected_token() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        save_policy(
            &vault,
            &dek,
            &GithubMcpPolicy {
                enabled: true,
                api_write_enabled: false,
                ..Default::default()
            },
        )
        .unwrap();
        let policy = load_policy(&vault, &dek);
        assert!(policy.enabled);
        assert!(!policy.api_write_enabled);
    }

    #[test]
    fn active_token_is_selected_by_tool_argument() {
        let (vault, dek, id) = token_entry("github");
        save_policy(
            &vault,
            &dek,
            &GithubMcpPolicy {
                enabled: true,
                api_write_enabled: false,
                ..Default::default()
            },
        )
        .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let (token, _) = prepare(
            &session,
            "github_get_repository",
            &json!({"credential_id":id,"owner":"octocat","repo":"other"}),
        )
        .unwrap();
        assert_eq!(token, "ghp_test_token_value");
    }

    #[test]
    fn credential_can_be_matched_by_title_or_omitted_when_unique() {
        let (vault, dek, _) = token_entry("github");
        save_policy(
            &vault,
            &dek,
            &GithubMcpPolicy {
                enabled: true,
                api_write_enabled: false,
                ..Default::default()
            },
        )
        .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let by_title = prepare(
            &session,
            "github_get_authenticated_user",
            &json!({"credential":"github"}),
        )
        .unwrap();
        assert_eq!(by_title.0, "ghp_test_token_value");
        let implicit = prepare(&session, "github_get_authenticated_user", &json!({})).unwrap();
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
        save_policy(
            &vault,
            &dek,
            &GithubMcpPolicy {
                enabled: true,
                api_write_enabled: false,
                ..Default::default()
            },
        )
        .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let text = call_tool(&mut session, "github_list_credentials", json!({})).unwrap();
        assert!(text.contains("github"));
        assert!(text.contains("is_default"));
        assert!(!text.contains("ghp_test_token_value"));
    }

    #[test]
    fn write_is_denied_when_desktop_confirm_rejects() {
        let (vault, dek, id) = token_entry("github");
        save_policy(
            &vault,
            &dek,
            &GithubMcpPolicy {
                enabled: true,
                api_write_enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let error = crate::confirm::with_auto(Some(false), || {
            call_tool(
                &mut session,
                "github_create_issue",
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
