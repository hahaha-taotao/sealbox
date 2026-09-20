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
const MAX_CONTENT_BYTES: usize = 64 * 1024;
const MAX_DESCRIPTION_BYTES: usize = 2 * 1024;
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
pub struct GithubMcpPolicy {
    pub enabled: bool,
}

impl Default for GithubMcpPolicy {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubCredentialMeta {
    pub id: String,
    pub title: String,
    pub account: Option<String>,
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
    body: Option<String>,
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

pub fn api_tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "github_list_credentials",
            "列出本地活动 GitHub API Token 的元数据（ID、名称、账号）。永不返回 Token。",
            schema(&[], &[]),
        ),
        tool(
            "github_get_authenticated_user",
            "读取指定 GitHub Token 对应账号的非敏感公开资料。只执行固定的 GET /user。",
            schema(&[("credential_id", string_schema(1, 100))], &["credential_id"]),
        ),
        tool(
            "github_list_repositories",
            "列出 GitHub 账号可见的仓库元数据。只执行固定的 GET /user/repos，并使用指定 Token。",
            schema(
                &[
                    ("credential_id", string_schema(1, 100)),
                    ("visibility", json!({"type":"string","enum":["all","public","private"],"default":"all"})),
                    ("affiliation", json!({"type":"string","enum":["owner","collaborator","organization_member"],"default":"owner"})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["credential_id"],
            ),
        ),
        tool(
            "github_get_repository",
            "读取 GitHub 仓库的非敏感元数据。只执行固定的 GET /repos/{owner}/{repo}。",
            schema(
                &[
                    ("credential_id", string_schema(1, 100)),
                    ("owner", string_schema(1, 100)),
                    ("repo", string_schema(1, 100)),
                ],
                &["credential_id", "owner", "repo"],
            ),
        ),
        tool(
            "github_get_file",
            "读取 GitHub 仓库中的文本文件。只执行固定的 GET contents endpoint，不接受任意 URL、请求头或请求体。",
            schema(
                &[
                    ("credential_id", string_schema(1, 100)),
                    ("owner", string_schema(1, 100)),
                    ("repo", string_schema(1, 100)),
                    ("path", string_schema(1, 500)),
                    ("ref", string_schema(1, 200)),
                ],
                &["credential_id", "owner", "repo", "path"],
            ),
        ),
        tool(
            "github_list_issues",
            "列出 GitHub 仓库的 Issue。只执行固定的 GET issues endpoint。",
            schema(
                &[
                    ("credential_id", string_schema(1, 100)),
                    ("owner", string_schema(1, 100)),
                    ("repo", string_schema(1, 100)),
                    ("state", json!({"type":"string","enum":["open","closed","all"],"default":"open"})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["credential_id", "owner", "repo"],
            ),
        ),
        tool(
            "github_list_pull_requests",
            "列出 GitHub 仓库的 Pull Request 元数据。只执行固定的 GET pulls endpoint。",
            schema(
                &[
                    ("credential_id", string_schema(1, 100)),
                    ("owner", string_schema(1, 100)),
                    ("repo", string_schema(1, 100)),
                    ("state", json!({"type":"string","enum":["open","closed","all"],"default":"open"})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["credential_id", "owner", "repo"],
            ),
        ),
    ]
}

pub fn tool_definitions() -> Vec<Value> {
    let mut tools = api_tool_definitions();
    tools.extend(crate::git_workspace::tool_definitions());
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

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "readOnly": true,
        "risk": "low"
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
    if value.get("credential_id").is_some()
        || value.get("scopes").is_some()
        || value.get("allowed_repositories").is_some()
    {
        return GithubMcpPolicy::default();
    }
    serde_json::from_value(value).unwrap_or_default()
}

pub fn save_policy(vault: &Vault, dek: &[u8; 32], policy: &GithubMcpPolicy) -> Result<(), String> {
    let normalized = normalize_policy(policy.clone())?;
    let raw = serde_json::to_string(&normalized).map_err(|e| e.to_string())?;
    vault
        .set_secret_setting(dek, POLICY_KEY, &raw)
        .map_err(|e| e.to_string())
}

pub fn normalize_policy(policy: GithubMcpPolicy) -> Result<GithubMcpPolicy, String> {
    Ok(GithubMcpPolicy {
        enabled: policy.enabled,
    })
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
    let fingerprint = github_credential_fingerprint(&args);
    match call_tool_text(session, name, args) {
        Ok(text) => {
            let result_count = serde_json::from_str::<Value>(&text).ok().and_then(|value| {
                value
                    .get("items")
                    .or_else(|| value.get("repositories"))
                    .and_then(Value::as_array)
                    .map(Vec::len)
            });
            Ok(GithubCallResult {
                text,
                status: 200,
                result_count,
                credential_fingerprint: fingerprint.unwrap_or_default(),
                context,
            })
        }
        Err(raw) => {
            let (status, parsed_reason, message) = parse_call_error(&raw);
            let reason = if raw == "GitHub MCP 能力未启用" {
                "disabled"
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

fn call_tool_text(session: &mut Session, name: &str, args: Value) -> Result<String, String> {
    if crate::git_workspace::is_git_tool(name) {
        return crate::git_workspace::call_tool_text(session, name, args);
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
        return serde_json::to_string_pretty(&credentials).map_err(|e| e.to_string());
    }
    let token = prepare(session, name, &args)?;
    let result = match name {
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
        _ => return Err("未知 GitHub 工具".into()),
    }?;
    session.touch();
    let serialized = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
    Ok(redact_text(&serialized, &[token.as_str()]))
}

fn prepare(session: &Session, name: &str, args: &Value) -> Result<String, String> {
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
    validate_arguments(&definition["inputSchema"], args)?;
    let credential_id = args
        .get("credential_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "缺少参数 credential_id".to_string())?;
    let payload = vault
        .get_active_secret(dek, credential_id)
        .map_err(|_| "GitHub Token 不存在或已在回收站".to_string())?;
    let SecretPayload::ApiToken { service, token, .. } = payload else {
        return Err("凭据必须是 GitHub API Token".into());
    };
    if !service.trim().eq_ignore_ascii_case("github") {
        return Err("凭据不是 GitHub API Token".into());
    }
    Ok(token)
}

fn audit_context(args: &Value) -> GithubAuditContext {
    let repository = match (
        args.get("owner").and_then(Value::as_str),
        args.get("repo").and_then(Value::as_str),
    ) {
        (Some(owner), Some(repo)) => Some(format!("{owner}/{repo}")),
        _ => None,
    };
    GithubAuditContext {
        repository,
        path: args.get("path").and_then(Value::as_str).map(str::to_string),
        reference: args.get("ref").and_then(Value::as_str).map(str::to_string),
    }
}

fn github_credential_fingerprint(args: &Value) -> Option<String> {
    let id = args.get("credential_id").and_then(Value::as_str)?;
    Some(sha256_hex(id.as_bytes())[..12].to_string())
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
    }
    Ok(())
}

fn repository_args(args: &Value) -> Result<String, String> {
    let owner = args
        .get("owner")
        .and_then(Value::as_str)
        .ok_or("缺少参数 owner")?;
    let repo = args
        .get("repo")
        .and_then(Value::as_str)
        .ok_or("缺少参数 repo")?;
    normalize_repository(&format!("{owner}/{repo}"))
}

pub fn normalize_repository(raw: &str) -> Result<String, String> {
    if raw.len() > 201
        || raw.is_empty()
        || raw.contains('%')
        || raw.contains('\\')
        || raw.chars().any(char::is_control)
    {
        return Err("仓库名格式不合法".into());
    }
    let mut parts = raw.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    if parts.next().is_some() || !valid_segment(owner) || !valid_segment(repo) {
        return Err("仓库名格式不合法".into());
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
    let page = args.get("page").and_then(Value::as_u64).unwrap_or(1);
    let per_page = args.get("per_page").and_then(Value::as_u64).unwrap_or(30);
    if !(1..=100).contains(&page) || !(1..=MAX_PAGE_SIZE).contains(&per_page) {
        return Err("分页参数超出范围".into());
    }
    Ok((page, per_page))
}

fn request_json<T>(
    token: &str,
    path: &str,
    map: impl FnOnce(&Value) -> Result<T, String>,
) -> Result<T, String> {
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
    let (body, truncated) = match response {
        Ok(response) => {
            let (_, body, truncated) = read_response(response);
            (body, truncated)
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
    map(&value).map_err(|error| format!("GitHub 响应处理失败: {error}"))
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
        labels: value
            .get("labels")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .take(20)
                    .filter_map(|item| limited_string(item.get("name")))
                    .collect()
            })
            .unwrap_or_default(),
        body: limited_string_with_cap(value.get("body"), MAX_DESCRIPTION_BYTES),
    })
    .ok()
}

fn pull_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubIssueDto {
        number: value.get("number").and_then(Value::as_i64),
        title: limited_string(value.get("title")),
        state: limited_string(value.get("state")),
        html_url: limited_string(value.get("html_url")),
        user: GithubOwnerDto {
            login: limited_string(value.get("user").and_then(|v| v.get("login"))),
        },
        labels: value
            .get("labels")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .take(20)
                    .filter_map(|item| limited_string(item.get("name")))
                    .collect()
            })
            .unwrap_or_default(),
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
    fn all_seven_tools_have_read_only_contracts_and_closed_schemas() {
        let expected = [
            "github_list_credentials",
            "github_get_authenticated_user",
            "github_list_repositories",
            "github_get_repository",
            "github_get_file",
            "github_list_issues",
            "github_list_pull_requests",
        ];
        let definitions = tool_definitions();
        for name in expected {
            let definition = definitions
                .iter()
                .find(|definition| definition["name"] == name)
                .expect("tool must be registered");
            assert_eq!(definition["readOnly"], true);
            assert_eq!(definition["risk"], "low");
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
            assert_eq!(definition["readOnly"], true);
        }
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
        save_policy(&vault, &dek, &GithubMcpPolicy { enabled: true }).unwrap();
        assert!(load_policy(&vault, &dek).enabled);
    }

    #[test]
    fn active_token_is_selected_by_tool_argument() {
        let (vault, dek, id) = token_entry("github");
        save_policy(&vault, &dek, &GithubMcpPolicy { enabled: true }).unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let token = prepare(
            &session,
            "github_get_repository",
            &json!({"credential_id":id,"owner":"octocat","repo":"other"}),
        )
        .unwrap();
        assert_eq!(token, "ghp_test_token_value");
    }

    #[test]
    fn credential_discovery_returns_metadata_without_token() {
        let (vault, dek, _) = token_entry("github");
        save_policy(&vault, &dek, &GithubMcpPolicy { enabled: true }).unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let text = call_tool(&mut session, "github_list_credentials", json!({})).unwrap();
        assert!(text.contains("github"));
        assert!(!text.contains("ghp_test_token_value"));
    }
}
