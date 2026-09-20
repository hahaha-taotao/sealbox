//! ZoomKey JIRA / CRM 作为 Sealbox 本机 MCP 的一部分。
//!
//! 设计见 `docs/superpowers/specs/2026-09-17-zoomkey-mcp-design.md`。
//!
//! 与 `github_mcp` 同一套模式：策略开关 → 凭证绑定 → 固定目标请求 → 审计 → 脱敏。
//! 差别在于 ZoomKey 的站点在 RFC1918 内网且强制 mTLS，因此多了 `target` 与 `tls` 两层。

pub mod crm;
pub mod jira;
pub mod target;
pub mod tls;

use crate::http_guard::sha256_hex;
use crate::session::Session;
use crate::vault::{EntryKind, SecretPayload, Vault};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;
use std::time::Duration;
use zeroize::Zeroizing;

pub const POLICY_KEY: &str = "zoomkey_mcp_policy";
pub const JIRA_SERVICE: &str = "zoomkey-jira";
pub const CRM_SERVICE: &str = "zoomkey-crm";
pub const DEFAULT_JIRA_BASE: &str = "https://jira.zoomkey.com.cn";
pub const DEFAULT_CRM_BASE: &str = "https://crm.zoomkey.com.cn/webservice.php";
const DEFAULT_HOSTS: [&str; 2] = ["jira.zoomkey.com.cn", "crm.zoomkey.com.cn"];
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ZoomkeyEndpointPolicy {
    pub base_url: String,
    pub credential_id: String,
    pub client_cert_id: String,
    pub ca_bundle_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ZoomkeyMcpPolicy {
    pub enabled: bool,
    pub allowed_hosts: Vec<String>,
    pub jira: ZoomkeyEndpointPolicy,
    pub crm: ZoomkeyEndpointPolicy,
}

impl Default for ZoomkeyMcpPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_hosts: DEFAULT_HOSTS.iter().map(|h| h.to_string()).collect(),
            jira: ZoomkeyEndpointPolicy {
                base_url: DEFAULT_JIRA_BASE.into(),
                ..Default::default()
            },
            crm: ZoomkeyEndpointPolicy {
                base_url: DEFAULT_CRM_BASE.into(),
                ..Default::default()
            },
        }
    }
}

pub fn normalize_policy(mut policy: ZoomkeyMcpPolicy) -> ZoomkeyMcpPolicy {
    policy.jira.base_url = policy
        .jira
        .base_url
        .trim()
        .trim_end_matches('/')
        .to_string();
    if policy.jira.base_url.is_empty() {
        policy.jira.base_url = DEFAULT_JIRA_BASE.into();
    }
    policy.crm.base_url = normalize_crm_base_url(&policy.crm.base_url);
    policy.jira.credential_id = policy.jira.credential_id.trim().to_string();
    policy.jira.client_cert_id = policy.jira.client_cert_id.trim().to_string();
    policy.jira.ca_bundle_path = policy.jira.ca_bundle_path.trim().to_string();
    policy.crm.credential_id = policy.crm.credential_id.trim().to_string();
    policy.crm.client_cert_id = policy.crm.client_cert_id.trim().to_string();
    policy.crm.ca_bundle_path = policy.crm.ca_bundle_path.trim().to_string();

    let mut hosts: Vec<String> = Vec::new();
    for host in &policy.allowed_hosts {
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() || hosts.contains(&host) {
            continue;
        }
        hosts.push(host);
    }
    if hosts.is_empty() {
        hosts = DEFAULT_HOSTS.iter().map(|h| h.to_string()).collect();
    }
    policy.allowed_hosts = hosts;
    policy
}

/// CRM 必须打到 Vtiger 的 `webservice.php`。站点首页（`/` 或 `/index.php`）
/// 会返回 HTTP 200 的登录页 HTML，客户端就会报「非 JSON 响应」。
fn normalize_crm_base_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return DEFAULT_CRM_BASE.into();
    }
    let without_fragment = trimmed.split('#').next().unwrap_or(trimmed);
    let without_query = without_fragment.split('?').next().unwrap_or(without_fragment);
    let url = without_query.trim_end_matches('/');
    if url.is_empty() {
        return DEFAULT_CRM_BASE.into();
    }
    let path = crm_url_path(url);
    if path.is_empty() || path.eq_ignore_ascii_case("/index.php") {
        return match crm_url_origin(url) {
            Some(origin) => format!("{origin}/webservice.php"),
            None => DEFAULT_CRM_BASE.into(),
        };
    }
    url.to_string()
}

fn crm_url_path(url: &str) -> &str {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    match rest.find('/') {
        Some(index) => &rest[index..],
        None => "",
    }
}

fn crm_url_origin(url: &str) -> Option<String> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        return None;
    };
    let hostport = rest.split('/').next().unwrap_or("").trim();
    if hostport.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{hostport}"))
}

pub fn load_policy(vault: &Vault, dek: &[u8; 32]) -> ZoomkeyMcpPolicy {
    let Some(raw) = vault.get_secret_setting(dek, POLICY_KEY).ok().flatten() else {
        return ZoomkeyMcpPolicy::default();
    };
    let Ok(value) = serde_json::from_str::<Value>(&raw) else {
        return ZoomkeyMcpPolicy::default();
    };
    serde_json::from_value(migrate_policy_value(value))
        .map(normalize_policy)
        .unwrap_or_default()
}

/// 旧策略有三道开关（内网例外 / JIRA / CRM）。任一打开都迁成总开关打开。
fn migrate_policy_value(mut value: Value) -> Value {
    let Some(object) = value.as_object_mut() else {
        return value;
    };
    if object.contains_key("enabled") {
        return value;
    }
    let enabled = object
        .get("allow_private_network")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || object
            .get("jira_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || object
            .get("crm_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    object.insert("enabled".into(), Value::Bool(enabled));
    object.remove("allow_private_network");
    object.remove("jira_enabled");
    object.remove("crm_enabled");
    value
}

pub fn save_policy(vault: &Vault, dek: &[u8; 32], policy: &ZoomkeyMcpPolicy) -> Result<(), String> {
    let normalized = normalize_policy(policy.clone());
    let raw = serde_json::to_string(&normalized).map_err(|e| e.to_string())?;
    vault
        .set_secret_setting(dek, POLICY_KEY, &raw)
        .map_err(|e| e.to_string())
}

#[derive(Clone, Debug, Serialize)]
pub struct ZoomkeyCredentialOption {
    pub id: String,
    pub title: String,
    pub account: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ZoomkeyCertOption {
    pub id: String,
    pub title: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ZoomkeyCandidates {
    pub jira_credentials: Vec<ZoomkeyCredentialOption>,
    pub crm_credentials: Vec<ZoomkeyCredentialOption>,
    pub client_certs: Vec<ZoomkeyCertOption>,
}

pub fn list_candidates(session: &Session) -> Result<ZoomkeyCandidates, String> {
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;

    let tokens = vault
        .list_entries(&crate::vault::ListFilter {
            kind: Some(EntryKind::ApiToken),
            ..Default::default()
        })
        .map_err(|e| e.to_string())?;
    let mut jira_credentials = Vec::new();
    let mut crm_credentials = Vec::new();
    for entry in tokens {
        let Ok(SecretPayload::ApiToken {
            service, account, ..
        }) = vault.get_active_secret(dek, &entry.id)
        else {
            continue;
        };
        let option = ZoomkeyCredentialOption {
            id: entry.id.clone(),
            title: entry.title.clone(),
            account,
        };
        if service.trim().eq_ignore_ascii_case(JIRA_SERVICE) {
            jira_credentials.push(option);
        } else if service.trim().eq_ignore_ascii_case(CRM_SERVICE) {
            crm_credentials.push(option);
        }
    }

    let certs = vault
        .list_entries(&crate::vault::ListFilter {
            kind: Some(EntryKind::ClientCert),
            ..Default::default()
        })
        .map_err(|e| e.to_string())?;
    let client_certs = certs
        .into_iter()
        .map(|entry| ZoomkeyCertOption {
            id: entry.id,
            title: entry.title,
        })
        .collect();

    Ok(ZoomkeyCandidates {
        jira_credentials,
        crm_credentials,
        client_certs,
    })
}

pub fn tool_definitions(policy: &ZoomkeyMcpPolicy) -> Vec<Value> {
    if !policy.enabled {
        return Vec::new();
    }
    let mut out = jira::tool_definitions();
    out.extend(crm::tool_definitions());
    out
}

pub fn tool_definitions_for_vault(
    vault: &Vault,
    dek: &[u8; 32],
    policy: &ZoomkeyMcpPolicy,
) -> Vec<Value> {
    if !policy.enabled {
        return Vec::new();
    }
    let mut out = Vec::new();
    if endpoint_ready(vault, dek, &policy.jira, JIRA_SERVICE) {
        out.extend(jira::tool_definitions());
    }
    if endpoint_ready(vault, dek, &policy.crm, CRM_SERVICE) {
        out.extend(crm::tool_definitions());
    }
    out
}

fn endpoint_ready(
    vault: &Vault,
    dek: &[u8; 32],
    endpoint: &ZoomkeyEndpointPolicy,
    service: &str,
) -> bool {
    if endpoint.base_url.trim().is_empty()
        || endpoint.credential_id.trim().is_empty()
        || endpoint.client_cert_id.trim().is_empty()
        || !std::path::Path::new(endpoint.ca_bundle_path.trim()).is_file()
    {
        return false;
    }
    let Ok(SecretPayload::ApiToken {
        service: entry_service,
        account,
        token,
    }) = vault.get_active_secret(dek, endpoint.credential_id.trim())
    else {
        return false;
    };
    if !entry_service.trim().eq_ignore_ascii_case(service)
        || account.as_deref().map(str::trim).unwrap_or("").is_empty()
        || token.trim().is_empty()
    {
        return false;
    }
    let Ok(SecretPayload::ClientCert {
        cert_pem,
        key_pem,
        passphrase,
    }) = vault.get_active_secret(dek, endpoint.client_cert_id.trim())
    else {
        return false;
    };
    if passphrase
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
    {
        crate::certificate::validate_client_cert(&cert_pem, &key_pem, None).is_ok()
    } else {
        false
    }
}

pub fn is_zoomkey_tool(name: &str) -> bool {
    name.starts_with("zoomkey_jira_") || name.starts_with("zoomkey_crm_")
}

fn endpoint_of(name: &str) -> Option<&'static str> {
    if name.starts_with("zoomkey_jira_") {
        Some("jira")
    } else if name.starts_with("zoomkey_crm_") {
        Some("crm")
    } else {
        None
    }
}

/// 一次工具调用的审计上下文。
#[derive(Clone, Debug, Default)]
pub struct ZoomkeyAuditContext {
    pub endpoint: String,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct ZoomkeyCallResult {
    pub text: String,
    pub status: u16,
    pub result_count: Option<usize>,
    pub credential_fingerprint: String,
    pub context: ZoomkeyAuditContext,
}

#[derive(Clone, Debug)]
pub struct ZoomkeyCallError {
    pub message: String,
    pub status: Option<u16>,
    pub reason: &'static str,
    pub credential_fingerprint: Option<String>,
    pub context: ZoomkeyAuditContext,
}

pub(crate) struct ToolOutcome {
    pub text: String,
    pub count: Option<usize>,
    pub detail: String,
}

#[derive(Debug)]
pub(crate) struct ToolFailure {
    pub message: String,
    pub status: Option<u16>,
    pub reason: &'static str,
    pub detail: String,
}

impl ToolFailure {
    pub(crate) fn validation(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: None,
            reason: "validation",
            detail: String::new(),
        }
    }

    pub(crate) fn request(message: impl Into<String>, status: Option<u16>) -> Self {
        Self {
            message: message.into(),
            status,
            reason: "remote_http",
            detail: String::new(),
        }
    }
}

pub fn call_tool_detailed(
    session: &mut Session,
    name: &str,
    args: Value,
) -> Result<ZoomkeyCallResult, ZoomkeyCallError> {
    let Some(endpoint) = endpoint_of(name) else {
        return Err(ZoomkeyCallError {
            message: format!("未知 ZoomKey 工具 {name}"),
            status: None,
            reason: "validation",
            credential_fingerprint: None,
            context: ZoomkeyAuditContext::default(),
        });
    };
    let fingerprint = credential_fingerprint(session, endpoint);
    let outcome = if endpoint == "jira" {
        jira::call(session, name, &args)
    } else {
        crm::call(session, name, &args)
    };
    match outcome {
        Ok(outcome) => {
            session.touch();
            Ok(ZoomkeyCallResult {
                text: outcome.text,
                status: 200,
                result_count: outcome.count,
                credential_fingerprint: fingerprint.unwrap_or_default(),
                context: ZoomkeyAuditContext {
                    endpoint: endpoint.to_string(),
                    detail: outcome.detail,
                },
            })
        }
        Err(failure) => Err(ZoomkeyCallError {
            message: failure.message,
            status: failure.status,
            reason: failure.reason,
            credential_fingerprint: fingerprint,
            context: ZoomkeyAuditContext {
                endpoint: endpoint.to_string(),
                detail: failure.detail,
            },
        }),
    }
}

pub fn call_tool(session: &mut Session, name: &str, args: Value) -> Result<String, String> {
    call_tool_detailed(session, name, args)
        .map(|result| result.text)
        .map_err(|error| error.message)
}

/// 用户在 MCP 页点「测试连接」：绕过总开关，但仍走白名单、证书与凭据校验。
pub fn test_connection(
    session: &mut Session,
    label: &'static str,
) -> Result<ZoomkeyCallResult, ZoomkeyCallError> {
    let fingerprint = credential_fingerprint(session, label);
    let runtime = build_runtime_for_test(session, label).map_err(|failure| ZoomkeyCallError {
        message: failure.message,
        status: failure.status,
        reason: failure.reason,
        credential_fingerprint: fingerprint.clone(),
        context: ZoomkeyAuditContext {
            endpoint: label.to_string(),
            detail: failure.detail,
        },
    })?;
    let args = serde_json::json!({ "ping": true });
    let outcome = if label == "jira" {
        jira::connection_status(&runtime, &args)
    } else {
        crm::connection_status(&runtime, &args)
    };
    match outcome {
        Ok(outcome) => {
            session.touch();
            Ok(ZoomkeyCallResult {
                text: outcome.text,
                status: 200,
                result_count: outcome.count,
                credential_fingerprint: fingerprint.unwrap_or_default(),
                context: ZoomkeyAuditContext {
                    endpoint: label.to_string(),
                    detail: outcome.detail,
                },
            })
        }
        Err(failure) => Err(ZoomkeyCallError {
            message: failure.message,
            status: failure.status,
            reason: failure.reason,
            credential_fingerprint: fingerprint,
            context: ZoomkeyAuditContext {
                endpoint: label.to_string(),
                detail: failure.detail,
            },
        }),
    }
}

fn credential_fingerprint(session: &Session, endpoint: &str) -> Option<String> {
    let vault = session.vault().ok()?;
    let dek = session.dek().ok()?;
    let policy = load_policy(vault, dek);
    let id = match endpoint {
        "jira" => policy.jira.credential_id,
        "crm" => policy.crm.credential_id,
        _ => return None,
    };
    if id.trim().is_empty() {
        return None;
    }
    Some(sha256_hex(id.trim().as_bytes())[..12].to_string())
}

/// 已配置好 mTLS 与地址钉住的运行时。
pub(crate) struct EndpointRuntime {
    pub base_url: String,
    pub origin: String,
    pub agent: ureq::Agent,
    pub username: String,
    pub secret: Zeroizing<String>,
}

pub(crate) fn build_runtime(
    session: &Session,
    label: &'static str,
) -> Result<EndpointRuntime, ToolFailure> {
    build_runtime_inner(session, label, true)
}

/// 页面上的「测试连接」可以在总开关关闭时先验证证书与凭据；MCP 工具调用仍必须启用。
pub(crate) fn build_runtime_for_test(
    session: &Session,
    label: &'static str,
) -> Result<EndpointRuntime, ToolFailure> {
    build_runtime_inner(session, label, false)
}

fn build_runtime_inner(
    session: &Session,
    label: &'static str,
    require_enabled: bool,
) -> Result<EndpointRuntime, ToolFailure> {
    let vault = session
        .vault()
        .map_err(|e| ToolFailure::validation(e.to_string()))?;
    let dek = session
        .dek()
        .map_err(|e| ToolFailure::validation(e.to_string()))?;
    let policy = load_policy(vault, dek);
    let (endpoint, service) = match label {
        "jira" => (&policy.jira, JIRA_SERVICE),
        "crm" => (&policy.crm, CRM_SERVICE),
        _ => return Err(ToolFailure::validation("未知 ZoomKey 端点")),
    };
    if require_enabled && !policy.enabled {
        return Err(ToolFailure::validation(
            "ZoomKey MCP 未启用，请先在 Sealbox 的 MCP 页面打开",
        ));
    }
    let pinned = target::pin(&endpoint.base_url, &policy.allowed_hosts)
        .map_err(ToolFailure::validation)?;

    if endpoint.credential_id.trim().is_empty() {
        return Err(ToolFailure::validation(format!(
            "尚未为 ZoomKey {label} 选择金库凭据"
        )));
    }
    let payload = vault
        .get_active_secret(dek, endpoint.credential_id.trim())
        .map_err(|_| ToolFailure::validation("所选凭据不存在或已在回收站"))?;
    let SecretPayload::ApiToken {
        service: entry_service,
        account,
        token,
    } = payload
    else {
        return Err(ToolFailure::validation("所选凭据必须是 API Token 类型"));
    };
    if !entry_service.trim().eq_ignore_ascii_case(service) {
        return Err(ToolFailure::validation(format!(
            "凭据的「服务」需要填 {service}"
        )));
    }
    let username = account.unwrap_or_default().trim().to_string();
    if username.is_empty() {
        return Err(ToolFailure::validation("凭据缺少账号"));
    }
    if token.trim().is_empty() {
        return Err(ToolFailure::validation("凭据缺少密钥"));
    }

    if endpoint.client_cert_id.trim().is_empty() {
        return Err(ToolFailure::validation(format!(
            "尚未为 ZoomKey {label} 选择客户端证书"
        )));
    }
    let cert_payload = vault
        .get_active_secret(dek, endpoint.client_cert_id.trim())
        .map_err(|_| ToolFailure::validation("所选客户端证书不存在或已在回收站"))?;
    let SecretPayload::ClientCert {
        cert_pem,
        key_pem,
        passphrase,
    } = cert_payload
    else {
        return Err(ToolFailure::validation("所选条目必须是「客户端证书」类型"));
    };
    if passphrase
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return Err(ToolFailure::validation(
            "暂不支持带口令的客户端私钥，请改用无口令的 PEM",
        ));
    }

    let ca_path = endpoint.ca_bundle_path.trim();
    if ca_path.is_empty() {
        return Err(ToolFailure::validation("尚未配置 CA bundle 路径"));
    }
    let ca_pem = std::fs::read_to_string(ca_path)
        .map_err(|e| ToolFailure::validation(format!("读取 CA bundle 失败: {e}")))?;

    let tls_config = tls::cached_client_config(&ca_pem, &cert_pem, &key_pem)
        .map_err(|e| ToolFailure::validation(tls::describe_key_error(&e)))?;
    let agent = tuned_agent_builder()
        .tls_config(tls_config)
        .resolver(pinned.resolver())
        .build();

    Ok(EndpointRuntime {
        base_url: endpoint.base_url.clone(),
        origin: pinned.origin(),
        agent,
        username,
        secret: Zeroizing::new(token),
    })
}

/// ZoomKey 的 agent 调参。抽成函数是为了让单测能用同一份配置复现连接复用问题
/// （见本模块 `agent_does_not_reuse_a_connection_the_server_closed`）。
///
/// **不要打开连接池。** `crm.zoomkey.com.cn` 的响应头是 `Connection: Upgrade, close`，
/// 而 ureq 只把「整串等于 `close`」判定为不可复用（`ureq::response::connection_option`
/// 里的 `c.eq_ignore_ascii_case("close")`），于是把一条服务端已经关闭的连接放回池里。
/// 一次 CRM 工具调用要连发多个请求（`getchallenge` → `login` → 业务接口），
/// 第二个请求复用到那条死连接就会报 `Network Error: Unexpected EOF`。
/// 两个站点都是内网低频调用，重建连接的代价远小于这条隐蔽的失败路径。
///
/// 手工回归：`cargo run --example zoomkey_probe -- <ca.pem> <cert.pem> <key.pem> <url>`，
/// 加 `PROBE_FLOW=1` 复现「getchallenge → login」两连请求，`PROBE_POOL=1` 做对照。
fn tuned_agent_builder() -> ureq::AgentBuilder {
    ureq::builder()
        .redirects(0)
        .timeout(Duration::from_secs(30))
        .timeout_connect(Duration::from_secs(10))
        .user_agent(concat!("Sealbox/", env!("CARGO_PKG_VERSION")))
        .max_idle_connections(0)
}

pub(crate) struct RawResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub truncated: bool,
}

pub(crate) fn read_capped(response: ureq::Response) -> RawResponse {
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
    RawResponse {
        status,
        body,
        truncated,
    }
}

/// 把 JSON 里过长的字符串截断，避免把整篇描述灌给模型。
pub(crate) fn trim_json(value: &mut Value, cap: usize) {
    match value {
        Value::String(text) => {
            if text.len() > cap {
                let mut end = cap;
                while end > 0 && !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
                text.push('…');
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                trim_json(item, cap);
            }
        }
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                trim_json(item, cap);
            }
        }
        _ => {}
    }
}

pub(crate) fn to_pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

pub(crate) fn as_string(args: &Value, key: &str) -> String {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

pub(crate) fn as_bool(args: &Value, key: &str) -> bool {
    match args.get(key) {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(text)) => matches!(
            text.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        _ => false,
    }
}

pub(crate) fn as_u64(args: &Value, key: &str, fallback: u64, min: u64, max: u64) -> u64 {
    let raw = args.get(key).and_then(Value::as_u64).unwrap_or(fallback);
    raw.clamp(min, max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_policy_is_fully_disabled() {
        let policy = ZoomkeyMcpPolicy::default();
        assert!(!policy.enabled);
        assert!(policy.jira.base_url.contains("jira.zoomkey.com.cn"));
        assert!(policy.crm.base_url.ends_with("/webservice.php"));
        assert!(tool_definitions(&policy).is_empty());
    }

    #[test]
    fn enabled_policy_exposes_both_endpoint_tools() {
        let policy = ZoomkeyMcpPolicy {
            enabled: true,
            ..Default::default()
        };
        let tools = tool_definitions(&policy);
        assert_eq!(tools.len(), 20);
        assert!(tools.iter().all(|t| t["readOnly"] == true));
        assert!(tools
            .iter()
            .all(|t| t["inputSchema"]["additionalProperties"] == false));
        assert_eq!(
            tools
                .iter()
                .filter(|t| t["name"].as_str().unwrap().starts_with("zoomkey_jira_"))
                .count(),
            10
        );
        assert_eq!(
            tools
                .iter()
                .filter(|t| t["name"].as_str().unwrap().starts_with("zoomkey_crm_"))
                .count(),
            10
        );
    }

    #[test]
    fn normalize_restores_hosts_and_base_urls() {
        let policy = ZoomkeyMcpPolicy {
            allowed_hosts: vec![
                "  ".into(),
                "JIRA.ZOOMKEY.COM.CN".into(),
                "jira.zoomkey.com.cn".into(),
            ],
            jira: ZoomkeyEndpointPolicy {
                base_url: "  ".into(),
                credential_id: "  abc  ".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let normalized = normalize_policy(policy);
        assert_eq!(normalized.allowed_hosts, vec!["jira.zoomkey.com.cn"]);
        assert_eq!(normalized.jira.base_url, DEFAULT_JIRA_BASE);
        assert_eq!(normalized.jira.credential_id, "abc");
    }

    #[test]
    fn crm_origin_is_rewritten_to_webservice() {
        assert_eq!(
            normalize_crm_base_url("https://crm.zoomkey.com.cn"),
            DEFAULT_CRM_BASE
        );
        assert_eq!(
            normalize_crm_base_url("https://crm.zoomkey.com.cn/"),
            DEFAULT_CRM_BASE
        );
        assert_eq!(
            normalize_crm_base_url("https://crm.zoomkey.com.cn/index.php"),
            DEFAULT_CRM_BASE
        );
        assert_eq!(
            normalize_crm_base_url("https://crm.zoomkey.com.cn/webservice.php"),
            DEFAULT_CRM_BASE
        );
        assert_eq!(
            normalize_crm_base_url("https://crm.zoomkey.com.cn/webservice.php/"),
            DEFAULT_CRM_BASE
        );
        assert_eq!(normalize_crm_base_url("  "), DEFAULT_CRM_BASE);
        assert_eq!(
            normalize_crm_base_url("https://crm.zoomkey.com.cn:8443"),
            "https://crm.zoomkey.com.cn:8443/webservice.php"
        );
        assert_eq!(
            normalize_crm_base_url("https://crm.zoomkey.com.cn/custom.php"),
            "https://crm.zoomkey.com.cn/custom.php"
        );
    }

    #[test]
    fn policy_round_trips_through_vault_settings() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        assert!(!load_policy(&vault, &dek).enabled);
        let policy = ZoomkeyMcpPolicy {
            enabled: true,
            ..Default::default()
        };
        save_policy(&vault, &dek, &policy).unwrap();
        let loaded = load_policy(&vault, &dek);
        assert!(loaded.enabled);
    }

    #[test]
    fn legacy_triple_switch_migrates_to_master_enabled() {
        let migrated = serde_json::from_value::<ZoomkeyMcpPolicy>(migrate_policy_value(json!({
            "jira_enabled": false,
            "crm_enabled": true,
            "allow_private_network": false,
            "allowed_hosts": ["jira.zoomkey.com.cn"],
            "jira": { "base_url": DEFAULT_JIRA_BASE },
            "crm": { "base_url": DEFAULT_CRM_BASE }
        })))
        .unwrap();
        assert!(migrated.enabled);
        assert_eq!(migrated.allowed_hosts, vec!["jira.zoomkey.com.cn"]);

        let still_off = serde_json::from_value::<ZoomkeyMcpPolicy>(migrate_policy_value(json!({
            "jira_enabled": false,
            "crm_enabled": false,
            "allow_private_network": false
        })))
        .unwrap();
        assert!(!still_off.enabled);

        let already_new = serde_json::from_value::<ZoomkeyMcpPolicy>(migrate_policy_value(json!({
            "enabled": false,
            "jira_enabled": true
        })))
        .unwrap();
        assert!(!already_new.enabled);
    }

    #[test]
    fn tool_names_route_to_the_right_endpoint() {
        assert!(is_zoomkey_tool("zoomkey_jira_nav"));
        assert!(is_zoomkey_tool("zoomkey_crm_query"));
        assert!(!is_zoomkey_tool("github_get_file"));
        assert_eq!(endpoint_of("zoomkey_jira_search_issues"), Some("jira"));
        assert_eq!(endpoint_of("zoomkey_crm_find_project"), Some("crm"));
        assert_eq!(endpoint_of("github_list_issues"), None);
    }

    #[test]
    fn disabled_endpoint_refuses_to_build_runtime() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let error = match build_runtime(&session, "jira") {
            Ok(_) => panic!("锁定的端点不应构建出运行时"),
            Err(error) => error,
        };
        assert!(error.message.contains("ZoomKey MCP 未启用"), "{}", error.message);
    }

    #[test]
    fn argument_helpers_clamp_and_coerce() {
        let args = json!({"limit": 900, "flag": "yes", "text": "  hi  "});
        assert_eq!(as_u64(&args, "limit", 20, 1, 100), 100);
        assert_eq!(as_u64(&args, "missing", 7, 1, 100), 7);
        assert!(as_bool(&args, "flag"));
        assert!(!as_bool(&args, "missing"));
        assert_eq!(as_string(&args, "text"), "hi");
    }

    #[test]
    fn trim_json_caps_long_strings() {
        let mut value = json!({"a": "x".repeat(50), "b": ["y".repeat(50)]});
        trim_json(&mut value, 10);
        assert_eq!(value["a"].as_str().unwrap().chars().count(), 11);
        assert_eq!(value["b"][0].as_str().unwrap().chars().count(), 11);
    }

    /// 回归：服务端用多 token 的 `Connection` 头声明关闭时，agent 不能复用这条连接。
    ///
    /// `crm.zoomkey.com.cn` 发的是 `Connection: Upgrade, close`（配套还有 `Upgrade: h2`）。
    /// ureq 只把「整串等于 `close`」判为不可复用（`c.eq_ignore_ascii_case("close")`），
    /// 于是把它当 keep-alive 放回连接池。真实服务端在响应之后还会补发一条 19 字节的
    /// TLS application_data 记录（HTTP/2 GOAWAY）再断开，而 ureq 取用池中连接前只做一次
    /// 非阻塞 `peek`——那条记录往往还没到，peek 返回 `WouldBlock`，于是判定连接可用。
    /// 结果就是一次工具调用里的第二个请求（`getchallenge` → `login`）写进一条正在被
    /// 服务端拆除的连接，拿不到任何响应字节，报 `Network Error: Unexpected EOF`。
    ///
    /// 注意请求必须是 **POST**：ureq 只会自动重试「幂等方法 + 复用了池中连接」
    /// （`Unit::is_retryable`），GET 会被悄悄重试掉，掩盖这个 bug。CRM 挂掉的正是
    /// `login` 那个 POST。
    ///
    /// 这里用一个本地服务端复现这个窗口：响应里带 `Connection: Upgrade, close`，
    /// 但**先不断开 TCP**；一旦客户端复用这条连接再发请求，就直接关掉、不给响应。
    #[test]
    fn agent_does_not_reuse_a_connection_the_server_closed() {
        use std::io::{Read, Write};
        use std::net::{Shutdown, TcpStream};

        /// 读到请求头结束（`\r\n\r\n`）就算一条请求，不解析内容。
        fn read_request(socket: &mut TcpStream) -> bool {
            let mut seen = Vec::new();
            let mut buffer = [0u8; 512];
            loop {
                match socket.read(&mut buffer) {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => {
                        seen.extend_from_slice(&buffer[..n]);
                        if seen.windows(4).any(|w| w == b"\r\n\r\n") || seen.len() > 8192 {
                            return true;
                        }
                    }
                }
            }
        }

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
        let port = listener.local_addr().unwrap().port();
        // 服务端线程故意不 join：测试进程退出时它随之结束。
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut socket) = incoming else { return };
                std::thread::spawn(move || {
                    let mut requests = 0usize;
                    loop {
                        if !read_request(&mut socket) {
                            return;
                        }
                        requests += 1;
                        if requests > 1 {
                            // 复用到了声明 close 的连接：不给响应，直接拆掉。
                            let _ = socket.shutdown(Shutdown::Both);
                            return;
                        }
                        let _ = socket.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: Upgrade, close\r\n\r\nok",
                        );
                    }
                });
            }
        });

        let agent = tuned_agent_builder().build();
        let url = format!("http://127.0.0.1:{port}/webservice.php");
        for round in 1..=2 {
            let response = agent
                .post(&url)
                .set("Content-Type", "application/x-www-form-urlencoded")
                .send_string("operation=login&username=probe&accessKey=0")
                .unwrap_or_else(|error| panic!("第 {round} 次请求失败: {error}"));
            assert_eq!(response.into_string().unwrap(), "ok", "第 {round} 次响应体不符");
        }
    }
}
