use crate::fill;
use crate::github_mcp;
use crate::lock::{idle_lock_if_needed, lock_session, recover_lock};
use crate::session::Session;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use uuid::Uuid;

const DEFAULT_PORT: u16 = 17891;
const PAIRING_SECS: u64 = 60;
const PAIRING_MAX_FAILURES: u32 = 5;
pub const LISTEN_CONFIG_KEY: &str = "mcp_listen_config";
const LISTEN_MODE_KEY: &str = "mcp_listen_mode";
const LISTEN_ADDRESS_KEY: &str = "mcp_listen_address";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenMode {
    Loopback,
    Lan,
    Address,
}

impl ListenMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Lan => "lan",
            Self::Address => "address",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenConfig {
    pub mode: ListenMode,
    pub address: Option<Ipv4Addr>,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            mode: ListenMode::Loopback,
            address: None,
        }
    }
}

impl ListenConfig {
    pub fn view(self) -> ListenConfigView {
        ListenConfigView {
            mode: self.mode.as_str().to_string(),
            address: self
                .address
                .map(|address| address.to_string())
                .unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListenConfigInput {
    pub mode: String,
    #[serde(default)]
    pub address: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ListenConfigView {
    pub mode: String,
    pub address: String,
}

pub fn is_private_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    matches!(
        octets,
        [10, _, _, _] | [172, 16..=31, _, _] | [192, 168, _, _]
    )
}

pub fn parse_listen_config(mode: &str, address: &str) -> Result<ListenConfig, String> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "loopback" => Ok(ListenConfig::default()),
        "lan" => Ok(ListenConfig {
            mode: ListenMode::Lan,
            address: None,
        }),
        "address" => {
            let raw = address.trim();
            let parsed = raw
                .parse::<Ipv4Addr>()
                .map_err(|_| "监听地址必须是 IPv4 地址".to_string())?;
            if !is_private_ipv4(parsed) {
                return Err("监听地址必须是本机私有 IPv4 地址".into());
            }
            Ok(ListenConfig {
                mode: ListenMode::Address,
                address: Some(parsed),
            })
        }
        _ => Err("监听模式必须是 loopback、lan 或 address".into()),
    }
}

struct PairingWindow {
    code: String,
    expires_at: Instant,
    failures: u32,
}

#[derive(Clone)]
pub struct McpState {
    pub running: Arc<AtomicBool>,
    pub port: Arc<Mutex<u16>>,
    pub token: Arc<Mutex<String>>,
    pub fill_token: Arc<Mutex<String>>,
    bound_host: Arc<Mutex<Ipv4Addr>>,
    configured: Arc<Mutex<ListenConfig>>,
    effective: Arc<Mutex<ListenConfig>>,
    locked: Arc<AtomicBool>,
    restart_on_lock: Arc<AtomicBool>,
    listener_epoch: Arc<AtomicU64>,
    listener_thread: Arc<Mutex<Option<JoinHandle<()>>>>,
    pairing: Arc<Mutex<Option<PairingWindow>>>,
}

impl Default for McpState {
    fn default() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            port: Arc::new(Mutex::new(DEFAULT_PORT)),
            token: Arc::new(Mutex::new(String::new())),
            fill_token: Arc::new(Mutex::new(String::new())),
            bound_host: Arc::new(Mutex::new(Ipv4Addr::LOCALHOST)),
            configured: Arc::new(Mutex::new(ListenConfig::default())),
            effective: Arc::new(Mutex::new(ListenConfig::default())),
            locked: Arc::new(AtomicBool::new(true)),
            restart_on_lock: Arc::new(AtomicBool::new(false)),
            listener_epoch: Arc::new(AtomicU64::new(0)),
            listener_thread: Arc::new(Mutex::new(None)),
            pairing: Arc::new(Mutex::new(None)),
        }
    }
}

fn new_pairing_code() -> String {
    const ALPH: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| ALPH[rng.gen_range(0..ALPH.len())] as char)
        .collect()
}

fn normalize_pairing_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn host_allowed(headers: &[(String, String)], local: SocketAddr) -> bool {
    let host = headers
        .iter()
        .find(|(k, _)| k == "host")
        .map(|(_, v)| v.trim().to_ascii_lowercase())
        .unwrap_or_default();
    host == local.to_string().to_ascii_lowercase()
}

fn peer_allowed(peer: SocketAddr, local: SocketAddr) -> bool {
    let IpAddr::V4(local_ip) = local.ip() else {
        return false;
    };
    let IpAddr::V4(peer_ip) = peer.ip() else {
        return false;
    };
    if local_ip.is_loopback() {
        return peer_ip.is_loopback();
    }
    is_private_ipv4(local_ip) && is_private_ipv4(peer_ip)
}

#[derive(Serialize)]
pub struct PairingStatus {
    pub active: bool,
    pub code: Option<String>,
    pub expires_in_secs: u64,
    pub port: u16,
}

impl McpState {
    pub fn open_pairing(&self) -> PairingStatus {
        let code = new_pairing_code();
        let expires_at = Instant::now() + Duration::from_secs(PAIRING_SECS);
        *recover_lock(&self.pairing) = Some(PairingWindow {
            code: code.clone(),
            expires_at,
            failures: 0,
        });
        PairingStatus {
            active: true,
            code: Some(code),
            expires_in_secs: PAIRING_SECS,
            port: *recover_lock(&self.port),
        }
    }

    pub fn pairing_status(&self) -> PairingStatus {
        let port = *recover_lock(&self.port);
        let mut slot = recover_lock(&self.pairing);
        if let Some(window) = slot.as_ref() {
            if let Some(left) = window.expires_at.checked_duration_since(Instant::now()) {
                if !left.is_zero() {
                    return PairingStatus {
                        active: true,
                        code: Some(window.code.clone()),
                        expires_in_secs: left.as_secs().saturating_add(1).min(PAIRING_SECS),
                        port,
                    };
                }
            }
            *slot = None;
        }
        PairingStatus {
            active: false,
            code: None,
            expires_in_secs: 0,
            port,
        }
    }

    fn consume_pairing(&self, raw_code: &str) -> Result<(), String> {
        let submitted = normalize_pairing_code(raw_code);
        let mut slot = recover_lock(&self.pairing);
        let Some(window) = slot.as_mut() else {
            return Err("pairing window closed".into());
        };
        if window.expires_at <= Instant::now() {
            *slot = None;
            return Err("pairing window closed".into());
        }
        if submitted.is_empty() || !constant_eq(&submitted, &window.code) {
            window.failures = window.failures.saturating_add(1);
            if window.failures >= PAIRING_MAX_FAILURES {
                *slot = None;
                return Err("pairing window closed".into());
            }
            return Err("invalid pairing code".into());
        }
        *slot = None;
        Ok(())
    }

    pub fn close_pairing(&self) {
        *recover_lock(&self.pairing) = None;
    }

    pub fn configured(&self) -> ListenConfig {
        *recover_lock(&self.configured)
    }

    pub fn effective(&self) -> ListenConfig {
        *recover_lock(&self.effective)
    }

    pub fn bound_host(&self) -> Ipv4Addr {
        *recover_lock(&self.bound_host)
    }

    fn set_configured(&self, config: ListenConfig) {
        *recover_lock(&self.configured) = config;
    }

    fn set_effective(&self, config: ListenConfig) {
        *recover_lock(&self.effective) = config;
    }
}

pub fn new_token() -> String {
    format!("sbx_{}", Uuid::new_v4().simple())
}

#[derive(Serialize, Deserialize)]
struct JsonRpcReq {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

fn tools_list(session: &Mutex<Session>) -> Value {
    let locked = lock_session(session);
    let (mcp_on, zoomkey_tools) = locked
        .vault()
        .ok()
        .and_then(|vault| {
            locked.dek().ok().map(|dek| {
                let zoomkey = crate::zoomkey::load_policy(vault, dek);
                (
                    zoomkey.enabled,
                    crate::zoomkey::tool_definitions_for_vault(vault, dek, &zoomkey),
                )
            })
        })
        .unwrap_or((false, Vec::new()));
    let mut tools: Vec<Value> = Vec::new();
    if mcp_on {
        tools.extend(github_mcp::tool_definitions_for_mcp());
    }
    tools.extend(zoomkey_tools);
    tools.extend(mail_tool_definitions());
    json!({ "tools": tools })
}

fn mail_tool_definitions() -> Vec<Value> {
    let annotations = github_mcp::annotations(true, false);
    let entry = json!({"type": "string", "minLength": 1, "maxLength": 128});
    let uid = json!({"type": "integer", "minimum": 1, "maximum": 4294967295u64});
    vec![
        json!({
            "name": "mail_accounts",
            "description": "列出已保存的邮箱账号（id、标题、地址、服务商、是否支持）。不含授权码。",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
            "readOnly": true,
            "risk": "low",
            "annotations": annotations.clone()
        }),
        json!({
            "name": "mail_list",
            "description": "只读列出邮箱收件箱，最多 50 封。beforeUid 表示只取比它更早的邮件。",
            "inputSchema": {
                "type": "object",
                "properties": {"entryId": entry.clone(), "beforeUid": uid.clone()},
                "required": ["entryId"],
                "additionalProperties": false
            },
            "readOnly": true,
            "risk": "low",
            "annotations": annotations.clone()
        }),
        json!({
            "name": "mail_read",
            "description": "只读读取一封邮件的纯文本和附件清单。不返回 HTML，不下载附件。",
            "inputSchema": {
                "type": "object",
                "properties": {"entryId": entry.clone(), "uid": uid.clone()},
                "required": ["entryId", "uid"],
                "additionalProperties": false
            },
            "readOnly": true,
            "risk": "low",
            "annotations": annotations.clone()
        }),
        json!({
            "name": "mail_download_attachment",
            "description": "把一封邮件的一个附件保存到已有目录中的新文件。不覆盖已有文件。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "entryId": entry,
                    "uid": uid.clone(),
                    "part": {"type": "string", "minLength": 1, "maxLength": 32},
                    "path": {"type": "string", "minLength": 1, "maxLength": 1024}
                },
                "required": ["entryId", "uid", "part", "path"],
                "additionalProperties": false
            },
            "readOnly": true,
            "risk": "low",
            "annotations": annotations
        }),
    ]
}

fn mail_audit_detail(operation: &str, decision: &str, reason: &str, entry: &str, uid: &str, part: &str) -> String {
    fn token(value: &str) -> String {
        let cleaned: String = value
            .chars()
            .filter(|ch| !ch.is_whitespace() && *ch != '=')
            .take(64)
            .collect();
        if cleaned.is_empty() { "-".into() } else { cleaned }
    }
    format!(
        "operation={} decision={} reason={} entry={} uid={} part={}",
        token(operation),
        token(decision),
        token(reason),
        token(entry),
        token(uid),
        token(part)
    )
}

fn mail_reason(message: &str) -> &'static str {
    match message {
        "登录失败，请检查授权码和 IMAP 是否已开启" => "login",
        "连接超时，请稍后重试" => "protocol",
        "这封邮件没有可显示的文本" => "empty",
        "首版不支持" => "unsupported",
        "附件过大，已拒绝下载" => "too_large",
        "无法保存附件" => "save",
        "不是邮箱授权码" => "not_mail",
        "参数无效" => "validation",
        _ if message.contains("锁定") => "locked",
        _ => "error",
    }
}

fn mail_arg_str<'a>(args: &'a Value, key: &str, required: bool) -> Result<Option<&'a str>, String> {
    match args.get(key) {
        None | Some(Value::Null) if !required => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value)),
        _ => Err("参数无效".into()),
    }
}

fn mail_arg_u32(args: &Value, key: &str, required: bool) -> Result<Option<u32>, String> {
    match args.get(key) {
        None | Some(Value::Null) if !required => Ok(None),
        Some(Value::Number(number)) => {
            let value = number.as_u64().filter(|value| (1..=u32::MAX as u64).contains(value));
            value.map(|value| Some(value as u32)).ok_or_else(|| "参数无效".into())
        }
        _ => Err("参数无效".into()),
    }
}

fn ensure_mail_keys(args: &Value, allowed: &[&str]) -> Result<(), String> {
    let object = args.as_object().ok_or("参数无效")?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("参数无效".into());
    }
    Ok(())
}

fn load_mail_secret(session: &crate::session::Session, entry_id: &str) -> Result<(String, String, zeroize::Zeroizing<String>), String> {
    let dek = *session.dek().map_err(|error| error.to_string())?;
    let payload = session
        .vault()
        .map_err(|error| error.to_string())?
        .get_active_secret(&dek, entry_id)
        .map_err(|error| error.to_string())?;
    match payload {
        crate::vault::SecretPayload::MailAuth { email, provider, auth_code } => {
            Ok((email, provider, zeroize::Zeroizing::new(auth_code)))
        }
        _ => Err("不是邮箱授权码".into()),
    }
}

fn call_mail_tool(session: &Mutex<Session>, name: &str, args: Value) -> Result<String, String> {
    let entry = args.get("entryId").and_then(Value::as_str).unwrap_or("-").to_string();
    let uid = args
        .get("uid")
        .and_then(Value::as_u64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".into());
    let part = args.get("part").and_then(Value::as_str).unwrap_or("-").to_string();
    let result = call_mail_inner(session, name, &args);
    if let Ok(vault) = lock_session(session).vault() {
        let (decision, reason, action) = match &result {
            Ok(_) => ("allow", "ok", "mcp_mail"),
            Err(error) => ("deny", mail_reason(error), "mcp_mail_denied"),
        };
        let _ = vault.audit(
            action,
            None,
            &mail_audit_detail(name, decision, reason, &entry, &uid, &part),
        );
    }
    result
}

fn call_mail_inner(session: &Mutex<Session>, name: &str, args: &Value) -> Result<String, String> {
    match name {
        "mail_accounts" => {
            ensure_mail_keys(args, &[])?;
            let session = lock_session(session);
            let dek = *session.dek().map_err(|error| error.to_string())?;
            let vault = session.vault().map_err(|error| error.to_string())?;
            let entries = vault
                .list_entries(&crate::vault::ListFilter {
                    kind: Some(crate::vault::EntryKind::MailAuth),
                    ..crate::vault::ListFilter::default()
                })
                .map_err(|error| error.to_string())?;
            let mut accounts = Vec::new();
            for entry in entries {
                let payload = vault.get_active_secret(&dek, &entry.id).map_err(|error| error.to_string())?;
                let crate::vault::SecretPayload::MailAuth { email, provider, auth_code } = payload else {
                    return Err("不是邮箱授权码".into());
                };
                drop(auth_code);
                accounts.push(sealbox_core::mail::MailAccount {
                    id: entry.id,
                    title: entry.title,
                    email,
                    provider: provider.clone(),
                    supported: sealbox_core::mail::endpoint(&provider).is_some(),
                });
            }
            serde_json::to_string(&accounts).map_err(|_| "参数无效".into())
        }
        "mail_list" => {
            ensure_mail_keys(args, &["entryId", "beforeUid"])?;
            let entry_id = mail_arg_str(args, "entryId", true)?.unwrap_or("");
            let before = mail_arg_u32(args, "beforeUid", false)?;
            let (email, provider, auth_code) = {
                let session = lock_session(session);
                load_mail_secret(&session, entry_id)?
            };
            let Some((host, port)) = sealbox_core::mail::endpoint(&provider) else {
                return Err(sealbox_core::mail::failure_message(sealbox_core::mail::MailFailure::Unsupported).into());
            };
            let mut io = sealbox_core::mail::connect_tls(host, port, std::time::Duration::from_secs(20))
                .map_err(sealbox_core::mail::failure_message)?;
            let messages = sealbox_core::mail::list_inbox(&mut io, &email, &auth_code, before, 50)
                .map_err(sealbox_core::mail::failure_message)?;
            drop(auth_code);
            serde_json::to_string(&messages).map_err(|_| "参数无效".into())
        }
        "mail_read" => {
            ensure_mail_keys(args, &["entryId", "uid"])?;
            let entry_id = mail_arg_str(args, "entryId", true)?.unwrap_or("");
            let uid = mail_arg_u32(args, "uid", true)?.ok_or("参数无效")?;
            let (email, provider, auth_code) = {
                let session = lock_session(session);
                load_mail_secret(&session, entry_id)?
            };
            let Some((host, port)) = sealbox_core::mail::endpoint(&provider) else {
                return Err(sealbox_core::mail::failure_message(sealbox_core::mail::MailFailure::Unsupported).into());
            };
            let mut text_io = sealbox_core::mail::connect_tls(host, port, std::time::Duration::from_secs(20))
                .map_err(sealbox_core::mail::failure_message)?;
            let body = sealbox_core::mail::fetch_body(&mut text_io, &email, &auth_code, uid)
                .map_err(sealbox_core::mail::failure_message)?;
            let mut list_io = sealbox_core::mail::connect_tls(host, port, std::time::Duration::from_secs(20))
                .map_err(sealbox_core::mail::failure_message)?;
            let attachments = sealbox_core::mail::list_attachments(&mut list_io, &email, &auth_code, uid)
                .map_err(sealbox_core::mail::failure_message)?;
            drop(auth_code);
            serde_json::to_string(&json!({
                "text": body.text,
                "truncated": body.truncated,
                "attachments": attachments
            }))
            .map_err(|_| "参数无效".into())
        }
        "mail_download_attachment" => {
            ensure_mail_keys(args, &["entryId", "uid", "part", "path"])?;
            let entry_id = mail_arg_str(args, "entryId", true)?.unwrap_or("");
            let uid = mail_arg_u32(args, "uid", true)?.ok_or("参数无效")?;
            let part = mail_arg_str(args, "part", true)?.unwrap_or("").to_string();
            let path = mail_arg_str(args, "path", true)?.unwrap_or("").to_string();
            let (email, provider, auth_code) = {
                let session = lock_session(session);
                load_mail_secret(&session, entry_id)?
            };
            let Some((host, port)) = sealbox_core::mail::endpoint(&provider) else {
                return Err(sealbox_core::mail::failure_message(sealbox_core::mail::MailFailure::Unsupported).into());
            };
            let mut io = sealbox_core::mail::connect_tls(host, port, std::time::Duration::from_secs(20))
                .map_err(sealbox_core::mail::failure_message)?;
            let bytes = sealbox_core::mail::fetch_attachment(&mut io, &email, &auth_code, uid, &part)
                .map_err(sealbox_core::mail::failure_message)?;
            drop(auth_code);
            let saved = sealbox_core::mail::write_exclusive(&path, &bytes).map_err(str::to_string)?;
            serde_json::to_string(&json!({"bytes": saved, "path": path})).map_err(|_| "参数无效".into())
        }
        _ => Err(format!("未知工具 {name}")),
    }
}

#[derive(Clone, Serialize)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(rename = "readOnly")]
    pub read_only: bool,
    pub risk: String,
}

pub fn tool_catalog(session: &Mutex<Session>) -> Vec<ToolInfo> {
    let list = tools_list(session);
    list["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| {
            Some(ToolInfo {
                name: t.get("name")?.as_str()?.to_string(),
                description: t.get("description")?.as_str()?.to_string(),
                input_schema: t.get("inputSchema")?.clone(),
                read_only: t.get("readOnly").and_then(Value::as_bool).unwrap_or(false),
                risk: t
                    .get("risk")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
            })
        })
        .collect()
}

fn format_github_audit_detail(
    operation: &str,
    decision: &str,
    reason: &str,
    status: Option<u16>,
    result_count: Option<usize>,
    credential_fingerprint: &str,
    context: &github_mcp::GithubAuditContext,
) -> String {
    let repository = context
        .repository
        .as_deref()
        .unwrap_or("-")
        .replace(['\r', '\n'], " ");
    let path = context
        .path
        .as_deref()
        .unwrap_or("-")
        .replace(['\r', '\n'], " ");
    let reference = context
        .reference
        .as_deref()
        .unwrap_or("-")
        .replace(['\r', '\n'], " ");
    format!(
        "operation={operation} decision={decision} reason={reason} repo={} path={} ref={} status={} count={} credential={}",
        repository,
        path,
        reference,
        status.map(|value| value.to_string()).unwrap_or_else(|| "-".into()),
        result_count.map(|value| value.to_string()).unwrap_or_else(|| "-".into()),
        credential_fingerprint,
    )
}

fn format_zoomkey_audit_detail(
    operation: &str,
    decision: &str,
    reason: &str,
    status: Option<u16>,
    result_count: Option<usize>,
    credential_fingerprint: &str,
    context: &crate::zoomkey::ZoomkeyAuditContext,
) -> String {
    let detail = context.detail.replace(['\r', '\n'], " ");
    format!(
        "operation={operation} decision={decision} reason={reason} endpoint={} detail={} status={} count={} credential={}",
        context.endpoint,
        if detail.is_empty() { "-" } else { &detail },
        status.map(|value| value.to_string()).unwrap_or_else(|| "-".into()),
        result_count.map(|value| value.to_string()).unwrap_or_else(|| "-".into()),
        credential_fingerprint,
    )
}

fn rpc_error(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn rpc_ok(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn tool_call_result(text: &str, is_error: bool) -> Value {
    let structured = serde_json::from_str::<Value>(text)
        .ok()
        .filter(|value| value.is_object() || value.is_array());
    let mut result = json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error
    });
    if let Some(value) = structured {
        result["structuredContent"] = value;
    }
    result
}

fn handle_rpc(session: &Mutex<Session>, mcp: &McpState, req: JsonRpcReq) -> Option<Value> {
    let out = match req.method.as_str() {
        "initialize" => rpc_ok(
            req.id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "sealbox", "version": env!("CARGO_PKG_VERSION") }
            }),
        ),
        "notifications/initialized" | "initialized" => return None,
        "ping" => rpc_ok(req.id, json!({})),
        "tools/list" => rpc_ok(req.id, tools_list(session)),
        "tools/call" => {
            let name = req
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = req.params.get("arguments").cloned().unwrap_or(json!({}));
            match call_tool(session, mcp, name, args) {
                Ok(text) => rpc_ok(req.id, tool_call_result(&text, false)),
                Err(e) => rpc_ok(req.id, tool_call_result(&e, true)),
            }
        }
        _ => rpc_error(req.id, -32601, "method not found"),
    };
    Some(out)
}

fn call_git_tool(session: &Mutex<Session>, name: &str, args: Value) -> Result<String, String> {
    let context = github_mcp::GithubAuditContext {
        path: args.get("path").and_then(Value::as_str).map(str::to_string),
        reference: args
            .get("branch")
            .or_else(|| args.get("tag"))
            .and_then(Value::as_str)
            .map(str::to_string),
        ..Default::default()
    };
    let prepared = {
        let mut s = lock_session(session);
        crate::git_workspace::prepare_tool(&mut s, name, args)
    };
    let text = match prepared {
        Ok(crate::git_workspace::PreparedGitOp::Immediate(text)) => Ok(text),
        Ok(crate::git_workspace::PreparedGitOp::Pending {
            payload,
            deny,
            exec,
        }) => {
            if crate::confirm::ask_payload(&payload) {
                let mut s = lock_session(session);
                if !s.is_unlocked() {
                    Err("金库已锁定。请先在 Sealbox 窗口解锁，再让我重试。".into())
                } else {
                    exec(&mut s)
                }
            } else {
                Err(deny)
            }
        }
        Err(error) => Err(error),
    };
    let s = lock_session(session);
    if let Ok(vault) = s.vault() {
        let detail = match &text {
            Ok(_) => format_github_audit_detail(name, "allow", "ok", Some(200), None, "", &context),
            Err(error) => format_github_audit_detail(
                name,
                "deny",
                if error.contains("拒绝") {
                    "denied"
                } else {
                    "error"
                },
                None,
                None,
                "",
                &context,
            ),
        };
        let action = if text.is_ok() {
            "mcp_github"
        } else {
            "mcp_github_denied"
        };
        let _ = vault.audit(action, None, &detail);
    }
    text
}

fn call_tool(
    session: &Mutex<Session>,
    mcp: &McpState,
    name: &str,
    args: Value,
) -> Result<String, String> {
    let locked = {
        let mut s = lock_session(session);
        let idle_locked = idle_lock_if_needed(&mut s, mcp);
        idle_locked || !s.is_unlocked()
    };
    if locked {
        let _ = crate::mcp::rebind_locked(mcp);
        return Err("金库已锁定。请先在 Sealbox 窗口解锁，再让我重试。".into());
    }
    if github_mcp::is_github_tool(name) {
        if crate::git_workspace::is_git_tool(name) {
            return call_git_tool(session, name, args);
        }
        let result = {
            let mut s = lock_session(session);
            github_mcp::call_tool_detailed(&mut s, name, args)
        };
        let s = lock_session(session);
        if let Ok(vault) = s.vault() {
            let detail = match &result {
                Ok(result) => format_github_audit_detail(
                    name,
                    "allow",
                    "ok",
                    Some(result.status),
                    result.result_count,
                    &result.credential_fingerprint,
                    &result.context,
                ),
                Err(error) => format_github_audit_detail(
                    name,
                    "deny",
                    error.reason,
                    error.status,
                    None,
                    error.credential_fingerprint.as_deref().unwrap_or(""),
                    &error.context,
                ),
            };
            let action = if result.is_ok() {
                "mcp_github"
            } else {
                "mcp_github_denied"
            };
            let _ = vault.audit(action, None, &detail);
        }
        return result
            .map(|result| result.text)
            .map_err(|error| error.message);
    }
    if matches!(
        name,
        "mail_accounts" | "mail_list" | "mail_read" | "mail_download_attachment"
    ) {
        return call_mail_tool(session, name, args);
    }
    if crate::zoomkey::is_zoomkey_tool(name) {
        let result = {
            let mut s = lock_session(session);
            crate::zoomkey::call_tool_detailed(&mut s, name, args)
        };
        let s = lock_session(session);
        if let Ok(vault) = s.vault() {
            let detail = match &result {
                Ok(result) => format_zoomkey_audit_detail(
                    name,
                    "allow",
                    "ok",
                    Some(result.status),
                    result.result_count,
                    &result.credential_fingerprint,
                    &result.context,
                ),
                Err(error) => format_zoomkey_audit_detail(
                    name,
                    "deny",
                    error.reason,
                    error.status,
                    None,
                    error.credential_fingerprint.as_deref().unwrap_or(""),
                    &error.context,
                ),
            };
            let action = if result.is_ok() {
                "mcp_zoomkey"
            } else {
                "mcp_zoomkey_denied"
            };
            let _ = vault.audit(action, None, &detail);
        }
        return result
            .map(|result| result.text)
            .map_err(|error| error.message);
    }
    match name {
        "list_credentials" | "copy_secret" | "http_request" => Err("该 MCP 工具已停用".into()),
        _ => Err(format!("未知工具 {name}")),
    }
}

struct HttpReq {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpReq, String> {
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| e.to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let path = parts
        .next()
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.push((key, val));
        }
    }
    let mut body = vec![0u8; content_length.min(1_000_000)];
    if !body.is_empty() {
        reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    }
    Ok(HttpReq {
        method,
        path,
        headers,
        body,
    })
}

fn write_http(stream: &mut TcpStream, status: &str, body: &[u8]) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(body);
}

fn handle_client(mut stream: TcpStream, session: Arc<Mutex<Session>>, mcp: McpState) {
    let (Ok(local), Ok(peer)) = (stream.local_addr(), stream.peer_addr()) else {
        return;
    };
    if !peer_allowed(peer, local) {
        write_http(
            &mut stream,
            "403 Forbidden",
            br#"{"ok":false,"error":"invalid peer"}"#,
        );
        return;
    }
    let Ok(req) = read_http_request(&mut stream) else {
        return;
    };
    let port = *recover_lock(&mcp.port);
    if !host_allowed(&req.headers, local) {
        write_http(
            &mut stream,
            "403 Forbidden",
            br#"{"ok":false,"error":"invalid host"}"#,
        );
        return;
    }
    if mcp.locked.load(Ordering::SeqCst) {
        write_http(
            &mut stream,
            "403 Forbidden",
            br#"{"ok":false,"error":"vault locked"}"#,
        );
        return;
    }
    if req.method == "OPTIONS" {
        write_http(&mut stream, "405 Method Not Allowed", b"{}");
        return;
    }
    let auth = req
        .headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    if req.path == "/fill/pair" {
        if req.method != "POST" {
            write_http(&mut stream, "405 Method Not Allowed", b"{}");
            return;
        }
        let unlocked = lock_session(&session).is_unlocked();
        if !unlocked {
            write_http(
                &mut stream,
                "403 Forbidden",
                br#"{"ok":false,"error":"vault locked"}"#,
            );
            return;
        }
        let v: Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
        let code = v.get("code").and_then(|x| x.as_str()).unwrap_or("");
        match mcp.consume_pairing(code) {
            Ok(()) => {
                if mcp.locked.load(Ordering::SeqCst) || !lock_session(&session).is_unlocked() {
                    write_http(
                        &mut stream,
                        "403 Forbidden",
                        br#"{"ok":false,"error":"vault locked"}"#,
                    );
                    return;
                }
                let fill_token = recover_lock(&mcp.fill_token).clone();
                let body = serde_json::to_vec(&json!({
                    "ok": true,
                    "fillToken": fill_token,
                    "port": port
                }))
                .unwrap_or_default();
                write_http(&mut stream, "200 OK", &body);
            }
            Err(msg) => {
                let body =
                    serde_json::to_vec(&json!({ "ok": false, "error": msg })).unwrap_or_default();
                write_http(&mut stream, "403 Forbidden", &body);
            }
        }
        return;
    }
    if req.path.starts_with("/fill") {
        if req.method != "POST" {
            write_http(&mut stream, "405 Method Not Allowed", b"{}");
            return;
        }
        let fill_token = recover_lock(&mcp.fill_token).clone();
        if auth != format!("Bearer {fill_token}") {
            write_http(
                &mut stream,
                "401 Unauthorized",
                br#"{"error":"invalid fill token"}"#,
            );
            return;
        }
        match fill::handle_fill_http(&session, &req.path, &req.body) {
            Ok(v) => {
                let bytes = serde_json::to_vec(&v).unwrap_or_else(|_| b"{}".to_vec());
                write_http(&mut stream, "200 OK", &bytes);
            }
            Err((code, msg)) => {
                let body =
                    serde_json::to_vec(&json!({ "ok": false, "error": msg })).unwrap_or_default();
                let status = match code {
                    403 => "403 Forbidden",
                    404 => "404 Not Found",
                    _ => "400 Bad Request",
                };
                write_http(&mut stream, status, &body);
            }
        }
        return;
    }
    if req.method != "POST" {
        write_http(&mut stream, "405 Method Not Allowed", b"{}");
        return;
    }
    let token = recover_lock(&mcp.token).clone();
    if auth != format!("Bearer {token}") {
        write_http(
            &mut stream,
            "401 Unauthorized",
            br#"{"error":"invalid token"}"#,
        );
        return;
    }
    let rpc: JsonRpcReq = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => {
            write_http(&mut stream, "400 Bad Request", br#"{"error":"bad json"}"#);
            return;
        }
    };
    match handle_rpc(&session, &mcp, rpc) {
        Some(resp) => {
            let bytes = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{}".to_vec());
            write_http(&mut stream, "200 OK", &bytes);
        }
        None => write_http(&mut stream, "204 No Content", b""),
    }
}

fn persisted_config(vault: &crate::vault::Vault) -> ListenConfig {
    if let Ok(Some(raw)) = vault.get_setting(LISTEN_CONFIG_KEY) {
        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            let mode = value.get("mode").and_then(Value::as_str).unwrap_or("");
            let address = value.get("address").and_then(Value::as_str).unwrap_or("");
            if let Ok(config) = parse_listen_config(mode, address) {
                return config;
            }
        }
    }
    // Read the pre-release split keys for a one-time backwards-compatible
    // migration; subsequent saves use the single atomic JSON setting.
    let mode = vault
        .get_setting(LISTEN_MODE_KEY)
        .ok()
        .flatten()
        .unwrap_or_else(|| "loopback".into());
    let address = vault
        .get_setting(LISTEN_ADDRESS_KEY)
        .ok()
        .flatten()
        .unwrap_or_default();
    parse_listen_config(&mode, &address).unwrap_or_default()
}

/// Read the non-secret preference before unlocking. Invalid or legacy values
/// fail closed to the loopback default and are never used to open a socket.
pub fn load_persisted_config(mcp: &McpState, path: &Path) {
    if let Ok(vault) = crate::vault::Vault::open(path.to_str().unwrap_or_default()) {
        mcp.set_configured(persisted_config(&vault));
    }
}

fn load_session_config(mcp: &McpState, session: &Arc<Mutex<Session>>) {
    let s = lock_session(session);
    if let Ok(vault) = s.vault() {
        mcp.set_configured(persisted_config(vault));
    }
}

fn lan_bind_ip() -> Result<Ipv4Addr, String> {
    use std::net::UdpSocket;
    // UDP connect asks the OS routing table for the source address without
    // sending a packet. Try representative RFC1918 destinations and refuse
    // to fall back to 0.0.0.0, which could expose a public interface.
    for target in [
        "10.0.0.1:9",
        "10.255.255.254:9",
        "172.16.0.1:9",
        "172.31.255.254:9",
        "192.168.0.1:9",
        "192.168.1.1:9",
        "192.168.255.254:9",
    ] {
        let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            continue;
        };
        if socket.connect(target).is_err() {
            continue;
        }
        let Ok(SocketAddr::V4(local)) = socket.local_addr() else {
            continue;
        };
        if is_private_ipv4(*local.ip()) {
            return Ok(*local.ip());
        }
    }
    Err("未找到本机私网 IPv4 地址，请改用 address 模式".into())
}

fn bind_ip(config: ListenConfig) -> Result<Ipv4Addr, String> {
    match config.mode {
        ListenMode::Loopback => Ok(Ipv4Addr::LOCALHOST),
        ListenMode::Lan => lan_bind_ip(),
        ListenMode::Address => config
            .address
            .filter(|address| is_private_ipv4(*address))
            .ok_or_else(|| "监听地址必须是本机私有 IPv4 地址".into()),
    }
}

fn stop_signal(mcp: &McpState, preserve_lock_restart: bool) {
    let was_running = mcp.running.swap(false, Ordering::SeqCst);
    if preserve_lock_restart && was_running {
        mcp.restart_on_lock.store(true, Ordering::SeqCst);
    }
    mcp.listener_epoch.fetch_add(1, Ordering::SeqCst);
    mcp.close_pairing();
}

fn join_listener(mcp: &McpState) {
    let handle = recover_lock(&mcp.listener_thread).take();
    let Some(handle) = handle else {
        return;
    };
    if handle.thread().id() != thread::current().id() {
        let _ = handle.join();
    }
}

fn bind_and_spawn(
    mcp: &McpState,
    config: ListenConfig,
    session: Arc<Mutex<Session>>,
    unlocked: bool,
) -> Result<u16, String> {
    let ip = bind_ip(config)?;
    let requested = SocketAddr::new(IpAddr::V4(ip), DEFAULT_PORT);
    let listener = TcpListener::bind(requested)
        .or_else(|_| TcpListener::bind(SocketAddr::new(IpAddr::V4(ip), 0)))
        .map_err(|error| format!("无法绑定 MCP 监听地址 {requested}: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("无法配置 MCP 监听器: {error}"))?;
    let local_addr = listener.local_addr().map_err(|e| e.to_string())?;
    let port = local_addr.port();
    *recover_lock(&mcp.port) = port;
    *recover_lock(&mcp.bound_host) = ip;
    mcp.set_effective(config);
    mcp.locked.store(!unlocked, Ordering::SeqCst);
    mcp.restart_on_lock.store(false, Ordering::SeqCst);
    mcp.running.store(true, Ordering::SeqCst);
    let epoch = mcp.listener_epoch.fetch_add(1, Ordering::SeqCst) + 1;
    remove_stale_bridge_file();
    let running = mcp.running.clone();
    let listener_epoch = mcp.listener_epoch.clone();
    let mcp_accept = mcp.clone();
    let handle = thread::spawn(move || {
        while running.load(Ordering::SeqCst) && listener_epoch.load(Ordering::SeqCst) == epoch {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    let session = session.clone();
                    let mcp = mcp_accept.clone();
                    thread::spawn(move || handle_client(stream, session, mcp));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
    });
    *recover_lock(&mcp.listener_thread) = Some(handle);
    Ok(port)
}

fn hydrate_tokens(mcp: &McpState, session: &Arc<Mutex<Session>>) {
    // A vault switch or failed secret read must never leave the previous
    // vault's bearer tokens in memory.
    recover_lock(&mcp.token).clear();
    recover_lock(&mcp.fill_token).clear();
    let mut loaded = None;
    {
        let s = lock_session(session);
        if let (Ok(vault), Ok(dek)) = (s.vault(), s.dek()) {
            let mcp_token = vault
                .get_secret_setting(dek, "mcp_token")
                .ok()
                .flatten()
                .filter(|token| !token.is_empty());
            let fill_token = vault
                .get_secret_setting(dek, "fill_token")
                .ok()
                .flatten()
                .filter(|token| !token.is_empty());
            loaded = Some((mcp_token, fill_token));
        }
    }
    let (mut mcp_token, mut fill_token) = loaded.unwrap_or((None, None));
    if mcp_token.is_none() {
        mcp_token = Some(new_token());
    }
    if fill_token.is_none() {
        fill_token = Some(fill::new_fill_token());
    }
    let mcp_token = mcp_token.unwrap_or_default();
    let fill_token = fill_token.unwrap_or_default();
    *recover_lock(&mcp.token) = mcp_token.clone();
    *recover_lock(&mcp.fill_token) = fill_token.clone();
    let s = lock_session(session);
    if let (Ok(vault), Ok(dek)) = (s.vault(), s.dek()) {
        let _ = vault.set_secret_setting(dek, "mcp_token", &mcp_token);
        let _ = vault.set_secret_setting(dek, "fill_token", &fill_token);
    }
}

fn restart_with_config(
    mcp: &McpState,
    config: ListenConfig,
    session: Arc<Mutex<Session>>,
    unlocked: bool,
) -> Result<u16, String> {
    if mcp.running.load(Ordering::SeqCst) {
        stop_signal(mcp, false);
    }
    join_listener(mcp);
    bind_and_spawn(mcp, config, session, unlocked)
}

pub fn apply_listen_config(
    mcp: &McpState,
    session: Arc<Mutex<Session>>,
    config: ListenConfig,
) -> Result<u16, String> {
    if !lock_session(&session).is_unlocked() {
        return Err("请先解锁金库再保存监听设置".into());
    }
    let previous = mcp.configured();
    let previous_effective = mcp.effective();
    let previous_locked = mcp.locked.load(Ordering::SeqCst);
    let was_running = mcp.running.load(Ordering::SeqCst);
    mcp.set_configured(config);
    mcp.locked.store(false, Ordering::SeqCst);
    if was_running && previous_effective == config {
        return Ok(*recover_lock(&mcp.port));
    }
    match restart_with_config(mcp, config, session.clone(), true) {
        Ok(port) => Ok(port),
        Err(error) => {
            mcp.set_configured(previous);
            mcp.locked.store(previous_locked, Ordering::SeqCst);
            mcp.set_effective(previous_effective);
            if was_running {
                let _ = restart_with_config(mcp, previous_effective, session, !previous_locked);
            }
            Err(error)
        }
    }
}

pub fn start(mcp: &McpState, session: Arc<Mutex<Session>>) -> Result<u16, String> {
    let unlocked = lock_session(&session).is_unlocked();
    if unlocked {
        load_session_config(mcp, &session);
        hydrate_tokens(mcp, &session);
        mcp.locked.store(false, Ordering::SeqCst);
    } else {
        mcp.locked.store(true, Ordering::SeqCst);
    }
    let desired = if unlocked {
        mcp.configured()
    } else {
        ListenConfig::default()
    };
    if mcp.running.load(Ordering::SeqCst) && mcp.effective() == desired {
        return Ok(*recover_lock(&mcp.port));
    }
    restart_with_config(mcp, desired, session, unlocked)
}

/// Signal the locked state without waiting for the listener thread. This is
/// safe to call from Session::lock while its mutex is held.
pub fn signal_locked(mcp: &McpState) {
    mcp.locked.store(true, Ordering::SeqCst);
    stop_signal(mcp, true);
    mcp.set_effective(ListenConfig::default());
    *recover_lock(&mcp.bound_host) = Ipv4Addr::LOCALHOST;
}

/// Rebind a previously running listener to loopback after the session mutex
/// has been released. It never uses the persisted LAN/address preference.
pub fn rebind_locked(mcp: &McpState) -> Result<u16, String> {
    mcp.locked.store(true, Ordering::SeqCst);
    if !mcp.restart_on_lock.swap(false, Ordering::SeqCst) {
        return Ok(*recover_lock(&mcp.port));
    }
    let session = crate::lock::active_session()
        .unwrap_or_else(|| Arc::new(Mutex::new(Session::default())));
    restart_with_config(mcp, ListenConfig::default(), session, false)
}

fn remove_stale_bridge_file() {
    let Some(base) = std::env::var_os("APPDATA") else {
        return;
    };
    let path = std::path::PathBuf::from(base)
        .join("com.sealbox.app")
        .join("fill.json");
    let _ = std::fs::remove_file(path);
}

pub fn stop(mcp: &McpState) {
    stop_signal(mcp, false);
    mcp.restart_on_lock.store(false, Ordering::SeqCst);
    join_listener(mcp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn disabled_github_tools_are_not_exposed() {
        let session = Mutex::new(Session::default());
        let listed = tools_list(&session);
        let names = listed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<Vec<_>>();
        assert!(!names.iter().any(|name| name.starts_with("github_")));
        for name in ["mail_accounts", "mail_list", "mail_read", "mail_download_attachment"] {
            assert!(names.contains(&name), "missing {name}");
        }
    }

    fn github_tool_names(enabled: bool) -> Vec<String> {
        let (vault, dek) =
            crate::vault::Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .set_secret_setting(
                &dek,
                "zoomkey_mcp_policy",
                &format!(r#"{{"enabled":{enabled}}}"#),
            )
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let listed = tools_list(&Mutex::new(session));
        listed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .filter(|name| name.starts_with("github_"))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn enabled_github_tools_are_exposed_as_a_single_capability() {
        let disabled = github_tool_names(false);
        assert!(disabled.is_empty());

        let enabled = github_tool_names(true);
        for name in [
            "github_repo_list",
            "github_repo_get",
            "github_git",
            "github_issues_get",
            "github_pr_create",
            "github_release_create",
            "github_list_credentials",
            "github_user_info",
        ] {
            assert!(enabled.iter().any(|tool| tool == name), "missing {name}");
        }

        let listed_tools = enabled
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<_>>();
        assert!(!listed_tools.iter().any(|name| *name == "github_get_file"));
        assert!(!listed_tools
            .iter()
            .any(|name| *name == "github_git_workspace_register"));
    }

    #[test]
    fn host_and_peer_match_actual_bound_address() {
        let local = "127.0.0.1:17891".parse::<SocketAddr>().unwrap();
        let peer = "127.0.0.1:50000".parse::<SocketAddr>().unwrap();
        assert!(host_allowed(
            &[("host".into(), "127.0.0.1:17891".into())],
            local
        ));
        assert!(!host_allowed(
            &[("host".into(), "localhost:17891".into())],
            local
        ));
        assert!(!host_allowed(&[], local));
        assert!(peer_allowed(peer, local));
        assert!(!peer_allowed(
            "192.168.1.20:50000".parse().unwrap(),
            local
        ));
        let lan = "192.168.1.20:17891".parse::<SocketAddr>().unwrap();
        assert!(peer_allowed(
            "192.168.1.30:50000".parse().unwrap(),
            lan
        ));
        assert!(!peer_allowed("8.8.8.8:50000".parse().unwrap(), lan));
    }

    #[test]
    fn listen_config_rejects_non_private_address() {
        assert_eq!(parse_listen_config("loopback", "").unwrap(), ListenConfig::default());
        assert_eq!(
            parse_listen_config("lan", "").unwrap(),
            ListenConfig { mode: ListenMode::Lan, address: None }
        );
        assert_eq!(
            parse_listen_config("address", "192.168.1.20").unwrap(),
            ListenConfig { mode: ListenMode::Address, address: Some("192.168.1.20".parse().unwrap()) }
        );
        for address in ["127.0.0.1", "0.0.0.0", "8.8.8.8", "224.0.0.1", "172.15.0.1"] {
            assert!(parse_listen_config("address", address).is_err(), "{address}");
        }
    }

    #[test]
    fn pairing_code_is_one_shot_and_windowed() {
        let mcp = McpState::default();
        let status = mcp.open_pairing();
        assert!(status.active);
        assert_eq!(status.expires_in_secs, 60);
        let code = status.code.unwrap();
        let current = mcp.pairing_status();
        assert!(current.active);
        assert!((1..=60).contains(&current.expires_in_secs));
        mcp.consume_pairing(&code).unwrap();
        assert!(mcp.consume_pairing(&code).is_err());
        assert!(!mcp.pairing_status().active);
    }

    #[test]
    fn json_tool_results_include_structured_content() {
        let result = tool_call_result(r#"{"ok":true,"pushed":false}"#, false);
        assert_eq!(result["structuredContent"]["ok"], true);
        assert_eq!(result["isError"], false);
        let list = tool_call_result(r#"[{"title":"github"}]"#, false);
        assert_eq!(list["structuredContent"][0]["title"], "github");
        let text = tool_call_result("not json", false);
        assert!(text.get("structuredContent").is_none());
    }

    #[test]
    fn enabled_github_tools_are_exposed_as_single_toggle() {
        assert!(github_tool_names(false).is_empty());
        let enabled = github_tool_names(true);
        for name in [
            "github_repo_list",
            "github_git",
            "github_issue_close",
            "github_list_credentials",
            "github_release_publish",
            "github_pr_merge",
        ] {
            assert!(enabled.iter().any(|tool| tool == name), "missing {name}");
        }
    }

    #[test]
    fn start_while_locked_does_not_mint_tokens() {
        let mutex = Arc::new(Mutex::new(Session::default()));
        let mcp = McpState::default();
        let port = start(&mcp, mutex).unwrap();
        assert_ne!(port, 0);
        assert!(recover_lock(&mcp.fill_token).is_empty());
        assert!(recover_lock(&mcp.token).is_empty());
        stop(&mcp);
    }

    fn github_session(enabled: bool) -> Mutex<Session> {
        let (vault, dek) = crate::vault::Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault.set_secret_setting(&dek, "zoomkey_mcp_policy", &format!(r#"{{"enabled":{enabled}}}"#)).unwrap();
        vault.upsert_entry(&dek, crate::vault::UpsertEntry {
            id: None,
            kind: crate::vault::EntryKind::ApiToken,
            title: "github".into(),
            account: Some("octocat".into()),
            url: None,
            folder_id: None,
            tags: Vec::new(),
            pinned: false,
            expires_at: None,
            notes: None,
            secret: crate::vault::SecretPayload::ApiToken {
                service: "github".into(),
                account: Some("octocat".into()),
                token: "ghp_test_token_value".into(),
            },
        }).unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        Mutex::new(session)
    }

    fn github_rpc(session: &Mutex<Session>, name: &str, args: Value) -> Value {
        handle_rpc(session, &McpState::default(), JsonRpcReq {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({"name":name,"arguments":args}),
        }).unwrap()
    }

    #[test]
    fn github_legacy_rpc_reads_and_denied_writes_reach_shared_handlers() {
        let session = github_session(true);
        let probe = crate::github_api::TransportProbe::install(|call| {
            assert_eq!(call.method, "GET");
            Ok(crate::github_api::HttpReply {
                status: 200,
                body: br#"{"number":7,"title":"bug","state":"open","login":"octocat"}"#.to_vec(),
            })
        });
        let read = github_rpc(&session, "github_issue", json!({"action":"get","repo":"o/r","number":7}));
        assert_eq!(read["result"]["isError"], false, "{read}");
        assert_eq!(read["result"]["structuredContent"]["number"], 7);
        assert_eq!(probe.calls()[0].url, "https://api.github.com/repos/o/r/issues/7");
        let alias = github_rpc(&session, "github_get_authenticated_user", json!({}));
        assert_eq!(alias["result"]["isError"], false, "{alias}");
        assert_eq!(alias["result"]["structuredContent"]["login"], "octocat");
        let denied = crate::confirm::with_auto(Some(false), || github_rpc(
            &session, "github_issue", json!({"action":"close","repo":"o/r","number":7}),
        ));
        assert_eq!(denied["result"]["isError"], true, "{denied}");
        assert!(denied["result"]["content"][0]["text"].as_str().unwrap().contains("拒绝"));
        let create_denied = crate::confirm::with_auto(Some(false), || github_rpc(
            &session, "github_issue", json!({"action":"create","repo":"o/r","title":"bug"}),
        ));
        assert_eq!(create_denied["result"]["isError"], true, "{create_denied}");
        assert!(create_denied["result"]["content"][0]["text"].as_str().unwrap().contains("拒绝"));
        assert_eq!(probe.calls().len(), 3);
        assert!(probe.calls().iter().all(|call| call.method == "GET"));
    }

    #[test]
    fn github_compatibility_rpc_respects_lock_and_mcp_switch() {
        let probe = crate::github_api::TransportProbe::install(|_| panic!("disabled calls must not reach HTTP"));
        for (session, expected) in [
            (Mutex::new(Session::default()), "锁定"),
            (github_session(false), "未启用"),
        ] {
            for (name, args) in [
                ("github_issue", json!({"action":"get","repo":"o/r","number":1})),
                ("github_pr", json!({"action":"list","repo":"o/r"})),
                ("github_release", json!({"action":"list","repo":"o/r"})),
                ("github_get_authenticated_user", json!({})),
            ] {
                let response = github_rpc(&session, name, args);
                assert_eq!(response["result"]["isError"], true);
                assert!(response["result"]["content"][0]["text"].as_str().unwrap().contains(expected), "{response}");
            }
        }
        assert!(probe.calls().is_empty());
    }

    #[test]
    fn github_rpc_catalog_contains_only_fine_grained_api_tools() {
        let response = handle_rpc(&github_session(true), &McpState::default(), JsonRpcReq {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/list".into(),
            params: json!({}),
        }).unwrap();
        let tools = response["result"]["tools"].as_array().unwrap();
        let names: std::collections::HashSet<_> = tools.iter().map(|tool| tool["name"].as_str().unwrap()).collect();
        assert_eq!(names.len(), tools.len());
        for name in ["github_issue", "github_pr", "github_release", "github_get_authenticated_user"] {
            assert!(!names.contains(name));
        }
        for name in ["github_issues_get", "github_issue_close", "github_git", "github_user_info"] {
            assert!(names.contains(name));
        }
    }

    #[test]
    fn locked_vault_errors() {
        let response = handle_rpc(
            &Mutex::new(Session::default()),
            &McpState::default(),
            JsonRpcReq {
                jsonrpc: "2.0".into(),
                id: Some(json!(1)),
                method: "tools/call".into(),
                params: json!({"name":"github_list_credentials","arguments":{}}),
            },
        )
        .unwrap();
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("锁定"));
    }
}
