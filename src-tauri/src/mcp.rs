use crate::fill;
use crate::github_mcp;
use crate::lock::{idle_lock_if_needed, lock_session, recover_lock};
use crate::session::Session;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const DEFAULT_PORT: u16 = 17891;
const PAIRING_SECS: u64 = 60;
const PAIRING_MAX_FAILURES: u32 = 5;

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
    pairing: Arc<Mutex<Option<PairingWindow>>>,
    callers: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

impl Default for McpState {
    fn default() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            port: Arc::new(Mutex::new(DEFAULT_PORT)),
            token: Arc::new(Mutex::new(String::new())),
            fill_token: Arc::new(Mutex::new(String::new())),
            pairing: Arc::new(Mutex::new(None)),
            callers: Arc::new(Mutex::new(HashMap::new())),
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

fn host_allowed(headers: &[(String, String)], port: u16) -> bool {
    let raw = headers
        .iter()
        .find(|(k, _)| k == "host")
        .map(|(_, v)| v.trim().to_ascii_lowercase())
        .unwrap_or_default();
    // [::1]:17891 -> ::1:17891. Clients commonly send localhost or IPv6 loopback.
    // Only the loopback name and the bound port are accepted.
    let host = if let Some(rest) = raw.strip_prefix('[') {
        rest.replacen("]:", ":", 1)
    } else {
        raw
    };
    host == format!("127.0.0.1:{port}")
        || host == format!("localhost:{port}")
        || host == format!("::1:{port}")
}

#[derive(Serialize)]
pub struct PairingStatus {
    pub active: bool,
    pub code: Option<String>,
    pub expires_in_secs: u64,
    pub port: u16,
}

impl McpState {
    fn open_caller(&self) -> Result<String, String> {
        let mut callers = recover_lock(&self.callers);
        callers.retain(|_, active| active.load(Ordering::SeqCst));
        if callers.len() >= 128 {
            return Err("MCP 会话过多，请在 Sealbox 重启 MCP".into());
        }
        let id = Uuid::new_v4().to_string();
        callers.insert(id.clone(), Arc::new(AtomicBool::new(true)));
        Ok(id)
    }

    fn caller_permit(&self, id: &str) -> Result<Arc<AtomicBool>, String> {
        recover_lock(&self.callers).get(id).cloned()
            .filter(|active| active.load(Ordering::SeqCst))
            .ok_or_else(|| "MCP 调用会话无效或已撤销，请重新 initialize".into())
    }

    fn revoke_caller(&self, id: &str) -> Result<(), String> {
        self.caller_permit(id)?.store(false, Ordering::SeqCst);
        Ok(())
    }

    pub fn invalidate_callers(&self) {
        let mut callers = recover_lock(&self.callers);
        for active in callers.values() { active.store(false, Ordering::SeqCst); }
        callers.clear();
    }

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

fn tools_list(_session: &Mutex<Session>) -> Value {
    // The catalog is a stable protocol surface, independent of credentials,
    // platform profiles, lock state and the execution switch.
    let mut tools = crate::credential_mcp::tool_definitions();
    tools.extend(crate::git_workspace::tool_definitions());
    tools.extend(mail_tool_definitions());
    for tool in &mut tools {
        if let Some(schema) = tool.get_mut("inputSchema") {
            sanitize_mcp_schema(schema);
        }
        if let Some(schema) = tool.get_mut("outputSchema") {
            sanitize_mcp_schema(schema);
        }
    }
    json!({ "tools": tools })
}

/// DSH's tool registry only accepts a small JSON Schema subset. Numeric and
/// string bounds stay in the server-side validator, but advertising them makes
/// `tools.register` reject the whole list, so the client reports startup failure
/// and registers nothing.
fn sanitize_mcp_schema(schema: &mut Value) {
    const KEEP: &[&str] = &[
        "type",
        "oneOf",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "const",
        "description",
        "title",
        "default",
        "examples",
    ];
    match schema {
        Value::Object(map) => {
            map.retain(|key, _| KEEP.contains(&key.as_str()));
            if let Some(props) = map.get_mut("properties").and_then(Value::as_object_mut) {
                for child in props.values_mut() {
                    sanitize_mcp_schema(child);
                }
            }
            if let Some(items) = map.get_mut("items") {
                sanitize_mcp_schema(items);
            }
            if let Some(branches) = map.get_mut("oneOf").and_then(Value::as_array_mut) {
                for child in branches {
                    sanitize_mcp_schema(child);
                }
            }
            if let Some(extra) = map.get("additionalProperties") {
                if !extra.is_boolean() {
                    map.insert("additionalProperties".into(), Value::Bool(false));
                }
            }
        }
        Value::Array(items) => {
            for child in items {
                sanitize_mcp_schema(child);
            }
        }
        _ => {}
    }
}

fn negotiated_protocol(params: &Value) -> String {
    const KNOWN: &[&str] = &[
        "2025-11-25",
        "2025-06-18",
        "2025-03-26",
        "2024-11-05",
        "2024-10-07",
    ];
    params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|version| KNOWN.contains(version))
        .unwrap_or("2025-03-26")
        .to_string()
}

const MAIL_ACTIONS: &[&str] = &["accounts", "list", "read", "save"];

fn mail_tool_definitions() -> Vec<Value> {
    vec![json!({
        "name": "mail",
        "description": "邮箱。action：accounts 列出账号（不含授权码）；list 只读收件箱，最多 50 封，可带 beforeUid；read 读取纯文本和附件清单；save 把一个附件保存到已有目录中的新文件，不覆盖。entryId 用于 list/read/save，uid 用于 read/save，part 与 path 仅 save。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": MAIL_ACTIONS, "description": "accounts、list、read、save"},
                "entryId": {"type": "string", "minLength": 1, "maxLength": 128, "description": "list、read、save"},
                "beforeUid": {"type": "integer", "minimum": 1, "maximum": 4294967295u64, "description": "仅 list"},
                "uid": {"type": "integer", "minimum": 1, "maximum": 4294967295u64, "description": "read、save"},
                "part": {"type": "string", "minLength": 1, "maxLength": 32, "description": "仅 save"},
                "path": {"type": "string", "minLength": 1, "maxLength": 1024, "description": "仅 save"}
            },
            "required": ["action"],
            "additionalProperties": false
        },
        "readOnly": false,
        "risk": "high",
        "annotations": github_mcp::annotations(false, true)
    })]
}

fn legacy_mail_action(name: &str) -> Option<&'static str> {
    match name {
        "mail_accounts" => Some("accounts"),
        "mail_list" => Some("list"),
        "mail_read" => Some("read"),
        "mail_download_attachment" => Some("save"),
        _ => None,
    }
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

fn call_mail_tool(session: &Mutex<Session>, name: &str, args: Value, permit: &AtomicBool, generation: u64) -> Result<String, String> {
    let entry = args.get("entryId").and_then(Value::as_str).unwrap_or("-").to_string();
    let secrets = {
        let s=lock_session(session);
        let vault=s.vault().map_err(|e|e.to_string())?;
        let dek=s.dek().map_err(|e|e.to_string())?;
        let ids=if entry=="-" {
            vault.list_entries(&crate::vault::ListFilter{kind:Some(crate::vault::EntryKind::MailAuth),..Default::default()}).map_err(|e|e.to_string())?.into_iter().map(|entry|entry.id).collect::<Vec<_>>()
        } else {vec![entry.clone()]};
        let mut secrets=zeroize::Zeroizing::new(Vec::new());
        for id in ids {
            if let Ok(mut payload)=vault.get_active_secret(dek,&id) {
                secrets.extend(crate::redact::secrets_from_payload(&payload));
                zeroize::Zeroize::zeroize(&mut payload);
            }
        }
        secrets
    };
    let uid = args
        .get("uid")
        .and_then(Value::as_u64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".into());
    let part = args.get("part").and_then(Value::as_str).unwrap_or("-").to_string();
    let guard=||require_call_authorized(&lock_session(session),permit,generation);
    let result = call_mail_inner(session, name, &args, &guard)
        .map(|text|redact_tool_text(text,&secrets)).map_err(|text|redact_tool_text(text,&secrets));
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

fn call_mail_inner(session: &Mutex<Session>, name: &str, args: &Value, guard: &dyn Fn()->Result<(),String>) -> Result<String, String> {
    let (action, args) = if name == "mail" {
        let action = args.get("action").and_then(Value::as_str).ok_or_else(|| {
            format!("mail 需要 action：{}", MAIL_ACTIONS.join("、"))
        })?;
        if !MAIL_ACTIONS.contains(&action) {
            return Err(format!(
                "mail 不支持 action={action}。可用 {}",
                MAIL_ACTIONS.join("、")
            ));
        }
        let mut args = args.clone();
        args.as_object_mut().map(|object| object.remove("action"));
        (action, args)
    } else {
        (
            legacy_mail_action(name).ok_or_else(|| format!("未知工具 {name}"))?,
            args.clone(),
        )
    };
    match action {
        "accounts" => {
            ensure_mail_keys(&args, &[])?;
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
        "list" => {
            ensure_mail_keys(&args, &["entryId", "beforeUid"])?;
            let entry_id = mail_arg_str(&args, "entryId", true)?.unwrap_or("");
            let before = mail_arg_u32(&args, "beforeUid", false)?;
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
        "read" => {
            ensure_mail_keys(&args, &["entryId", "uid"])?;
            let entry_id = mail_arg_str(&args, "entryId", true)?.unwrap_or("");
            let uid = mail_arg_u32(&args, "uid", true)?.ok_or("参数无效")?;
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
        "save" => {
            ensure_mail_keys(&args, &["entryId", "uid", "part", "path"])?;
            let entry_id = mail_arg_str(&args, "entryId", true)?.unwrap_or("");
            let uid = mail_arg_u32(&args, "uid", true)?.ok_or("参数无效")?;
            let part = mail_arg_str(&args, "part", true)?.unwrap_or("").to_string();
            let path = mail_arg_str(&args, "path", true)?.unwrap_or("").to_string();
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
            guard()?;
            let saved = sealbox_core::mail::write_exclusive(&path, &bytes).map_err(str::to_string)?;
            serde_json::to_string(&json!({"bytes": saved, "path": path})).map_err(|_| "参数无效".into())
        }
        _ => Err(format!(
            "mail 不支持 action={action}。可用 {}",
            MAIL_ACTIONS.join("、")
        )),
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

fn handle_rpc(session: &Mutex<Session>, mcp: &McpState, req: JsonRpcReq, caller: &str) -> Option<Value> {
    let out = match req.method.as_str() {
        "initialize" => rpc_ok(
            req.id.clone(),
            json!({
                "protocolVersion": negotiated_protocol(&req.params),
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
            match call_tool(session, mcp, caller, name, args) {
                Ok(text) => rpc_ok(req.id, tool_call_result(&text, false)),
                Err(e) => rpc_ok(req.id, tool_call_result(&e, true)),
            }
        }
        _ => rpc_error(req.id, -32601, "method not found"),
    };
    Some(out)
}

fn call_git_tool(session: &Mutex<Session>, name: &str, args: Value, permit: &AtomicBool, generation: u64) -> Result<String, String> {
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
                require_call_authorized(&s, permit, generation).and_then(|_| exec(&mut s))
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
            "mcp_git"
        } else {
            "mcp_git_denied"
        };
        let _ = vault.audit(action, None, &detail);
    }
    text
}

fn require_call_authorized(s: &Session, permit: &AtomicBool, generation: u64) -> Result<(), String> {
    if !permit.load(Ordering::SeqCst) { return Err("当前调用方的授权已撤销".into()); }
    if !s.is_unlocked() || s.generation() != generation {
        return Err("金库已锁定或解锁会话已改变，请重新调用".into());
    }
    crate::credential_mcp::require_enabled(s)
}

enum PreparedRemote {
    Http(crate::profile_http::PreparedHttp),
    Builtin(crate::http_profiles::PreparedBuiltinCall),
}

impl PreparedRemote {
    fn confirmation(&self) -> Option<&crate::confirm::ConfirmPayload> {
        match self {
            Self::Http(p) => p.confirmation.as_ref(),
            Self::Builtin(p) => p.confirmation.as_ref(),
        }
    }
    fn execute(self) -> Result<(u16, String), String> {
        match self {
            Self::Http(p) => p.execute().map(|text| {
                let status=serde_json::from_str::<Value>(&text).ok().and_then(|value|value.get("status").and_then(Value::as_u64)).unwrap_or(200) as u16;
                (status,text)
            }),
            Self::Builtin(p) => p.execute_with_status_after_confirmation(true),
        }
    }
}

fn call_http_tool(session: &Mutex<Session>, permit: &AtomicBool, args: Value) -> Result<String, String> {
    // Resolve only registered metadata for audit; never log an attacker supplied
    // operation name, URL, body or query when validation itself fails.
    let id=args.get("credential_id").and_then(Value::as_str).unwrap_or("").to_string();
    let requested_op=args.get("op").and_then(Value::as_str).unwrap_or("");
    let (origin,op_name)={
        let s=lock_session(session);
        crate::http_profiles::effective_profile(&s,&id).ok().flatten().map(|profile|{
            let op=profile.operations.iter().find(|op|op.name==requested_op).map(|op|op.name.clone()).unwrap_or_else(||"-".into());
            (profile.origin,op)
        }).unwrap_or_else(||("-".into(),"-".into()))
    };
    let result=call_http_tool_inner(session,permit,args);
    let mut s=lock_session(session);
    if let Ok(vault)=s.vault() {
        let status=result.as_ref().ok().map(|(status,_)|status.to_string()).unwrap_or_else(||"-".into());
        let reason=match &result {Ok(_)=>"ok",Err(e) if e.contains("拒绝")=>"denied",Err(e) if e.contains("撤销")=>"revoked",Err(_)=>"validation_or_request"};
        let detail=format!("operation=http_call op={} decision={} reason={} origin={} credential={} status={}",
            audit_token(&op_name),if result.is_ok(){"allow"}else{"deny"},reason,audit_token(&origin),&crate::http_guard::sha256_hex(id.as_bytes())[..12],status);
        let _=vault.audit(if result.is_ok(){"mcp_http"}else{"mcp_http_denied"},None,&detail);
    }
    if result.is_ok(){s.touch();}
    result.map(|(_,text)|text)
}

fn call_http_tool_inner(session: &Mutex<Session>, permit: &AtomicBool, args: Value) -> Result<(u16, String), String> {
    crate::credential_mcp::validate_tool("http_call", &args)?;
    let id = args["credential_id"].as_str().ok_or("缺少凭据 ID")?;
    let op_name = args["op"].as_str().ok_or("缺少操作名")?;
    let params = &args["params"];
    let (prepared, generation, revision, profile_bytes, cert_revision, secrets) = {
        let s = lock_session(session);
        crate::credential_mcp::require_enabled(&s)?;
        let profile = crate::http_profiles::effective_profile(&s, id)?
            .ok_or("该凭据没有 HTTP profile，请先在 Sealbox 登记操作")?;
        sealbox_core::profile::validate_profile(&profile)?;
        let operation = profile.operations.iter().find(|operation| operation.name == op_name)
            .ok_or_else(|| format!("未知操作。该凭据可用操作：{}", profile.operations.iter().map(|op|op.name.as_str()).collect::<Vec<_>>().join("、")))?;
        sealbox_core::profile::validate_operation_params(operation, params)?;
        let vault = s.vault().map_err(|e|e.to_string())?;
        let dek = s.dek().map_err(|e|e.to_string())?;
        let mut payload = vault.get_active_secret(dek, id).map_err(|_|"凭据不存在或已在回收站".to_string())?;
        let secrets = zeroize::Zeroizing::new(crate::redact::secrets_from_payload(&payload));
        zeroize::Zeroize::zeroize(&mut payload);
        let cert_revision = profile.auth.client_cert_id.as_ref().filter(|id|!id.is_empty())
            .map(|id| vault.entry_revision(id).map(|revision|(id.clone(),revision))).transpose().map_err(|e|e.to_string())?;
        let prepared = if let Some(prepared) = crate::http_profiles::prepare_builtin(&s, id, &profile, op_name, params.clone()) {
            PreparedRemote::Builtin(prepared?)
        } else {
            PreparedRemote::Http(crate::profile_http::prepare(&s, id, &profile, operation, params)?)
        };
        (prepared, s.generation(), vault.entry_revision(id).map_err(|e|e.to_string())?,
            serde_json::to_vec(&profile).map_err(|_|"profile 编码失败".to_string())?, cert_revision, secrets)
    };
    let result = (|| {
        if let Some(payload) = prepared.confirmation() {
            if !crate::confirm::ask_payload(payload) { return Err("用户拒绝了这次写操作".into()); }
        }
        // Never retain the vault mutex while waiting for a human. Check everything
        // again after approval: lock/revoke/profile edits must invalidate it.
        {
            let s = lock_session(session);
            require_call_authorized(&s, permit, generation)?;
            let vault = s.vault().map_err(|e|e.to_string())?;
            if vault.entry_revision(id).map_err(|e|e.to_string())? != revision {
                return Err("凭据或 profile 已改变，请重新调用".into());
            }
            let current = crate::http_profiles::effective_profile(&s,id)?.ok_or("profile 已移除")?;
            if serde_json::to_vec(&current).map_err(|_|"profile 编码失败".to_string())? != profile_bytes {
                return Err("profile 策略已改变，请重新调用".into());
            }
            if let Some((cert_id, revision)) = &cert_revision {
                if &vault.entry_revision(cert_id).map_err(|e|e.to_string())? != revision {
                    return Err("客户端证书已改变，请重新调用".into());
                }
            }
        }
        prepared.execute()
    })();
    result.map(|(status,text)| (status,redact_tool_text(text,&secrets)))
        .map_err(|text| redact_tool_text(text,&secrets))
}

fn audit_token(input:&str)->String {
    input.chars().filter(|c|!c.is_control() && !c.is_whitespace() && *c!='=').take(256).collect()
}

fn redact_tool_text(text:String,secrets:&[String])->String {
    let text = match serde_json::from_str::<Value>(&text) {
        Ok(value) => serde_json::to_string(&crate::credential_mcp::redact_value(value,secrets)).unwrap_or_else(|_|"响应编码失败".into()),
        Err(_) => {
            let mut text=text;
            for secret in secrets.iter().filter(|s|!s.is_empty()) {text=text.replace(secret,"[REDACTED]");}
            crate::redact::redact_text(&text,&[])
        }
    };
    const MAX:usize = 64*1024;
    if text.len()<=MAX {return text;}
    let mut end=MAX;
    while !text.is_char_boundary(end) {end-=1;}
    json!({"text":&text[..end],"truncated":true}).to_string()
}

fn call_tool(
    session: &Mutex<Session>,
    mcp: &McpState,
    caller: &str,
    name: &str,
    args: Value,
) -> Result<String, String> {
    let permit = mcp.caller_permit(caller)?;
    if !crate::credential_mcp::TOOL_NAMES.contains(&name) {
        return Err(format!("未知 MCP 工具。可用 {}", crate::credential_mcp::TOOL_NAMES.join("、")));
    }
    if name == "vault_revoke" {
        crate::credential_mcp::validate_tool(name,&args)?;
        mcp.revoke_caller(caller)?;
        let s=lock_session(session);
        if let Ok(vault)=s.vault() {let _=vault.audit("mcp_revoke",None,"scope=current_caller decision=allow");}
        return Ok(json!({"revoked":true,"scope":"current_caller","reauthorization_required":true}).to_string());
    }
    let generation = {
        let mut s = lock_session(session);
        idle_lock_if_needed(&mut s, mcp);
        if !s.is_unlocked() {
            return Err("金库已锁定。请先在 Sealbox 窗口解锁，再让我重试。".into());
        }
        crate::credential_mcp::require_enabled(&s)?;
        s.generation()
    };
    match name {
        "vault_list" | "vault_describe" => {
            let mut s=lock_session(session);
            let result=if name=="vault_list" {crate::credential_mcp::list(&s,&args)} else {crate::credential_mcp::describe(&s,&args)};
            if let Ok(vault)=s.vault() {let _=vault.audit("mcp_vault",None,&format!("operation={name} decision={}",if result.is_ok(){"allow"}else{"deny"}));}
            if result.is_ok() {s.touch();}
            result
        },
        "http_call" => call_http_tool(session,&permit,args),
        "git" => call_git_tool(session,name,args,&permit,generation),
        "mail" => {
            let definition=mail_tool_definitions().remove(0);
            let action=args.get("action").and_then(Value::as_str).unwrap_or("");
            if !MAIL_ACTIONS.contains(&action) {return Err(format!("mail 需要合法 action：{}",MAIL_ACTIONS.join("、")));}
            github_mcp::validate_tool_arguments(&definition["inputSchema"],&args)?;
            if action=="save" && !crate::confirm::ask("保存邮件附件","允许把附件保存到本机新文件？",&[("目标文件",args.get("path").and_then(Value::as_str).unwrap_or("").to_string())]) {
                return Err("用户拒绝了这次写操作".into());
            }
            require_call_authorized(&lock_session(session),&permit,generation)?;
            call_mail_tool(session,name,args,&permit,generation)
        },
        _ => unreachable!(),
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
    write_http_with_session(stream,status,body,None);
}

fn write_http_with_session(stream: &mut TcpStream, status: &str, body: &[u8], caller: Option<&str>) {
    let session_header=caller.map(|id|format!("Mcp-Session-Id: {id}\r\n")).unwrap_or_default();
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{session_header}Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(body);
}

fn handle_client(mut stream: TcpStream, session: Arc<Mutex<Session>>, mcp: McpState) {
    let Ok(req) = read_http_request(&mut stream) else {
        return;
    };
    let port = *recover_lock(&mcp.port);
    if !host_allowed(&req.headers, port) {
        write_http(
            &mut stream,
            "403 Forbidden",
            br#"{"ok":false,"error":"invalid host"}"#,
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
        if fill_token.is_empty() || !constant_eq(&auth, &format!("Bearer {fill_token}")) {
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
    if token.is_empty() || !constant_eq(&auth, &format!("Bearer {token}")) {
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
    let initializing=rpc.method=="initialize";
    let caller=if initializing {
        match mcp.open_caller() {
            Ok(id)=>id,
            Err(_)=>{write_http(&mut stream,"429 Too Many Requests",br#"{"error":"too many MCP sessions"}"#);return;}
        }
    } else {
        let Some(id)=req.headers.iter().find(|(key,_)|key=="mcp-session-id").map(|(_,value)|value.as_str()) else {
            write_http(&mut stream,"400 Bad Request",br#"{"error":"Mcp-Session-Id required; initialize first"}"#);
            return;
        };
        if mcp.caller_permit(id).is_err() {
            write_http(&mut stream,"404 Not Found",br#"{"error":"MCP session revoked or expired; initialize again"}"#);
            return;
        }
        id.to_string()
    };
    match handle_rpc(&session, &mcp, rpc, &caller) {
        Some(resp) => {
            let bytes = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{}".to_vec());
            write_http_with_session(&mut stream, "200 OK", &bytes, initializing.then_some(caller.as_str()));
        }
        None => write_http(&mut stream, "204 No Content", b""),
    }
}

pub fn start(mcp: &McpState, session: Arc<Mutex<Session>>) -> Result<u16, String> {
    if mcp.running.load(Ordering::SeqCst) {
        return Ok(*recover_lock(&mcp.port));
    }
    {
        let unlocked = lock_session(&session).is_unlocked();
        if unlocked {
            {
                let s = lock_session(&session);
                if let (Ok(v), Ok(dek)) = (s.vault(), s.dek()) {
                    if let Ok(Some(tok)) = v.get_secret_setting(dek, "mcp_token") {
                        if !tok.is_empty() {
                            *recover_lock(&mcp.token) = tok;
                        }
                    }
                    if let Ok(Some(tok)) = v.get_secret_setting(dek, "fill_token") {
                        if !tok.is_empty() {
                            *recover_lock(&mcp.fill_token) = tok;
                        }
                    }
                }
            }
            let mut token = recover_lock(&mcp.token);
            let minted_token = if token.is_empty() {
                *token = new_token();
                Some(token.clone())
            } else {
                None
            };
            drop(token);
            if let Some(tok) = minted_token {
                let s = lock_session(&session);
                if let (Ok(v), Ok(dek)) = (s.vault(), s.dek()) {
                    let _ = v.set_secret_setting(dek, "mcp_token", &tok);
                }
            }
            let mut fill = recover_lock(&mcp.fill_token);
            let minted_fill = if fill.is_empty() {
                *fill = fill::new_fill_token();
                Some(fill.clone())
            } else {
                None
            };
            drop(fill);
            if let Some(tok) = minted_fill {
                let s = lock_session(&session);
                if let (Ok(v), Ok(dek)) = (s.vault(), s.dek()) {
                    let _ = v.set_secret_setting(dek, "fill_token", &tok);
                }
            }
        }
    }
    let listener = TcpListener::bind(("127.0.0.1", DEFAULT_PORT))
        .or_else(|_| TcpListener::bind("127.0.0.1:0"))
        .map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    *recover_lock(&mcp.port) = port;
    mcp.running.store(true, Ordering::SeqCst);
    remove_stale_bridge_file();
    let running = mcp.running.clone();
    let mcp_accept = mcp.clone();
    thread::spawn(move || {
        listener.set_nonblocking(true).ok();
        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, addr)) => {
                    if !addr.ip().is_loopback() {
                        continue;
                    }
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
    Ok(port)
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
    mcp.running.store(false, Ordering::SeqCst);
    mcp.close_pairing();
    mcp.invalidate_callers();
}

#[cfg(test)]
#[path = "mcp_surface_tests.rs"]
mod tests;
