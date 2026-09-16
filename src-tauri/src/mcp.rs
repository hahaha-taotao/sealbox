use crate::fill;
use crate::http_guard::{
    assert_public_target, credential_allows_url, parse_http_url, sha256_hex, summarize_response,
    PublicResolver,
};
use crate::lock::{idle_lock_if_needed, lock_session, recover_lock};
use crate::redact::{redact_text, secrets_from_payload};
use crate::session::Session;
use crate::vault::{EntryKind, ListFilter, SecretPayload, SortBy};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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

#[derive(Clone, Serialize)]
pub struct HttpLogEntry {
    pub id: String,
    pub at: String,
    pub credential_id: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub bytes: usize,
    pub sha256: String,
    pub body: String,
}

#[derive(Clone)]
pub struct McpState {
    pub running: Arc<AtomicBool>,
    pub port: Arc<Mutex<u16>>,
    pub token: Arc<Mutex<String>>,
    pub fill_token: Arc<Mutex<String>>,
    pairing: Arc<Mutex<Option<PairingWindow>>>,
    http_logs: Arc<Mutex<Vec<HttpLogEntry>>>,
}

impl Default for McpState {
    fn default() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            port: Arc::new(Mutex::new(DEFAULT_PORT)),
            token: Arc::new(Mutex::new(String::new())),
            fill_token: Arc::new(Mutex::new(String::new())),
            pairing: Arc::new(Mutex::new(None)),
            http_logs: Arc::new(Mutex::new(Vec::new())),
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
    let host = headers
        .iter()
        .find(|(k, _)| k == "host")
        .map(|(_, v)| v.trim().to_ascii_lowercase())
        .unwrap_or_default();
    host == format!("127.0.0.1:{port}")
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

    pub fn http_logs(&self) -> Vec<HttpLogEntry> {
        recover_lock(&self.http_logs).clone()
    }

    pub fn clear_http_logs(&self) {
        recover_lock(&self.http_logs).clear();
    }

    #[cfg(test)]
    pub fn seed_http_log(&self) {
        self.push_http_log(HttpLogEntry {
            id: "test-log".into(),
            at: "now".into(),
            credential_id: "c".into(),
            method: "GET".into(),
            url: "https://example.com".into(),
            status: 200,
            bytes: 12,
            sha256: "abc".into(),
            body: "secret-body".into(),
        });
    }

    fn push_http_log(&self, entry: HttpLogEntry) {
        let mut logs = recover_lock(&self.http_logs);
        logs.insert(0, entry);
        logs.truncate(20);
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

fn tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": "list_credentials",
                "description": "列出本地金库中的凭据元数据（名称、类型、账号）。永不返回密码、Token 或私钥。金库须已在 Sealbox 中解锁。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "可选，按键名/账号/网址筛选" },
                        "kind": { "type": "string", "enum": ["website", "api_token", "ssh", "mailbox", "mail_auth", "server", "database"] }
                    }
                }
            },
            {
                "name": "http_request",
                "description": "用指定凭据在本机代发 HTTP。Authorization 仅在目标 origin 与凭据绑定网址/服务一致时注入；拒绝回环、内网和云元数据；不跟随重定向。永不把响应正文返回给模型，只返回状态码、长度和 SHA256；完整响应只在 Sealbox 窗口查看。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "credential_id": { "type": "string" },
                        "method": { "type": "string", "description": "GET/POST/PUT/PATCH/DELETE，默认 GET" },
                        "url": { "type": "string" },
                        "body": { "type": "string" }
                    },
                    "required": ["credential_id", "url"]
                }
            },
            {
                "name": "copy_secret",
                "description": "把指定凭据的主秘密复制到本机剪贴板（约 20 秒后清空）。不把明文返回给模型。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "credential_id": { "type": "string" }
                    },
                    "required": ["credential_id"]
                }
            }
        ]
    })
}

#[derive(Clone, Serialize)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
}

pub fn tool_catalog() -> Vec<ToolInfo> {
    let list = tools_list();
    list["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| {
            Some(ToolInfo {
                name: t.get("name")?.as_str()?.to_string(),
                description: t.get("description")?.as_str()?.to_string(),
            })
        })
        .collect()
}

fn rpc_error(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn rpc_ok(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn handle_rpc(session: &Mutex<Session>, mcp: &McpState, req: JsonRpcReq) -> Option<Value> {
    let out = match req.method.as_str() {
        "initialize" => rpc_ok(
            req.id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "sealbox", "version": "0.1.0" }
            }),
        ),
        "notifications/initialized" | "initialized" => return None,
        "ping" => rpc_ok(req.id, json!({})),
        "tools/list" => rpc_ok(req.id, tools_list()),
        "tools/call" => {
            let name = req
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = req.params.get("arguments").cloned().unwrap_or(json!({}));
            match call_tool(session, mcp, name, args) {
                Ok(text) => rpc_ok(
                    req.id,
                    json!({ "content": [{ "type": "text", "text": text }] }),
                ),
                Err(e) => rpc_ok(
                    req.id,
                    json!({ "content": [{ "type": "text", "text": e }], "isError": true }),
                ),
            }
        }
        _ => rpc_error(req.id, -32601, "method not found"),
    };
    Some(out)
}

fn call_tool(
    session: &Mutex<Session>,
    mcp: &McpState,
    name: &str,
    args: Value,
) -> Result<String, String> {
    let mut s = lock_session(session);
    idle_lock_if_needed(&mut s, mcp);
    if !s.is_unlocked() {
        return Err("金库已锁定。请先在 Sealbox 窗口解锁，再让我重试。".into());
    }
    match name {
        "list_credentials" => {
            let query = args
                .get("query")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let kind = args
                .get("kind")
                .and_then(|v| v.as_str())
                .and_then(|k| match k {
                    "website" => Some(EntryKind::Website),
                    "api_token" => Some(EntryKind::ApiToken),
                    "ssh" => Some(EntryKind::Ssh),
                    "mailbox" => Some(EntryKind::Mailbox),
                    "mail_auth" => Some(EntryKind::MailAuth),
                    "server" => Some(EntryKind::Server),
                    "database" => Some(EntryKind::Database),
                    _ => None,
                });
            let vault = s.vault().map_err(|e| e.to_string())?;
            let list = vault
                .list_entries(&ListFilter {
                    query,
                    kind,
                    folder_id: None,
                    uncategorized: false,
                    tag: None,
                    trash: false,
                    sort: SortBy::UseCount,
                })
                .map_err(|e| e.to_string())?;
            let _ = vault.audit("mcp_list", None, "ok");
            let slim: Vec<Value> = list
                .into_iter()
                .map(|e| {
                    json!({
                        "id": e.id,
                        "kind": e.kind,
                        "title": e.title,
                        "account": e.account,
                        "url": e.url,
                        "has_totp": e.has_totp
                    })
                })
                .collect();
            Ok(serde_json::to_string_pretty(&slim).unwrap_or_else(|_| "[]".into()))
        }
        "copy_secret" => {
            let id = args
                .get("credential_id")
                .and_then(|v| v.as_str())
                .ok_or("缺少 credential_id")?;
            let dek = *s.dek().map_err(|e| e.to_string())?;
            let payload = {
                let vault = s.vault().map_err(|e| e.to_string())?;
                vault.get_secret(&dek, id).map_err(|e| e.to_string())?
            };
            let text = match &payload {
                SecretPayload::Website { password, .. } => password.clone(),
                SecretPayload::ApiToken { token, .. } => token.clone(),
                SecretPayload::Ssh { private_key, .. } => private_key.clone(),
                SecretPayload::Mailbox { password, .. } => password.clone(),
                SecretPayload::MailAuth { auth_code, .. } => auth_code.clone(),
                SecretPayload::Server { password, .. } => password.clone(),
                SecretPayload::Database { password, .. } => password.clone(),
            };
            crate::clipboard::write_text(&text)?;
            s.remember_clipboard(&text);
            let vault = s.vault().map_err(|e| e.to_string())?;
            let _ = vault.bump_use(id);
            let _ = vault.audit("mcp_copy", Some(id), "clipboard");
            s.touch();
            Ok("已复制到本机剪贴板，约 20 秒后清空。明文没有返回。".into())
        }
        "http_request" => {
            let id = args
                .get("credential_id")
                .and_then(|v| v.as_str())
                .ok_or("缺少 credential_id")?;
            let url = args.get("url").and_then(|v| v.as_str()).ok_or("缺少 url")?;
            let method = args
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("GET")
                .to_uppercase();
            match method.as_str() {
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" => {}
                _ => return Err("不支持的 HTTP 方法".into()),
            }
            let body = args
                .get("body")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let target = parse_http_url(url, true)?;
            assert_public_target(&target)?;
            let dek = *s.dek().map_err(|e| e.to_string())?;
            let (payload, entry_url) = {
                let vault = s.vault().map_err(|e| e.to_string())?;
                let payload = vault.get_secret(&dek, id).map_err(|e| e.to_string())?;
                let listed = vault
                    .list_entries(&ListFilter::default())
                    .map_err(|e| e.to_string())?;
                let entry_url = listed
                    .iter()
                    .find(|e| e.id == id)
                    .and_then(|e| e.url.clone());
                (payload, entry_url)
            };
            credential_allows_url(&payload, entry_url.as_deref(), url)?;
            let mut known = secrets_from_payload(&payload);
            known.push(recover_lock(&mcp.token).clone());
            known.push(recover_lock(&mcp.fill_token).clone());
            let auth = match &payload {
                SecretPayload::ApiToken { token, .. } => Some(format!("Bearer {token}")),
                SecretPayload::Website {
                    password, username, ..
                } => {
                    let user = username.clone().unwrap_or_default();
                    let raw = format!("{user}:{password}");
                    Some(format!(
                        "Basic {}",
                        base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            raw.as_bytes()
                        )
                    ))
                }
                _ => {
                    return Err("该类型凭据不能用于 http_request，请选 API Token 或网站账号".into())
                }
            };
            drop(s);
            let agent = ureq::builder()
                .redirects(0)
                .timeout(Duration::from_secs(15))
                .timeout_connect(Duration::from_secs(8))
                .resolver(PublicResolver)
                .user_agent("Sealbox/0.1")
                .build();
            let mut req = agent.request(&method, url);
            if let Some(a) = &auth {
                req = req.set("Authorization", a);
            }
            let resp = if let Some(b) = body {
                req.send_string(&b)
            } else {
                req.call()
            };
            let (status, bytes) = match resp {
                Ok(r) => read_response_limited(r, 256_000),
                Err(ureq::Error::Status(_, r)) => read_response_limited(r, 256_000),
                Err(e) => return Err(format!("请求失败: {e}")),
            };
            let refs: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
            let text = String::from_utf8_lossy(&bytes);
            let redacted = redact_text(&text, &refs);
            let summary = summarize_response(status, &bytes);
            mcp.push_http_log(HttpLogEntry {
                id: Uuid::new_v4().to_string(),
                at: chrono::Utc::now().to_rfc3339(),
                credential_id: id.to_string(),
                method: method.clone(),
                url: url.to_string(),
                status,
                bytes: bytes.len(),
                sha256: sha256_hex(&bytes),
                body: truncate_utf8(&redacted, 64_000),
            });
            let mut s = lock_session(session);
            if let Ok(vault) = s.vault() {
                let _ = vault.bump_use(id);
                let _ = vault.audit("mcp_http", Some(id), &format!("{method} {status}"));
            }
            s.touch();
            Ok(summary)
        }
        _ => Err(format!("未知工具 {name}")),
    }
}

/// Truncate on a UTF-8 character boundary. Slicing at a raw byte index
/// (`&s[..n]`) panics if `n` lands inside a multi-byte character — a remote
/// HTTP body of CJK text can hit that with `panic = "abort"`.
fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut end = max_bytes.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

fn read_response_limited(r: ureq::Response, max: usize) -> (u16, Vec<u8>) {
    let status = r.status();
    let mut reader = r.into_reader();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match reader.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                let remain = max.saturating_sub(buf.len());
                if remain == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n.min(remain)]);
            }
            Err(_) => break,
        }
    }
    (status, buf)
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
    mcp.clear_http_logs();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{SecretPayload, UpsertEntry, Vault};

    #[test]
    fn list_credentials_omits_secrets() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .upsert_entry(
                &dek,
                UpsertEntry {
                    id: None,
                    kind: EntryKind::ApiToken,
                    title: "github".into(),
                    account: Some("octocat".into()),
                    url: None,
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::ApiToken {
                        service: "github".into(),
                        account: Some("octocat".into()),
                        token: "ghp_should_never_appear_in_list".into(),
                    },
                },
            )
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let mutex = Mutex::new(session);
        let mcp = McpState::default();
        let req = JsonRpcReq {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({ "name": "list_credentials", "arguments": {} }),
        };
        let resp = handle_rpc(&mutex, &mcp, req).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("github"));
        assert!(!text.contains("ghp_should_never_appear_in_list"));
    }

    #[test]
    fn list_credentials_does_not_refresh_idle_timer() {
        let (session, _id) = unlocked_with_github();
        {
            let mut s = session.lock().unwrap();
            s.idle_secs = 2;
            s.age_last_active(Duration::from_secs(1));
        }
        let mcp = McpState::default();
        let req = JsonRpcReq {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({ "name": "list_credentials", "arguments": {} }),
        };
        let resp = handle_rpc(&session, &mcp, req).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("github"));
        let mut s = session.lock().unwrap();
        s.age_last_active(Duration::from_millis(1500));
        assert!(
            s.maybe_idle_lock(),
            "listing credentials must not keep the vault unlocked"
        );
        assert!(!s.is_unlocked());
    }

    #[test]
    fn copy_secret_refreshes_idle_timer() {
        let (session, id) = unlocked_with_github();
        {
            let mut s = session.lock().unwrap();
            s.idle_secs = 2;
            s.age_last_active(Duration::from_secs(1));
        }
        let mcp = McpState::default();
        let req = JsonRpcReq {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({
                "name": "copy_secret",
                "arguments": { "credential_id": id }
            }),
        };
        let resp = handle_rpc(&session, &mcp, req).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("剪贴板"));
        let mut s = session.lock().unwrap();
        s.age_last_active(Duration::from_millis(1500));
        assert!(!s.maybe_idle_lock());
        assert!(s.is_unlocked());
    }

    #[test]
    fn locked_vault_errors() {
        let mutex = Mutex::new(Session::default());
        let mcp = McpState::default();
        let req = JsonRpcReq {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({ "name": "list_credentials", "arguments": {} }),
        };
        let resp = handle_rpc(&mutex, &mcp, req).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("锁定"));
    }

    #[test]
    fn tools_fail_after_explicit_lock() {
        let (session, id) = unlocked_with_github();
        {
            let mut s = session.lock().unwrap();
            s.lock();
        }
        let mcp = McpState::default();
        let list = handle_rpc(
            &session,
            &mcp,
            JsonRpcReq {
                jsonrpc: "2.0".into(),
                id: Some(json!(1)),
                method: "tools/call".into(),
                params: json!({ "name": "list_credentials", "arguments": {} }),
            },
        )
        .unwrap();
        let list_text = list["result"]["content"][0]["text"].as_str().unwrap();
        assert!(list_text.contains("锁定"), "{list_text}");
        assert!(!list_text.contains("github"));
        let copy = handle_rpc(
            &session,
            &mcp,
            JsonRpcReq {
                jsonrpc: "2.0".into(),
                id: Some(json!(2)),
                method: "tools/call".into(),
                params: json!({
                    "name": "copy_secret",
                    "arguments": { "credential_id": id }
                }),
            },
        )
        .unwrap();
        let copy_text = copy["result"]["content"][0]["text"].as_str().unwrap();
        assert!(copy_text.contains("锁定"), "{copy_text}");
    }

    #[test]
    fn host_must_be_loopback_with_port() {
        assert!(host_allowed(
            &[("host".into(), "127.0.0.1:17891".into())],
            17891
        ));
        assert!(!host_allowed(
            &[("host".into(), "localhost:17891".into())],
            17891
        ));
        assert!(!host_allowed(
            &[("host".into(), "evil.example".into())],
            17891
        ));
        assert!(!host_allowed(
            &[("host".into(), "127.0.0.1:1".into())],
            17891
        ));
        assert!(!host_allowed(&[], 17891));
    }

    #[test]
    fn pairing_code_is_one_shot_and_windowed() {
        let mcp = McpState::default();
        assert!(mcp.consume_pairing("ABCD2345").is_err());
        let status = mcp.open_pairing();
        let code = status.code.unwrap();
        assert_eq!(code.len(), 8);
        assert!(mcp.consume_pairing("WRONGCOD").is_err());
        mcp.consume_pairing(&code.to_ascii_lowercase()).unwrap();
        assert!(mcp.consume_pairing(&code).is_err());
        let again = mcp.open_pairing();
        let code2 = again.code.unwrap();
        for _ in 0..PAIRING_MAX_FAILURES {
            let _ = mcp.consume_pairing("00000000");
        }
        assert!(mcp.consume_pairing(&code2).is_err());
    }

    fn unlocked_with_github() -> (Mutex<Session>, String) {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let dto = vault
            .upsert_entry(
                &dek,
                UpsertEntry {
                    id: None,
                    kind: EntryKind::ApiToken,
                    title: "github".into(),
                    account: Some("octocat".into()),
                    url: None,
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::ApiToken {
                        service: "github".into(),
                        account: Some("octocat".into()),
                        token: "ghp_abcdefghijklmnopqrstuvwxyz012345".into(),
                    },
                },
            )
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        (Mutex::new(session), dto.id)
    }

    fn call_http(session: &Mutex<Session>, mcp: &McpState, id: &str, url: &str) -> String {
        let req = JsonRpcReq {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({
                "name": "http_request",
                "arguments": { "credential_id": id, "url": url }
            }),
        };
        let resp = handle_rpc(session, mcp, req).unwrap();
        resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn http_request_rejects_unbound_origin() {
        let (session, id) = unlocked_with_github();
        let mcp = McpState::default();
        let text = call_http(&session, &mcp, &id, "https://evil.example/steal");
        assert!(text.contains("origin") || text.contains("拒绝"));
        assert!(mcp.http_logs().is_empty());
    }

    #[test]
    fn http_request_rejects_loopback_even_with_github_token() {
        let (session, id) = unlocked_with_github();
        let mcp = McpState::default();
        *recover_lock(&mcp.fill_token) = "fill_0123456789abcdef0123456789abcdef".into();
        let text = call_http(&session, &mcp, &id, "http://127.0.0.1:17891/fill/pair");
        assert!(text.contains("内网") || text.contains("拒绝") || text.contains("origin"));
        assert!(!text.contains("fill_"));
        assert!(mcp.http_logs().is_empty());
    }

    #[test]
    fn http_request_rejects_cloud_metadata() {
        let (session, id) = unlocked_with_github();
        let mcp = McpState::default();
        let text = call_http(
            &session,
            &mcp,
            &id,
            "http://169.254.169.254/latest/meta-data/",
        );
        assert!(text.contains("内网") || text.contains("拒绝"));
    }

    #[test]
    fn tool_catalog_matches_tools_list() {
        let catalog = tool_catalog();
        assert_eq!(catalog.len(), 3);
        assert_eq!(catalog[0].name, "list_credentials");
        assert!(catalog.iter().any(|t| t.name == "http_request"));
        assert!(catalog.iter().any(|t| t.name == "copy_secret"));
        for t in &catalog {
            assert!(!t.description.is_empty());
        }
    }

    #[test]
    fn http_request_tool_result_never_includes_response_body() {
        let summary =
            summarize_response(200, b"{\"token\":\"ghp_abcdefghijklmnopqrstuvwxyz012345\"}");
        assert!(summary.starts_with("HTTP 200\n"));
        assert!(summary.contains("sha256:"));
        assert!(!summary.contains("ghp_"));
        assert!(!summary.contains("token"));
        let tools = tools_list();
        let desc = tools["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "http_request")
            .unwrap()["description"]
            .as_str()
            .unwrap();
        assert!(desc.contains("永不把响应正文返回给模型"));
    }

    #[test]
    fn truncate_utf8_does_not_split_multibyte_chars() {
        // "测" is 3 bytes; a 8000-byte (or 4-byte) cut can land in the middle.
        let s = "测".repeat(3000);
        assert!(!s.is_char_boundary(8000));
        let cut = truncate_utf8(&s, 8000);
        assert!(cut.ends_with('…'));
        assert!(cut.is_char_boundary(cut.len() - "…".len()));
        assert!(std::panic::catch_unwind(|| {
            let _ = &s[..8000];
        })
        .is_err());
        let tiny = truncate_utf8("你好世界", 4);
        assert_eq!(tiny, "你…");
        assert_eq!(truncate_utf8("abc", 8), "abc");
    }

    #[test]
    fn truncate_utf8_production_cap_survives_cjk_body() {
        // Same length the HTTP log uses. "测" is 3 bytes, so 64_000 lands mid-char.
        let s = "测".repeat(25_000);
        assert!(s.len() > 64_000);
        assert!(!s.is_char_boundary(64_000));
        let cut = truncate_utf8(&s, 64_000);
        assert!(cut.ends_with('…'));
        assert!(cut.len() <= 64_000 + "…".len());
        assert!(cut.is_char_boundary(cut.len()));
        assert!(std::panic::catch_unwind(|| {
            let _ = &s[..64_000];
        })
        .is_err());
    }

    fn post_json(port: u16, path: &str, body: &Value, bearer: Option<&str>) -> (u16, Value) {
        let mut req = ureq::post(&format!("http://127.0.0.1:{port}{path}"))
            .set("Host", &format!("127.0.0.1:{port}"))
            .set("Content-Type", "application/json");
        if let Some(tok) = bearer {
            req = req.set("Authorization", &format!("Bearer {tok}"));
        }
        match req.send_string(&body.to_string()) {
            Ok(resp) => {
                let status = resp.status();
                let text = resp.into_string().unwrap_or_default();
                (status, serde_json::from_str(&text).unwrap_or(json!({})))
            }
            Err(ureq::Error::Status(code, resp)) => {
                let text = resp.into_string().unwrap_or_default();
                (code, serde_json::from_str(&text).unwrap_or(json!({})))
            }
            Err(e) => panic!("request {path} failed: {e}"),
        }
    }

    #[test]
    fn start_persists_encrypted_tokens_and_fill_http_requires_pairing() {
        let dir = std::env::temp_dir().join(format!("sealbox-mcp-http-{}", Uuid::new_v4()));
        let app_dir = dir.join("com.sealbox.app");
        std::fs::create_dir_all(&app_dir).unwrap();
        let stale = app_dir.join("fill.json");
        std::fs::write(&stale, r#"{"port":1,"fillToken":"leak"}"#).unwrap();
        let old_appdata = std::env::var_os("APPDATA");
        std::env::set_var("APPDATA", &dir);

        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .upsert_entry(
                &dek,
                UpsertEntry {
                    id: None,
                    kind: EntryKind::Website,
                    title: "GitHub".into(),
                    account: Some("octocat".into()),
                    url: Some("https://github.com".into()),
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::Website {
                        url: Some("https://github.com".into()),
                        username: Some("octocat".into()),
                        password: "gh-pass".into(),
                        totp_secret: None,
                    },
                },
            )
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let mutex = Arc::new(Mutex::new(session));
        let mcp = McpState::default();
        let port = start(&mcp, mutex.clone()).expect("mcp start");
        assert_ne!(port, 0);
        assert!(
            !stale.exists(),
            "start must delete leftover fill.json instead of rewriting it"
        );

        {
            let s = lock_session(&mutex);
            let vault = s.vault().unwrap();
            let dek = s.dek().unwrap();
            let fill = vault
                .get_secret_setting(dek, "fill_token")
                .unwrap()
                .unwrap();
            let mcp_tok = vault.get_secret_setting(dek, "mcp_token").unwrap().unwrap();
            assert!(fill.starts_with("fill_"));
            assert!(mcp_tok.starts_with("sbx_"));
            assert!(vault.get_setting("fill_token").unwrap().is_none());
            assert!(vault.get_setting("mcp_token").unwrap().is_none());
            let enc = vault.get_setting("fill_token_enc").unwrap().unwrap();
            assert!(!enc.contains(&fill));
        }

        let (status, body) = post_json(port, "/fill/status", &json!({}), None);
        assert_eq!(status, 401, "{body}");
        assert_eq!(body["error"], "invalid fill token");

        let pairing = mcp.open_pairing();
        let code = pairing.code.expect("pairing code");
        let (status, body) = post_json(port, "/fill/pair", &json!({ "code": code }), None);
        assert_eq!(status, 200, "{body}");
        let fill_token = body["fillToken"].as_str().unwrap().to_string();
        assert!(fill_token.starts_with("fill_"));
        assert_eq!(body["port"], port);

        let (status, body) = post_json(port, "/fill/status", &json!({}), Some(&fill_token));
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["unlocked"], true);

        let (status, body) = post_json(
            port,
            "/fill/match",
            &json!({ "url": "https://github.com/login" }),
            Some(&fill_token),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["matches"].as_array().unwrap().len(), 1);

        stop(&mcp);
        match old_appdata {
            Some(v) => std::env::set_var("APPDATA", v),
            None => std::env::remove_var("APPDATA"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_while_locked_does_not_mint_fill_token() {
        let mutex = Arc::new(Mutex::new(Session::default()));
        assert!(!lock_session(&mutex).is_unlocked());
        let mcp = McpState::default();
        let port = start(&mcp, mutex).expect("mcp start while locked");
        assert_ne!(port, 0);
        assert!(
            recover_lock(&mcp.fill_token).is_empty(),
            "locked boot must not mint a fill token that would invalidate pairing"
        );
        assert!(recover_lock(&mcp.token).is_empty());
        stop(&mcp);
    }
}
