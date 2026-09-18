use crate::fill;
use crate::github_mcp;
use crate::lock::{idle_lock_if_needed, lock_session, recover_lock};
use crate::session::Session;
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

#[derive(Clone)]
pub struct McpState {
    pub running: Arc<AtomicBool>,
    pub port: Arc<Mutex<u16>>,
    pub token: Arc<Mutex<String>>,
    pub fill_token: Arc<Mutex<String>>,
    pairing: Arc<Mutex<Option<PairingWindow>>>,
}

impl Default for McpState {
    fn default() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            port: Arc::new(Mutex::new(DEFAULT_PORT)),
            token: Arc::new(Mutex::new(String::new())),
            fill_token: Arc::new(Mutex::new(String::new())),
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
    let (github_enabled, zoomkey_tools) = locked
        .vault()
        .ok()
        .and_then(|vault| {
            locked.dek().ok().map(|dek| {
                let github = github_mcp::load_policy(vault, dek).enabled;
                let zoomkey = crate::zoomkey::load_policy(vault, dek);
                (
                    github,
                    crate::zoomkey::tool_definitions_for_vault(vault, dek, &zoomkey),
                )
            })
        })
        .unwrap_or((false, Vec::new()));
    let mut tools: Vec<Value> = Vec::new();
    if github_enabled {
        tools.extend(github_mcp::tool_definitions());
    }
    tools.extend(zoomkey_tools);
    json!({ "tools": tools })
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
        "tools/list" => rpc_ok(req.id, tools_list(session)),
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
    if github_mcp::is_github_tool(name) {
        let result = github_mcp::call_tool_detailed(&mut s, name, args);
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
    if crate::zoomkey::is_zoomkey_tool(name) {
        let result = crate::zoomkey::call_tool_detailed(&mut s, name, args);
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
    }

    #[test]
    fn enabled_github_tools_are_exposed_as_a_single_capability() {
        let (vault, dek) =
            crate::vault::Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .set_secret_setting(&dek, "github_mcp_policy", r#"{"enabled":true}"#)
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let listed = tools_list(&Mutex::new(session));
        let names = listed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .filter(|name| name.starts_with("github_"))
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 16);
        assert!(names.contains(&"github_list_credentials"));
        assert!(names.contains(&"github_get_file"));
        assert!(names.contains(&"github_git_status"));
        assert!(names.contains(&"github_git_clone"));
        assert!(!names.contains(&"github_git_list"));
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
        assert!(!host_allowed(&[], 17891));
    }

    #[test]
    fn pairing_code_is_one_shot_and_windowed() {
        let mcp = McpState::default();
        let status = mcp.open_pairing();
        let code = status.code.unwrap();
        mcp.consume_pairing(&code).unwrap();
        assert!(mcp.consume_pairing(&code).is_err());
    }

    #[test]
    fn enabled_github_tools_are_exposed_as_single_toggle() {
        let (vault, dek) =
            crate::vault::Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .set_secret_setting(&dek, "github_mcp_policy", r#"{"enabled":true}"#)
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let listed = tools_list(&Mutex::new(session));
        let github_names = listed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .filter(|name| name.starts_with("github_"))
            .collect::<Vec<_>>();
        assert_eq!(github_names.len(), 16);
        assert!(github_names.contains(&"github_list_credentials"));
        assert!(github_names.contains(&"github_git_push"));
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
