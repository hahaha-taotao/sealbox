use crate::redact::{redact_text, secrets_from_payload};
use crate::session::Session;
use crate::vault::{EntryKind, ListFilter, SecretPayload, SortBy};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use uuid::Uuid;

const DEFAULT_PORT: u16 = 17891;

#[derive(Clone)]
pub struct McpState {
    pub running: Arc<AtomicBool>,
    pub port: Arc<Mutex<u16>>,
    pub token: Arc<Mutex<String>>,
}

impl Default for McpState {
    fn default() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            port: Arc::new(Mutex::new(DEFAULT_PORT)),
            token: Arc::new(Mutex::new(String::new())),
        }
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
                        "kind": { "type": "string", "enum": ["website", "api_token", "ssh"] }
                    }
                }
            },
            {
                "name": "http_request",
                "description": "用指定凭据在本机代发 HTTP 请求。Authorization 由金库填写，响应会脱敏，模型看不到明文 Token。",
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

fn rpc_error(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn rpc_ok(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn handle_rpc(session: &Mutex<Session>, req: JsonRpcReq) -> Option<Value> {
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
            let name = req.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = req.params.get("arguments").cloned().unwrap_or(json!({}));
            match call_tool(session, name, args) {
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

fn call_tool(session: &Mutex<Session>, name: &str, args: Value) -> Result<String, String> {
    let mut s = session.lock().map_err(|e| e.to_string())?;
    s.maybe_idle_lock();
    if !s.is_unlocked() {
        return Err("金库已锁定。请先在 Sealbox 窗口解锁，再让我重试。".into());
    }
    s.touch();
    match name {
        "list_credentials" => {
            let query = args
                .get("query")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let kind = args.get("kind").and_then(|v| v.as_str()).and_then(|k| match k {
                "website" => Some(EntryKind::Website),
                "api_token" => Some(EntryKind::ApiToken),
                "ssh" => Some(EntryKind::Ssh),
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
            };
            crate::clipboard::write_text(&text)?;
            s.remember_clipboard(&text);
            let vault = s.vault().map_err(|e| e.to_string())?;
            let _ = vault.bump_use(id);
            let _ = vault.audit("mcp_copy", Some(id), "clipboard");
            Ok("已复制到本机剪贴板，约 20 秒后清空。明文没有返回。".into())
        }
        "http_request" => {
            let id = args
                .get("credential_id")
                .and_then(|v| v.as_str())
                .ok_or("缺少 credential_id")?;
            let url = args.get("url").and_then(|v| v.as_str()).ok_or("缺少 url")?;
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                return Err("url 必须以 http:// 或 https:// 开头".into());
            }
            let method = args
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("GET")
                .to_uppercase();
            let body = args.get("body").and_then(|v| v.as_str()).map(|s| s.to_string());
            let dek = *s.dek().map_err(|e| e.to_string())?;
            let (payload, extra_secrets) = {
                let vault = s.vault().map_err(|e| e.to_string())?;
                let payload = vault.get_secret(&dek, id).map_err(|e| e.to_string())?;
                let mut extra = Vec::new();
                if let Ok(all) = vault.list_entries(&ListFilter::default()) {
                    for e in all.iter().take(40) {
                        if let Ok(p) = vault.get_secret(&dek, &e.id) {
                            extra.extend(secrets_from_payload(&p));
                        }
                    }
                }
                (payload, extra)
            };
            let mut known = secrets_from_payload(&payload);
            known.extend(extra_secrets);
            let auth = match &payload {
                SecretPayload::ApiToken { token, .. } => Some(format!("Bearer {token}")),
                SecretPayload::Website {
                    password,
                    username,
                    ..
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
                SecretPayload::Ssh { .. } => {
                    return Err("SSH 凭据不能用于 http_request，请选 API Token 或网站账号".into());
                }
            };
            drop(s);
            let mut req = ureq::request(&method, url);
            if let Some(a) = &auth {
                req = req.set("Authorization", a);
            }
            req = req.set("User-Agent", "Sealbox/0.1");
            let resp = if let Some(b) = body {
                req.send_string(&b)
            } else {
                req.call()
            };
            let (status, text) = match resp {
                Ok(r) => {
                    let st = r.status();
                    let t = r.into_string().unwrap_or_default();
                    (st, t)
                }
                Err(ureq::Error::Status(code, r)) => {
                    let t = r.into_string().unwrap_or_default();
                    (code, t)
                }
                Err(e) => return Err(format!("请求失败: {e}")),
            };
            let refs: Vec<&str> = known.iter().map(|s| s.as_str()).collect();
            let redacted = redact_text(&text, &refs);
            let mut s = session.lock().map_err(|e| e.to_string())?;
            if let Ok(vault) = s.vault() {
                let _ = vault.bump_use(id);
                let _ = vault.audit("mcp_http", Some(id), &format!("{method} {status}"));
            }
            let clipped = if redacted.len() > 8000 {
                format!("{}…", &redacted[..8000])
            } else {
                redacted
            };
            Ok(format!("HTTP {status}\n{clipped}"))
        }
        _ => Err(format!("未知工具 {name}")),
    }
}

struct HttpReq {
    method: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpReq, String> {
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).map_err(|e| e.to_string())?;
    let method = request_line
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
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
        headers,
        body,
    })
}

fn write_http(stream: &mut TcpStream, status: &str, body: &[u8]) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(body);
}

fn handle_client(mut stream: TcpStream, session: Arc<Mutex<Session>>, token: String) {
    let Ok(req) = read_http_request(&mut stream) else {
        return;
    };
    if req.method == "OPTIONS" {
        write_http(&mut stream, "204 No Content", b"");
        return;
    }
    if req.method != "POST" {
        write_http(&mut stream, "405 Method Not Allowed", b"{}");
        return;
    }
    let auth = req
        .headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
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
    match handle_rpc(&session, rpc) {
        Some(resp) => {
            let bytes = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{}".to_vec());
            write_http(&mut stream, "200 OK", &bytes);
        }
        None => write_http(&mut stream, "204 No Content", b""),
    }
}

pub fn start(mcp: &McpState, session: Arc<Mutex<Session>>) -> Result<u16, String> {
    if mcp.running.load(Ordering::SeqCst) {
        return Ok(*mcp.port.lock().unwrap());
    }
    {
        let mut token = mcp.token.lock().unwrap();
        if token.is_empty() {
            *token = new_token();
        }
    }
    let token_clone = mcp.token.lock().unwrap().clone();
    let listener = TcpListener::bind(("127.0.0.1", DEFAULT_PORT))
        .or_else(|_| TcpListener::bind("127.0.0.1:0"))
        .map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    *mcp.port.lock().unwrap() = port;
    mcp.running.store(true, Ordering::SeqCst);
    let running = mcp.running.clone();
    thread::spawn(move || {
        listener.set_nonblocking(true).ok();
        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, addr)) => {
                    if !addr.ip().is_loopback() {
                        continue;
                    }
                    let session = session.clone();
                    let token = token_clone.clone();
                    thread::spawn(move || handle_client(stream, session, token));
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

pub fn stop(mcp: &McpState) {
    mcp.running.store(false, Ordering::SeqCst);
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
        let req = JsonRpcReq {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({ "name": "list_credentials", "arguments": {} }),
        };
        let resp = handle_rpc(&mutex, req).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("github"));
        assert!(!text.contains("ghp_should_never_appear_in_list"));
    }

    #[test]
    fn locked_vault_errors() {
        let mutex = Mutex::new(Session::default());
        let req = JsonRpcReq {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: json!({ "name": "list_credentials", "arguments": {} }),
        };
        let resp = handle_rpc(&mutex, req).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("锁定"));
    }
}
