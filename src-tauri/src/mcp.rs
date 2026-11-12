use crate::fill;
use crate::github_mcp;
use crate::lock::{lock_session, recover_lock};
use crate::session::Session;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const DEFAULT_PORT: u16 = 17891;
pub const LISTEN_MODE_LOOPBACK: &str = "loopback";
pub const LISTEN_MODE_LAN: &str = "lan";
pub const LISTEN_MODE_ADDRESS: &str = "address";
pub const LISTEN_CONFIG_KEY: &str = "mcp_listen_config";
const PAIRING_SECS: u64 = 60;
const PAIRING_MAX_FAILURES: u32 = 5;
/// Absolute lifetime of one MCP session ticket. Clients re-`initialize`
/// transparently, so this bounds how long a leaked session id stays useful.
const SESSION_ABS_TTL_SECS: u64 = 24 * 60 * 60;
/// Idle lifetime. A ticket that stops being used expires even before the
/// absolute deadline, so a stolen id cannot be parked and replayed later.
const SESSION_IDLE_TTL_SECS: u64 = 2 * 60 * 60;
const MAX_HTTP_LINE: usize = 8192;
const MAX_HTTP_HEADERS: usize = 64 * 1024;
const MAX_HTTP_BODY: usize = 1_000_000;
const MAX_ACTIVE_CONNECTIONS: usize = 128;
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

/// Tailscale IPv4 addresses come from the shared CGNAT range 100.64.0.0/10.
/// Keep this separate from RFC1918 so peer checks cannot mix the two network
/// classes accidentally.
pub fn is_tailscale_ipv4(address: Ipv4Addr) -> bool {
    matches!(address.octets(), [100, 64..=127, _, _])
}

fn is_listenable_ipv4(address: Ipv4Addr) -> bool {
    is_private_ipv4(address) || is_tailscale_ipv4(address)
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
            if !is_listenable_ipv4(parsed) {
                return Err("监听地址必须是本机私有或 Tailscale IPv4 地址".into());
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct ListenPolicy {
    mode: String,
    address: String,
}

impl ListenPolicy {
    fn loopback() -> Self {
        Self {
            mode: LISTEN_MODE_LOOPBACK.into(),
            address: String::new(),
        }
    }

    fn lan_ip(&self) -> Result<Ipv4Addr, String> {
        match self.mode.as_str() {
            LISTEN_MODE_LAN => local_private_ipv4()
                .ok_or_else(|| "未找到可用的 RFC1918 局域网 IPv4 地址".to_string()),
            LISTEN_MODE_ADDRESS => self
                .address
                .parse::<Ipv4Addr>()
                .map_err(|_| "指定监听地址无效".to_string()),
            _ => Err("当前监听模式不需要局域网地址".into()),
        }
    }
}

#[derive(Clone)]
pub struct McpState {
    pub running: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
    active_connections: Arc<AtomicUsize>,
    pub port: Arc<Mutex<u16>>,
    pub token: Arc<Mutex<String>>,
    pub fill_token: Arc<Mutex<String>>,
    /// True while the vault is not yet unlocked; listeners remain loopback-only then.
    pub locked: Arc<AtomicBool>,
    listen_mode: Arc<Mutex<String>>,
    listen_address: Arc<Mutex<String>>,
    active_mode: Arc<Mutex<String>>,
    active_address: Arc<Mutex<String>>,
    listener_threads: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// Why the configured LAN listener could not bind and MCP fell back to
    /// loopback-only. `None` means the listener bound as configured. Shown in
    /// the UI instead of failing silently.
    last_error: Arc<Mutex<Option<String>>>,
    pairing: Arc<Mutex<Option<PairingWindow>>>,
    callers: Arc<Mutex<HashMap<String, Arc<Caller>>>>,
}

impl Default for McpState {
    fn default() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            generation: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            port: Arc::new(Mutex::new(DEFAULT_PORT)),
            token: Arc::new(Mutex::new(String::new())),
            fill_token: Arc::new(Mutex::new(String::new())),
            locked: Arc::new(AtomicBool::new(true)),
            listen_mode: Arc::new(Mutex::new(LISTEN_MODE_LOOPBACK.into())),
            listen_address: Arc::new(Mutex::new(String::new())),
            active_mode: Arc::new(Mutex::new(LISTEN_MODE_LOOPBACK.into())),
            active_address: Arc::new(Mutex::new(String::new())),
            listener_threads: Arc::new(Mutex::new(Vec::new())),
            last_error: Arc::new(Mutex::new(None)),
            pairing: Arc::new(Mutex::new(None)),
            callers: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

fn private_ipv4(ip: Ipv4Addr) -> bool {
    is_private_ipv4(ip)
}

pub fn normalize_listen_config(mode: &str, address: &str) -> Result<(String, String), String> {
    match mode.trim().to_ascii_lowercase().as_str() {
        LISTEN_MODE_LOOPBACK => Ok((LISTEN_MODE_LOOPBACK.into(), String::new())),
        LISTEN_MODE_LAN => Ok((LISTEN_MODE_LAN.into(), String::new())),
        LISTEN_MODE_ADDRESS => {
            let address = address.trim();
            let ip = address
                .parse::<Ipv4Addr>()
                .map_err(|_| "指定地址必须是 IPv4 地址".to_string())?;
            if !is_listenable_ipv4(ip) {
                return Err("指定地址必须是本机私有或 Tailscale IPv4 地址".into());
            }
            Ok((LISTEN_MODE_ADDRESS.into(), ip.to_string()))
        }
        _ => Err("监听模式必须是 loopback、lan 或 address".into()),
    }
}

fn local_private_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if private_ipv4(ip) => Some(ip),
        _ => None,
    }
}

fn persisted_listen_config(vault: &crate::vault::Vault) -> (String, String) {
    if let Ok(Some(raw)) = vault.get_setting(LISTEN_CONFIG_KEY) {
        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            let mode = value.get("mode").and_then(Value::as_str).unwrap_or("");
            let address = value.get("address").and_then(Value::as_str).unwrap_or("");
            if let Ok(config) = normalize_listen_config(mode, address) {
                return config;
            }
        }
    }
    let mode = vault
        .get_setting(LISTEN_MODE_KEY)
        .ok()
        .flatten()
        .unwrap_or_else(|| LISTEN_MODE_LOOPBACK.into());
    let address = vault
        .get_setting(LISTEN_ADDRESS_KEY)
        .ok()
        .flatten()
        .unwrap_or_default();
    normalize_listen_config(&mode, &address)
        .unwrap_or_else(|_| (LISTEN_MODE_LOOPBACK.into(), String::new()))
}

/// Load the persisted non-secret listener preference before the vault unlocks.
/// Invalid values fail closed to loopback and are never used for binding.
pub fn load_persisted_config(mcp: &McpState, path: &Path) {
    if let Ok(vault) = crate::vault::Vault::open(path.to_str().unwrap_or_default()) {
        let (mode, address) = persisted_listen_config(&vault);
        let _ = mcp.set_listen_config(&mode, &address);
    }
}

impl McpState {
    pub fn listen_config(&self) -> (String, String) {
        (
            recover_lock(&self.listen_mode).clone(),
            recover_lock(&self.listen_address).clone(),
        )
    }

    pub fn set_listen_config(&self, mode: &str, address: &str) -> Result<(), String> {
        let (mode, address) = normalize_listen_config(mode, address)?;
        *recover_lock(&self.listen_mode) = mode;
        *recover_lock(&self.listen_address) = address;
        Ok(())
    }

    fn configured_policy(&self) -> ListenPolicy {
        let (mode, address) = self.listen_config();
        ListenPolicy { mode, address }
    }

    pub fn set_last_error(&self, error: Option<String>) {
        *recover_lock(&self.last_error) = error;
    }

    pub fn last_error(&self) -> Option<String> {
        recover_lock(&self.last_error).clone()
    }

    fn set_active_policy(&self, policy: &ListenPolicy) {
        *recover_lock(&self.active_mode) = policy.mode.clone();
        *recover_lock(&self.active_address) = policy.address.clone();
    }

    pub fn active_config(&self) -> (String, String) {
        (
            recover_lock(&self.active_mode).clone(),
            recover_lock(&self.active_address).clone(),
        )
    }

    pub fn active_host(&self) -> String {
        let (mode, address) = self.active_config();
        match mode.as_str() {
            LISTEN_MODE_ADDRESS | LISTEN_MODE_LAN if !address.is_empty() => address,
            _ => "127.0.0.1".into(),
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

fn parse_host_port(raw: &str) -> Option<(String, u16)> {
    let raw = raw.trim().to_ascii_lowercase();
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_string(), port.parse().ok()?));
    }
    let (host, port) = raw.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

fn host_allowed_with_policy(
    headers: &[(String, String)],
    port: u16,
    policy: &ListenPolicy,
    peer_ip: IpAddr,
) -> bool {
    let mut hosts = headers.iter().filter(|(k, _)| k == "host");
    let Some((_, raw)) = hosts.next() else {
        return false;
    };
    if hosts.next().is_some() {
        return false;
    }
    let Some((host, host_port)) = parse_host_port(raw) else {
        return false;
    };
    if host_port != port {
        return false;
    }
    match policy.mode.as_str() {
        LISTEN_MODE_LOOPBACK => {
            host == "127.0.0.1" || host == "localhost" || host == "::1"
        }
        LISTEN_MODE_LAN | LISTEN_MODE_ADDRESS => {
            if peer_ip.is_loopback() {
                host == "127.0.0.1" || host == "localhost" || host == "::1"
            } else {
                host == policy.address
            }
        }
        _ => false,
    }
}

fn host_allowed(headers: &[(String, String)], port: u16) -> bool {
    host_allowed_with_policy(
        headers,
        port,
        &ListenPolicy::loopback(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    )
}

fn peer_allowed(ip: IpAddr, policy: &ListenPolicy) -> bool {
    match policy.mode.as_str() {
        LISTEN_MODE_LOOPBACK => ip.is_loopback(),
        LISTEN_MODE_LAN | LISTEN_MODE_ADDRESS => {
            if ip.is_loopback() {
                return true;
            }
            let local = policy.address.parse::<Ipv4Addr>().ok();
            match (local, ip) {
                (Some(local), IpAddr::V4(peer)) if is_tailscale_ipv4(local) => {
                    is_tailscale_ipv4(peer)
                }
                (_, IpAddr::V4(peer)) => is_private_ipv4(peer),
                _ => false,
            }
        }
        _ => false,
    }
}

fn destination_allowed(ip: IpAddr, policy: &ListenPolicy) -> bool {
    if ip.is_loopback() {
        return true;
    }
    match policy.mode.as_str() {
        LISTEN_MODE_LAN => matches!(ip, IpAddr::V4(ip) if private_ipv4(ip)),
        LISTEN_MODE_ADDRESS => policy
            .address
            .parse::<Ipv4Addr>()
            .map(|wanted| ip == IpAddr::V4(wanted))
            .unwrap_or(false),
        _ => false,
    }
}

#[derive(Serialize)]
pub struct PairingStatus {
    pub active: bool,
    pub code: Option<String>,
    pub expires_in_secs: u64,
    pub port: u16,
}

/// One MCP session ticket. Carries its own lifetime and capability scope so a
/// request is authorized per session instead of by a single global switch.
struct Caller {
    active: AtomicBool,
    /// Absolute deadline; a client must `initialize` again after this.
    expires_at: Instant,
    /// Deadline extended on every accepted call; stops parked tickets.
    idle_deadline: Mutex<Instant>,
    /// Tool names this session may call.
    tools: std::collections::HashSet<&'static str>,
}

impl Caller {
    fn alive(&self) -> bool {
        self.active.load(Ordering::SeqCst)
            && Instant::now() < self.expires_at
            && Instant::now() < *recover_lock(&self.idle_deadline)
    }

    fn touch(&self) {
        *recover_lock(&self.idle_deadline) = Instant::now() + Duration::from_secs(SESSION_IDLE_TTL_SECS);
    }

    fn allows_tool(&self, tool: &str) -> bool {
        self.tools.contains(tool)
    }
}

impl McpState {
    fn open_caller(&self) -> Result<String, String> {
        let mut callers = recover_lock(&self.callers);
        callers.retain(|_, caller| caller.alive());
        if callers.len() >= 128 {
            return Err("MCP 会话过多，请在 Sealbox 重启 MCP".into());
        }
        let id = Uuid::new_v4().to_string();
        callers.insert(id.clone(), Arc::new(Caller {
            active: AtomicBool::new(true),
            expires_at: Instant::now() + Duration::from_secs(SESSION_ABS_TTL_SECS),
            idle_deadline: Mutex::new(Instant::now() + Duration::from_secs(SESSION_IDLE_TTL_SECS)),
            // Every session starts with the full stable six-tool surface and
            // narrows through per-call scope checks; `vault_revoke` can only
            // ever end the caller's own ticket.
            tools: crate::credential_mcp::TOOL_NAMES.iter().copied().collect(),
        }));
        Ok(id)
    }

    fn caller_permit(&self, id: &str) -> Result<Arc<Caller>, String> {
        let caller = recover_lock(&self.callers).get(id).cloned()
            .filter(|caller| caller.alive())
            .ok_or_else(|| String::from("MCP 调用会话无效或已过期，请重新 initialize"))?;
        caller.touch();
        Ok(caller)
    }

    fn revoke_caller(&self, id: &str) -> Result<(), String> {
        self.caller_permit(id)?.active.store(false, Ordering::SeqCst);
        Ok(())
    }

    pub fn invalidate_callers(&self) {
        let mut callers = recover_lock(&self.callers);
        for caller in callers.values() { caller.active.store(false, Ordering::SeqCst); }
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

const MAIL_ACTIONS: &[&str] = &["accounts", "folders", "list", "search", "read", "save"];

fn mail_tool_definitions() -> Vec<Value> {
    vec![json!({
        "name": "mail",
        "description": "邮箱（只读）。action：accounts 列出账号（不含授权码）；folders 列出账号的文件夹与角色；list 只读一个文件夹，最多 50 封，可带 folder、beforeUid、filter、keyword；search 只在已同步的本地缓存里按主题/发件人搜，不联网；read 读取纯文本和附件清单；save 把一个附件保存到已有目录中的新文件，不覆盖。entryId 用于除 accounts 外的动作，folder 省略时为收件箱，uid 用于 read/save，part 与 path 仅 save。不能发信、删信、标记或移动邮件。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": MAIL_ACTIONS, "description": "accounts、folders、list、search、read、save"},
                "entryId": {"type": "string", "minLength": 1, "maxLength": 128, "description": "除 accounts 外的动作"},
                "folder": {"type": "string", "minLength": 1, "maxLength": 512, "description": "list、read、save；省略时为 INBOX"},
                "beforeUid": {"type": "integer", "minimum": 1, "maximum": 4294967295u64, "description": "仅 list"},
                "filter": {"type": "string", "enum": ["all", "unread", "attached", "flagged"], "description": "仅 list"},
                "keyword": {"type": "string", "maxLength": 200, "description": "list 按主题/发件人在服务器搜索；search 搜本地缓存"},
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

fn call_mail_tool(session: &Mutex<Session>, name: &str, args: Value, permit: &Caller, generation: u64) -> Result<String, String> {
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
                .list_entries(&crate::vault::ListFilter::default())
                .map_err(|error| error.to_string())?;
            let mut accounts = Vec::new();
            for entry in entries {
                if entry.kind != crate::vault::EntryKind::MailAuth
                    && entry.kind != crate::vault::EntryKind::Mailbox
                {
                    continue;
                }
                let payload = vault.get_active_secret(&dek, &entry.id).map_err(|error| error.to_string())?;
                let supported = crate::commands::mail_endpoint_for_payload(&payload).is_some();
                let (email, provider) = match &payload {
                    crate::vault::SecretPayload::MailAuth { email, provider, .. } => {
                        (email.clone(), provider.clone())
                    }
                    crate::vault::SecretPayload::Mailbox { email, .. } => {
                        (email.clone(), "custom".to_string())
                    }
                    _ => continue,
                };
                accounts.push(sealbox_core::mail::MailAccount {
                    id: entry.id,
                    title: entry.title,
                    email,
                    provider: provider.clone(),
                    provider_label: sealbox_core::mail_provider::provider_label(&provider).to_string(),
                    supported,
                });
            }
            serde_json::to_string(&accounts).map_err(|_| "参数无效".into())
        }
        "folders" => {
            ensure_mail_keys(&args, &["entryId"])?;
            let entry_id = mail_arg_str(&args, "entryId", true)?.unwrap_or("");
            let (email, auth_code, host, port) = {
                let session = lock_session(session);
                load_mail_resolved(&session, entry_id)?
            };
            let mut io = sealbox_core::mail::connect_tls(&host, port, std::time::Duration::from_secs(20))
                .map_err(sealbox_core::mail::failure_message)?;
            let folders = sealbox_core::mail::list_folders(&mut io, &email, &auth_code)
                .map_err(sealbox_core::mail::failure_message)?;
            drop(auth_code);
            serde_json::to_string(&folders).map_err(|_| "参数无效".into())
        }
        "search" => {
            // Reads the local cache only: an AI caller cannot turn a search into a mailbox
            // download or use it to probe folders that were never synced.
            ensure_mail_keys(&args, &["entryId", "keyword"])?;
            let entry_id = mail_arg_str(&args, "entryId", true)?.unwrap_or("");
            let keyword = mail_arg_str(&args, "keyword", true)?.unwrap_or("");
            let session = lock_session(session);
            session
                .vault()
                .map_err(|error| error.to_string())?
                .get_active_secret(&*session.dek().map_err(|error| error.to_string())?, entry_id)
                .map_err(|_| "不是邮箱账号".to_string())?;
            let hits = session
                .vault()
                .map_err(|error| error.to_string())?
                .mail_search_cached(entry_id, keyword, 50)
                .map_err(|error| error.to_string())?;
            let payload: Vec<Value> = hits
                .into_iter()
                .map(|(folder, message)| {
                    json!({
                        "folder": folder,
                        "uid": message.uid,
                        "from": message.from,
                        "subject": message.subject,
                        "date": message.date,
                        "seen": message.seen,
                    })
                })
                .collect();
            serde_json::to_string(&payload).map_err(|_| "参数无效".into())
        }
        "list" => {
            ensure_mail_keys(&args, &["entryId", "beforeUid", "folder", "filter", "keyword"])?;
            let entry_id = mail_arg_str(&args, "entryId", true)?.unwrap_or("");
            let before = mail_arg_u32(&args, "beforeUid", false)?;
            let folder = mail_arg_str(&args, "folder", false)?.unwrap_or("INBOX").to_string();
            let keyword = mail_arg_str(&args, "keyword", false)?.unwrap_or("").to_string();
            let filter = sealbox_core::mail_folder::MailFilter::parse(
                mail_arg_str(&args, "filter", false)?.unwrap_or(""),
            )
            .ok_or("参数无效")?;
            let (email, auth_code, host, port) = {
                let session = lock_session(session);
                load_mail_resolved(&session, entry_id)?
            };
            let mut io = sealbox_core::mail::connect_tls(&host, port, std::time::Duration::from_secs(20))
                .map_err(sealbox_core::mail::failure_message)?;
            let messages = sealbox_core::mail::list_folder(
                &mut io,
                &email,
                &auth_code,
                &folder,
                before,
                50,
                filter,
                &keyword,
            )
            .map_err(sealbox_core::mail::failure_message)?;
            drop(auth_code);
            serde_json::to_string(&messages).map_err(|_| "参数无效".into())
        }
        "read" => {
            ensure_mail_keys(&args, &["entryId", "uid", "folder"])?;
            let entry_id = mail_arg_str(&args, "entryId", true)?.unwrap_or("");
            let uid = mail_arg_u32(&args, "uid", true)?.ok_or("参数无效")?;
            let folder = mail_arg_str(&args, "folder", false)?.unwrap_or("INBOX").to_string();
            let (email, auth_code, host, port) = {
                let session = lock_session(session);
                load_mail_resolved(&session, entry_id)?
            };
            let mut text_io = sealbox_core::mail::connect_tls(&host, port, std::time::Duration::from_secs(20))
                .map_err(sealbox_core::mail::failure_message)?;
            let body = sealbox_core::mail::fetch_body_in(&mut text_io, &email, &auth_code, &folder, uid)
                .map_err(sealbox_core::mail::failure_message)?;
            let mut list_io = sealbox_core::mail::connect_tls(&host, port, std::time::Duration::from_secs(20))
                .map_err(sealbox_core::mail::failure_message)?;
            let attachments = sealbox_core::mail::list_attachments_in(&mut list_io, &email, &auth_code, &folder, uid)
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
            ensure_mail_keys(&args, &["entryId", "uid", "part", "path", "folder"])?;
            let entry_id = mail_arg_str(&args, "entryId", true)?.unwrap_or("");
            let uid = mail_arg_u32(&args, "uid", true)?.ok_or("参数无效")?;
            let part = mail_arg_str(&args, "part", true)?.unwrap_or("").to_string();
            let path = mail_arg_str(&args, "path", true)?.unwrap_or("").to_string();
            let folder = mail_arg_str(&args, "folder", false)?.unwrap_or("INBOX").to_string();
            let (email, auth_code, host, port) = {
                let session = lock_session(session);
                load_mail_resolved(&session, entry_id)?
            };
            let mut io = sealbox_core::mail::connect_tls(&host, port, std::time::Duration::from_secs(20))
                .map_err(sealbox_core::mail::failure_message)?;
            let bytes = sealbox_core::mail::fetch_attachment_in(&mut io, &email, &auth_code, &folder, uid, &part)
                .map_err(sealbox_core::mail::failure_message)?;
            drop(auth_code);
            guard()?;
            let saved = sealbox_core::mail::write_exclusive(&path, &bytes).map_err(str::to_string)?;
            // Echo only the file name: the absolute path is host layout the
            // model has no need to learn.
            let name = std::path::Path::new(&path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            serde_json::to_string(&json!({"bytes": saved, "name": name})).map_err(|_| "参数无效".into())
        }
        _ => Err(format!(
            "mail 不支持 action={action}。可用 {}",
            MAIL_ACTIONS.join("、")
        )),
    }
}

/// Resolves an entry to `(email, credential, imap_host, imap_port)`. The host comes from the
/// vault entry — a built-in preset for `mail_auth`, the stored host for `mailbox` — never from
/// the tool arguments.
fn load_mail_resolved(
    session: &crate::session::Session,
    entry_id: &str,
) -> Result<(String, zeroize::Zeroizing<String>, String, u16), String> {
    let dek = *session.dek().map_err(|error| error.to_string())?;
    let payload = session
        .vault()
        .map_err(|error| error.to_string())?
        .get_active_secret(&dek, entry_id)
        .map_err(|error| error.to_string())?;
    let (email, endpoint) = match &payload {
        crate::vault::SecretPayload::MailAuth { email, provider, .. } => (
            email.clone(),
            sealbox_core::mail_provider::server_for_provider(provider),
        ),
        crate::vault::SecretPayload::Mailbox { email, imap_host, imap_port, .. } => (
            email.clone(),
            sealbox_core::mail_provider::server_for_mailbox(email, imap_host.as_deref(), *imap_port),
        ),
        _ => return Err("不是邮箱账号".into()),
    };
    let secret = match payload {
        crate::vault::SecretPayload::MailAuth { auth_code, .. } => auth_code,
        crate::vault::SecretPayload::Mailbox { password, .. } => password,
        _ => return Err("不是邮箱账号".into()),
    };
    let Some((host, port)) = endpoint else {
        return Err(sealbox_core::mail::failure_message(sealbox_core::mail::MailFailure::Unsupported).into());
    };
    Ok((email, zeroize::Zeroizing::new(secret), host, port))
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

fn call_git_tool(session: &Mutex<Session>, name: &str, args: Value, permit: &Caller, generation: u64) -> Result<String, String> {
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

fn require_call_authorized(s: &Session, permit: &Caller, generation: u64) -> Result<(), String> {
    if !permit.alive() { return Err("当前调用方的授权已撤销或过期".into()); }
    if s.generation() != generation {
        return Err("解锁会话已改变，请重新调用".into());
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

fn call_http_tool(session: &Mutex<Session>, permit: &Caller, args: Value) -> Result<String, String> {
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
    let s=lock_session(session);
    if let Ok(vault)=s.vault() {
        let status=result.as_ref().ok().map(|(status,_)|status.to_string()).unwrap_or_else(||"-".into());
        let reason=match &result {Ok(_)=>"ok",Err(e) if e.contains("拒绝")=>"denied",Err(e) if e.contains("撤销")=>"revoked",Err(_)=>"validation_or_request"};
        let detail=format!("operation=http_call op={} decision={} reason={} origin={} credential={} status={}",
            audit_token(&op_name),if result.is_ok(){"allow"}else{"deny"},reason,audit_token(&origin),&crate::http_guard::sha256_hex(id.as_bytes())[..12],status);
        let _=vault.audit(if result.is_ok(){"mcp_http"}else{"mcp_http_denied"},None,&detail);
    }
    result.map(|(_,text)|text)
}

fn call_http_tool_inner(session: &Mutex<Session>, permit: &Caller, args: Value) -> Result<(u16, String), String> {
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
    // The session ticket is the authorization unit: a valid ticket that does
    // not cover this tool is a denial, not an unknown error. Audited so a
    // narrowed ticket cannot be probed silently.
    if !permit.allows_tool(name) {
        let s=lock_session(session);
        if let Ok(vault)=s.vault() {
            let _=vault.audit("mcp_scope",None,&format!("tool={name} decision=deny reason=not_granted"));
        }
        return Err(format!("当前会话未获授权调用 {name}，请重新 initialize"));
    }
    if name == "vault_revoke" {
        crate::credential_mcp::validate_tool(name,&args)?;
        mcp.revoke_caller(caller)?;
        let s=lock_session(session);
        if let Ok(vault)=s.vault() {let _=vault.audit("mcp_revoke",None,"scope=current_caller decision=allow");}
        return Ok(json!({"revoked":true,"scope":"current_caller","reauthorization_required":true}).to_string());
    }
    let generation = {
        let s = lock_session(session);
        crate::credential_mcp::require_enabled(&s)?;
        s.generation()
    };
    match name {
        "vault_list" | "vault_describe" => {
            let s=lock_session(session);
            let result=if name=="vault_list" {crate::credential_mcp::list(&s,&args)} else {crate::credential_mcp::describe(&s,&args)};
            if let Ok(vault)=s.vault() {let _=vault.audit("mcp_vault",None,&format!("operation={name} decision={}",if result.is_ok(){"allow"}else{"deny"}));}
            result
        },
        "http_call" => call_http_tool(session,&permit,args),
        "git" => call_git_tool(session,name,args,&permit,generation),
        "mail" => {
            let definition=mail_tool_definitions().remove(0);
            let action=args.get("action").and_then(Value::as_str).unwrap_or("");
            if !MAIL_ACTIONS.contains(&action) {return Err(format!("mail 需要合法 action：{}",MAIL_ACTIONS.join("、")));}
            github_mcp::validate_tool_arguments(&definition["inputSchema"],&args)?;
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

fn read_limited_line<R: BufRead>(reader: &mut R, max: usize) -> Result<String, String> {
    let mut bytes = Vec::new();
    loop {
        let buf = reader.fill_buf().map_err(|e| e.to_string())?;
        if buf.is_empty() {
            break;
        }
        let take = buf
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1)
            .unwrap_or(buf.len());
        if bytes.len().saturating_add(take) > max {
            return Err("HTTP 行过长".into());
        }
        let chunk = buf[..take].to_vec();
        reader.consume(take);
        bytes.extend_from_slice(&chunk);
        if chunk.last() == Some(&b'\n') {
            break;
        }
    }
    String::from_utf8(bytes).map_err(|_| "HTTP 行不是 UTF-8".into())
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpReq, String> {
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let mut reader = BufReader::new(stream);
    let request_line = read_limited_line(&mut reader, MAX_HTTP_LINE)?;
    if request_line.len() > MAX_HTTP_LINE || !request_line.ends_with('\n') {
        return Err("HTTP 请求行过长或不完整".into());
    }
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
    let mut header_bytes = request_line.len();
    let mut content_length = 0usize;
    loop {
        let line = read_limited_line(&mut reader, MAX_HTTP_LINE)?;
        header_bytes = header_bytes.saturating_add(line.len());
        if header_bytes > MAX_HTTP_HEADERS {
            return Err("HTTP 请求头过大".into());
        }
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err("HTTP 请求头无效".into());
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().to_string();
        if key == "content-length" {
            content_length = val.parse().map_err(|_| "Content-Length 无效".to_string())?;
        }
        headers.push((key, val));
    }
    if content_length > MAX_HTTP_BODY {
        return Err("HTTP 请求体过大".into());
    }
    let mut body = vec![0u8; content_length];
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

fn handle_client(
    mut stream: TcpStream,
    session: Arc<Mutex<Session>>,
    mcp: McpState,
    policy: ListenPolicy,
    peer_ip: IpAddr,
    local_ip: IpAddr,
    generation: u64,
) {
    if !mcp.running.load(Ordering::SeqCst) || mcp.generation.load(Ordering::SeqCst) != generation {
        return;
    }
    if mcp.locked.load(Ordering::SeqCst) {
        write_http(&mut stream, "403 Forbidden", br#"{"ok":false,"error":"vault locked"}"#);
        return;
    }
    let Ok(req) = read_http_request(&mut stream) else {
        return;
    };
    let port = *recover_lock(&mcp.port);
    if !mcp.running.load(Ordering::SeqCst) || mcp.generation.load(Ordering::SeqCst) != generation {
        return;
    }
    if !peer_allowed(peer_ip, &policy) || !destination_allowed(local_ip, &policy) {
        write_http(&mut stream, "403 Forbidden", br#"{"ok":false,"error":"address not allowed"}"#);
        return;
    }
    if !host_allowed_with_policy(&req.headers, port, &policy, peer_ip) {
        write_http(
            &mut stream,
            "403 Forbidden",
            br#"{"ok":false,"error":"invalid host"}"#,
        );
        return;
    }
    if policy.mode != LISTEN_MODE_LOOPBACK && req.path != "/mcp" {
        write_http(&mut stream, "404 Not Found", br#"{"error":"LAN MCP only serves /mcp"}"#);
        return;
    }
    if req.path != "/mcp" && !req.path.starts_with("/fill") {
        write_http(&mut stream, "404 Not Found", b"{}");
        return;
    }
    if req.method == "OPTIONS" {
        write_http(&mut stream, "405 Method Not Allowed", b"{}");
        return;
    }
    let mut authorization_headers = req.headers.iter().filter(|(k, _)| k == "authorization");
    let auth = authorization_headers.next().map(|(_, v)| v.clone()).unwrap_or_default();
    if authorization_headers.next().is_some() {
        write_http(&mut stream, "400 Bad Request", br#"{"error":"duplicate authorization"}"#);
        return;
    }
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
                    write_http(&mut stream, "403 Forbidden", br#"{"ok":false,"error":"vault locked"}"#);
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
        let mut session_headers = req.headers.iter().filter(|(key, _)| key == "mcp-session-id");
        let Some((_, id)) = session_headers.next() else {
            write_http(&mut stream,"400 Bad Request",br#"{"error":"Mcp-Session-Id required; initialize first"}"#);
            return;
        };
        if session_headers.next().is_some() {
            write_http(&mut stream,"400 Bad Request",br#"{"error":"duplicate Mcp-Session-Id"}"#);
            return;
        }
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

struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn spawn_listener(
    listener: TcpListener,
    running: Arc<AtomicBool>,
    session: Arc<Mutex<Session>>,
    mcp: McpState,
    policy: ListenPolicy,
    generation: u64,
) -> JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).ok();
        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, addr)) => {
                    let peer_ip = addr.ip();
                    let local_ip = stream
                        .local_addr()
                        .map(|address| address.ip())
                        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
                    if !peer_allowed(peer_ip, &policy) || !destination_allowed(local_ip, &policy) {
                        continue;
                    }
                    let active = mcp.active_connections.fetch_add(1, Ordering::SeqCst);
                    if active >= MAX_ACTIVE_CONNECTIONS {
                        mcp.active_connections.fetch_sub(1, Ordering::SeqCst);
                        continue;
                    }
                    let guard = ConnectionGuard(mcp.active_connections.clone());
                    let session = session.clone();
                    let mcp = mcp.clone();
                    let policy = policy.clone();
                    thread::spawn(move || {
                        let _guard = guard;
                        handle_client(stream, session, mcp, policy, peer_ip, local_ip, generation);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
    })
}

pub fn start(mcp: &McpState, session: Arc<Mutex<Session>>) -> Result<u16, String> {
    // Re-evaluate unlock/policy/config on every start request. Startup begins with
    // loopback before unlock; the subsequent unlock must be able to rebind LAN.
    if mcp.running.load(Ordering::SeqCst) {
        stop(mcp);
    }
    let (unlocked, enabled) = {
        let s = lock_session(&session);
        let unlocked = s.is_unlocked();
        let enabled = if unlocked {
            match (s.vault(), s.dek()) {
                (Ok(vault), Ok(dek)) => crate::zoomkey::mcp_enabled(vault, dek),
                _ => false,
            }
        } else {
            false
        };
        (unlocked, enabled)
    };
    mcp.locked.store(!unlocked, Ordering::SeqCst);
    if unlocked {
        {
            let s = lock_session(&session);
            if let Ok(vault) = s.vault() {
                let (mode, address) = persisted_listen_config(vault);
                let _ = mcp.set_listen_config(&mode, &address);
            }
        }
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
    // A locked vault or disabled MCP never exposes the configured LAN address.
    let policy = if unlocked && enabled {
        mcp.configured_policy()
    } else {
        ListenPolicy::loopback()
    };
    let loopback_listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PORT))
        .or_else(|_| TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        .map_err(|e| e.to_string())?;
    let port = loopback_listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut listeners = vec![(loopback_listener, ListenPolicy::loopback())];
    let mut bind_error = None;
    let active_policy = if policy.mode == LISTEN_MODE_LOOPBACK {
        policy
    } else {
        match policy.lan_ip() {
            Ok(ip) => {
                let address = ip.to_string();
                match TcpListener::bind(SocketAddr::new(IpAddr::V4(ip), port)) {
                    Ok(lan_listener) => {
                        let mut active = policy;
                        active.address = address;
                        listeners.push((lan_listener, active.clone()));
                        active
                    }
                    Err(error) => {
                        bind_error = Some(format!("无法绑定 MCP 局域网地址 {address}:{port}: {error}"));
                        ListenPolicy::loopback()
                    }
                }
            }
            Err(error) => {
                bind_error = Some(error);
                ListenPolicy::loopback()
            }
        }
    };
    *recover_lock(&mcp.port) = port;
    mcp.set_active_policy(&active_policy);
    // A failed LAN bind falls back to loopback. That is a supported degraded
    // mode, not a start failure: the loopback listeners below are about to
    // start and `running` becomes true. Returning Err from here used to make
    // every caller believe MCP was down (so the next start skipped `stop`),
    // leaking a full set of listener threads each retry. Surface the reason
    // instead of the failure.
    if let Some(error) = &bind_error {
        eprintln!("sealbox: MCP 局域网监听不可用，已回退到仅本机监听：{error}");
    }
    mcp.set_last_error(bind_error.clone());
    let generation = mcp.generation.fetch_add(1, Ordering::SeqCst).saturating_add(1);
    mcp.running.store(true, Ordering::SeqCst);
    remove_stale_bridge_file();
    let running = mcp.running.clone();
    let handles = listeners
        .into_iter()
        .map(|(listener, listener_policy)| {
            spawn_listener(listener, running.clone(), session.clone(), mcp.clone(), listener_policy, generation)
        })
        .collect::<Vec<_>>();
    *recover_lock(&mcp.listener_threads) = handles;
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
    mcp.set_last_error(None);
    mcp.generation.fetch_add(1, Ordering::SeqCst);
    mcp.close_pairing();
    mcp.invalidate_callers();
    let handles = std::mem::take(&mut *recover_lock(&mcp.listener_threads));
    for handle in handles {
        let _ = handle.join();
    }
    mcp.set_active_policy(&ListenPolicy::loopback());
}

/// Mark MCP locked while the session mutex may still be held. Listener threads
/// do not touch the session, so joining them here closes the old LAN socket
/// before a loopback-only rebind.
pub fn signal_locked(mcp: &McpState) {
    mcp.running.store(false, Ordering::SeqCst);
    mcp.locked.store(true, Ordering::SeqCst);
    mcp.generation.fetch_add(1, Ordering::SeqCst);
    mcp.close_pairing();
    mcp.invalidate_callers();
    let handles = std::mem::take(&mut *recover_lock(&mcp.listener_threads));
    for handle in handles {
        let _ = handle.join();
    }
    mcp.set_active_policy(&ListenPolicy::loopback());
}

#[cfg(test)]
#[path = "mcp_surface_tests.rs"]
mod tests;
