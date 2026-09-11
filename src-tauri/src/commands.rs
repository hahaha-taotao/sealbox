use crate::backup::{export_envelope, import_envelope};
use crate::clipboard;
use crate::hello;
use crate::mcp::{self, McpState};
use crate::session::Session;
use crate::totp::{generate_password, ssh_fingerprint, totp_now};
use crate::vault::{
    AuditEvent, Counts, EntryDto, FolderDto, ListFilter, SecretPayload, UpsertEntry, Vault,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};

pub struct AppState {
    pub session: Arc<Mutex<Session>>,
    pub mcp: McpState,
    pub db_path: Mutex<Option<PathBuf>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            session: Arc::new(Mutex::new(Session::default())),
            mcp: McpState::default(),
            db_path: Mutex::new(None),
        }
    }
}

fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("vault.db"))
}

fn map_err(e: impl ToString) -> String {
    e.to_string()
}

#[derive(Serialize)]
pub struct Status {
    pub initialized: bool,
    pub unlocked: bool,
    pub hello_enabled: bool,
    pub hello_available: bool,
    pub counts: Option<Counts>,
}

#[tauri::command]
pub fn get_status(app: AppHandle, state: State<AppState>) -> Result<Status, String> {
    let path = vault_path(&app)?;
    *state.db_path.lock().unwrap() = Some(path.clone());
    let initialized = path.exists();
    let mut session = state.session.lock().unwrap();
    session.maybe_idle_lock();
    let unlocked = session.is_unlocked();
    let hello_enabled = if initialized {
        if session.vault.is_none() {
            if let Ok(v) = Vault::open(path.to_str().unwrap_or_default()) {
                session.vault = Some(v);
            }
        }
        session
            .vault
            .as_ref()
            .and_then(|v| v.hello_enabled().ok())
            .unwrap_or(false)
    } else {
        false
    };
    if unlocked {
        let idle = session.vault().ok().and_then(|v| v.get_setting("idle_secs").ok()).flatten();
        let clip = session.vault().ok().and_then(|v| v.get_setting("clipboard_secs").ok()).flatten();
        let hk = session.vault().ok().and_then(|v| v.get_setting("hotkey").ok()).flatten();
        if let Some(idle) = idle.and_then(|s| s.parse::<u64>().ok()) {
            session.idle_secs = idle.max(60);
        }
        if let Some(clip) = clip.and_then(|s| s.parse::<u64>().ok()) {
            session.clipboard_secs = clip.clamp(5, 120);
        }
        if let Some(hk) = hk {
            session.hotkey = hk;
        }
    }
    let counts = if unlocked {
        session.vault().ok().and_then(|v| v.counts().ok())
    } else {
        None
    };
    Ok(Status {
        initialized,
        unlocked,
        hello_enabled,
        hello_available: hello::hello_available(),
        counts,
    })
}

#[tauri::command]
pub fn home_overview(state: State<AppState>) -> Result<HomeOverview, String> {
    let mut session = state.session.lock().unwrap();
    session.maybe_idle_lock();
    let vault = session.vault().map_err(map_err)?;
    Ok(HomeOverview {
        counts: vault.counts().map_err(map_err)?,
        recent: vault.recent_entries(8).map_err(map_err)?,
        expiring: vault.expiring_entries(30).map_err(map_err)?,
    })
}

#[derive(Serialize)]
pub struct HomeOverview {
    pub counts: Counts,
    pub recent: Vec<EntryDto>,
    pub expiring: Vec<EntryDto>,
}

#[tauri::command]
pub fn setup_vault(app: AppHandle, state: State<AppState>, password: String) -> Result<(), String> {
    if password.chars().count() < 10 {
        return Err("主密码至少 10 位".into());
    }
    let path = vault_path(&app)?;
    if path.exists() {
        return Err("金库已存在".into());
    }
    let dek = Vault::create(path.to_str().unwrap(), &password).map_err(map_err)?;
    let vault = Vault::open(path.to_str().unwrap()).map_err(map_err)?;
    let mut session = state.session.lock().unwrap();
    session.set_unlocked(vault, dek);
    Ok(())
}

#[tauri::command]
pub fn unlock_vault(app: AppHandle, state: State<AppState>, password: String) -> Result<(), String> {
    let path = vault_path(&app)?;
    let vault = Vault::open(path.to_str().unwrap()).map_err(map_err)?;
    let mut session = state.session.lock().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(session.unlock_delay_ms()));
    match vault.unlock(&password) {
        Ok(dek) => {
            let _ = vault.audit("unlock", None, "ok");
            let _ = vault.purge_expired_trash(chrono::Utc::now(), 30);
            session.set_unlocked(vault, dek);
            Ok(())
        }
        Err(e) => {
            let _ = vault.audit("unlock", None, "fail");
            session.note_failed_unlock();
            Err(e.to_string())
        }
    }
}

#[tauri::command]
pub fn unlock_hello(app: AppHandle, state: State<AppState>) -> Result<(), String> {
    if !hello::prompt_hello()? {
        return Err("Windows Hello 未通过".into());
    }
    let key = hello::load_hello_key()?;
    let path = vault_path(&app)?;
    let vault = Vault::open(path.to_str().unwrap()).map_err(map_err)?;
    let dek = vault.unlock_with_hello_key(&key).map_err(map_err)?;
    let _ = vault.audit("unlock_hello", None, "ok");
    state.session.lock().unwrap().set_unlocked(vault, dek);
    Ok(())
}

#[tauri::command]
pub fn lock_vault(state: State<AppState>) -> Result<(), String> {
    let mut session = state.session.lock().unwrap();
    if session.clipboard_should_clear(&clipboard::read_text().unwrap_or_default()) {
        let _ = clipboard::clear();
    }
    session.clear_clipboard_mark();
    session.lock();
    Ok(())
}

#[tauri::command]
pub fn list_entries(state: State<AppState>, filter: ListFilter) -> Result<Vec<EntryDto>, String> {
    let mut session = state.session.lock().unwrap();
    session.maybe_idle_lock();
    session.touch();
    let vault = session.vault().map_err(map_err)?;
    vault.list_entries(&filter).map_err(map_err)
}

#[tauri::command]
pub fn create_entry(state: State<AppState>, mut input: UpsertEntry) -> Result<EntryDto, String> {
    if let SecretPayload::Ssh {
        private_key,
        public_fingerprint,
        ..
    } = &mut input.secret
    {
        if public_fingerprint.is_none() {
            *public_fingerprint = ssh_fingerprint(private_key);
        }
    }
    let mut session = state.session.lock().unwrap();
    session.maybe_idle_lock();
    let dek = *session.dek().map_err(map_err)?;
    session.touch();
    session.vault().map_err(map_err)?.upsert_entry(&dek, input).map_err(map_err)
}

#[tauri::command]
pub fn update_entry(state: State<AppState>, input: UpsertEntry) -> Result<EntryDto, String> {
    create_entry(state, input)
}

#[tauri::command]
pub fn delete_entries(state: State<AppState>, ids: Vec<String>) -> Result<usize, String> {
    let mut session = state.session.lock().unwrap();
    session.touch();
    session.vault().map_err(map_err)?.soft_delete(&ids).map_err(map_err)
}

#[tauri::command]
pub fn restore_entries(state: State<AppState>, ids: Vec<String>) -> Result<usize, String> {
    let mut session = state.session.lock().unwrap();
    session.touch();
    session.vault().map_err(map_err)?.restore(&ids).map_err(map_err)
}

#[tauri::command]
pub fn empty_trash(state: State<AppState>) -> Result<usize, String> {
    let mut session = state.session.lock().unwrap();
    session.touch();
    session.vault().map_err(map_err)?.empty_trash().map_err(map_err)
}

#[tauri::command]
pub fn pin_entry(state: State<AppState>, id: String, pinned: bool) -> Result<(), String> {
    let mut session = state.session.lock().unwrap();
    session.touch();
    session.vault().map_err(map_err)?.set_pinned(&id, pinned).map_err(map_err)
}

#[tauri::command]
pub fn list_folders(state: State<AppState>) -> Result<Vec<FolderDto>, String> {
    state
        .session
        .lock()
        .unwrap()
        .vault()
        .map_err(map_err)?
        .list_folders()
        .map_err(map_err)
}

#[tauri::command]
pub fn create_folder(state: State<AppState>, name: String) -> Result<FolderDto, String> {
    state
        .session
        .lock()
        .unwrap()
        .vault()
        .map_err(map_err)?
        .create_folder(&name)
        .map_err(map_err)
}

#[tauri::command]
pub fn list_tags(state: State<AppState>) -> Result<Vec<String>, String> {
    state
        .session
        .lock()
        .unwrap()
        .vault()
        .map_err(map_err)?
        .list_tags()
        .map_err(map_err)
}

#[tauri::command]
pub fn list_audit(state: State<AppState>) -> Result<Vec<AuditEvent>, String> {
    state
        .session
        .lock()
        .unwrap()
        .vault()
        .map_err(map_err)?
        .list_audit(200)
        .map_err(map_err)
}

fn primary_secret(payload: &SecretPayload) -> String {
    match payload {
        SecretPayload::Website { password, .. } => password.clone(),
        SecretPayload::ApiToken { token, .. } => token.clone(),
        SecretPayload::Ssh { private_key, .. } => private_key.clone(),
        SecretPayload::Mailbox { password, .. } => password.clone(),
        SecretPayload::MailAuth { auth_code, .. } => auth_code.clone(),
        SecretPayload::Server { password, .. } => password.clone(),
    }
}

fn account_of(payload: &SecretPayload) -> Option<String> {
    match payload {
        SecretPayload::Website { username, .. } => username.clone(),
        SecretPayload::ApiToken { account, .. } => account.clone(),
        SecretPayload::Ssh { .. } => None,
        SecretPayload::Mailbox { email, .. } => Some(email.clone()),
        SecretPayload::MailAuth { email, .. } => Some(email.clone()),
        SecretPayload::Server { username, .. } => Some(username.clone()),
    }
}

#[tauri::command]
pub fn copy_secret(state: State<AppState>, id: String, field: String) -> Result<(), String> {
    let mut session = state.session.lock().unwrap();
    session.maybe_idle_lock();
    let dek = *session.dek().map_err(|_| "需要先解锁".to_string())?;
    let payload = {
        let vault = session.vault().map_err(map_err)?;
        vault.get_secret(&dek, &id).map_err(map_err)?
    };
    let text = match field.as_str() {
        "account" => account_of(&payload).unwrap_or_default(),
        "totp" => {
            let SecretPayload::Website { totp_secret, .. } = &payload else {
                return Err("没有 TOTP".into());
            };
            let secret = totp_secret.as_ref().ok_or("没有 TOTP")?;
            totp_now(secret)?
        }
        _ => primary_secret(&payload),
    };
    if text.is_empty() {
        return Err("没有可复制的内容".into());
    }
    clipboard::write_text(&text)?;
    session.remember_clipboard(&text);
    {
        let vault = session.vault().map_err(map_err)?;
        let _ = vault.bump_use(&id);
        let _ = vault.audit("copy", Some(&id), &field);
    }
    session.touch();
    Ok(())
}

#[tauri::command]
pub fn reveal_secret(state: State<AppState>, id: String) -> Result<SecretPayload, String> {
    let mut session = state.session.lock().unwrap();
    session.maybe_idle_lock();
    let dek = *session.dek().map_err(|_| "需要先解锁".to_string())?;
    let payload = {
        let vault = session.vault().map_err(map_err)?;
        let payload = vault.get_secret(&dek, &id).map_err(map_err)?;
        let _ = vault.audit("reveal", Some(&id), "ok");
        payload
    };
    session.touch();
    Ok(payload)
}

#[tauri::command]
pub fn get_notes(state: State<AppState>, id: String) -> Result<Option<String>, String> {
    let mut session = state.session.lock().unwrap();
    let dek = *session.dek().map_err(|_| "需要先解锁".to_string())?;
    session
        .vault()
        .map_err(map_err)?
        .get_notes(&dek, &id)
        .map_err(map_err)
}

#[tauri::command]
pub fn tick_idle(state: State<AppState>) -> Result<bool, String> {
    let mut session = state.session.lock().unwrap();
    if session.clipboard_should_clear(&clipboard::read_text().unwrap_or_default()) {
        let _ = clipboard::clear();
        session.clear_clipboard_mark();
    }
    Ok(session.maybe_idle_lock())
}

#[derive(Deserialize)]
pub struct PasswordOpts {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
}

#[tauri::command]
pub fn gen_password(opts: PasswordOpts) -> String {
    generate_password(opts.length, opts.upper, opts.lower, opts.digits, opts.symbols)
}

#[tauri::command]
pub fn export_backup(state: State<AppState>, password: String, path: String) -> Result<(), String> {
    let mut session = state.session.lock().unwrap();
    let dek = *session.dek().map_err(|_| "需要先解锁".to_string())?;
    let vault = session.vault().map_err(map_err)?;
    let bytes = export_envelope(vault, &dek, &password).map_err(map_err)?;
    std::fs::write(Path::new(&path), bytes).map_err(|e| e.to_string())?;
    let _ = vault.audit("export", None, "ok");
    Ok(())
}

#[tauri::command]
pub fn import_backup(
    app: AppHandle,
    state: State<AppState>,
    password: String,
    path: String,
    overwrite: bool,
) -> Result<(usize, usize), String> {
    let bytes = std::fs::read(Path::new(&path)).map_err(|e| e.to_string())?;
    let db = vault_path(&app)?;
    let mut session = state.session.lock().unwrap();
    if !db.exists() {
        let dek = Vault::create(db.to_str().unwrap(), &password).map_err(map_err)?;
        let vault = Vault::open(db.to_str().unwrap()).map_err(map_err)?;
        let n = import_envelope(&vault, &dek, &bytes, &password, overwrite).map_err(map_err)?;
        session.set_unlocked(vault, dek);
        return Ok(n);
    }
    let dek = *session.dek().map_err(|_| "需要先解锁".to_string())?;
    let vault = session.vault().map_err(map_err)?;
    import_envelope(vault, &dek, &bytes, &password, overwrite).map_err(map_err)
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Settings {
    pub idle_secs: u64,
    pub clipboard_secs: u64,
    pub hotkey: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            idle_secs: 900,
            clipboard_secs: 20,
            hotkey: "Ctrl+Shift+Space".into(),
        }
    }
}

#[tauri::command]
pub fn settings_get(state: State<AppState>) -> Settings {
    let s = state.session.lock().unwrap();
    Settings {
        idle_secs: s.idle_secs,
        clipboard_secs: s.clipboard_secs,
        hotkey: s.hotkey.clone(),
    }
}

#[tauri::command]
pub fn settings_set(app: AppHandle, state: State<AppState>, settings: Settings) -> Result<(), String> {
    let mut s = state.session.lock().unwrap();
    s.idle_secs = settings.idle_secs.max(60);
    s.clipboard_secs = settings.clipboard_secs.clamp(5, 120);
    s.hotkey = settings.hotkey.clone();
    if let Ok(v) = s.vault() {
        let _ = v.set_setting("idle_secs", &s.idle_secs.to_string());
        let _ = v.set_setting("clipboard_secs", &s.clipboard_secs.to_string());
        let _ = v.set_setting("hotkey", &s.hotkey);
    }
    drop(s);
    register_hotkey(&app, &settings.hotkey)
}

pub fn register_hotkey(app: &AppHandle, hotkey: &str) -> Result<(), String> {
    use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};
    let shortcut = parse_hotkey(hotkey)?;
    let _ = app.global_shortcut().unregister_all();
    let app2 = app.clone();
    app.global_shortcut()
        .on_shortcut(shortcut, move |app, _sc, event| {
            if event.state != ShortcutState::Pressed {
                return;
            }
            if let Some(win) = app.get_webview_window("quick") {
                let _ = win.show();
                let _ = win.set_always_on_top(true);
                let _ = win.unminimize();
                let _ = win.set_focus();
            }
            let _ = app2.emit_to("quick", "quick-search", ());
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn parse_hotkey(s: &str) -> Result<tauri_plugin_global_shortcut::Shortcut, String> {
    use tauri_plugin_global_shortcut::{Code, Modifiers, Shortcut};
    let lower = s.to_ascii_lowercase();
    let mut mods = Modifiers::empty();
    if lower.contains("ctrl") {
        mods |= Modifiers::CONTROL;
    }
    if lower.contains("shift") {
        mods |= Modifiers::SHIFT;
    }
    if lower.contains("alt") {
        mods |= Modifiers::ALT;
    }
    if lower.contains("super") || lower.contains("meta") || lower.contains("win") {
        mods |= Modifiers::SUPER;
    }
    let code = if lower.contains("space") {
        Code::Space
    } else if lower.contains("keyk") || lower.ends_with("+k") {
        Code::KeyK
    } else if lower.contains("keyp") || lower.ends_with("+p") {
        Code::KeyP
    } else {
        Code::Space
    };
    Ok(Shortcut::new(Some(mods), code))
}

#[tauri::command]
pub fn set_hello_enabled(state: State<AppState>, enabled: bool) -> Result<(), String> {
    let mut session = state.session.lock().unwrap();
    let dek = *session.dek().map_err(|_| "需要先解锁".to_string())?;
    let vault = session.vault().map_err(map_err)?;
    if enabled {
        hello::enable_hello(vault, &dek)
    } else {
        hello::disable_hello(vault, &dek)
    }
}

#[tauri::command]
pub fn change_master(
    state: State<AppState>,
    old_password: String,
    new_password: String,
) -> Result<(), String> {
    let mut session = state.session.lock().unwrap();
    let dek = *session.dek().map_err(|_| "需要先解锁".to_string())?;
    let vault = session.vault().map_err(map_err)?;
    vault
        .change_master_password(&dek, &old_password, &new_password)
        .map_err(map_err)?;
    if vault.hello_enabled().unwrap_or(false) {
        hello::enable_hello(vault, &dek)?;
    }
    Ok(())
}

#[derive(Serialize)]
pub struct McpStatus {
    pub running: bool,
    pub port: u16,
    pub token: String,
    pub url: String,
    pub fill_token: String,
    pub fill_url: String,
}

fn mcp_status_of(state: &AppState) -> McpStatus {
    let port = *state.mcp.port.lock().unwrap();
    let token = state.mcp.token.lock().unwrap().clone();
    let fill_token = state.mcp.fill_token.lock().unwrap().clone();
    McpStatus {
        running: state.mcp.running.load(std::sync::atomic::Ordering::SeqCst),
        port,
        token: token.clone(),
        url: format!("http://127.0.0.1:{port}/mcp"),
        fill_token: fill_token.clone(),
        fill_url: format!("http://127.0.0.1:{port}/fill"),
    }
}

#[tauri::command]
pub fn mcp_status(state: State<AppState>) -> McpStatus {
    mcp_status_of(&state)
}

#[tauri::command]
pub fn mcp_start(state: State<AppState>) -> Result<McpStatus, String> {
    let port = mcp::start(&state.mcp, state.session.clone())?;
    if let Ok(v) = state.session.lock().unwrap().vault() {
        let _ = v.audit("mcp_start", None, &format!("port={port}"));
    }
    Ok(mcp_status_of(&state))
}

#[tauri::command]
pub fn mcp_stop(state: State<AppState>) -> Result<McpStatus, String> {
    mcp::stop(&state.mcp);
    if let Ok(v) = state.session.lock().unwrap().vault() {
        let _ = v.audit("mcp_stop", None, "ok");
    }
    Ok(mcp_status_of(&state))
}

#[tauri::command]
pub fn mcp_rotate_token(state: State<AppState>) -> Result<McpStatus, String> {
    *state.mcp.token.lock().unwrap() = mcp::new_token();
    if state.mcp.running.load(std::sync::atomic::Ordering::SeqCst) {
        mcp::stop(&state.mcp);
        std::thread::sleep(std::time::Duration::from_millis(120));
        mcp::start(&state.mcp, state.session.clone())?;
    }
    Ok(mcp_status_of(&state))
}

#[tauri::command]
pub fn fill_rotate_token(state: State<AppState>) -> Result<McpStatus, String> {
    *state.mcp.fill_token.lock().unwrap() = crate::fill::new_fill_token();
    if state.mcp.running.load(std::sync::atomic::Ordering::SeqCst) {
        mcp::stop(&state.mcp);
        std::thread::sleep(std::time::Duration::from_millis(120));
        mcp::start(&state.mcp, state.session.clone())?;
    }
    Ok(mcp_status_of(&state))
}

#[tauri::command]
pub fn window_control(app: AppHandle, action: String) -> Result<(), String> {
    let win = app.get_webview_window("main").ok_or("no window")?;
    match action.as_str() {
        "minimize" => win.minimize().map_err(map_err),
        "maximize" => {
            if win.is_maximized().unwrap_or(false) {
                win.unmaximize().map_err(map_err)
            } else {
                win.maximize().map_err(map_err)
            }
        }
        "close" => win.hide().map_err(map_err),
        "show" => {
            let _ = win.unminimize();
            win.show().map_err(map_err)?;
            win.set_focus().map_err(map_err)
        }
        _ => Ok(()),
    }
}
