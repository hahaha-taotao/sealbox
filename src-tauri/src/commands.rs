use crate::backup::{export_envelope, import_envelope};
use crate::clipboard;
use crate::hello;
use crate::session::Session;
use crate::totp::{generate_password, ssh_fingerprint, totp_now};
use crate::vault::{
    AuditEvent, Counts, EntryDto, FolderDto, ListFilter, SecretPayload, UpsertEntry, Vault,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State};

pub struct AppState {
    pub session: Mutex<Session>,
    pub db_path: Mutex<Option<PathBuf>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            session: Mutex::new(Session::default()),
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
    }
}

fn account_of(payload: &SecretPayload) -> Option<String> {
    match payload {
        SecretPayload::Website { username, .. } => username.clone(),
        SecretPayload::ApiToken { account, .. } => account.clone(),
        SecretPayload::Ssh { .. } => None,
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
        hotkey: "Ctrl+Shift+Space".into(),
    }
}

#[tauri::command]
pub fn settings_set(state: State<AppState>, settings: Settings) -> Result<(), String> {
    let mut s = state.session.lock().unwrap();
    s.idle_secs = settings.idle_secs.max(60);
    s.clipboard_secs = settings.clipboard_secs.clamp(5, 120);
    Ok(())
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
    session
        .vault()
        .map_err(map_err)?
        .change_master_password(&dek, &old_password, &new_password)
        .map_err(map_err)
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
        _ => Ok(()),
    }
}
