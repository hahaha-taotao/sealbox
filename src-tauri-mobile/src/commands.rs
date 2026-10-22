use crate::clipboard;
use crate::session::Session;
use crate::update::{self, MobileRelease};
use base64::{engine::general_purpose::STANDARD, Engine};
use sealbox_core::sync::{self, SyncConfig, SyncKind, SyncReport, SyncView};
use sealbox_core::totp::{ssh_fingerprint, totp_now};
use sealbox_core::vault::{Counts, EntryDto, FolderDto, ListFilter, SecretPayload, UpsertEntry, Vault};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};

pub struct AppState {
    pub session: Arc<Mutex<Session>>,
    pub auto: Mutex<crate::auto_sync::AutoSync>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            session: Arc::new(Mutex::new(Session::default())),
            auto: Mutex::new(crate::auto_sync::AutoSync::default()),
        }
    }
}

fn map_err(error: impl ToString) -> String {
    error.to_string()
}

pub(crate) fn lock_session(session: &Mutex<Session>) -> std::sync::MutexGuard<'_, Session> {
    session.lock().unwrap_or_else(|poison| poison.into_inner())
}

pub(crate) fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(map_err)?;
    std::fs::create_dir_all(&dir).map_err(map_err)?;
    Ok(dir.join("vault.db"))
}

fn setting_u64(vault: &Vault, key: &str, fallback: u64) -> u64 {
    vault
        .get_setting(key)
        .ok()
        .flatten()
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

fn apply_settings(session: &mut Session) {
    let (idle, clip) = {
        let Ok(vault) = session.vault() else {
            return;
        };
        (
            setting_u64(vault, "idle_secs", 60).max(30),
            setting_u64(vault, "clipboard_secs", 20).clamp(5, 120),
        )
    };
    session.idle_secs = idle;
    session.clipboard_secs = clip;
}

fn persist_settings(session: &Session) -> Result<(), String> {
    let vault = session.vault().map_err(map_err)?;
    vault
        .set_setting("idle_secs", &session.idle_secs.to_string())
        .map_err(map_err)?;
    vault
        .set_setting("clipboard_secs", &session.clipboard_secs.to_string())
        .map_err(map_err)
}

#[derive(Serialize)]
pub struct Status {
    pub initialized: bool,
    pub unlocked: bool,
    pub counts: Option<Counts>,
    pub biometry_enabled: bool,
}

#[tauri::command]
pub fn get_status(app: AppHandle, state: State<AppState>) -> Result<Status, String> {
    let path = vault_path(&app)?;
    let initialized = Vault::is_initialized(path.to_str().unwrap_or_default());
    let mut session = lock_session(&state.session);
    let unlocked = session.is_unlocked();
    if unlocked {
        apply_settings(&mut session);
    }
    let counts = if unlocked {
        session.vault().ok().and_then(|vault| vault.counts().ok())
    } else {
        None
    };
    let biometry_enabled = if initialized {
        Vault::open(path.to_str().unwrap_or_default())
            .ok()
            .and_then(|vault| vault.get_setting("biometry_enabled").ok().flatten())
            .as_deref()
            == Some("1")
    } else {
        false
    };
    Ok(Status {
        initialized,
        unlocked,
        counts,
        biometry_enabled,
    })
}

#[tauri::command]
pub fn setup_vault(app: AppHandle, state: State<AppState>, password: String) -> Result<(), String> {
    if password.chars().count() < 10 {
        return Err("主密码至少 10 位".into());
    }
    let path = vault_path(&app)?;
    let path_str = path.to_str().ok_or("金库路径无效")?;
    let dek = Vault::create(path_str, &password).map_err(map_err)?;
    let vault = Vault::open(path_str).map_err(map_err)?;
    vault.set_setting("idle_secs", "60").map_err(map_err)?;
    vault.set_setting("clipboard_secs", "20").map_err(map_err)?;
    lock_session(&state.session).set_unlocked(vault, dek);
    Ok(())
}

#[tauri::command]
pub fn unlock_vault(app: AppHandle, state: State<AppState>, password: String) -> Result<(), String> {
    let path = vault_path(&app)?;
    let path_str = path.to_str().ok_or("金库路径无效")?;
    let mut session = lock_session(&state.session);
    let delay = session.unlock_delay_ms();
    drop(session);
    if delay > 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay));
    }
    let vault = Vault::open(path_str).map_err(map_err)?;
    match vault.unlock(&password) {
        Ok(dek) => {
            let mut session = lock_session(&state.session);
            session.set_unlocked(vault, dek);
            apply_settings(&mut session);
            if let Ok(vault) = session.vault() {
                crate::auto_sync::refresh_from_vault(&state, vault);
            }
            Ok(())
        }
        Err(error) => {
            lock_session(&state.session).note_failed_unlock();
            Err(map_err(error))
        }
    }
}

#[tauri::command]
pub fn unlock_with_dek(app: AppHandle, state: State<AppState>, dek_b64: String) -> Result<(), String> {
    let bytes = STANDARD.decode(dek_b64.trim()).map_err(|_| "指纹保存的密钥无效")?;
    if bytes.len() != 32 {
        return Err("指纹保存的密钥无效".into());
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&bytes);
    let path = vault_path(&app)?;
    let vault = Vault::open(path.to_str().unwrap_or_default()).map_err(map_err)?;
    if vault.dek_matches(&dek).is_err() {
        return Err("指纹解锁已失效，请用主密码重新打开".into());
    }
    let mut session = lock_session(&state.session);
    session.set_unlocked(vault, dek);
    apply_settings(&mut session);
    if let Ok(vault) = session.vault() {
        crate::auto_sync::refresh_from_vault(&state, vault);
    }
    Ok(())
}

#[tauri::command]
pub fn export_dek(state: State<AppState>) -> Result<String, String> {
    let session = lock_session(&state.session);
    let dek = session.dek().map_err(map_err)?;
    Ok(STANDARD.encode(dek))
}

#[tauri::command]
pub fn set_biometry_enabled(app: AppHandle, state: State<AppState>, enabled: bool) -> Result<(), String> {
    let path = vault_path(&app)?;
    let session = lock_session(&state.session);
    session.dek().map_err(map_err)?;
    let vault = Vault::open(path.to_str().unwrap_or_default()).map_err(map_err)?;
    vault
        .set_setting("biometry_enabled", if enabled { "1" } else { "0" })
        .map_err(map_err)
}

#[tauri::command]
pub fn lock_vault(state: State<AppState>) -> Result<(), String> {
    lock_session(&state.session).lock();
    Ok(())
}

#[tauri::command]
pub fn tick_idle(state: State<AppState>) -> Result<bool, String> {
    let mut session = lock_session(&state.session);
    let locked = session.maybe_idle_lock();
    if !locked && session.clipboard_deadline_due() {
        let current = clipboard::read_text().unwrap_or_default();
        if session.clipboard_should_clear(&current) {
            let _ = clipboard::clear();
            session.clear_clipboard_mark();
        }
    }
    Ok(locked || !session.is_unlocked())
}

#[tauri::command]
pub fn list_entries(state: State<AppState>, filter: ListFilter) -> Result<Vec<EntryDto>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.list_entries(&filter).map_err(map_err)
}

#[tauri::command]
pub fn list_counts(state: State<AppState>, filter: ListFilter) -> Result<Counts, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.counts_for(&filter).map_err(map_err)
}

#[tauri::command]
pub fn list_folders(state: State<AppState>) -> Result<Vec<FolderDto>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.list_folders().map_err(map_err)
}

#[tauri::command]
pub fn create_folder(state: State<AppState>, name: String) -> Result<FolderDto, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.create_folder(&name).map_err(map_err)
}

#[tauri::command]
pub fn rename_folder(state: State<AppState>, id: String, name: String) -> Result<FolderDto, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .rename_folder(&id, &name)
        .map_err(map_err)
}

#[tauri::command]
pub fn delete_folder(state: State<AppState>, id: String) -> Result<usize, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.delete_folder(&id).map_err(map_err)
}

#[tauri::command]
pub fn list_tags(state: State<AppState>) -> Result<Vec<String>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.list_tags().map_err(map_err)
}

#[tauri::command]
pub fn create_entry(state: State<AppState>, mut input: UpsertEntry) -> Result<EntryDto, String> {
    if let SecretPayload::Ssh {
        private_key,
        public_fingerprint,
        ..
    } = &mut input.secret
    {
        if public_fingerprint.as_deref().unwrap_or("").is_empty() {
            *public_fingerprint = ssh_fingerprint(private_key);
        }
    }
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .upsert_entry_with_duplicate_policy(&dek, input, true)
        .map_err(map_err)
}

#[tauri::command]
pub fn delete_entries(state: State<AppState>, ids: Vec<String>) -> Result<usize, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.soft_delete(&ids).map_err(map_err)
}

#[tauri::command]
pub fn restore_entries(state: State<AppState>, ids: Vec<String>) -> Result<usize, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.restore(&ids).map_err(map_err)
}

#[tauri::command]
pub fn empty_trash(state: State<AppState>) -> Result<usize, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.empty_trash().map_err(map_err)
}

#[tauri::command]
pub fn pin_entry(state: State<AppState>, id: String, pinned: bool) -> Result<(), String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.set_pinned(&id, pinned).map_err(map_err)
}

fn primary_secret(payload: &SecretPayload) -> Result<String, String> {
    match payload {
        SecretPayload::Website { password, .. } => Ok(password.clone()),
        SecretPayload::ApiToken { token, .. } => Ok(token.clone()),
        SecretPayload::Ssh { private_key, .. } => Ok(private_key.clone()),
        SecretPayload::Mailbox { password, .. } => Ok(password.clone()),
        SecretPayload::MailAuth { auth_code, .. } => Ok(auth_code.clone()),
        SecretPayload::Server { password, .. } => Ok(password.clone()),
        SecretPayload::Database { password, .. } => Ok(password.clone()),
        SecretPayload::ClientCert { .. } => Err("客户端证书私钥不能复制".into()),
    }
}

fn account_of(payload: &SecretPayload) -> Option<String> {
    match payload {
        SecretPayload::Website { username, .. } => username.clone(),
        SecretPayload::ApiToken { account, .. } => account.clone(),
        SecretPayload::Mailbox { email, .. } | SecretPayload::MailAuth { email, .. } => Some(email.clone()),
        SecretPayload::Server { username, .. } | SecretPayload::Database { username, .. } => Some(username.clone()),
        SecretPayload::Ssh { .. } | SecretPayload::ClientCert { .. } => None,
    }
}

#[tauri::command]
pub fn copy_secret(state: State<AppState>, id: String, field: String) -> Result<(), String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let payload = session.vault().map_err(map_err)?.get_active_secret(&dek, &id).map_err(map_err)?;
    let text = match field.as_str() {
        "account" => account_of(&payload).unwrap_or_default(),
        "totp" => {
            let SecretPayload::Website { totp_secret, .. } = &payload else {
                return Err("没有 TOTP".into());
            };
            totp_now(totp_secret.as_deref().unwrap_or(""))?
        }
        "cert" => {
            let SecretPayload::ClientCert { cert_pem, .. } = &payload else {
                return Err("不是客户端证书".into());
            };
            cert_pem.clone()
        }
        _ => primary_secret(&payload)?,
    };
    if text.trim().is_empty() {
        return Err("没有可复制的内容".into());
    }
    clipboard::write_text(&text)?;
    session.remember_clipboard(&text);
    let _ = session.vault().map_err(map_err)?.bump_use(&id);
    Ok(())
}

#[tauri::command]
pub fn reveal_secret(state: State<AppState>, id: String) -> Result<SecretPayload, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let payload = session.vault().map_err(map_err)?.get_active_secret(&dek, &id).map_err(map_err)?;
    if matches!(payload, SecretPayload::ClientCert { .. }) {
        return Err("客户端证书私钥不返回到界面".into());
    }
    Ok(payload)
}

#[tauri::command]
pub fn get_notes(state: State<AppState>, id: String) -> Result<Option<String>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    session.vault().map_err(map_err)?.get_notes(&dek, &id).map_err(map_err)
}

#[derive(Serialize)]
pub struct SettingsView {
    pub idle_secs: u64,
    pub clipboard_secs: u64,
    pub biometry_enabled: bool,
}

#[tauri::command]
pub fn settings_get(state: State<AppState>) -> Result<SettingsView, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    apply_settings(&mut session);
    let idle_secs = session.idle_secs;
    let clipboard_secs = session.clipboard_secs;
    let biometry_enabled = session
        .vault()
        .map_err(map_err)?
        .get_setting("biometry_enabled")
        .ok()
        .flatten()
        .as_deref()
        == Some("1");
    Ok(SettingsView {
        idle_secs,
        clipboard_secs,
        biometry_enabled,
    })
}

#[tauri::command]
pub fn settings_set(state: State<AppState>, idle_secs: u64, clipboard_secs: u64) -> Result<(), String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.idle_secs = idle_secs.max(30);
    session.clipboard_secs = clipboard_secs.clamp(5, 120);
    persist_settings(&session)
}

#[tauri::command]
pub fn sync_status(state: State<AppState>) -> Result<SyncView, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    sync::view(session.vault().map_err(map_err)?).map_err(map_err)
}

#[derive(Deserialize)]
pub struct SyncSaveInput {
    pub kind: SyncKind,
    pub endpoint: String,
    pub username: String,
    pub secret: Option<String>,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub prefix: Option<String>,
    #[serde(default)]
    pub auto_sync: Option<bool>,
    #[serde(default)]
    pub auto_sync_secs: Option<u64>,
}

#[tauri::command]
pub fn sync_save(state: State<AppState>, input: SyncSaveInput) -> Result<SyncView, String> {
    let (view, auto) = {
        let mut session = lock_session(&state.session);
        session.require_unlocked().map_err(map_err)?;
        let dek = *session.dek().map_err(map_err)?;
        let vault = session.vault().map_err(map_err)?;
        sync::save_config(
            vault,
            &dek,
            SyncConfig {
                kind: input.kind,
                endpoint: input.endpoint,
                username: input.username,
                bucket: input.bucket.unwrap_or_default(),
                region: input.region.unwrap_or_default(),
                prefix: input.prefix.unwrap_or_default(),
            },
            input.secret.as_deref(),
        )?;
        let auto =
            sync::save_auto(vault, input.auto_sync, input.auto_sync_secs).map_err(map_err)?;
        (sync::view(vault).map_err(map_err)?, auto)
    };
    crate::auto_sync::apply(&state, auto.enabled, auto.secs);
    Ok(view)
}

#[tauri::command]
pub fn sync_clear(state: State<AppState>) -> Result<(), String> {
    {
        let mut session = lock_session(&state.session);
        session.require_unlocked().map_err(map_err)?;
        sync::clear_config(session.vault().map_err(map_err)?).map_err(map_err)?;
    }
    crate::auto_sync::apply(&state, false, sync::DEFAULT_AUTO_SYNC_SECS);
    Ok(())
}

#[tauri::command]
pub fn app_version() -> String {
    update::current_version()
}

#[tauri::command]
pub fn check_mobile_update() -> Result<MobileRelease, String> {
    update::check()
}

#[derive(Serialize)]
pub struct UpdateDownload {
    pub path: String,
    pub bytes: u64,
}

#[tauri::command]
pub fn download_mobile_update(app: AppHandle, url: String) -> Result<UpdateDownload, String> {
    let dir = app
        .path()
        .app_cache_dir()
        .map_err(map_err)?;
    let path = update::download(&url, &dir, |bytes, total| {
        let _ = app.emit(
            "mobile-update-progress",
            serde_json::json!({ "bytes": bytes, "total": total }),
        );
    })?;
    let bytes = std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
    Ok(UpdateDownload {
        path: path.to_string_lossy().into_owned(),
        bytes,
    })
}

#[tauri::command]
pub fn install_mobile_update(app: AppHandle, state: State<AppState>, path: String) -> Result<(), String> {
    let path = PathBuf::from(&path);
    let cache_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if cache_name != "sealbox-mobile-update.apk" || path.components().count() < 2 {
        return Err("只能安装本次下载的更新包".into());
    }
    let cache = app.path().app_cache_dir().map_err(map_err)?;
    let expected = cache.join("sealbox-mobile-update.apk");
    let actual = path.canonicalize().map_err(|error| format!("找不到安装包：{error}"))?;
    let expected = expected
        .canonicalize()
        .map_err(|error| format!("找不到安装包：{error}"))?;
    if actual != expected {
        return Err("只能安装本次下载的更新包".into());
    }
    {
        let mut session = lock_session(&state.session);
        session.lock();
    }
    let _ = app.emit("lock-now", ());
    update::install_apk(&actual)
}

#[tauri::command]
pub fn sync_now(state: State<AppState>) -> Result<SyncReport, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    sync::sync_now(session.vault().map_err(map_err)?, &dek)
}
