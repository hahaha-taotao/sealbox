use crate::clipboard;
use crate::session::Session;
use crate::update::{self, MobileRelease};
use base64::{engine::general_purpose::STANDARD, Engine};
use sealbox_core::backup::{self, RestoreOptions};
use sealbox_core::csv;
use sealbox_core::sync::{self, SyncConfig, SyncKind, SyncReport, SyncView};
use sealbox_core::sync::SyncRuntime;
use sealbox_core::totp::{ssh_fingerprint, totp_now};
use sealbox_core::vault::{
    Counts, EntryDto, EntryProfile, FolderDto, ListFilter, SecretPayload, UpsertEntry, Vault,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroize;

pub struct AppState {
    pub session: Arc<Mutex<Session>>,
    pub auto: Mutex<crate::auto_sync::AutoSync>,
    pub transfer: Mutex<crate::transfer::TransferCache>,
    pub sync_runtime: Arc<Mutex<SyncRuntime>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            session: Arc::new(Mutex::new(Session::default())),
            auto: Mutex::new(crate::auto_sync::AutoSync::default()),
            transfer: Mutex::new(crate::transfer::TransferCache::default()),
            sync_runtime: Arc::new(Mutex::new(SyncRuntime::default())),
        }
    }
}

fn map_err(error: impl ToString) -> String {
    error.to_string()
}

pub(crate) fn lock_session(session: &Mutex<Session>) -> std::sync::MutexGuard<'_, Session> {
    session.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn lock_transfer(state: &AppState) -> std::sync::MutexGuard<'_, crate::transfer::TransferCache> {
    state.transfer.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn lock_runtime(state: &AppState) -> std::sync::MutexGuard<'_, SyncRuntime> {
    state.sync_runtime.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// New unlock generation only. Does not discard a backup or CSV preview.
pub(crate) fn invalidate_sync_runtime(state: &AppState) {
    lock_runtime(state).invalidate();
}

/// Lock, idle lock, master-password change, and sync-config change.
/// A pinned backup-restore token is kept by `TransferCache::clear`.
pub(crate) fn discard_transfer_and_runtime(state: &AppState) {
    lock_transfer(state).clear();
    lock_runtime(state).invalidate();
}

pub(crate) fn invalidate_runtime(state: &AppState) {
    discard_transfer_and_runtime(state);
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
    {
        let mut session = lock_session(&state.session);
        session.set_unlocked(vault, dek);
        let _ = session.take_lock_event();
    }
    invalidate_sync_runtime(&state);
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
            {
                let mut session = lock_session(&state.session);
                session.set_unlocked(vault, dek);
                apply_settings(&mut session);
                if let Ok(vault) = session.vault() {
                    crate::auto_sync::refresh_from_vault(&state, vault);
                }
                let _ = session.take_lock_event();
            }
            invalidate_sync_runtime(&state);
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
    {
        let mut session = lock_session(&state.session);
        session.set_unlocked(vault, dek);
        apply_settings(&mut session);
        if let Ok(vault) = session.vault() {
            crate::auto_sync::refresh_from_vault(&state, vault);
        }
        let _ = session.take_lock_event();
    }
    invalidate_sync_runtime(&state);
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
    {
        let mut session = lock_session(&state.session);
        session.lock();
        let _ = session.take_lock_event();
    }
    discard_transfer_and_runtime(&state);
    Ok(())
}

#[tauri::command]
pub fn tick_idle(state: State<AppState>) -> Result<bool, String> {
    let (locked, lock_event, unlocked) = {
        let mut session = lock_session(&state.session);
        let locked = session.maybe_idle_lock();
        if !locked && session.clipboard_deadline_due() {
            let current = clipboard::read_text().unwrap_or_default();
            if session.clipboard_should_clear(&current) {
                let _ = clipboard::clear();
                session.clear_clipboard_mark();
            }
        }
        let lock_event = session.take_lock_event();
        let unlocked = session.is_unlocked();
        (locked, lock_event, unlocked)
    };
    // No DEK means the first-run screen. Do not wipe its backup preview.
    if locked || lock_event {
        discard_transfer_and_runtime(&state);
    }
    Ok(locked || !unlocked)
}

#[tauri::command]
pub fn list_entries(state: State<AppState>, filter: ListFilter) -> Result<Vec<EntryDto>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .search_entries(&dek, &filter)
        .map_err(map_err)
}

#[tauri::command]
pub fn list_counts(state: State<AppState>, filter: ListFilter) -> Result<Counts, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .counts_for_search(&dek, &filter)
        .map_err(map_err)
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
pub fn merge_folders(state: State<AppState>, source_id: String, target_id: String) -> Result<usize, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.merge_folders(&source_id, &target_id).map_err(map_err)
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
pub fn rename_tag(state: State<AppState>, old_name: String, new_name: String) -> Result<(), String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.rename_tag(&old_name, &new_name).map_err(map_err)
}

#[tauri::command]
pub fn delete_tag(state: State<AppState>, name: String) -> Result<usize, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.delete_tag(&name).map_err(map_err)
}

#[tauri::command]
pub fn merge_tags(state: State<AppState>, source_name: String, target_name: String) -> Result<usize, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.merge_tags(&source_name, &target_name).map_err(map_err)
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

#[tauri::command]
pub fn entry_profile(state: State<AppState>, id: String) -> Result<EntryProfile, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let profile = session
        .vault()
        .map_err(map_err)?
        .entry_profile(&dek, &id)
        .map_err(map_err)?;
    let _ = session.vault().map_err(map_err)?.audit("view", Some(&id), "ok");
    Ok(profile)
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
    invalidate_runtime(&state);
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
    invalidate_runtime(&state);
    crate::auto_sync::apply(&state, false, sync::DEFAULT_AUTO_SYNC_SECS);
    Ok(())
}

#[tauri::command]
pub fn app_version() -> String {
    update::current_version()
}

#[tauri::command]
pub async fn check_mobile_update() -> Result<MobileRelease, String> {
    tauri::async_runtime::spawn_blocking(update::check)
        .await
        .map_err(|error| error.to_string())?
}

#[derive(Serialize)]
pub struct UpdateDownload {
    pub path: String,
    pub bytes: u64,
}

#[tauri::command]
pub async fn download_mobile_update(app: AppHandle, url: String) -> Result<UpdateDownload, String> {
    let dir = app
        .path()
        .app_cache_dir()
        .map_err(map_err)?;
    let emitter = app.clone();
    let path = tauri::async_runtime::spawn_blocking(move || {
        update::download(&url, &dir, |bytes, total| {
            let _ = emitter.emit(
                "mobile-update-progress",
                serde_json::json!({ "bytes": bytes, "total": total }),
            );
        })
    })
    .await
    .map_err(|error| error.to_string())??;
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
    // Start the system installer first: a failure must stay visible in the update dialog instead
    // of locking the vault and silently closing it.
    update::install_apk(&actual)?;
    {
        let mut session = lock_session(&state.session);
        session.lock();
    }
    invalidate_runtime(&state);
    let _ = app.emit("lock-now", ());
    Ok(())
}

#[tauri::command]
pub fn sync_now(app: AppHandle, state: State<AppState>) -> Result<SyncReport, String> {
    let (vault, dek) = open_unlocked_copy(&app, &state)?;
    let still_unlocked = || lock_session(&state.session).is_unlocked();
    let mut runtime = state.sync_runtime.lock().unwrap_or_else(|p| p.into_inner());
    sync::sync_now_with_runtime(&mut runtime, &vault, &dek, &still_unlocked)
}

#[derive(Serialize)]
pub struct DocumentRef {
    pub uri: String,
    pub name: String,
}

fn document_ref(document: Option<crate::saf::SelectedDocument>) -> Option<DocumentRef> {
    document.map(|document| DocumentRef { uri: document.uri, name: document.name })
}

#[tauri::command]
pub fn document_open(app: AppHandle, mime_types: Vec<String>) -> Result<Option<DocumentRef>, String> {
    let types: Vec<&str> = mime_types.iter().map(String::as_str).collect();
    let selected = tauri::async_runtime::block_on(crate::saf::pick_open(&app, &types))?;
    Ok(document_ref(selected))
}

#[tauri::command]
pub fn document_save(app: AppHandle, suggested_name: String, mime: String) -> Result<Option<DocumentRef>, String> {
    let selected = tauri::async_runtime::block_on(crate::saf::pick_save(&app, &suggested_name, &mime))?;
    Ok(document_ref(selected))
}

const MAX_CSV_BYTES: usize = 5 * 1024 * 1024;

#[derive(Serialize)]
pub struct BackupPreview {
    pub token: String,
    pub summary: backup::BackupInspection,
}

#[derive(Serialize)]
pub struct CsvPreview {
    pub token: String,
    pub summary: csv::CsvImportPreview,
}

#[tauri::command]
pub fn backup_inspect(app: AppHandle, state: State<AppState>, uri: String, backup_password: String) -> Result<BackupPreview, String> {
    let bytes = tauri::async_runtime::block_on(crate::saf::read(&app, &uri, backup::MAX_BACKUP_BYTES))?;
    let summary = backup::inspect(&bytes, &backup_password).map_err(map_err)?;
    let token = state.transfer.lock().unwrap_or_else(|p| p.into_inner()).put_backup(bytes, backup_password)?;
    Ok(BackupPreview { token, summary })
}

#[derive(Serialize)]
pub struct RestoreResult {
    pub imported: usize,
    pub skipped: usize,
}

#[tauri::command]
pub fn backup_restore(state: State<AppState>, token: String, overwrite: bool, restore_settings: bool) -> Result<RestoreResult, String> {
    let result = {
        let mut session = lock_session(&state.session);
        session.require_unlocked().map_err(map_err)?;
        let (bytes, password) = lock_transfer(&state).take_backup(&token)?;
        let dek = *session.dek().map_err(map_err)?;
        backup::restore_into_with_options(
            session.vault().map_err(map_err)?,
            &dek,
            &bytes,
            &password,
            RestoreOptions { overwrite, restore_settings },
        )
        .map_err(map_err)?
    };
    invalidate_sync_runtime(&state);
    Ok(RestoreResult { imported: result.0, skipped: result.1 })
}

#[tauri::command]
pub fn backup_restore_new(
    app: AppHandle,
    state: State<AppState>,
    token: String,
    new_password: Option<String>,
    restore_settings: bool,
) -> Result<RestoreResult, String> {
    let path = vault_path(&app)?;
    let path = path.to_str().ok_or("金库路径无效")?.to_string();
    if Vault::exists(&path) {
        return Err("金库文件已存在，请解锁后合并恢复".into());
    }
    // Pin before copying the bytes out. Lock and the idle tick must not drop
    // this token, and this command must not lock or create an empty vault.
    lock_transfer(&state).pin_backup(&token)?;
    let (bytes, password) = lock_transfer(&state).take_backup(&token)?;
    if Vault::exists(&path) {
        return Err("金库文件已存在，请解锁后合并恢复".into());
    }
    let mut dek = backup::restore_new_with_options(
        &path,
        &bytes,
        &password,
        new_password.as_deref(),
        RestoreOptions { overwrite: true, restore_settings },
    )
    .map_err(map_err)?;
    dek.zeroize();
    let counts = Vault::open(&path).map_err(map_err)?.counts().map_err(map_err)?;
    let imported = usize::try_from(counts.total.max(0)).unwrap_or(0)
        + usize::try_from(counts.trash.max(0)).unwrap_or(0);
    Ok(RestoreResult { imported, skipped: 0 })
}

#[tauri::command]
pub fn backup_export(app: AppHandle, state: State<AppState>, uri: String, password: String, include_settings: bool) -> Result<(), String> {
    let bytes = {
        let mut session = lock_session(&state.session);
        session.require_unlocked().map_err(map_err)?;
        let dek = *session.dek().map_err(map_err)?;
        backup::export(session.vault().map_err(map_err)?, &dek, &password, include_settings).map_err(map_err)?
    };
    tauri::async_runtime::block_on(crate::saf::write_new(&app, &uri, bytes))
}

#[tauri::command]
pub fn csv_preview(app: AppHandle, state: State<AppState>, uri: String) -> Result<CsvPreview, String> {
    let bytes = tauri::async_runtime::block_on(crate::saf::read(&app, &uri, MAX_CSV_BYTES))?;
    let summary = {
        let mut session = lock_session(&state.session);
        session.require_unlocked().map_err(map_err)?;
        let dek = *session.dek().map_err(map_err)?;
        csv::preview_bytes(session.vault().map_err(map_err)?, &dek, &bytes).map_err(map_err)?
    };
    let token = state.transfer.lock().unwrap_or_else(|p| p.into_inner()).put_csv(bytes)?;
    Ok(CsvPreview { token, summary })
}

#[tauri::command]
pub fn csv_commit(state: State<AppState>, token: String, password: String, risk_confirmed: bool, overwrite: bool) -> Result<csv::CsvImportResult, String> {
    if !risk_confirmed {
        return Err("请确认 CSV 明文风险后再继续".into());
    }
    {
        let mut session = lock_session(&state.session);
        session.require_unlocked().map_err(map_err)?;
        let dek = *session.dek().map_err(map_err)?;
        let mut opened = session
            .vault()
            .map_err(map_err)?
            .unlock(&password)
            .map_err(|_| "主密码不正确".to_string())?;
        let matches = opened == dek;
        opened.zeroize();
        if !matches {
            return Err("主密码不正确".into());
        }
    }
    let bytes = lock_transfer(&state).take_csv(&token)?;
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    csv::commit_rows(session.vault().map_err(map_err)?, &dek, &bytes, overwrite).map_err(map_err)
}

#[tauri::command]
pub fn csv_export(app: AppHandle, state: State<AppState>, uri: String, password: String, risk_confirmed: bool) -> Result<(), String> {
    if !risk_confirmed {
        return Err("请确认 CSV 明文风险后再继续".into());
    }
    let bytes = {
        let mut session = lock_session(&state.session);
        session.require_unlocked().map_err(map_err)?;
        let dek = *session.dek().map_err(map_err)?;
        let mut opened = session
            .vault()
            .map_err(map_err)?
            .unlock(&password)
            .map_err(|_| "主密码不正确".to_string())?;
        let matches = opened == dek;
        opened.zeroize();
        if !matches {
            return Err("主密码不正确".into());
        }
        csv::export_websites(session.vault().map_err(map_err)?, &dek, &password).map_err(map_err)?
    };
    tauri::async_runtime::block_on(crate::saf::write_new(&app, &uri, bytes))
}

#[tauri::command]
pub fn change_master(state: State<AppState>, old_password: String, new_password: String) -> Result<(), String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let mut dek = *session.dek().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .change_master_password(&dek, &old_password, &new_password)
        .map_err(map_err)?;
    dek.zeroize();
    session
        .vault()
        .map_err(map_err)?
        .set_setting("biometry_enabled", "0")
        .map_err(map_err)?;
    session.lock();
    let _ = session.take_lock_event();
    drop(session);
    discard_transfer_and_runtime(&state);
    Ok(())
}

#[tauri::command]
pub fn import_client_cert(
    app: AppHandle,
    state: State<AppState>,
    input: Value,
    cert_uri: Option<String>,
    key_uri: Option<String>,
    passphrase: Option<String>,
) -> Result<EntryDto, String> {
    let meta: ClientCertMeta = serde_json::from_value(input).map_err(|_| "证书资料无效".to_string())?;
    match (present_uri(cert_uri), present_uri(key_uri)) {
        (None, None) => update_client_cert_metadata(&state, &meta),
        (Some(cert_uri), Some(key_uri)) => {
            import_client_cert_files(&app, &state, meta, &cert_uri, &key_uri, passphrase)
        }
        _ => Err("请同时选择证书与私钥，或不选择以保留原证书".into()),
    }
}

#[derive(Deserialize)]
struct ClientCertMeta {
    #[serde(default)]
    id: Option<String>,
    title: String,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    folder_id: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    pinned: bool,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    notes: Option<String>,
}

fn present_uri(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() { None } else { Some(trimmed) }
    })
}

fn read_pem(app: &AppHandle, uri: &str, max_bytes: usize, label: &str) -> Result<zeroize::Zeroizing<String>, String> {
    let bytes = tauri::async_runtime::block_on(crate::saf::read(app, uri, max_bytes))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| format!("{label}不是有效的 UTF-8 文本"))?;
    Ok(zeroize::Zeroizing::new(text.to_string()))
}

/// Metadata only. The stored ciphertext, including the private key, stays untouched.
fn update_client_cert_metadata(state: &AppState, meta: &ClientCertMeta) -> Result<EntryDto, String> {
    let id = meta
        .id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .ok_or("请先选择要更新的证书条目")?;
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .update_entry_metadata(
            &dek,
            id,
            &meta.title,
            meta.account.as_deref(),
            meta.url.as_deref(),
            meta.folder_id.as_deref(),
            &meta.tags,
            meta.pinned,
            meta.expires_at.as_deref(),
            meta.notes.as_deref(),
        )
        .map_err(map_err)
}

fn import_client_cert_files(
    app: &AppHandle,
    state: &AppState,
    meta: ClientCertMeta,
    cert_uri: &str,
    key_uri: &str,
    passphrase: Option<String>,
) -> Result<EntryDto, String> {
    let cert = read_pem(app, cert_uri, sealbox_core::certificate::MAX_CERT_PEM_BYTES, "客户端证书")?;
    let key = read_pem(app, key_uri, sealbox_core::certificate::MAX_KEY_PEM_BYTES, "客户端私钥")?;
    let (cert_pem, key_pem, passphrase, _) =
        sealbox_core::certificate::prepare_client_cert(&cert, &key, passphrase.as_deref()).map_err(map_err)?;
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .upsert_entry(
            &dek,
            UpsertEntry {
                id: meta.id,
                kind: sealbox_core::vault::EntryKind::ClientCert,
                title: meta.title,
                account: meta.account,
                url: meta.url,
                folder_id: meta.folder_id,
                tags: meta.tags,
                pinned: meta.pinned,
                expires_at: meta.expires_at,
                notes: meta.notes,
                secret: SecretPayload::ClientCert { cert_pem, key_pem, passphrase },
            },
        )
        .map_err(map_err)
}

#[derive(Deserialize)]
pub struct SyncCommitInput { pub id: String, pub choice: sync::ConflictChoice, pub confirm_delete_edit: bool }

#[tauri::command]
pub fn sync_preview(app: AppHandle, state: State<AppState>) -> Result<sync::SyncPreview, String> {
    let (vault, dek) = open_unlocked_copy(&app, &state)?;
    state.sync_runtime.lock().unwrap_or_else(|p| p.into_inner()).preview(&vault, &dek)
}

#[tauri::command]
pub fn sync_commit(app: AppHandle, state: State<AppState>, token: String, resolutions: Vec<SyncCommitInput>) -> Result<SyncReport, String> {
    let (vault, dek) = open_unlocked_copy(&app, &state)?;
    let choices = resolutions.into_iter().map(|r| sync::SyncResolution { id: r.id, choice: r.choice, confirm_delete_edit: r.confirm_delete_edit }).collect::<Vec<_>>();
    let still_unlocked = || lock_session(&state.session).is_unlocked();
    state.sync_runtime.lock().unwrap_or_else(|p| p.into_inner()).commit(&vault, &dek, &token, &choices, &still_unlocked)
}

fn open_unlocked_copy(app: &AppHandle, state: &AppState) -> Result<(Vault, [u8; 32]), String> {
    let dek = {
        let mut session = lock_session(&state.session);
        session.require_unlocked().map_err(map_err)?;
        *session.dek().map_err(map_err)?
    };
    let path = vault_path(app)?;
    let vault = Vault::open(path.to_str().unwrap_or_default()).map_err(map_err)?;
    Ok((vault, dek))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailListRequest {
    pub entry_id: String,
    pub before_uid: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailBodyRequest {
    pub entry_id: String,
    pub uid: u32,
}

fn load_mail_auth(state: &AppState, id: &str) -> Result<(String, String, zeroize::Zeroizing<String>), String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let payload = session.vault().map_err(map_err)?.get_active_secret(&dek, id).map_err(map_err)?;
    match payload {
        SecretPayload::MailAuth { email, provider, auth_code } => Ok((email, provider, zeroize::Zeroizing::new(auth_code))),
        _ => Err("不是邮箱授权码".into()),
    }
}

#[tauri::command]
pub fn mail_accounts(state: State<AppState>) -> Result<Vec<sealbox_core::mail::MailAccount>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let filter = ListFilter {
        kind: Some(sealbox_core::vault::EntryKind::MailAuth),
        ..ListFilter::default()
    };
    let entries = vault.list_entries(&filter).map_err(map_err)?;
    entries
        .into_iter()
        .map(|entry| {
            let payload = vault.get_active_secret(&dek, &entry.id).map_err(map_err)?;
            let SecretPayload::MailAuth { email, provider, .. } = payload else {
                return Err("不是邮箱授权码".into());
            };
            Ok(sealbox_core::mail::MailAccount {
                id: entry.id,
                title: entry.title,
                email,
                provider: provider.clone(),
                supported: sealbox_core::mail::endpoint(&provider).is_some(),
            })
        })
        .collect()
}

#[tauri::command]
pub fn mail_list(state: State<AppState>, request: MailListRequest) -> Result<Vec<sealbox_core::mail::MailMessage>, String> {
    let (email, provider, auth_code) = load_mail_auth(&state, &request.entry_id)?;
    let Some((host, port)) = sealbox_core::mail::endpoint(&provider) else {
        return Err(sealbox_core::mail::failure_message(sealbox_core::mail::MailFailure::Unsupported).into());
    };
    let mut io = sealbox_core::mail::connect_tls(host, port, std::time::Duration::from_secs(20))
        .map_err(sealbox_core::mail::failure_message)?;
    let messages = sealbox_core::mail::list_inbox(&mut io, &email, &auth_code, request.before_uid, 50)
        .map_err(sealbox_core::mail::failure_message)?;
    drop(auth_code);
    let session = lock_session(&state.session);
    session.vault().map_err(map_err)?.audit("mail_list", Some(&request.entry_id), "").map_err(map_err)?;
    Ok(messages)
}

#[tauri::command]
pub fn mail_body(state: State<AppState>, request: MailBodyRequest) -> Result<sealbox_core::mail::MailBody, String> {
    let (email, provider, auth_code) = load_mail_auth(&state, &request.entry_id)?;
    let Some((host, port)) = sealbox_core::mail::endpoint(&provider) else {
        return Err(sealbox_core::mail::failure_message(sealbox_core::mail::MailFailure::Unsupported).into());
    };
    let mut io = sealbox_core::mail::connect_tls(host, port, std::time::Duration::from_secs(20))
        .map_err(sealbox_core::mail::failure_message)?;
    let body = sealbox_core::mail::fetch_body(&mut io, &email, &auth_code, request.uid)
        .map_err(sealbox_core::mail::failure_message)?;
    drop(auth_code);
    let session = lock_session(&state.session);
    session.vault().map_err(map_err)?.audit("mail_body", Some(&request.entry_id), "").map_err(map_err)?;
    Ok(body)
}

#[tauri::command]
pub fn sync_verify_conditional(app: AppHandle, state: State<AppState>) -> Result<sync::ConditionalSupportReport, String> {
    let (vault, dek) = open_unlocked_copy(&app, &state)?;
    let still_unlocked = || lock_session(&state.session).is_unlocked();
    sync::verify_conditional_support(&vault, &dek, &still_unlocked)
}
