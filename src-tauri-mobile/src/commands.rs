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
    let clip = {
        let Ok(vault) = session.vault() else {
            return;
        };
        setting_u64(vault, "clipboard_secs", 20).clamp(5, 120)
    };
    session.clipboard_secs = clip;
}

fn persist_settings(session: &Session) -> Result<(), String> {
    let vault = session.vault().map_err(map_err)?;
    vault
        .set_setting("clipboard_secs", &session.clipboard_secs.to_string())
        .map_err(map_err)
}

#[tauri::command]
pub fn credential_profile_get(
    state: State<AppState>,
    id: String,
) -> Result<Option<sealbox_core::profile::CredentialProfile>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = session.dek().map_err(map_err)?;
    session.vault().map_err(map_err)?.credential_profile(dek, &id).map_err(map_err)
}

#[tauri::command]
pub fn credential_profile_set(
    state: State<AppState>,
    id: String,
    profile: Option<sealbox_core::profile::CredentialProfile>,
) -> Result<Option<sealbox_core::profile::CredentialProfile>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    vault.set_credential_profile(&dek, &id, profile.as_ref()).map_err(map_err)?;
    let _ = vault.audit("credential_profile", Some(&id), if profile.is_some() { "set" } else { "reset" });
    vault.credential_profile(&dek, &id).map_err(map_err)
}

#[tauri::command]
pub fn credential_profile_reset(
    state: State<AppState>,
    id: String,
) -> Result<Option<sealbox_core::profile::CredentialProfile>, String> {
    credential_profile_set(state, id, None)
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
pub fn tick_idle(state: State<AppState>) -> Result<bool, String> {
    let mut session = lock_session(&state.session);
    if session.clipboard_deadline_due() {
        let current = clipboard::read_text().unwrap_or_default();
        if session.clipboard_should_clear(&current) {
            let _ = clipboard::clear();
            session.clear_clipboard_mark();
        }
    }
    let _ = session.take_lock_event();
    Ok(!session.is_unlocked())
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
    // 桌面端同样记录复制动作；手机端缺了这条，秘密外流就完全无痕。
    let _ = session.vault().map_err(map_err)?.audit("copy", Some(&id), &field);
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
    let _ = session.vault().map_err(map_err)?.audit("reveal", Some(&id), "ok");
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
    pub clipboard_secs: u64,
    pub biometry_enabled: bool,
}

#[tauri::command]
pub fn settings_get(state: State<AppState>) -> Result<SettingsView, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    apply_settings(&mut session);
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
        clipboard_secs,
        biometry_enabled,
    })
}

#[tauri::command]
pub fn settings_set(state: State<AppState>, clipboard_secs: u64) -> Result<(), String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.clipboard_secs = clipboard_secs.clamp(5, 120);
    persist_settings(&session)
}

#[tauri::command]
pub fn sync_status(state: State<AppState>) -> Result<SyncView, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    sync::view_with_dek(session.vault().map_err(map_err)?, &dek)
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
        (sync::view_with_dek(vault, &dek)?, auto)
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

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailListRequest {
    pub entry_id: String,
    #[serde(default)]
    pub folder: Option<String>,
    pub before_uid: Option<u32>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub keyword: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailBodyRequest {
    pub entry_id: String,
    pub uid: u32,
    #[serde(default)]
    pub folder: Option<String>,
    /// Record the read in the local cache once the body is served. Defaults to true, and never
    /// reaches the server: the folder is opened read-only and the body is fetched `BODY.PEEK`.
    #[serde(default = "mail_mark_seen_default")]
    pub mark_seen: bool,
}

/// Defaults to `true`: reading a message marks it read locally, as the reader always has.
fn mail_mark_seen_default() -> bool {
    true
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailPrefetchRequest {
    pub entry_id: String,
    #[serde(default)]
    pub folder: Option<String>,
    /// Capped at [`MAIL_PREFETCH_LIMIT`]; omitted uses that same cap.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// How many bodies one prefetch pass may fetch. Eight keeps a pass short enough that the phone
/// stays responsive while it runs.
const MAIL_PREFETCH_LIMIT: u32 = 8;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailFoldersRequest {
    pub entry_id: String,
    #[serde(default)]
    pub refresh: bool,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailAttachmentRequest {
    pub entry_id: String,
    pub uid: u32,
    #[serde(default)]
    pub folder: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailSaveAttachmentRequest {
    pub entry_id: String,
    pub uid: u32,
    pub part: String,
    /// A SAF content URI on Android, or an absolute path when one is supplied.
    pub path: String,
    #[serde(default)]
    pub folder: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailProbeRequest {
    pub entry_id: Option<String>,
    pub email: Option<String>,
    pub secret: Option<String>,
    pub imap_host: Option<String>,
    pub imap_port: Option<u16>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailProbeReport {
    pub host: String,
    pub port: u16,
    pub folders: Vec<sealbox_core::mail::MailFolder>,
    pub unread: u32,
}

/// A page of a folder as the reader receives it. `cached` means the rows came from the local
/// store, `fetchedAt` is the newest cache write (ISO-8601) or `null` for a live page.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailListResult {
    pub messages: Vec<sealbox_core::mail::MailMessage>,
    pub cached: bool,
    pub fetched_at: Option<String>,
}

/// A resolved mailbox. The IMAP host always comes from the vault entry, never from the request.
struct MailSession {
    account: sealbox_core::mail::MailAccount,
    email: String,
    secret: zeroize::Zeroizing<String>,
    host: String,
    port: u16,
}

fn mail_endpoint_for(payload: &SecretPayload) -> Option<(String, u16)> {
    match payload {
        SecretPayload::MailAuth { provider, .. } => sealbox_core::mail_provider::server_for_provider(provider),
        SecretPayload::Mailbox { email, imap_host, imap_port, .. } => {
            sealbox_core::mail_provider::server_for_mailbox(email, imap_host.as_deref(), *imap_port)
        }
        _ => None,
    }
}

fn mail_session_from(payload: &SecretPayload, id: &str, title: &str) -> Option<MailSession> {
    let (email, provider, secret) = match payload {
        SecretPayload::MailAuth { email, provider, auth_code } => {
            (email.clone(), provider.clone(), auth_code.clone())
        }
        SecretPayload::Mailbox { email, password, .. } => (email.clone(), "custom".to_string(), password.clone()),
        _ => return None,
    };
    let endpoint = mail_endpoint_for(payload);
    let account = sealbox_core::mail::MailAccount {
        id: id.to_string(),
        title: title.to_string(),
        email: email.clone(),
        provider: provider.clone(),
        provider_label: sealbox_core::mail_provider::provider_label(&provider).to_string(),
        supported: endpoint.is_some(),
    };
    let (host, port) = endpoint.unwrap_or_default();
    Some(MailSession { account, email, secret: zeroize::Zeroizing::new(secret), host, port })
}

fn load_mail_session(state: &AppState, id: &str) -> Result<MailSession, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let payload = vault.get_active_secret(&dek, id).map_err(map_err)?;
    let title = vault
        .list_entries(&sealbox_core::vault::ListFilter::default())
        .ok()
        .and_then(|entries| entries.into_iter().find(|entry| entry.id == id))
        .map(|entry| entry.title)
        .unwrap_or_default();
    mail_session_from(&payload, id, &title).ok_or_else(|| "不是邮箱账号".to_string())
}

/// The same resolution for callers that already hold a session guard: the background prefetch
/// takes the lock itself, so it cannot borrow the `State` version without deadlocking on it.
fn load_mail_session_with(vault: &Vault, dek: &[u8; 32], id: &str) -> Result<MailSession, String> {
    let payload = vault.get_active_secret(dek, id).map_err(map_err)?;
    let title = vault
        .list_entries(&sealbox_core::vault::ListFilter::default())
        .ok()
        .and_then(|entries| entries.into_iter().find(|entry| entry.id == id))
        .map(|entry| entry.title)
        .unwrap_or_default();
    mail_session_from(&payload, id, &title).ok_or_else(|| "不是邮箱账号".to_string())
}

fn mail_connect(session: &MailSession) -> Result<sealbox_core::mail::TlsImap, String> {
    if !session.account.supported {
        return Err(sealbox_core::mail::failure_message(sealbox_core::mail::MailFailure::Unsupported).into());
    }
    sealbox_core::mail::connect_tls(&session.host, session.port, std::time::Duration::from_secs(20))
        .map_err(|failure| sealbox_core::mail::failure_message(failure).to_string())
}

fn mail_audit(state: &AppState, action: &str, entry_id: &str, detail: &str) {
    let session = lock_session(&state.session);
    if let Ok(vault) = session.vault() {
        let _ = vault.audit(action, Some(entry_id), detail);
    }
}

fn folder_or_inbox(folder: &Option<String>) -> String {
    match folder.as_deref().map(str::trim) {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => "INBOX".to_string(),
    }
}

/// A folder's live unread count, or 0 when the store cannot answer (locked vault).
fn vault_mail_folder_unread(
    session: &std::sync::MutexGuard<'_, Session>,
    entry_id: &str,
    folder: &str,
) -> u32 {
    session
        .vault()
        .ok()
        .and_then(|vault| vault.mail_folder_unread(entry_id, folder).ok())
        .unwrap_or(0)
}

fn static_role(role: &str) -> &'static str {
    match role {
        "inbox" => "inbox",
        "sent" => "sent",
        "drafts" => "drafts",
        "archive" => "archive",
        "trash" => "trash",
        _ => "other",
    }
}

#[tauri::command]
pub fn mail_accounts(state: State<AppState>) -> Result<Vec<sealbox_core::mail::MailAccount>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let entries = vault
        .list_entries(&sealbox_core::vault::ListFilter::default())
        .map_err(map_err)?;
    let mut accounts = Vec::new();
    for entry in entries {
        if entry.kind != sealbox_core::vault::EntryKind::MailAuth
            && entry.kind != sealbox_core::vault::EntryKind::Mailbox
        {
            continue;
        }
        let payload = vault.get_active_secret(&dek, &entry.id).map_err(map_err)?;
        if let Some(found) = mail_session_from(&payload, &entry.id, &entry.title) {
            accounts.push(found.account);
        }
    }
    Ok(accounts)
}

#[tauri::command]
pub fn mail_folders(
    state: State<AppState>,
    request: MailFoldersRequest,
) -> Result<Vec<sealbox_core::mail::MailFolder>, String> {
    let mail = load_mail_session(&state, &request.entry_id)?;
    if !request.refresh {
        let session = lock_session(&state.session);
        let cached = session
            .vault()
            .map_err(map_err)?
            .mail_cached_folders(&request.entry_id)
            .map_err(map_err)?;
        if !cached.is_empty() {
            return Ok(cached
                .into_iter()
                .map(|folder| sealbox_core::mail::MailFolder {
                    display: sealbox_core::mail_folder::role_display(&folder.role),
                    // Live count, not the stored snapshot: a folder listed before any sync has no
                    // snapshot, and a snapshot the user cannot act on is worse than a live count.
                    unread: vault_mail_folder_unread(&session, &request.entry_id, &folder.name),
                    name: folder.name,
                    role: static_role(&folder.role),
                })
                .collect());
        }
    }
    let mut io = mail_connect(&mail)?;
    let mut folders = sealbox_core::mail::list_folders(&mut io, &mail.email, &mail.secret)
        .map_err(sealbox_core::mail::failure_message)?;
    {
        let session = lock_session(&state.session);
        let vault = session.vault().map_err(map_err)?;
        vault.mail_save_folders(&request.entry_id, &folders).map_err(map_err)?;
        // Every number comes from the live local count, so the folder row, the badge and the
        // list always agree.
        for folder in folders.iter_mut() {
            folder.unread = vault.mail_folder_unread(&request.entry_id, &folder.name).unwrap_or(0);
        }
    }
    mail_audit(&state, "mail_folders", &request.entry_id, "");
    Ok(folders)
}

/// One page of a folder, cache first: a folder that has been opened before is served from
/// SQLite without touching TLS, and only an empty cache pays for a round trip. There is no
/// background refresher on Android (a phone may be on a metered link), so `mail_sync` is the
/// caller's way to pull new mail.
#[tauri::command]
pub fn mail_list(state: State<AppState>, request: MailListRequest) -> Result<MailListResult, String> {
    let folder = folder_or_inbox(&request.folder);
    let filter = sealbox_core::mail_folder::MailFilter::parse(request.filter.as_deref().unwrap_or(""))
        .ok_or_else(|| "未知的筛选条件".to_string())?;
    let local_filter = sealbox_core::mail_store::LocalFilter::parse(filter.as_str())
        .ok_or_else(|| "未知的筛选条件".to_string())?;
    let keyword = request.keyword.clone().unwrap_or_default();
    {
        let mut session = lock_session(&state.session);
        session.require_unlocked().map_err(map_err)?;
        let cached = session
            .vault()
            .map_err(map_err)?
            .mail_list_local(
                &request.entry_id,
                &folder,
                request.before_uid,
                50,
                local_filter,
                &keyword,
            )
            .map_err(map_err)?;
        if !cached.is_empty() {
            let fetched_at = session
                .vault()
                .map_err(map_err)?
                .mail_page_fetched_at(&request.entry_id, &folder)
                .map_err(map_err)?;
            return Ok(MailListResult {
                messages: cached.into_iter().map(cached_to_message).collect(),
                cached: true,
                fetched_at,
            });
        }
    }
    let mail = load_mail_session(&state, &request.entry_id)?;
    let mut io = mail_connect(&mail)?;
    let messages = sealbox_core::mail::list_folder(
        &mut io,
        &mail.email,
        &mail.secret,
        &folder,
        request.before_uid,
        50,
        filter,
        &keyword,
    )
    .map_err(sealbox_core::mail::failure_message)?;
    // Nothing to store, but the answer is still live: the server just said this page is empty.
    if messages.is_empty() {
        return Ok(MailListResult { messages, cached: false, fetched_at: None });
    }
    {
        let session = lock_session(&state.session);
        let vault = session.vault().map_err(map_err)?;
        let previews = vec![String::new(); messages.len()];
        vault
            .mail_upsert_messages(&request.entry_id, &folder, &messages, &previews)
            .map_err(map_err)?;
    }
    mail_audit(&state, "mail_list", &request.entry_id, "");
    Ok(MailListResult { messages, cached: false, fetched_at: None })
}

/// A cached row as the reader expects it: merged read state plus the teaser the cache already
/// holds. The teaser is the only thing a live page cannot supply, so it is the only thing a
/// cached page adds.
fn cached_to_message(cached: sealbox_core::mail_store::CachedMessage) -> sealbox_core::mail::MailMessage {
    sealbox_core::mail::MailMessage {
        uid: cached.uid,
        from: cached.from,
        subject: cached.subject,
        date: cached.date,
        has_attachment: cached.has_attachment,
        seen: cached.seen,
        flagged: cached.flagged,
        preview: sealbox_core::mail_store::clamp_preview(&cached.preview),
    }
}

#[tauri::command]
pub fn mail_body(state: State<AppState>, request: MailBodyRequest) -> Result<sealbox_core::mail::MailBody, String> {
    let folder = folder_or_inbox(&request.folder);
    {
        let session = lock_session(&state.session);
        if let Ok(vault) = session.vault() {
            if let Some(body) = vault
                .mail_cached_body(&request.entry_id, &folder, request.uid)
                .map_err(map_err)?
            {
                if request.mark_seen {
                    let _ = vault.mail_mark_local_seen(&request.entry_id, &folder, request.uid);
                }
                return Ok(body);
            }
        }
    }
    let mail = load_mail_session(&state, &request.entry_id)?;
    let mut io = mail_connect(&mail)?;
    let body = sealbox_core::mail::fetch_body_in(&mut io, &mail.email, &mail.secret, &folder, request.uid)
        .map_err(sealbox_core::mail::failure_message)?;
    {
        let session = lock_session(&state.session);
        if let Ok(vault) = session.vault() {
            let _ = vault.mail_save_body(&request.entry_id, &folder, request.uid, &body);
            if request.mark_seen {
                let _ = vault.mail_mark_local_seen(&request.entry_id, &folder, request.uid);
            }
        }
    }
    mail_audit(&state, "mail_body", &request.entry_id, "");
    Ok(body)
}

/// Warms the body cache for the newest messages of a folder that have none yet.
///
/// Returns immediately and does the work on a background thread: this is fired on entering the
/// reader, and a pass over eight large messages would otherwise keep grabbing the session lock
/// while the phone is trying to render. The worker builds its own IMAP connection and only takes
/// the lock to read candidates and to store each body — never across a network round trip.
///
/// The count cannot be known before the pass runs, so the return value is the number of passes
/// *accepted*: 1 when this call queued one, 0 when one for the same account+folder was already
/// running. There is no event channel to report the body count on Android, so the result is not
/// surfaced; the reader simply finds the bodies already cached.
///
/// Read-only towards the mailbox: `BODY.PEEK` and a read-only folder, cache writes only.
#[tauri::command]
pub fn mail_prefetch(state: State<AppState>, request: MailPrefetchRequest) -> Result<u32, String> {
    let folder = folder_or_inbox(&request.folder);
    let limit = request.limit.unwrap_or(MAIL_PREFETCH_LIMIT).clamp(1, MAIL_PREFETCH_LIMIT) as usize;
    let key = format!("prefetch:{}:{}", request.entry_id, folder);
    if !mail_prefetch_lock().acquire(&key) {
        return Ok(0);
    }
    let session = Arc::clone(&state.session);
    let entry_id = request.entry_id.clone();
    std::thread::spawn(move || {
        let run = || -> Result<(), String> {
            let candidates = {
                let mut guard = session.lock().unwrap_or_else(|poison| poison.into_inner());
                guard.require_unlocked().map_err(map_err)?;
                guard
                    .vault()
                    .map_err(map_err)?
                    .mail_prefetch_candidates(&entry_id, &folder, limit)
                    .map_err(map_err)?
            };
            if candidates.is_empty() {
                return Ok(());
            }
            let mail = {
                let mut guard = session.lock().unwrap_or_else(|poison| poison.into_inner());
                guard.require_unlocked().map_err(map_err)?;
                let dek = *guard.dek().map_err(map_err)?;
                let vault = guard.vault().map_err(map_err)?;
                load_mail_session_with(vault, &dek, &entry_id)?
            };
            let mut io = mail_connect(&mail)?;
            for uid in candidates {
                // One unreachable message must not abort the rest of the pass.
                let Ok(body) =
                    sealbox_core::mail::fetch_body_in(&mut io, &mail.email, &mail.secret, &folder, uid)
                else {
                    continue;
                };
                let guard = session.lock().unwrap_or_else(|poison| poison.into_inner());
                let Ok(vault) = guard.vault() else { continue };
                let _ = vault.mail_save_body(&entry_id, &folder, uid, &body);
            }
            Ok(())
        };
        let _ = run();
        mail_prefetch_lock().release(&key);
    });
    Ok(1)
}

/// One prefetch pass per account+folder at a time; repeated calls are folded into the running
/// pass instead of queueing more network work.
fn mail_prefetch_lock() -> &'static MailPrefetchLock {
    static LOCK: std::sync::OnceLock<MailPrefetchLock> = std::sync::OnceLock::new();
    LOCK.get_or_init(MailPrefetchLock::default)
}

#[derive(Default)]
struct MailPrefetchLock {
    busy: Mutex<std::collections::HashSet<String>>,
}

impl MailPrefetchLock {
    /// `true` when the caller now owns the key and must release it.
    fn acquire(&self, key: &str) -> bool {
        let mut busy = self.busy.lock().unwrap_or_else(|poison| poison.into_inner());
        busy.insert(key.to_string())
    }

    fn release(&self, key: &str) {
        let mut busy = self.busy.lock().unwrap_or_else(|poison| poison.into_inner());
        busy.remove(key);
    }
}

/// Unread per role from the local cache, so every folder number and the badge agree.
#[tauri::command]
pub fn mail_unread_by_role(state: State<AppState>) -> Result<sealbox_core::mail_store::UnreadByRole, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.mail_unread_by_role().map_err(map_err)
}

#[tauri::command]
pub fn mail_attachments(
    state: State<AppState>,
    request: MailAttachmentRequest,
) -> Result<Vec<sealbox_core::mail::MailAttachment>, String> {
    let mail = load_mail_session(&state, &request.entry_id)?;
    let folder = folder_or_inbox(&request.folder);
    let mut io = mail_connect(&mail)?;
    let attachments = sealbox_core::mail::list_attachments_in(&mut io, &mail.email, &mail.secret, &folder, request.uid)
        .map_err(sealbox_core::mail::failure_message)?;
    mail_audit(&state, "mail_attachments", &request.entry_id, "");
    Ok(attachments)
}

#[tauri::command]
pub fn mail_save_attachment(
    app: AppHandle,
    state: State<AppState>,
    request: MailSaveAttachmentRequest,
) -> Result<u64, String> {
    let mail = load_mail_session(&state, &request.entry_id)?;
    let folder = folder_or_inbox(&request.folder);
    let mut io = mail_connect(&mail)?;
    let bytes = sealbox_core::mail::fetch_attachment_in(&mut io, &mail.email, &mail.secret, &folder, request.uid, &request.part)
        .map_err(sealbox_core::mail::failure_message)?;
    // The picker hands back a `content://` URI, so the write goes through SAF, same as the other
    // document exports.
    let len = bytes.len() as u64;
    tauri::async_runtime::block_on(crate::saf::write_new(&app, &request.path, bytes))?;
    mail_audit(
        &state,
        "mail_save_attachment",
        &request.entry_id,
        &format!("part={}", request.part),
    );
    Ok(len)
}

#[tauri::command]
pub fn mail_discover(request: MailDiscoverRequest) -> Result<sealbox_core::mail_provider::DiscoveredServer, String> {
    sealbox_core::mail_provider::auto_detect(request.email.trim()).ok_or_else(|| "请输入有效的邮箱地址".to_string())
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailDiscoverRequest {
    pub email: String,
}

#[tauri::command]
pub fn mail_test(state: State<AppState>, request: MailProbeRequest) -> Result<MailProbeReport, String> {
    let (email, secret, host, port) = match request.entry_id.as_deref().filter(|id| !id.is_empty()) {
        Some(id) => {
            let mail = load_mail_session(&state, id)?;
            (mail.email.clone(), mail.secret.to_string(), mail.host.clone(), mail.port)
        }
        None => {
            let email = request.email.clone().unwrap_or_default();
            let secret = request.secret.clone().unwrap_or_default();
            let (host, port) = sealbox_core::mail_provider::server_for_mailbox(
                &email,
                request.imap_host.as_deref(),
                request.imap_port,
            )
            .ok_or_else(|| "请填写 IMAP 主机".to_string())?;
            (email, secret, host, port)
        }
    };
    if email.trim().is_empty() || secret.trim().is_empty() {
        return Err("请填写邮箱地址和授权码".into());
    }
    let mut io = sealbox_core::mail::connect_tls(&host, port, std::time::Duration::from_secs(20))
        .map_err(sealbox_core::mail::failure_message)?;
    let probe = sealbox_core::mail::probe_account(&mut io, email.trim(), &secret)
        .map_err(sealbox_core::mail::failure_message)?;
    Ok(MailProbeReport { host, port, folders: probe.folders, unread: probe.unread })
}

#[tauri::command]
pub fn mail_unread_count(state: State<AppState>) -> Result<u32, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session.vault().map_err(map_err)?.mail_badge_unread().map_err(map_err)
}

/// How many cached messages a badge folder keeps after a sync: enough for weeks of scrolling
/// without growing the phone's database without bound.
const MAIL_SYNC_KEEP: usize = 300;

/// Pulls the newest page of the badge folders for every account so the mobile list can show
/// cached mail without a live connection. There is no background poller on Android; this runs
/// only when the page asks for it.
///
/// Failures are per folder, mirroring the desktop: a folder that fails is skipped and the rest
/// still sync, so one broken mailbox does not cost the others their new mail. The function only
/// fails when the store itself cannot be reached at all.
#[tauri::command]
pub fn mail_sync(state: State<AppState>) -> Result<u32, String> {
    let accounts = mail_accounts(state.clone())?;
    for account in accounts.iter().filter(|account| account.supported) {
        // An unreachable account is reported by the badge command, not by aborting the loop.
        let Ok(mail) = load_mail_session(&state, &account.id) else { continue };
        let Ok(mut io) = mail_connect(&mail) else { continue };
        let Ok(folders) = sealbox_core::mail::list_folders(&mut io, &mail.email, &mail.secret) else {
            continue;
        };
        for folder in folders.iter().filter(|folder| matches!(folder.role, "inbox" | "archive")) {
            let _ = sync_mail_folder(&state, &account.id, &mail, &mut io, folder);
        }
    }
    // The badge is a convenience: a store that cannot answer falls back to 0 rather than failing
    // a sync that already stored what it fetched.
    let session = lock_session(&state.session);
    Ok(session
        .vault()
        .ok()
        .and_then(|vault| vault.mail_badge_unread().ok())
        .unwrap_or(0))
}

/// One badge folder. Returns a fixed, credential-free reason on failure; the server's own reply
/// never leaves this function, and neither does the authorization code.
fn sync_mail_folder(
    state: &AppState,
    entry_id: &str,
    mail: &MailSession,
    io: &mut sealbox_core::mail::TlsImap,
    folder: &sealbox_core::mail::MailFolder,
) -> Result<(), String> {
    let messages = sealbox_core::mail::list_folder(
        io,
        &mail.email,
        &mail.secret,
        &folder.name,
        None,
        50,
        sealbox_core::mail_folder::MailFilter::All,
        "",
    )
    // Mapped to a fixed sentence on purpose: `failure_message` is credential-free, but the point
    // here is that nothing about the failure reaches the caller at all.
    .map_err(|_| "部分文件夹同步失败".to_string())?;
    let unread = sealbox_core::mail::unread_count(io, &mail.email, &mail.secret, &folder.name).unwrap_or(0);
    let session = lock_session(&state.session);
    let vault = session.vault().map_err(map_err)?;
    let previews = vec![String::new(); messages.len()];
    vault
        .mail_upsert_messages(entry_id, &folder.name, &messages, &previews)
        .map_err(map_err)?;
    vault
        .mail_save_folders_unread(entry_id, &folder.name, folder.role, unread)
        .map_err(map_err)?;
    // Cache only: the phone keeps the newest few hundred and the server keeps everything.
    let _ = vault.mail_sweep_folder(entry_id, &folder.name, MAIL_SYNC_KEEP, &[]);
    Ok(())
}

#[tauri::command]
pub fn sync_verify_conditional(app: AppHandle, state: State<AppState>) -> Result<sync::ConditionalSupportReport, String> {
    let (vault, dek) = open_unlocked_copy(&app, &state)?;
    let still_unlocked = || lock_session(&state.session).is_unlocked();
    let result = sync::verify_conditional_support(&vault, &dek, &still_unlocked)?;
    crate::auto_sync::resume(&state);
    Ok(result)
}
