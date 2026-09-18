use crate::assistant;
use crate::backup::{export_envelope, import_envelope};
use crate::clipboard;
use crate::github_mcp::{self, GithubMcpPolicy};
use crate::hello;
use crate::lock::{idle_lock_if_needed, lock_everything, lock_session, recover_lock};
use crate::mcp::{self, McpState};
use crate::session::Session;
use crate::totp::{generate_passphrase, generate_password_with_options, ssh_fingerprint, totp_now};
use crate::vault::{
    AuditEvent, Counts, EntryDto, FolderDto, ListFilter, SecretPayload, UpsertEntry, Vault,
};
use crate::zoomkey::{self, ZoomkeyCandidates, ZoomkeyMcpPolicy};
use serde::{Deserialize, Serialize};
use serde_json::json;
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
        let session = Arc::new(Mutex::new(Session::default()));
        let mcp = McpState::default();
        crate::lock::register_active_session(&session);
        crate::lock::register_active_mcp(&mcp);
        Self {
            session,
            mcp,
            db_path: Mutex::new(None),
        }
    }
}

fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("vault.db"))
}

fn map_err(e: impl ToString) -> String {
    e.to_string()
}

fn require_existing_vault(path: &Path) -> Result<Vault, String> {
    let path = path.to_str().unwrap_or_default();
    if !Vault::is_initialized(path) {
        return Err(crate::vault::VaultError::NotInitialized.to_string());
    }
    Vault::open(path).map_err(map_err)
}

fn peek_hello_enabled(path: &Path) -> bool {
    Vault::open(path.to_str().unwrap_or_default())
        .ok()
        .and_then(|v| v.hello_enabled().ok())
        .unwrap_or(false)
}

fn bind_open_vault(session: &mut Session, path: &Path) {
    if !session.is_unlocked() || session.vault().is_ok() {
        return;
    }
    if let Ok(v) = Vault::open(path.to_str().unwrap_or_default()) {
        session.attach_vault_if_unlocked(v);
    }
}

fn apply_bridge_tokens(state: &AppState, vault: &Vault, dek: &[u8; 32]) {
    if let Ok(Some(tok)) = vault.get_secret_setting(dek, "fill_token") {
        if !tok.is_empty() {
            *recover_lock(&state.mcp.fill_token) = tok;
        }
    }
    if let Ok(Some(tok)) = vault.get_secret_setting(dek, "mcp_token") {
        if !tok.is_empty() {
            *recover_lock(&state.mcp.token) = tok;
        }
    }
}

fn load_bridge_tokens(state: &AppState, session: &Session) {
    let Ok(v) = session.vault() else {
        return;
    };
    let Ok(dek) = session.dek() else {
        return;
    };
    apply_bridge_tokens(state, v, dek);
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
    *recover_lock(&state.db_path) = Some(path.clone());
    let initialized = Vault::is_initialized(path.to_str().unwrap_or_default());
    let mut session = lock_session(&state.session);
    idle_lock_if_needed(&mut session, &state.mcp);
    let unlocked = session.is_unlocked();
    if initialized && unlocked {
        bind_open_vault(&mut session, &path);
    }
    let hello_enabled = if !initialized {
        false
    } else if unlocked {
        session
            .vault()
            .ok()
            .and_then(|v| v.hello_enabled().ok())
            .unwrap_or(false)
    } else {
        peek_hello_enabled(&path)
    };
    if initialized && unlocked {
        load_bridge_tokens(&state, &session);
    }
    if unlocked {
        let idle = session
            .vault()
            .ok()
            .and_then(|v| v.get_setting("idle_secs").ok())
            .flatten();
        let clip = session
            .vault()
            .ok()
            .and_then(|v| v.get_setting("clipboard_secs").ok())
            .flatten();
        let hk = session
            .vault()
            .ok()
            .and_then(|v| v.get_setting("hotkey").ok())
            .flatten();
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
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
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
    if Vault::is_initialized(path.to_str().unwrap_or_default()) {
        return Err("金库已存在".into());
    }
    let dek = Vault::create(path.to_str().unwrap(), &password).map_err(map_err)?;
    let vault = Vault::open(path.to_str().unwrap()).map_err(map_err)?;
    let mut session = lock_session(&state.session);
    session.set_unlocked(vault, dek);
    drop(session);
    hydrate_bridge_tokens(&state);
    let _ = mcp::start(&state.mcp, state.session.clone());
    Ok(())
}

#[tauri::command]
pub fn unlock_vault(
    app: AppHandle,
    state: State<AppState>,
    password: String,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    let vault = require_existing_vault(&path)?;
    let mut session = lock_session(&state.session);
    std::thread::sleep(std::time::Duration::from_millis(session.unlock_delay_ms()));
    match vault.unlock(&password) {
        Ok(dek) => {
            let _ = vault.audit("unlock", None, "ok");
            let _ = vault.purge_expired_trash(chrono::Utc::now(), 30);
            session.set_unlocked(vault, dek);
            drop(session);
            hydrate_bridge_tokens(&state);
            let _ = mcp::start(&state.mcp, state.session.clone());
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
    let vault = require_existing_vault(&path)?;
    let dek = vault.unlock_with_hello_key(&key).map_err(map_err)?;
    let _ = vault.audit("unlock_hello", None, "ok");
    lock_session(&state.session).set_unlocked(vault, dek);
    hydrate_bridge_tokens(&state);
    let _ = mcp::start(&state.mcp, state.session.clone());
    Ok(())
}

fn persist_tokens(state: &AppState) {
    let s = lock_session(&state.session);
    let Ok(v) = s.vault() else {
        return;
    };
    let Ok(dek) = s.dek() else {
        return;
    };
    let fill = recover_lock(&state.mcp.fill_token).clone();
    let mcp_tok = recover_lock(&state.mcp.token).clone();
    if !fill.is_empty() {
        let _ = v.set_secret_setting(dek, "fill_token", &fill);
    }
    if !mcp_tok.is_empty() {
        let _ = v.set_secret_setting(dek, "mcp_token", &mcp_tok);
    }
}

fn hydrate_bridge_tokens(state: &AppState) {
    {
        let s = lock_session(&state.session);
        let Ok(v) = s.vault() else {
            return;
        };
        let Ok(dek) = s.dek() else {
            return;
        };
        apply_bridge_tokens(state, v, dek);
    }
    {
        let mut fill = recover_lock(&state.mcp.fill_token);
        if fill.is_empty() {
            *fill = crate::fill::new_fill_token();
        }
    }
    {
        let mut mcp_tok = recover_lock(&state.mcp.token);
        if mcp_tok.is_empty() {
            *mcp_tok = crate::mcp::new_token();
        }
    }
    persist_tokens(state);
}

fn copy_owned_text(session: &mut Session, text: &str) -> Result<(), String> {
    session.require_unlocked().map_err(map_err)?;
    if text.is_empty() {
        return Err("没有可复制的内容".into());
    }
    clipboard::write_text(text)?;
    session.remember_clipboard(text);
    Ok(())
}

#[tauri::command]
pub fn lock_vault(state: State<AppState>) -> Result<(), String> {
    lock_everything(&state.session, &state.mcp);
    Ok(())
}

#[tauri::command]
pub fn list_entries(state: State<AppState>, filter: ListFilter) -> Result<Vec<EntryDto>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .list_entries(&filter)
        .map_err(map_err)
}

#[tauri::command]
pub fn list_counts(state: State<AppState>, filter: ListFilter) -> Result<Counts, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .counts_for(&filter)
        .map_err(map_err)
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
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .upsert_entry(&dek, input)
        .map_err(map_err)
}

#[tauri::command]
pub fn update_entry(state: State<AppState>, input: UpsertEntry) -> Result<EntryDto, String> {
    create_entry(state, input)
}

#[tauri::command]
pub fn delete_entries(state: State<AppState>, ids: Vec<String>) -> Result<usize, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .soft_delete(&ids)
        .map_err(map_err)
}

#[tauri::command]
pub fn restore_entries(state: State<AppState>, ids: Vec<String>) -> Result<usize, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .restore(&ids)
        .map_err(map_err)
}

#[tauri::command]
pub fn empty_trash(state: State<AppState>) -> Result<usize, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .empty_trash()
        .map_err(map_err)
}

#[tauri::command]
pub fn pin_entry(state: State<AppState>, id: String, pinned: bool) -> Result<(), String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .set_pinned(&id, pinned)
        .map_err(map_err)
}

#[tauri::command]
pub fn list_folders(state: State<AppState>) -> Result<Vec<FolderDto>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .list_folders()
        .map_err(map_err)
}

#[tauri::command]
pub fn create_folder(state: State<AppState>, name: String) -> Result<FolderDto, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .create_folder(&name)
        .map_err(map_err)
}

#[tauri::command]
pub fn list_tags(state: State<AppState>) -> Result<Vec<String>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .list_tags()
        .map_err(map_err)
}

#[tauri::command]
pub fn list_audit(state: State<AppState>) -> Result<Vec<AuditEvent>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .list_audit(200)
        .map_err(map_err)
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
        SecretPayload::ClientCert { .. } => Err("客户端证书私钥不能通过通用复制功能导出".into()),
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
        SecretPayload::Database { username, .. } => Some(username.clone()),
        SecretPayload::ClientCert { .. } => None,
    }
}

#[tauri::command]
pub fn copy_secret(state: State<AppState>, id: String, field: String) -> Result<(), String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let payload = {
        let vault = session.vault().map_err(map_err)?;
        vault.get_active_secret(&dek, &id).map_err(map_err)?
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
        _ => primary_secret(&payload)?,
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
    Ok(())
}

#[tauri::command]
pub fn reveal_secret(state: State<AppState>, id: String) -> Result<SecretPayload, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let payload = {
        let vault = session.vault().map_err(map_err)?;
        let payload = vault.get_active_secret(&dek, &id).map_err(map_err)?;
        if matches!(payload, SecretPayload::ClientCert { .. }) {
            return Err("客户端证书私钥不能通过通用显示功能返回到界面".into());
        }
        let _ = vault.audit("reveal", Some(&id), "ok");
        payload
    };
    Ok(payload)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientCertInfo {
    pub id: String,
    pub title: String,
    pub fingerprint: Option<String>,
    pub certificate_count: Option<usize>,
    pub has_passphrase: bool,
}

#[tauri::command]
pub fn client_cert_info(state: State<AppState>, id: String) -> Result<ClientCertInfo, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let entry = vault
        .list_entries(&crate::vault::ListFilter {
            kind: Some(crate::vault::EntryKind::ClientCert),
            ..Default::default()
        })
        .map_err(map_err)?
        .into_iter()
        .find(|entry| entry.id == id)
        .ok_or_else(|| "客户端证书不存在或已在回收站".to_string())?;
    let payload = vault.get_active_secret(&dek, &id).map_err(map_err)?;
    let SecretPayload::ClientCert {
        cert_pem,
        key_pem,
        passphrase,
    } = payload
    else {
        return Err("条目不是客户端证书".into());
    };
    let metadata = crate::certificate::validate_client_cert(&cert_pem, &key_pem, passphrase.as_deref()).ok();
    Ok(ClientCertInfo {
        id: entry.id,
        title: entry.title,
        fingerprint: entry.fingerprint.or_else(|| metadata.as_ref().map(|value| value.fingerprint.clone())),
        certificate_count: metadata.as_ref().map(|value| value.certificate_count),
        has_passphrase: passphrase.is_some(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateClientCertMetadataInput {
    pub id: String,
    pub title: String,
    pub account: Option<String>,
    pub url: Option<String>,
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
    pub pinned: bool,
    pub expires_at: Option<String>,
    pub notes: Option<String>,
}

#[tauri::command]
pub fn update_client_cert_metadata(
    state: State<AppState>,
    input: UpdateClientCertMetadataInput,
) -> Result<EntryDto, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .update_entry_metadata(
            &dek,
            &input.id,
            &input.title,
            input.account.as_deref(),
            input.url.as_deref(),
            input.folder_id.as_deref(),
            &input.tags,
            input.pinned,
            input.expires_at.as_deref(),
            input.notes.as_deref(),
        )
        .map_err(map_err)
}

#[tauri::command]
pub fn copy_client_cert(state: State<AppState>, id: String) -> Result<(), String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let cert_pem = {
        let vault = session.vault().map_err(map_err)?;
        let payload = vault.get_active_secret(&dek, &id).map_err(map_err)?;
        let SecretPayload::ClientCert { cert_pem, .. } = payload else {
            return Err("条目不是客户端证书".into());
        };
        cert_pem
    };
    clipboard::write_text(&cert_pem)?;
    session.remember_clipboard(&cert_pem);
    if let Ok(vault) = session.vault() {
        let _ = vault.bump_use(&id);
        let _ = vault.audit("copy_certificate", Some(&id), "public_pem");
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportClientCertInput {
    pub id: Option<String>,
    pub title: String,
    pub cert_path: String,
    pub key_path: String,
    pub passphrase: Option<String>,
    pub account: Option<String>,
    pub url: Option<String>,
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
    pub pinned: bool,
    pub expires_at: Option<String>,
    pub notes: Option<String>,
}

#[tauri::command]
pub fn import_client_cert(
    state: State<AppState>,
    input: ImportClientCertInput,
) -> Result<EntryDto, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let cert_pem = crate::certificate::read_text_file(
        &input.cert_path,
        "客户端证书文件",
        crate::certificate::MAX_CERT_PEM_BYTES,
    )
    .map_err(map_err)?;
    let key_pem = crate::certificate::read_text_file(
        &input.key_path,
        "客户端私钥文件",
        crate::certificate::MAX_KEY_PEM_BYTES,
    )
    .map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .upsert_entry(
            &dek,
            UpsertEntry {
                id: input.id,
                kind: crate::vault::EntryKind::ClientCert,
                title: input.title,
                account: input.account,
                url: input.url,
                folder_id: input.folder_id,
                tags: input.tags,
                pinned: input.pinned,
                expires_at: input.expires_at,
                notes: input.notes,
                secret: SecretPayload::ClientCert {
                    cert_pem,
                    key_pem,
                    passphrase: input.passphrase,
                },
            },
        )
        .map_err(map_err)
}

#[tauri::command]
pub fn get_notes(state: State<AppState>, id: String) -> Result<Option<String>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .get_notes(&dek, &id)
        .map_err(map_err)
}

#[tauri::command]
pub fn tick_idle(state: State<AppState>) -> Result<bool, String> {
    let mut session = lock_session(&state.session);
    if session.clipboard_should_clear(&clipboard::read_text().unwrap_or_default()) {
        let _ = clipboard::clear();
        session.clear_clipboard_mark();
    }
    let locked = idle_lock_if_needed(&mut session, &state.mcp);
    Ok(locked)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOpts {
    #[serde(default = "default_password_mode")]
    pub mode: String,
    #[serde(default = "default_password_length")]
    pub length: usize,
    #[serde(default = "default_true")]
    pub upper: bool,
    #[serde(default = "default_true")]
    pub lower: bool,
    #[serde(default = "default_true")]
    pub digits: bool,
    #[serde(default = "default_true")]
    pub symbols: bool,
    #[serde(default = "default_false")]
    pub ensure_each: bool,
    #[serde(default = "default_passphrase_words")]
    pub word_count: usize,
    #[serde(default = "default_passphrase_separator")]
    pub separator: String,
}

fn default_password_mode() -> String {
    "password".into()
}

fn default_password_length() -> usize {
    20
}

fn default_passphrase_words() -> usize {
    4
}

fn default_passphrase_separator() -> String {
    "-".into()
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

#[tauri::command]
pub fn gen_password(opts: PasswordOpts) -> String {
    if opts.mode == "passphrase" {
        return generate_passphrase(opts.word_count, &opts.separator);
    }
    generate_password_with_options(
        opts.length,
        opts.upper,
        opts.lower,
        opts.digits,
        opts.symbols,
        opts.ensure_each,
    )
}

#[tauri::command]
pub fn export_backup(state: State<AppState>, password: String, path: String) -> Result<(), String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
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
    let mut session = lock_session(&state.session);
    if !Vault::is_initialized(db.to_str().unwrap_or_default()) {
        let dek = Vault::create(db.to_str().unwrap(), &password).map_err(map_err)?;
        let vault = Vault::open(db.to_str().unwrap()).map_err(map_err)?;
        let n = import_envelope(&vault, &dek, &bytes, &password, overwrite).map_err(map_err)?;
        session.set_unlocked(vault, dek);
        return Ok(n);
    }
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
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
    let s = lock_session(&state.session);
    Settings {
        idle_secs: s.idle_secs,
        clipboard_secs: s.clipboard_secs,
        hotkey: s.hotkey.clone(),
    }
}

#[tauri::command]
pub fn settings_set(
    app: AppHandle,
    state: State<AppState>,
    settings: Settings,
) -> Result<(), String> {
    let mut s = lock_session(&state.session);
    idle_lock_if_needed(&mut s, &state.mcp);
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
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
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
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
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
    pub url: String,
    pub fill_url: String,
    pub has_token: bool,
    pub has_fill_token: bool,
}

fn mcp_status_of(state: &AppState) -> McpStatus {
    let port = *recover_lock(&state.mcp.port);
    let has_token = !recover_lock(&state.mcp.token).is_empty();
    let has_fill_token = !recover_lock(&state.mcp.fill_token).is_empty();
    McpStatus {
        running: state.mcp.running.load(std::sync::atomic::Ordering::SeqCst),
        port,
        url: format!("http://127.0.0.1:{port}/mcp"),
        fill_url: format!("http://127.0.0.1:{port}/fill"),
        has_token,
        has_fill_token,
    }
}

#[tauri::command]
pub fn mcp_status(state: State<AppState>) -> McpStatus {
    mcp_status_of(&state)
}

#[tauri::command]
pub fn mcp_start(state: State<AppState>) -> Result<McpStatus, String> {
    let port = mcp::start(&state.mcp, state.session.clone())?;
    if let Ok(v) = lock_session(&state.session).vault() {
        let _ = v.audit("mcp_start", None, &format!("port={port}"));
    }
    Ok(mcp_status_of(&state))
}

#[tauri::command]
pub fn mcp_stop(state: State<AppState>) -> Result<McpStatus, String> {
    mcp::stop(&state.mcp);
    if let Ok(v) = lock_session(&state.session).vault() {
        let _ = v.audit("mcp_stop", None, "ok");
    }
    Ok(mcp_status_of(&state))
}

#[tauri::command]
pub fn mcp_rotate_token(state: State<AppState>) -> Result<McpStatus, String> {
    let tok = mcp::new_token();
    {
        let mut session = lock_session(&state.session);
        session.require_unlocked().map_err(map_err)?;
        *recover_lock(&state.mcp.token) = tok.clone();
        let dek = *session.dek().map_err(map_err)?;
        let vault = session.vault().map_err(map_err)?;
        let _ = vault.set_secret_setting(&dek, "mcp_token", &tok);
        let _ = vault.audit("mcp_rotate", None, "ok");
    }
    if state.mcp.running.load(std::sync::atomic::Ordering::SeqCst) {
        mcp::stop(&state.mcp);
        std::thread::sleep(std::time::Duration::from_millis(120));
        mcp::start(&state.mcp, state.session.clone())?;
    }
    Ok(mcp_status_of(&state))
}

#[tauri::command]
pub fn fill_rotate_token(state: State<AppState>) -> Result<McpStatus, String> {
    let tok = crate::fill::new_fill_token();
    {
        let mut session = lock_session(&state.session);
        session.require_unlocked().map_err(map_err)?;
        *recover_lock(&state.mcp.fill_token) = tok.clone();
        let dek = *session.dek().map_err(map_err)?;
        let vault = session.vault().map_err(map_err)?;
        let _ = vault.set_secret_setting(&dek, "fill_token", &tok);
        let _ = vault.audit("fill_rotate", None, "ok");
    }
    Ok(mcp_status_of(&state))
}

fn mcp_config_snippet(url: &str, token: &str) -> String {
    format!(
        "{{\n  \"mcpServers\": {{\n    \"sealbox\": {{\n      \"url\": \"{url}\",\n      \"headers\": {{\n        \"Authorization\": \"Bearer {token}\"\n      }}\n    }}\n  }}\n}}"
    )
}

#[tauri::command]
pub fn reveal_mcp_token(state: State<AppState>) -> Result<String, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let tok = recover_lock(&state.mcp.token).clone();
    if tok.is_empty() {
        return Err("没有 MCP Token".into());
    }
    Ok(tok)
}

#[tauri::command]
pub fn reveal_fill_token(state: State<AppState>) -> Result<String, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let tok = recover_lock(&state.mcp.fill_token).clone();
    if tok.is_empty() {
        return Err("没有填表 Token".into());
    }
    Ok(tok)
}

#[tauri::command]
pub fn copy_mcp_token(state: State<AppState>) -> Result<(), String> {
    let tok = recover_lock(&state.mcp.token).clone();
    let mut session = lock_session(&state.session);
    copy_owned_text(&mut session, &tok)?;
    if let Ok(v) = session.vault() {
        let _ = v.audit("copy_mcp_token", None, "clipboard");
    }
    Ok(())
}

#[tauri::command]
pub fn copy_fill_token(state: State<AppState>) -> Result<(), String> {
    let tok = recover_lock(&state.mcp.fill_token).clone();
    let mut session = lock_session(&state.session);
    copy_owned_text(&mut session, &tok)?;
    if let Ok(v) = session.vault() {
        let _ = v.audit("copy_fill_token", None, "clipboard");
    }
    Ok(())
}

#[tauri::command]
pub fn copy_mcp_snippet(state: State<AppState>) -> Result<(), String> {
    let url = mcp_status_of(&state).url;
    let tok = recover_lock(&state.mcp.token).clone();
    if tok.is_empty() {
        return Err("没有 MCP Token".into());
    }
    let snippet = mcp_config_snippet(&url, &tok);
    let mut session = lock_session(&state.session);
    copy_owned_text(&mut session, &snippet)?;
    if let Ok(v) = session.vault() {
        let _ = v.audit("copy_mcp_snippet", None, "clipboard");
    }
    Ok(())
}

#[tauri::command]
pub fn fill_open_pairing(state: State<AppState>) -> Result<mcp::PairingStatus, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    if !state.mcp.running.load(std::sync::atomic::Ordering::SeqCst) {
        drop(session);
        mcp::start(&state.mcp, state.session.clone())?;
    } else {
        drop(session);
    }
    let status = state.mcp.open_pairing();
    if let Ok(v) = lock_session(&state.session).vault() {
        let _ = v.audit(
            "fill_pair_open",
            None,
            &format!("secs={}", status.expires_in_secs),
        );
    }
    Ok(status)
}

#[tauri::command]
pub fn fill_pairing_status(state: State<AppState>) -> mcp::PairingStatus {
    state.mcp.pairing_status()
}

#[tauri::command]
pub fn mcp_tools(state: State<AppState>) -> Vec<mcp::ToolInfo> {
    mcp::tool_catalog(&state.session)
}

#[tauri::command]
pub fn github_mcp_policy_get(state: State<AppState>) -> Result<GithubMcpPolicy, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let dek = session.dek().map_err(map_err)?;
    Ok(github_mcp::load_policy(vault, dek))
}

#[tauri::command]
pub fn github_mcp_policy_set(
    state: State<AppState>,
    policy: GithubMcpPolicy,
) -> Result<GithubMcpPolicy, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let normalized = github_mcp::normalize_policy(policy)?;
    let dek = *session.dek().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    github_mcp::save_policy(vault, &dek, &normalized)?;
    let _ = vault.audit(
        "mcp_github_policy",
        None,
        if normalized.enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    Ok(normalized)
}

#[tauri::command]
pub fn zoomkey_policy_get(state: State<AppState>) -> Result<ZoomkeyMcpPolicy, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let dek = session.dek().map_err(map_err)?;
    Ok(zoomkey::load_policy(vault, dek))
}

#[tauri::command]
pub fn zoomkey_policy_set(
    state: State<AppState>,
    policy: ZoomkeyMcpPolicy,
) -> Result<ZoomkeyMcpPolicy, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let normalized = zoomkey::normalize_policy(policy);
    let dek = *session.dek().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    zoomkey::save_policy(vault, &dek, &normalized)?;
    let _ = vault.audit(
        "mcp_zoomkey_policy",
        None,
        &format!(
            "jira={} crm={} private_network={}",
            on_off(normalized.jira_enabled),
            on_off(normalized.crm_enabled),
            on_off(normalized.allow_private_network),
        ),
    );
    Ok(normalized)
}

#[tauri::command]
pub fn zoomkey_candidates(state: State<AppState>) -> Result<ZoomkeyCandidates, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    zoomkey::list_candidates(&session)
}

/// 用户主动触发的连通性自检，不经过 MCP 路由，但仍然写审计。
#[tauri::command]
pub fn zoomkey_test_connection(state: State<AppState>, endpoint: String) -> Result<String, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let label: &'static str = match endpoint.trim().to_ascii_lowercase().as_str() {
        "jira" => "jira",
        "crm" => "crm",
        _ => return Err("endpoint 必须是 jira 或 crm".into()),
    };
    let name = format!("zoomkey_{label}_connection_status");
    let outcome = zoomkey::call_tool_detailed(&mut session, &name, json!({ "ping": true }));
    if let Ok(vault) = session.vault() {
        let detail = match &outcome {
            Ok(_) => format!("endpoint={label} decision=allow"),
            Err(error) => format!(
                "endpoint={label} decision=deny reason={} status={}",
                error.reason,
                error
                    .status
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".into())
            ),
        };
        let _ = vault.audit("mcp_zoomkey_test", None, &detail);
    }
    outcome
        .map(|result| result.text)
        .map_err(|error| error.message)
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

#[tauri::command]
pub fn assistant_config_get(
    state: State<AppState>,
) -> Result<assistant::AssistantConfigView, String> {
    let mut session = lock_session(&state.session);
    assistant::config_get(&mut session)
}

#[tauri::command]
pub fn assistant_config_set(
    state: State<AppState>,
    input: assistant::AssistantConfigInput,
) -> Result<assistant::AssistantConfigView, String> {
    let mut session = lock_session(&state.session);
    assistant::config_set(&mut session, input)
}

#[tauri::command]
pub fn assistant_mcp_probe(state: State<AppState>) -> Result<assistant::AssistantMcpProbe, String> {
    assistant::mcp_probe(&state.session, &state.mcp)
}

#[tauri::command]
pub fn assistant_chat(
    state: State<AppState>,
    request: assistant::AssistantChatRequest,
) -> Result<assistant::AssistantChatResponse, String> {
    assistant::chat(&state.session, &state.mcp, request)
}

#[tauri::command]
pub fn extension_install_status(
    app: AppHandle,
) -> Result<crate::extension_install::ExtensionInstallStatus, String> {
    crate::extension_install::status_for_app(&app)
}

#[tauri::command]
pub fn extension_install(
    app: AppHandle,
) -> Result<crate::extension_install::ExtensionInstallStatus, String> {
    crate::extension_install::install_for_app(&app)
}

#[tauri::command]
pub fn extension_open_folder(app: AppHandle) -> Result<(), String> {
    crate::extension_install::open_folder_for_app(&app)
}

#[tauri::command]
pub fn extension_open_browser(app: AppHandle, browser: String) -> Result<String, String> {
    crate::extension_install::open_browser_for_app(&app, &browser)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;
    use crate::vault::Vault;

    fn temp_vault_path() -> (PathBuf, [u8; 32]) {
        let dir = std::env::temp_dir().join(format!("sealbox-lock-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.db");
        let dek =
            Vault::create(path.to_str().unwrap(), "correct horse battery staple extra").unwrap();
        (path, dek)
    }

    #[test]
    fn require_existing_vault_missing_file_is_not_initialized() {
        let dir = std::env::temp_dir().join(format!("sealbox-unlock-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.db");
        match require_existing_vault(&path) {
            Err(err) => assert!(
                err.contains("not initialized"),
                "unlock must fail closed instead of creating a vault: {err}"
            ),
            Ok(_) => panic!("missing vault file must not open"),
        }
        assert!(!path.exists());
    }

    #[test]
    fn require_existing_vault_opens_initialized_file() {
        let (path, _) = temp_vault_path();
        assert!(require_existing_vault(&path).is_ok());
    }

    #[test]
    fn require_existing_vault_empty_leftover_is_not_initialized() {
        let dir = std::env::temp_dir().join(format!("sealbox-leftover-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.db");
        crate::db::open(path.to_str().unwrap()).unwrap();
        assert!(path.exists());
        match require_existing_vault(&path) {
            Err(err) => assert!(
                err.contains("not initialized"),
                "schema-only leftover must not look like a real vault: {err}"
            ),
            Ok(_) => panic!("schema-only leftover must not open as a vault"),
        }
        assert!(!Vault::is_initialized(path.to_str().unwrap()));
    }

    #[test]
    fn bind_open_vault_while_locked_does_not_attach() {
        let (path, dek) = temp_vault_path();
        let vault = Vault::open(path.to_str().unwrap()).unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        session.lock();
        bind_open_vault(&mut session, &path);
        assert!(!session.is_unlocked());
        assert!(session.vault().is_err());
    }

    #[test]
    fn bind_open_vault_reattaches_missing_handle_only_when_unlocked() {
        let (path, dek) = temp_vault_path();
        let vault = Vault::open(path.to_str().unwrap()).unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        session.drop_vault_handle();
        assert!(session.is_unlocked());
        assert!(session.vault().is_err());
        bind_open_vault(&mut session, &path);
        assert!(session.vault().is_ok());
    }

    #[test]
    fn peek_hello_enabled_does_not_need_session() {
        let (path, dek) = temp_vault_path();
        let vault = Vault::open(path.to_str().unwrap()).unwrap();
        vault.set_hello(&dek, Some(&[7u8; 32])).unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        session.lock();
        assert!(peek_hello_enabled(&path));
        assert!(session.vault().is_err());
        assert!(!session.is_unlocked());
    }

    fn sample_site() -> UpsertEntry {
        UpsertEntry {
            id: None,
            kind: crate::vault::EntryKind::Website,
            title: "jira".into(),
            account: Some("alice".into()),
            url: Some("https://jira.example.com".into()),
            folder_id: None,
            tags: vec!["work".into()],
            pinned: false,
            expires_at: None,
            notes: None,
            secret: SecretPayload::Website {
                url: Some("https://jira.example.com".into()),
                username: Some("alice".into()),
                password: "s3cret-pass".into(),
                totp_secret: None,
            },
        }
    }

    #[test]
    fn lock_blocks_list_and_empty_trash_until_password_unlock() {
        let (path, dek) = temp_vault_path();
        let vault = Vault::open(path.to_str().unwrap()).unwrap();
        let created = vault.upsert_entry(&dek, sample_site()).unwrap();
        vault.soft_delete(&[created.id.clone()]).unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);

        session.lock();
        assert!(!session.is_unlocked());
        assert!(session.require_unlocked().is_err());
        assert!(session.vault().is_err());
        bind_open_vault(&mut session, &path);
        assert!(session.vault().is_err());

        let vault = Vault::open(path.to_str().unwrap()).unwrap();
        let dek = vault.unlock("correct horse battery staple extra").unwrap();
        session.set_unlocked(vault, dek);
        assert!(session.require_unlocked().is_ok());
        let trash = session
            .vault()
            .unwrap()
            .list_entries(&ListFilter {
                trash: true,
                ..ListFilter::default()
            })
            .unwrap();
        assert_eq!(trash.len(), 1);
        assert_eq!(trash[0].id, created.id);
        assert_eq!(session.vault().unwrap().empty_trash().unwrap(), 1);
        assert!(session
            .vault()
            .unwrap()
            .list_entries(&ListFilter {
                trash: true,
                ..ListFilter::default()
            })
            .unwrap()
            .is_empty());
    }

    #[test]
    fn hydrate_bridge_tokens_prefers_vault_over_ephemeral_boot_token() {
        let (path, dek) = temp_vault_path();
        let vault = Vault::open(path.to_str().unwrap()).unwrap();
        vault
            .set_secret_setting(&dek, "fill_token", "fill_from_disk")
            .unwrap();
        vault
            .set_secret_setting(&dek, "mcp_token", "sbx_from_disk")
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let state = AppState {
            session: Arc::new(Mutex::new(session)),
            mcp: McpState::default(),
            db_path: Mutex::new(None),
        };
        *recover_lock(&state.mcp.fill_token) = "fill_ephemeral_boot".into();
        *recover_lock(&state.mcp.token) = "sbx_ephemeral_boot".into();
        hydrate_bridge_tokens(&state);
        assert_eq!(
            recover_lock(&state.mcp.fill_token).as_str(),
            "fill_from_disk"
        );
        assert_eq!(recover_lock(&state.mcp.token).as_str(), "sbx_from_disk");
    }

    #[test]
    fn load_bridge_tokens_while_locked_does_not_read_or_reattach() {
        let (path, dek) = temp_vault_path();
        let vault = Vault::open(path.to_str().unwrap()).unwrap();
        vault
            .set_secret_setting(&dek, "mcp_token", "mcp_locked_probe")
            .unwrap();
        vault
            .set_secret_setting(&dek, "fill_token", "fill_locked_probe")
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        session.lock();
        let state = AppState {
            session: Arc::new(Mutex::new(Session::default())),
            mcp: McpState::default(),
            db_path: Mutex::new(None),
        };
        load_bridge_tokens(&state, &session);
        assert!(recover_lock(&state.mcp.token).is_empty());
        assert!(recover_lock(&state.mcp.fill_token).is_empty());
        assert!(session.vault().is_err());
        assert!(!session.is_unlocked());
    }

    #[test]
    fn load_bridge_tokens_decrypts_after_unlock_and_drops_plaintext() {
        let (path, dek) = temp_vault_path();
        let vault = Vault::open(path.to_str().unwrap()).unwrap();
        vault.set_setting("mcp_token", "mcp_legacy_plain").unwrap();
        vault
            .set_setting("fill_token", "fill_legacy_plain")
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let state = AppState {
            session: Arc::new(Mutex::new(Session::default())),
            mcp: McpState::default(),
            db_path: Mutex::new(None),
        };
        load_bridge_tokens(&state, &session);
        assert_eq!(recover_lock(&state.mcp.token).as_str(), "mcp_legacy_plain");
        assert_eq!(
            recover_lock(&state.mcp.fill_token).as_str(),
            "fill_legacy_plain"
        );
        let vault = session.vault().unwrap();
        assert!(vault.get_setting("mcp_token").unwrap().is_none());
        assert!(vault.get_setting("fill_token").unwrap().is_none());
        let enc = vault.get_setting("mcp_token_enc").unwrap().unwrap();
        assert!(!enc.contains("mcp_legacy_plain"));
    }

    #[test]
    fn mcp_status_omits_tokens() {
        let state = AppState {
            session: Arc::new(Mutex::new(Session::default())),
            mcp: McpState::default(),
            db_path: Mutex::new(None),
        };
        *recover_lock(&state.mcp.token) = "sbx_should_not_serialize".into();
        *recover_lock(&state.mcp.fill_token) = "fill_should_not_serialize".into();
        let status = mcp_status_of(&state);
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("sbx_should_not_serialize"));
        assert!(!json.contains("fill_should_not_serialize"));
        assert!(status.has_token);
        assert!(status.has_fill_token);
    }

    #[test]
    fn copy_owned_text_marks_clipboard_for_timed_clear() {
        let secret = format!("sealbox-copy-token-{}", uuid::Uuid::new_v4());
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        session.clipboard_secs = 120;
        match copy_owned_text(&mut session, &secret) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("skip: clipboard write failed: {e}");
                return;
            }
        }
        let got = clipboard::read_text().unwrap_or_default();
        if got != secret {
            eprintln!("skip: clipboard roundtrip failed, got {got:?}");
            return;
        }
        assert!(session.clipboard_owned(&secret));
        assert!(!session.clipboard_should_clear(&secret));
        session.lock();
        let after = clipboard::read_text().unwrap_or_default();
        assert_ne!(after, secret);
    }
}
