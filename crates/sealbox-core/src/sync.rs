use crate::crypto::{decrypt, encrypt, Encrypted};
use crate::http_guard::{assert_public_target, parse_http_url, PublicResolver};
use crate::profile::{CredentialProfile, open_profile_blob, validate_for_secret};
use crate::vault::{
    BackupEntry, BackupSnapshot, SecretPayload, Tombstone, Vault, VaultError, TOMBSTONE_ENTRY,
    TOMBSTONE_FOLDER,
};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 6] = b"SBOXS1";
const OBJECT_NAME: &str = "sealbox/vault.sboxsync";
const MAX_REMOTE_BYTES: usize = 64 * 1024 * 1024;
/// How long a deletion keeps being broadcast. Older clients that stayed
/// offline longer than this can still resurrect an item.
const TOMBSTONE_RETENTION_DAYS: i64 = 180;
/// Auto sync is per-device: the interval lives in the local settings table.
pub const DEFAULT_AUTO_SYNC_SECS: u64 = 60;
pub const MIN_AUTO_SYNC_SECS: u64 = 15;
pub const MAX_AUTO_SYNC_SECS: u64 = 86_400;
/// Returned when a background sync notices the vault locked mid-flight.
pub const SYNC_ABORTED: &str = "已锁定，本次同步已中止";
/// Conditional writes stay fail-closed until this exact endpoint/credential binding
/// has been explicitly verified by the operator.
pub const SYNC_CONDITIONAL_WRITE_UNVERIFIED: &str = "sync_conditional_write_unverified";
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SyncKind {
    Webdav,
    S3,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncConfig {
    pub kind: SyncKind,
    pub endpoint: String,
    pub username: String,
    pub bucket: String,
    pub region: String,
    pub prefix: String,
}

impl SyncConfig {
    fn normalize(mut self) -> Result<Self, String> {
        self.endpoint = self.endpoint.trim().trim_end_matches('/').to_string();
        self.username = self.username.trim().to_string();
        self.bucket = self.bucket.trim().trim_matches('/').to_string();
        self.region = self.region.trim().to_string();
        self.prefix = self.prefix.trim().trim_matches('/').to_string();
        if self.endpoint.is_empty() {
            return Err("同步地址不能为空".into());
        }
        let target = parse_http_url(&self.endpoint, true)?;
        assert_public_target(&target)?;
        if !self.endpoint.starts_with("https://") {
            return Err("同步地址必须使用 https".into());
        }
        match self.kind {
            SyncKind::Webdav => {
                if self.username.is_empty() {
                    return Err("WebDAV 需要用户名".into());
                }
            }
            SyncKind::S3 => {
                if self.username.is_empty() {
                    return Err("S3 需要 Access Key".into());
                }
                if self.bucket.is_empty() {
                    return Err("S3 需要 Bucket".into());
                }
                if self.region.is_empty() {
                    self.region = "us-east-1".into();
                }
            }
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AutoSyncSettings {
    pub enabled: bool,
    pub secs: u64,
}

/// Auto sync never schedules work until a target exists, so a vault that was
/// never set up stays quiet. Once configured it defaults to on, every 60s.
pub fn auto_settings(vault: &Vault) -> Result<AutoSyncSettings, VaultError> {
    let configured = vault.get_setting("sync_config")?.is_some();
    let enabled = configured && vault.get_setting("sync_auto")?.as_deref() != Some("0");
    let secs = vault
        .get_setting("sync_auto_secs")?
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(DEFAULT_AUTO_SYNC_SECS)
        .clamp(MIN_AUTO_SYNC_SECS, MAX_AUTO_SYNC_SECS);
    Ok(AutoSyncSettings { enabled, secs })
}

/// `None` keeps the stored value, so callers can save only what changed.
pub fn save_auto(
    vault: &Vault,
    enabled: Option<bool>,
    secs: Option<u64>,
) -> Result<AutoSyncSettings, VaultError> {
    let current = auto_settings(vault)?;
    let settings = AutoSyncSettings {
        enabled: enabled.unwrap_or(current.enabled),
        secs: secs
            .unwrap_or(current.secs)
            .clamp(MIN_AUTO_SYNC_SECS, MAX_AUTO_SYNC_SECS),
    };
    vault.set_setting("sync_auto", if settings.enabled { "1" } else { "0" })?;
    vault.set_setting("sync_auto_secs", &settings.secs.to_string())?;
    Ok(settings)
}

#[derive(Serialize, Deserialize)]
struct SyncFile {
    blob: Encrypted,
    device_id: String,
    written_at: String,
}

/// Secrets travel inside the sync key's ciphertext, not under a device DEK.
/// `notes` is omitted on old files, whose blobs were sealed with a vault key.
#[derive(Clone, Serialize, Deserialize)]
struct SyncEntry {
    #[serde(flatten)]
    entry: BackupEntry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret: Option<SecretPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    // This plaintext metadata is carried only inside the sync-key ciphertext.
    // Device-specific profile_blob is cleared, then resealed with the target DEK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<CredentialProfile>,
}

impl Drop for SyncEntry {
    fn drop(&mut self) {
        self.notes.zeroize();
        self.entry.secret_blob.zeroize();
        if let Some(blob) = &mut self.entry.notes_blob { blob.zeroize(); }
        if let Some(blob) = &mut self.entry.profile_blob { blob.zeroize(); }
        if let Some(secret) = &mut self.secret {
            match secret {
                SecretPayload::Website { url, username, password, totp_secret } => {
                    url.zeroize(); username.zeroize(); password.zeroize(); totp_secret.zeroize();
                }
                SecretPayload::ApiToken { service, account, token } => { service.zeroize(); account.zeroize(); token.zeroize(); }
                SecretPayload::Ssh { key_type, private_key, passphrase, public_fingerprint } => {
                    key_type.zeroize(); private_key.zeroize(); passphrase.zeroize(); public_fingerprint.zeroize();
                }
                SecretPayload::Mailbox { email, password, imap_host, smtp_host, .. } => {
                    email.zeroize(); password.zeroize(); imap_host.zeroize(); smtp_host.zeroize();
                }
                SecretPayload::MailAuth { email, provider, auth_code } => { email.zeroize(); provider.zeroize(); auth_code.zeroize(); }
                SecretPayload::Server { host, protocol, username, password, .. } => {
                    host.zeroize(); protocol.zeroize(); username.zeroize(); password.zeroize();
                }
                SecretPayload::Database { engine, host, database, username, password, .. } => {
                    engine.zeroize(); host.zeroize(); database.zeroize(); username.zeroize(); password.zeroize();
                }
                SecretPayload::ClientCert { cert_pem, key_pem, passphrase } => { cert_pem.zeroize(); key_pem.zeroize(); passphrase.zeroize(); }
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct SyncSnapshot {
    folders: Vec<crate::vault::FolderDto>,
    tags: Vec<String>,
    entries: Vec<SyncEntry>,
    /// Entries and folders removed for good. Old snapshot files predate this
    /// field, so it defaults to empty.
    #[serde(default)]
    deleted: Vec<Tombstone>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SyncView {
    pub configured: bool,
    pub kind: Option<SyncKind>,
    pub endpoint: String,
    pub username: String,
    pub bucket: String,
    pub region: String,
    pub prefix: String,
    pub has_secret: bool,
    pub device_id: String,
    pub last_sync_at: Option<String>,
    pub last_result: Option<String>,
    pub auto_sync: bool,
    pub auto_sync_secs: u64,
    pub conditional_verified: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SyncReport {
    pub pulled: usize,
    pub pushed: usize,
    pub unchanged: usize,
    pub removed: usize,
    pub conflicts: Vec<String>,
    pub remote_missing: bool,
    pub phase: SyncPhase,
    pub blocked: Option<String>,
    pub retryable: bool,
    pub conflict_details: Vec<SyncConflict>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyncPhase { Preview, Conflicts, Committed, LocalPending, Blocked }

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind { EditEdit, DeleteEdit }

/// UI-only summary. Never persist titles or payloads in sync audit/settings.
#[derive(Clone, Debug, Serialize)]
pub struct SyncConflict {
    pub id: String,
    pub title: String,
    pub kind: ConflictKind,
    pub local_deleted: bool,
    pub remote_deleted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConflictChoice { Local, Remote, Both }

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SyncResolution {
    pub id: String,
    pub choice: ConflictChoice,
    /// Required for every delete/edit conflict, independently of the choice.
    pub confirm_delete_edit: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SyncPreview {
    pub token: String,
    pub expires_in_secs: u64,
    pub report: SyncReport,
}

/// A strong validator, including quotes. Weak/missing validators fail closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrongEtag(String);
impl StrongEtag {
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"')
            || value[1..value.len()-1].bytes().any(|c| c == b'"' || c < 0x21 || c == 0x7f)
        { return Err("sync_strong_etag_required".into()); }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

pub struct RemoteObject { pub body: Vec<u8>, pub etag: StrongEtag }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteCondition { Match(StrongEtag), Missing }
impl WriteCondition {
    fn header(&self) -> (&'static str, &str) {
        match self { Self::Match(etag) => ("if-match", etag.as_str()), Self::Missing => ("if-none-match", "*") }
    }
}

/// Implementations MUST enforce conditional writes atomically, not GET-then-PUT.
/// HTTP implementations require an administrator-verified provider capability;
/// arbitrary WebDAV/S3-compatible servers are not assumed to honor headers.
pub trait RemoteStore {
    fn get(&self) -> Result<Option<RemoteObject>, String>;
    fn put(&self, body: &[u8], condition: &WriteCondition) -> Result<(), String>;
}

#[derive(Clone)]
pub struct SyncBaseline {
    pub snapshot: BackupSnapshot,
    pub tombstones: Vec<Tombstone>,
}

/// Atomic compare-and-replace seam; useful for deterministic failure tests too.
pub trait LocalSyncStore {
    fn read(&self) -> Result<SyncBaseline, String>;
    fn apply(&self, dek: &[u8; 32], expected: &SyncBaseline, replacement: &SyncBaseline) -> Result<(), String>;
}
impl LocalSyncStore for Vault {
    fn read(&self) -> Result<SyncBaseline, String> {
        Ok(SyncBaseline { snapshot: self.snapshot_for_backup().map_err(|e| e.to_string())?,
            tombstones: self.sync_tombstones().map_err(|e| e.to_string())? })
    }
    fn apply(&self, dek: &[u8; 32], expected: &SyncBaseline, replacement: &SyncBaseline) -> Result<(), String> {
        self.replace_sync_bundle_if_unchanged(dek, &expected.snapshot, &expected.tombstones,
            &replacement.snapshot, &replacement.tombstones).map_err(|e| e.to_string())
    }
}

const PREVIEW_TTL: Duration = Duration::from_secs(600);
/// How long a COS lease survives a crash before another device may steal it.
const COS_LEASE_TTL_SECS: i64 = 180;
/// Ignore an expiry that is this close to now: clocks on two devices drift.
const COS_LEASE_SKEW_SECS: i64 = 30;
pub const SYNC_TOKEN_EXPIRED: &str = "sync_token_expired";
pub const SYNC_LOCAL_CHANGED: &str = "sync_local_changed";
pub const SYNC_REMOTE_CHANGED: &str = "sync_remote_changed";

struct PendingSync {
    token: String,
    created: Instant,
    generation: u64,
    binding: String,
    dek_digest: String,
    key: Zeroizing<[u8; 32]>,
    baseline: SyncBaseline,
    local_digest: String,
    local: SyncSnapshot,
    remote: Option<SyncSnapshot>,
    condition: WriteCondition,
    legacy: bool,
    report: SyncReport,
    /// After a successful remote write, retries ONLY apply this local bundle.
    uploaded: Option<(SyncSnapshot, SyncBaseline)>,
}

/// Owned by each AppState behind its own mutex. Invalidate before lock, DEK
/// replacement or configuration changes; a new unlock session uses a new generation.
#[derive(Default)]
pub struct SyncRuntime { generation: u64, pending: Option<PendingSync> }
impl SyncRuntime {
    pub fn invalidate(&mut self) {
        self.pending = None;
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn preview(&mut self, vault: &Vault, dek: &[u8;32]) -> Result<SyncPreview, String> {
        let (client, key, binding) = configured_client(vault, dek)?;
        self.preview_with_store(vault, &client, dek, key, &binding)
    }

    pub fn commit(&mut self, vault: &Vault, dek: &[u8;32], token: &str,
        choices: &[SyncResolution], still_wanted: &dyn Fn() -> bool) -> Result<SyncReport, String> {
        if !still_wanted() { self.invalidate(); return Err(SYNC_ABORTED.into()); }
        if self.pending.as_ref().is_some_and(|p| p.created.elapsed() >= PREVIEW_TTL) {
            self.invalidate(); return Err(SYNC_TOKEN_EXPIRED.into());
        }
        if self.pending.as_ref().is_some_and(|p| p.dek_digest != hex::encode(Sha256::digest(dek))) {
            self.invalidate(); return Err("sync_session_changed".into());
        }
        if !self.pending.as_ref().is_some_and(|p| p.uploaded.is_some()) {
            require_conditional_support(vault, dek)?;
        }
        let (client, _, binding) = configured_client(vault, dek)?;
        let result = self.commit_with_store(vault, &client, dek, &binding, token, choices, still_wanted);
        if let Ok(report) = &result {
            if report.phase == SyncPhase::Committed { persist_report(vault, report); }
        }
        result
    }

    /// `binding` must identify configuration AND credential; never expose it to UI.
    /// `key` is the derived sync encryption key, NOT a vault DEK.
    pub fn preview_with_store(&mut self, local_store: &dyn LocalSyncStore, remote_store: &dyn RemoteStore,
        dek: &[u8;32], key: [u8;32], binding: &str) -> Result<SyncPreview, String> {
        if self.pending.as_ref().is_some_and(|p| p.created.elapsed() >= PREVIEW_TTL) {
            self.invalidate();
        }
        // A pending remote-success/local-failure must not be silently discarded.
        if self.pending.as_ref().is_some_and(|p| p.uploaded.is_some()) {
            return Err("sync_local_retry_pending".into());
        }
        self.pending = None;
        let key = Zeroizing::new(key);
        let baseline = local_store.read()?;
        let mut local = SyncSnapshot::from_vault(dek, &baseline.snapshot)?;
        local.deleted = baseline.tombstones.clone();
        let object = remote_store.get()?;
        let (remote, condition, legacy, report) = match object {
            Some(object) => {
                let (remote, legacy) = decode_snapshot(&key, Some(dek), &object.body)?;
                let (_, report) = merge_snapshots(&local, &remote);
                (Some(remote), WriteCondition::Match(object.etag), legacy, report)
            }
            None => (None, WriteCondition::Missing, false, missing_report(&local)),
        };
        let token = uuid::Uuid::new_v4().to_string();
        let mut report = report;
        report.phase = if report.conflict_details.is_empty() { SyncPhase::Preview } else { SyncPhase::Conflicts };
        self.pending = Some(PendingSync { token: token.clone(), created: Instant::now(),
            generation: self.generation, binding: binding.into(), dek_digest: hex::encode(Sha256::digest(dek)),
            key, local_digest: full_snapshot_digest(&local), baseline, local, remote, condition, legacy,
            report: report.clone(), uploaded: None });
        Ok(SyncPreview { token, expires_in_secs: PREVIEW_TTL.as_secs(), report })
    }

    pub fn commit_with_store(&mut self, local_store: &dyn LocalSyncStore, remote_store: &dyn RemoteStore,
        dek: &[u8;32], binding: &str, token: &str, choices: &[SyncResolution],
        still_wanted: &dyn Fn() -> bool) -> Result<SyncReport, String> {
        if !still_wanted() { self.invalidate(); return Err(SYNC_ABORTED.into()); }
        let p = self.pending.as_ref().ok_or("sync_token_invalid")?;
        if p.created.elapsed() >= PREVIEW_TTL { self.invalidate(); return Err(SYNC_TOKEN_EXPIRED.into()); }
        if p.token != token { return Err("sync_token_invalid".into()); }
        if p.generation != self.generation || p.binding != binding
            || p.dek_digest != hex::encode(Sha256::digest(dek)) {
            self.invalidate(); return Err("sync_session_changed".into());
        }
        let p = self.pending.as_mut().expect("checked pending");
        let current = local_store.read()?;
        let mut current_open = SyncSnapshot::from_vault(dek, &current.snapshot)?;
        current_open.deleted = current.tombstones.clone();
        if full_snapshot_digest(&current_open) != p.local_digest {
            return Ok(blocked_report(&p.report, SYNC_LOCAL_CHANGED, p.uploaded.is_some()));
        }
        if p.uploaded.is_none() {
            validate_choices(&p.report.conflict_details, choices)?;
            // Re-read for early feedback; the PUT condition remains mandatory.
            let latest = remote_store.get()?;
            let latest_condition = latest.map(|o| WriteCondition::Match(o.etag)).unwrap_or(WriteCondition::Missing);
            if latest_condition != p.condition { return Ok(blocked_report(&p.report, SYNC_REMOTE_CHANGED, true)); }
            let merged = match &p.remote {
                Some(remote) => resolve_snapshots(&p.local, remote, choices)?,
                None => p.local.clone(),
            };
            let changed = p.legacy || p.remote.as_ref().map_or(true, |remote| full_snapshot_digest(&merged) != full_snapshot_digest(remote));
            let sealed = SyncBaseline { snapshot: merged.seal(dek)?, tombstones: merged.deleted.clone() };
            if !still_wanted() { self.invalidate(); return Err(SYNC_ABORTED.into()); }
            if changed {
                let bytes = encode_snapshot(&p.key, &merged, "sync-runtime").map_err(|e| e.to_string())?;
                // Errors, including 412/unsupported condition, leave the token intact.
                remote_store.put(&bytes, &p.condition)?;
            }
            p.uploaded = Some((merged, sealed));
        }
        if !still_wanted() { self.invalidate(); return Err(SYNC_ABORTED.into()); }
        let (merged, sealed) = p.uploaded.as_ref().expect("prepared bundle");
        if full_snapshot_digest(merged) != p.local_digest {
            if let Err(_error) = local_store.apply(dek, &p.baseline, sealed) {
                let mut report = blocked_report(&p.report, "sync_local_apply_pending", true);
                report.phase = SyncPhase::LocalPending;
                return Ok(report);
            }
        }
        // Even a push-only run must notice a local edit that arrived during PUT.
        // No replacement is needed in that case, but success must not discard
        // the pending state or claim this newer local content was synchronized.
        if full_snapshot_digest(merged) == p.local_digest {
            let after = local_store.read()?;
            let mut after_open = SyncSnapshot::from_vault(dek, &after.snapshot)?;
            after_open.deleted = after.tombstones;
            if full_snapshot_digest(&after_open) != p.local_digest {
                return Ok(blocked_report(&p.report, SYNC_LOCAL_CHANGED, true));
            }
        }
        let mut report = p.report.clone();
        report.phase = SyncPhase::Committed;
        report.blocked = None;
        report.retryable = false;
        self.pending = None;
        Ok(report)
    }
}

fn blocked_report(report: &SyncReport, code: &str, retryable: bool) -> SyncReport {
    let mut report = report.clone();
    report.phase = SyncPhase::Blocked;
    report.blocked = Some(code.into());
    report.retryable = retryable;
    report
}

fn missing_report(local: &SyncSnapshot) -> SyncReport {
    SyncReport { pulled: 0, pushed: local.entries.len(), unchanged: 0, removed: 0,
        conflicts: vec![], remote_missing: true, phase: SyncPhase::Preview,
        blocked: None, retryable: false, conflict_details: vec![] }
}

fn configured_client(vault: &Vault, dek: &[u8;32]) -> Result<(RemoteClient, [u8;32], String), String> {
    let config = load_config(vault).map_err(|e| e.to_string())?.ok_or("还没有配置同步")?;
    let secret = Zeroizing::new(vault.get_secret_setting(dek, "sync_secret").map_err(|e| e.to_string())?
        .filter(|s| !s.is_empty()).ok_or("同步密钥缺失，请重新保存")?);
    let key = sync_key(&secret);
    let mut hash = Sha256::new();
    hash.update(serde_json::to_vec(&config).map_err(|e| e.to_string())?);
    hash.update(key);
    let binding = hex::encode(hash.finalize());
    let mut client = RemoteClient::new(&config, &secret)?;
    // Explicit local operator attestation; never infer CAS from a successful PUT.
    client.conditional_verified = vault.get_setting("sync_conditional_verified").map_err(|e| e.to_string())?.as_deref() == Some(&binding);
    Ok((client, key, binding))
}

/// Operator must verify this exact endpoint/credential supports atomic If-Match
/// and If-None-Match before storing the returned binding as sync_conditional_verified.
/// Verification must use a disposable probe object, NEVER the vault object.
pub fn conditional_capability_binding(vault: &Vault, dek: &[u8;32]) -> Result<String, String> {
    configured_client(vault, dek).map(|(_, _, binding)| binding)
}

/// Check the attestation for the current normalized config and sync secret.
/// Missing or stale markers are simply unverified; no network request is made.
pub fn conditional_support_verified(vault: &Vault, dek: &[u8; 32]) -> Result<bool, String> {
    match configured_client(vault, dek) {
        Ok((client, _, _)) => Ok(client.conditional_verified),
        Err(error) if error == "还没有配置同步" || error == "同步密钥缺失，请重新保存" => Ok(false),
        Err(error) => Err(error),
    }
}

/// Tencent COS implements PUT Object as an unconditional replacement for a
/// same-named object and ignores If-Match/If-None-Match, so writes go through
/// the create-only lease in `cos_put` instead.
fn is_tencent_cos_endpoint(endpoint: &str) -> bool {
    let Ok(target) = parse_http_url(endpoint, true) else {
        return false;
    };
    let host = target.host.trim_end_matches('.').to_ascii_lowercase();
    host == "myqcloud.com"
        || host
            .strip_suffix(".myqcloud.com")
            .is_some_and(|prefix| !prefix.is_empty())
}

/// An unreadable lease is treated as stale: a broken holder must not block sync
/// forever, and the probe rejects endpoints that cannot create objects atomically.
fn cos_lease_expired(body: &[u8]) -> bool {
    let expires_at = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("expires_at").and_then(|v| v.as_str()).map(str::to_string))
        .and_then(|text| chrono::DateTime::parse_from_rfc3339(&text).ok());
    match expires_at {
        Some(at) => {
            chrono::Utc::now()
                > at.with_timezone(&chrono::Utc) + chrono::Duration::seconds(COS_LEASE_SKEW_SECS)
        }
        None => true,
    }
}

/// Keep background callers away from RemoteClient::put until the operator has
/// explicitly verified the exact endpoint/credential binding.
pub fn require_conditional_support(vault: &Vault, dek: &[u8; 32]) -> Result<(), String> {
    let (client, _, _) = configured_client(vault, dek)?;
    if client.conditional_verified {
        Ok(())
    } else {
        Err(SYNC_CONDITIONAL_WRITE_UNVERIFIED.into())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ConditionalSupportReport {
    pub verified: bool,
    pub probe_cleaned: bool,
    /// Probe exercises this endpoint now, not a universal provider guarantee.
    pub scope: String,
}

/// Explicit user-triggered, disposable-object capability probe. No incorrect
/// precondition is EVER sent to the vault object. Abort still cleans the probe.
pub fn verify_conditional_support(vault: &Vault, dek: &[u8;32],
    still_wanted: &dyn Fn() -> bool) -> Result<ConditionalSupportReport, String> {
    if !still_wanted() { return Err(SYNC_ABORTED.into()); }
    let (mut client, _, binding) = configured_client(vault, dek)?;
    client.object_key = format!("{}.probe-{}", client.object_key, uuid::Uuid::new_v4());
    client.conditional_verified = true; // Only this isolated client, never persisted yet.
    if client.get()?.is_some() { return Err("sync_probe_collision".into()); }
    let result = probe_conditions(&client, still_wanted);
    // Cleanup even after ambiguous network write errors; UUID is owned by this run.
    let cleanup = client.delete_probe().and_then(|()| {
        if client.get()?.is_some() { Err("sync_probe_cleanup_failed".into()) } else { Ok(()) }
    });
    if let Err(cleanup_error) = cleanup {
        return Err(format!("sync_probe_cleanup_failed: {cleanup_error}; probe={}; result={}",
            client.object_key, result.err().unwrap_or_else(|| "conditions_passed".into())));
    }
    result?;
    if !still_wanted() { return Err(SYNC_ABORTED.into()); }
    // A settings/credential change during the probe cannot attest the new target.
    if configured_client(vault, dek)?.2 != binding { return Err("sync_session_changed".into()); }
    vault.set_setting("sync_conditional_verified", &binding).map_err(|e| e.to_string())?;
    Ok(ConditionalSupportReport { verified: true, probe_cleaned: true,
        scope: "verified conditional PUT on an isolated object at this endpoint; provider behavior may change".into() })
}

fn probe_conditions(remote: &dyn RemoteStore, still_wanted: &dyn Fn() -> bool) -> Result<(), String> {
    let check = || if still_wanted() { Ok(()) } else { Err(SYNC_ABORTED.to_string()) };
    let first_body = uuid::Uuid::new_v4().to_string().into_bytes();
    let second_body = uuid::Uuid::new_v4().to_string().into_bytes();
    check()?;
    remote.put(&first_body, &WriteCondition::Missing)?;
    let first = remote.get()?.ok_or("sync_probe_missing")?;
    if first.body != first_body { return Err("sync_probe_content_changed".into()); }
    check()?;
    let bad = StrongEtag::parse(&format!("\"{}\"", uuid::Uuid::new_v4()))?;
    require_rejected(remote.put(&second_body, &WriteCondition::Match(bad)))?;
    let unchanged = remote.get()?.ok_or("sync_probe_missing")?;
    if unchanged.etag != first.etag || unchanged.body != first_body { return Err("sync_conditional_write_unsupported".into()); }
    check()?;
    remote.put(&second_body, &WriteCondition::Match(first.etag.clone()))?;
    let second = remote.get()?.ok_or("sync_probe_missing")?;
    if second.body != second_body || second.etag == first.etag { return Err("sync_probe_validator_not_updated".into()); }
    check()?;
    require_rejected(remote.put(&first_body, &WriteCondition::Match(first.etag)))?;
    require_rejected(remote.put(&first_body, &WriteCondition::Missing))?;
    let unchanged = remote.get()?.ok_or("sync_probe_missing")?;
    if unchanged.etag != second.etag || unchanged.body != second_body { return Err("sync_conditional_write_unsupported".into()); }
    check()
}

fn require_rejected(result: Result<(), String>) -> Result<(), String> {
    match result {
        Err(error) if error == "sync_precondition_failed" => Ok(()),
        Err(error) => Err(format!("sync_probe_inconclusive: {error}")),
        Ok(()) => Err("sync_conditional_write_unsupported".into()),
    }
}

fn persist_report(vault: &Vault, report: &SyncReport) {
    let summary = format!("pulled={} pushed={} unchanged={} removed={} conflicts={}",
        report.pulled, report.pushed, report.unchanged, report.removed, report.conflicts.len());
    let _ = vault.set_setting("sync_last_at", &chrono::Utc::now().to_rfc3339());
    let _ = vault.set_setting("sync_last_result", &summary);
    let _ = vault.audit("sync", None, &summary);
}

pub fn view(vault: &Vault) -> Result<SyncView, VaultError> {
    let config = load_config(vault)?;
    let auto = auto_settings(vault)?;
    Ok(SyncView {
        configured: config.is_some(),
        kind: config.as_ref().map(|c| c.kind.clone()),
        endpoint: config
            .as_ref()
            .map(|c| c.endpoint.clone())
            .unwrap_or_default(),
        username: config
            .as_ref()
            .map(|c| c.username.clone())
            .unwrap_or_default(),
        bucket: config.as_ref().map(|c| c.bucket.clone()).unwrap_or_default(),
        region: config
            .as_ref()
            .map(|c| c.region.clone())
            .unwrap_or_else(|| "us-east-1".into()),
        prefix: config.as_ref().map(|c| c.prefix.clone()).unwrap_or_default(),
        has_secret: vault.get_setting("sync_secret_enc")?.is_some(),
        device_id: device_id(vault)?,
        last_sync_at: vault.get_setting("sync_last_at")?,
        last_result: vault.get_setting("sync_last_result")?,
        auto_sync: auto.enabled,
        auto_sync_secs: auto.secs,
        // `view` has no DEK, so this is only a cheap hint. Commands that have
        // the unlocked DEK replace it with `view_with_dek`'s exact binding check.
        conditional_verified: vault.get_setting("sync_conditional_verified")?.is_some(),
    })
}

/// Build a sync view with the binding checked against the current config and
/// secret. A marker alone is never treated as proof of provider capability.
pub fn view_with_dek(vault: &Vault, dek: &[u8; 32]) -> Result<SyncView, String> {
    // Resolve/migrate the secret before building the view so legacy plaintext
    // settings do not make `has_secret` look false for this response.
    let conditional_verified = conditional_support_verified(vault, dek)?;
    let mut view = view(vault).map_err(|error| error.to_string())?;
    view.conditional_verified = conditional_verified;
    Ok(view)
}

pub fn save_config(
    vault: &Vault,
    dek: &[u8; 32],
    config: SyncConfig,
    secret: Option<&str>,
) -> Result<(), String> {
    let config = config.normalize()?;
    let secret = secret.map(str::trim).filter(|s| !s.is_empty());
    // Read through the migration-aware accessor before deciding whether a
    // secret is missing. Legacy databases may only have `sync_secret`.
    let has_existing_secret = vault
        .get_secret_setting(dek, "sync_secret")
        .map_err(|e| e.to_string())?
        .is_some();
    if secret.is_none() && !has_existing_secret {
        return Err("第一次保存需要填写同步密钥".into());
    }
    // Validate before changing the config so a rejected replacement cannot
    // leave a valid old attestation paired with a partially saved config.
    if let Some(secret) = secret {
        if secret.len() < 8 {
            return Err("同步密钥至少 8 位".into());
        }
    }
    let json = serde_json::to_string(&config).map_err(|e| e.to_string())?;
    vault
        .set_setting("sync_config", &json)
        .map_err(|e| e.to_string())?;
    if let Some(secret) = secret {
        let key = sync_key(secret);
        let check = encrypt(&key, b"sealbox-sync-v1").map_err(|e| e.to_string())?;
        vault
            .set_secret_setting(dek, "sync_secret", secret)
            .map_err(|e| e.to_string())?;
        vault
            .set_setting("sync_key_check", &hex::encode(check.to_bytes()))
            .map_err(|e| e.to_string())?;
    }

    // The binding includes the normalized config and derived sync key. Preserve
    // it only when both are unchanged; any changed endpoint/credential must be
    // explicitly re-verified by the operator.
    let previous_binding = vault
        .get_setting("sync_conditional_verified")
        .map_err(|e| e.to_string())?;
    if let Some(previous_binding) = previous_binding {
        let current_binding = conditional_capability_binding(vault, dek)?;
        if previous_binding != current_binding {
            vault
                .delete_setting("sync_conditional_verified")
                .map_err(|e| e.to_string())?;
        }
    }
    let _ = vault.audit("sync_config", None, "saved");
    Ok(())
}

pub fn clear_config(vault: &Vault) -> Result<(), VaultError> {
    for key in [
        "sync_config",
        "sync_secret_enc",
        "sync_secret",
        "sync_key_check",
        "sync_last_at",
        "sync_last_result",
        "sync_auto",
        "sync_auto_secs",
        "sync_conditional_verified",
    ] {
        vault.delete_setting(key)?;
    }
    let _ = vault.audit("sync_config", None, "cleared");
    Ok(())
}

pub fn sync_now(vault: &Vault, dek: &[u8; 32]) -> Result<SyncReport, String> {
    sync_now_guarded(vault, dek, &|| true)
}

/// `still_wanted` runs between the network round trips and the writes, so
/// background sync can stop once the vault locks.
pub fn sync_now_guarded(
    vault: &Vault,
    dek: &[u8; 32],
    still_wanted: &dyn Fn() -> bool,
) -> Result<SyncReport, String> {
    // Legacy callers still retain a remote-success/local-failure bundle. New
    // AppState callers own a runtime and invalidate it when their session locks.
    static LEGACY_RUNTIME: std::sync::OnceLock<std::sync::Mutex<SyncRuntime>> = std::sync::OnceLock::new();
    let mut runtime = LEGACY_RUNTIME.get_or_init(|| std::sync::Mutex::new(SyncRuntime::default()))
        .lock().map_err(|_| "sync_runtime_unavailable")?;
    sync_now_with_runtime(&mut runtime, vault, dek, still_wanted)
}

pub fn sync_now_with_runtime(runtime: &mut SyncRuntime, vault: &Vault, dek: &[u8;32],
    still_wanted: &dyn Fn() -> bool) -> Result<SyncReport, String> {
    if !still_wanted() { runtime.invalidate(); return Err(SYNC_ABORTED.into()); }
    if let Some(p) = runtime.pending.as_ref().filter(|p| p.uploaded.is_some()) {
        let token = p.token.clone();
        return runtime.commit(vault, dek, &token, &[], still_wanted);
    }
    // This single-stage entry is also used by both auto-sync implementations.
    // Reject before preview/GET so an unverified target never reaches PUT.
    require_conditional_support(vault, dek)?;
    let preview = runtime.preview(vault, dek)?;
    if !preview.report.conflict_details.is_empty() {
        return Ok(blocked_report(&preview.report, "sync_conflicts_require_resolution", false));
    }
    runtime.commit(vault, dek, &preview.token, &[], still_wanted)
}

fn load_config(vault: &Vault) -> Result<Option<SyncConfig>, VaultError> {
    let Some(raw) = vault.get_setting("sync_config")? else {
        return Ok(None);
    };
    let config: SyncConfig = serde_json::from_str(&raw)?;
    Ok(Some(
        config.normalize().map_err(|_| VaultError::CorruptBackup)?,
    ))
}

fn device_id(vault: &Vault) -> Result<String, VaultError> {
    if let Some(id) = vault.get_setting("sync_device_id")? {
        if !id.is_empty() {
            return Ok(id);
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    vault.set_setting("sync_device_id", &id)?;
    Ok(id)
}

fn sync_key(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"sealbox-sync-v1\0");
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

impl SyncSnapshot {
    fn from_vault(dek: &[u8; 32], snapshot: &BackupSnapshot) -> Result<Self, String> {
        let entries = snapshot
            .entries
            .iter()
            .map(|entry| SyncEntry::from_sealed(dek, entry).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            folders: snapshot.folders.clone(),
            tags: snapshot.tags.clone(),
            entries,
            deleted: Vec::new(),
        })
    }

    fn seal(&self, dek: &[u8; 32]) -> Result<BackupSnapshot, String> {
        let entries = self
            .entries
            .iter()
            .map(|entry| entry.seal(dek).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(BackupSnapshot {
            folders: self.folders.clone(),
            tags: self.tags.clone(),
            entries,
        })
    }
}

impl SyncEntry {
    fn from_sealed(dek: &[u8; 32], entry: &BackupEntry) -> Result<Self, VaultError> {
        let secret_bytes = decrypt(dek, &Encrypted::from_bytes(&entry.secret_blob)?)?;
        let secret: SecretPayload =
            serde_json::from_slice(&secret_bytes).map_err(|_| VaultError::CorruptBackup)?;
        let notes = match &entry.notes_blob {
            Some(blob) => {
                let bytes = decrypt(dek, &Encrypted::from_bytes(blob)?)?;
                Some(String::from_utf8(bytes).map_err(|_| VaultError::CorruptBackup)?)
            }
            None => None,
        };
        if secret.kind() != crate::vault::EntryKind::parse(&entry.kind)? { return Err(VaultError::CorruptBackup); }
        let profile = entry.profile_blob.as_ref().map(|blob| open_profile_blob(dek, blob, &secret)).transpose()?;
        let mut entry = entry.clone();
        entry.secret_blob.clear();
        entry.notes_blob = None;
        entry.profile_blob = None;
        Ok(Self {
            entry,
            secret: Some(secret),
            notes,
            profile,
        })
    }

    fn open_legacy(&self, dek: Option<&[u8; 32]>) -> Result<Self, String> {
        if self.secret.is_some() {
            return Ok(self.clone());
        }
        let Some(dek) = dek else {
            return Err("远端同步文件是旧格式，且无法用本机保险库密钥解开".into());
        };
        Self::from_sealed(dek, &self.entry).map_err(|_| {
            "远端条目是用另一台设备的保险库密钥加密的，请在那台设备上再同步一次".into()
        })
    }

    fn seal(&self, dek: &[u8; 32]) -> Result<BackupEntry, VaultError> {
        let secret = self.secret.as_ref().ok_or(VaultError::CorruptBackup)?;
        if secret.kind() != crate::vault::EntryKind::parse(&self.entry.kind)? { return Err(VaultError::CorruptBackup); }
        if let Some(profile) = &self.profile { validate_for_secret(profile, secret).map_err(VaultError::InvalidProfile)?; }
        let mut entry = self.entry.clone();
        entry.profile_blob = self.profile.as_ref().map(|profile| {
            let plain = Zeroizing::new(serde_json::to_vec(profile)?);
            encrypt(dek, &plain).map(|blob| blob.to_bytes()).map_err(VaultError::from)
        }).transpose()?;
        let secret = serde_json::to_vec(secret)?;
        entry.secret_blob = encrypt(dek, &secret)?.to_bytes();
        entry.notes_blob = match &self.notes {
            Some(notes) => Some(encrypt(dek, notes.as_bytes())?.to_bytes()),
            None => None,
        };
        Ok(entry)
    }
}

fn encode_snapshot(
    key: &[u8; 32],
    snapshot: &SyncSnapshot,
    device_id: &str,
) -> Result<Vec<u8>, VaultError> {
    let json = serde_json::to_vec(snapshot)?;
    let file = SyncFile {
        blob: encrypt(key, &json)?,
        device_id: device_id.to_string(),
        written_at: chrono::Utc::now().to_rfc3339(),
    };
    let mut out = Vec::from(*MAGIC);
    out.extend(serde_json::to_vec(&file)?);
    Ok(out)
}

/// Returns the snapshot plus whether the remote file was the old, device-sealed
/// format. Callers must rewrite that file, even when the merged content is
/// unchanged, or other devices keep failing to open it.
fn decode_snapshot(
    key: &[u8; 32],
    dek: Option<&[u8; 32]>,
    bytes: &[u8],
) -> Result<(SyncSnapshot, bool), String> {
    if bytes.len() < MAGIC.len() + 16 || &bytes[..MAGIC.len()] != MAGIC {
        return Err("远端文件不是 Sealbox 同步快照".into());
    }
    let file: SyncFile = serde_json::from_slice(&bytes[MAGIC.len()..])
        .map_err(|_| "远端同步文件损坏".to_string())?;
    let json = decrypt(key, &file.blob).map_err(|_| "同步密钥无法解开远端文件".to_string())?;
    if let Ok(mut snapshot) = serde_json::from_slice::<SyncSnapshot>(&json) {
        let legacy = snapshot.entries.iter().any(|entry| entry.secret.is_none());
        if legacy {
            snapshot.entries = snapshot
                .entries
                .iter()
                .map(|entry| entry.open_legacy(dek))
                .collect::<Result<Vec<_>, _>>()?;
        }
        for entry in &snapshot.entries {
            let secret = entry.secret.as_ref().ok_or("远端同步凭据缺失")?;
            if let Some(profile) = &entry.profile {
                validate_for_secret(profile, secret).map_err(|_| "远端同步 profile 无效".to_string())?;
            }
            if entry.entry.profile_blob.is_some() { return Err("远端同步 profile 未转换为可移植格式".into()); }
        }
        return Ok((snapshot, legacy));
    }
    let legacy: BackupSnapshot =
        serde_json::from_slice(&json).map_err(|_| "远端同步内容损坏".to_string())?;
    let Some(dek) = dek else {
        return Err("远端同步文件是旧格式，且无法用本机保险库密钥解开".into());
    };
    let snapshot = SyncSnapshot::from_vault(dek, &legacy).map_err(|_| {
        "远端条目是用另一台设备的保险库密钥加密的，请在那台设备上再同步一次".to_string()
    })?;
    Ok((snapshot, true))
}

fn sorted_tombstones(snapshot: &SyncSnapshot) -> Vec<Tombstone> {
    let mut deleted = snapshot.deleted.clone();
    deleted.sort_by(|a, b| {
        (a.kind.as_str(), a.id.as_str()).cmp(&(b.kind.as_str(), b.id.as_str()))
    });
    deleted
}

/// Everything both sides must agree on for an entry to count as unchanged.
/// `use_count`/`last_used_at` move on every autofill without touching
/// `updated_at`, so they are excluded here and merged separately.
fn normalized_entry(entry: &SyncEntry) -> SyncEntry {
    let mut copy = entry.clone();
    copy.entry.use_count = 0;
    copy.entry.last_used_at = None;
    copy
}

/// Full content digest for optimistic concurrency, including usage metadata.
fn full_snapshot_digest(snapshot: &SyncSnapshot) -> String {
    let mut snapshot = snapshot.clone();
    snapshot.entries.sort_by(|a,b| a.entry.id.cmp(&b.entry.id));
    snapshot.folders.sort_by(|a,b| a.id.cmp(&b.id));
    snapshot.tags.sort();
    snapshot.deleted = sorted_tombstones(&snapshot);
    hex::encode(Sha256::digest(serde_json::to_vec(&snapshot).expect("serializable snapshot")))
}

fn detect_conflicts(local: &SyncSnapshot, remote: &SyncSnapshot) -> Vec<SyncConflict> {
    let mut conflicts = Vec::new();
    for left in &local.entries {
        if let Some(right) = remote.entries.iter().find(|r| r.entry.id == left.entry.id) {
            let ld = left.entry.deleted_at.is_some();
            let rd = right.entry.deleted_at.is_some();
            if ld != rd || (cmp_time(&left.entry.updated_at, &right.entry.updated_at) == std::cmp::Ordering::Equal
                && entry_digest(left) != entry_digest(right)) {
                conflicts.push(SyncConflict { id: left.entry.id.clone(), title: left.entry.title.clone(),
                    kind: if ld != rd { ConflictKind::DeleteEdit } else { ConflictKind::EditEdit },
                    local_deleted: ld, remote_deleted: rd });
            }
        }
    }
    for (deleted_side, edited_side, local_deleted) in [(local, remote, true), (remote, local, false)] {
        for tomb in &deleted_side.deleted {
            if tomb.kind != TOMBSTONE_ENTRY { continue; }
            if let Some(entry) = edited_side.entries.iter().find(|e| e.entry.id == tomb.id && e.entry.deleted_at.is_none()) {
                if !conflicts.iter().any(|c| c.id == tomb.id) {
                    conflicts.push(SyncConflict { id: tomb.id.clone(), title: entry.entry.title.clone(),
                        kind: ConflictKind::DeleteEdit, local_deleted, remote_deleted: !local_deleted });
                }
            }
        }
    }
    conflicts.sort_by(|a,b| a.id.cmp(&b.id));
    conflicts
}

fn validate_choices(conflicts: &[SyncConflict], choices: &[SyncResolution]) -> Result<(), String> {
    if choices.len() != conflicts.len() { return Err("sync_all_choices_required".into()); }
    let mut seen = std::collections::HashSet::new();
    for choice in choices {
        if !seen.insert(&choice.id) { return Err("sync_duplicate_choice".into()); }
        let conflict = conflicts.iter().find(|c| c.id == choice.id).ok_or("sync_unknown_choice")?;
        if conflict.kind == ConflictKind::DeleteEdit && !choice.confirm_delete_edit {
            return Err("sync_delete_edit_confirmation_required".into());
        }
    }
    Ok(())
}

fn resolve_snapshots(local: &SyncSnapshot, remote: &SyncSnapshot, choices: &[SyncResolution]) -> Result<SyncSnapshot, String> {
    let conflicts = detect_conflicts(local, remote);
    validate_choices(&conflicts, choices)?;
    let (mut merged, _) = merge_snapshots(local, remote);
    for choice in choices {
        let left = local.entries.iter().find(|e| e.entry.id == choice.id);
        let right = remote.entries.iter().find(|e| e.entry.id == choice.id);
        let lt = local.deleted.iter().find(|t| t.kind == TOMBSTONE_ENTRY && t.id == choice.id);
        let rt = remote.deleted.iter().find(|t| t.kind == TOMBSTONE_ENTRY && t.id == choice.id);
        merged.entries.retain(|e| e.entry.id != choice.id);
        merged.deleted.retain(|t| t.kind != TOMBSTONE_ENTRY || t.id != choice.id);
        let mut add_state = |entry: Option<&SyncEntry>, tomb: Option<&Tombstone>| {
            if let Some(tomb) = tomb { merged.deleted.push(tomb.clone()); }
            else if let Some(entry) = entry { merged.entries.push(entry.clone()); }
        };
        match choice.choice {
            ConflictChoice::Local => add_state(left, lt),
            ConflictChoice::Remote => add_state(right, rt),
            ConflictChoice::Both => {
                let left_deleted = lt.is_some() || left.is_some_and(|e| e.entry.deleted_at.is_some());
                let right_deleted = rt.is_some() || right.is_some_and(|e| e.entry.deleted_at.is_some());
                if left_deleted || right_deleted {
                    if left_deleted { add_state(left, lt); } else { add_state(right, rt); }
                    let edited = if left_deleted { right } else { left };
                    if let Some(edited) = edited {
                        let mut copy = edited.clone();
                        copy.entry.id = uuid::Uuid::new_v4().to_string();
                        copy.entry.deleted_at = None;
                        merged.entries.push(copy);
                    }
                } else {
                    add_state(left, None);
                    if let Some(right) = right {
                        let mut copy = right.clone();
                        copy.entry.id = uuid::Uuid::new_v4().to_string();
                        merged.entries.push(copy);
                    }
                }
            }
        }
    }
    // Reapply folder aliases to newly copied conflict entries too.
    remap_folders(&mut merged, local, remote);
    Ok(merged)
}

#[cfg(test)]
fn snapshot_digest(snapshot: &SyncSnapshot) -> String {
    let mut entries: Vec<SyncEntry> = snapshot.entries.iter().map(normalized_entry).collect();
    entries.sort_by(|a, b| a.entry.id.cmp(&b.entry.id));
    let mut folders = snapshot.folders.clone();
    folders.sort_by(|a, b| a.id.cmp(&b.id));
    let mut tags = snapshot.tags.clone();
    tags.sort();
    #[derive(Serialize)]
    struct Digest<'a> {
        folders: &'a [crate::vault::FolderDto],
        tags: &'a [String],
        entries: &'a [SyncEntry],
        deleted: Vec<Tombstone>,
    }
    let digest = Digest {
        folders: &folders,
        tags: &tags,
        entries: &entries,
        deleted: sorted_tombstones(snapshot),
    };
    hex::encode(Sha256::digest(
        serde_json::to_vec(&digest).unwrap_or_default(),
    ))
}

/// Returns true when the tombstone removes the entry. An entry edited after
/// its tombstone wins instead, and the stale tombstone is dropped.
fn apply_entry_tombstone(
    tombstones: &mut HashMap<(String, String), String>,
    entry: &SyncEntry,
) -> bool {
    let key = (TOMBSTONE_ENTRY.to_string(), entry.entry.id.clone());
    match tombstones.get(&key) {
        Some(at) if cmp_time(&entry.entry.updated_at, at) != std::cmp::Ordering::Greater => true,
        Some(_) => {
            tombstones.remove(&key);
            false
        }
        None => false,
    }
}

/// Usage counters are per-device bookkeeping, not user content, so keep the
/// furthest value instead of letting one device rewind the other.
fn merge_usage(mut kept: SyncEntry, other: &SyncEntry) -> SyncEntry {
    kept.entry.use_count = kept.entry.use_count.max(other.entry.use_count);
    kept.entry.last_used_at = match (&kept.entry.last_used_at, &other.entry.last_used_at) {
        (Some(left), Some(right)) => Some(if cmp_time(left, right) == std::cmp::Ordering::Less {
            right.clone()
        } else {
            left.clone()
        }),
        (Some(value), None) | (None, Some(value)) => Some(value.clone()),
        (None, None) => None,
    };
    kept
}

fn prune_tombstones(tombstones: HashMap<(String, String), String>) -> Vec<Tombstone> {
    let cutoff = chrono::Utc::now() - chrono::Duration::days(TOMBSTONE_RETENTION_DAYS);
    let mut deleted: Vec<Tombstone> = tombstones
        .into_iter()
        .filter(|(_, at)| parse_time(at).map_or(true, |time| time >= cutoff))
        .map(|((kind, id), deleted_at)| Tombstone {
            kind,
            id,
            deleted_at,
        })
        .collect();
    deleted.sort_by(|a, b| {
        (a.kind.as_str(), a.id.as_str()).cmp(&(b.kind.as_str(), b.id.as_str()))
    });
    deleted
}

fn merge_snapshots(local: &SyncSnapshot, remote: &SyncSnapshot) -> (SyncSnapshot, SyncReport) {
    let mut tombstones: HashMap<(String, String), String> = HashMap::new();
    for item in local.deleted.iter().chain(remote.deleted.iter()) {
        let key = (item.kind.clone(), item.id.clone());
        let keep_existing = tombstones
            .get(&key)
            .is_some_and(|current| cmp_time(current, &item.deleted_at) != std::cmp::Ordering::Less);
        if !keep_existing {
            tombstones.insert(key, item.deleted_at.clone());
        }
    }

    let mut remote_by_id: HashMap<&str, &SyncEntry> = remote
        .entries
        .iter()
        .map(|e| (e.entry.id.as_str(), e))
        .collect();
    let mut entries = Vec::new();
    let mut pulled = 0usize;
    let mut pushed = 0usize;
    let mut unchanged = 0usize;
    let mut removed = 0usize;
    let mut conflicts = Vec::new();

    for local_entry in &local.entries {
        if apply_entry_tombstone(&mut tombstones, local_entry) {
            remote_by_id.remove(local_entry.entry.id.as_str());
            removed += 1;
            continue;
        }
        match remote_by_id.remove(local_entry.entry.id.as_str()) {
            None => {
                pushed += 1;
                entries.push(local_entry.clone());
            }
            Some(remote_entry) => {
                let local_deleted = local_entry.entry.deleted_at.is_some();
                let remote_deleted = remote_entry.entry.deleted_at.is_some();
                match cmp_time(&local_entry.entry.updated_at, &remote_entry.entry.updated_at) {
                    std::cmp::Ordering::Greater => {
                        pushed += 1;
                        entries.push(merge_usage(local_entry.clone(), remote_entry));
                    }
                    std::cmp::Ordering::Less => {
                        pulled += 1;
                        entries.push(merge_usage(remote_entry.clone(), local_entry));
                    }
                    std::cmp::Ordering::Equal if local_deleted != remote_deleted => {
                        // A delete and an edit landed in the same instant.
                        // Keep the delete, otherwise the item silently returns.
                        if remote_deleted {
                            pulled += 1;
                            entries.push(remote_entry.clone());
                        } else {
                            pushed += 1;
                            entries.push(local_entry.clone());
                        }
                    }
                    std::cmp::Ordering::Equal => {
                        if entry_digest(local_entry) == entry_digest(remote_entry) {
                            unchanged += 1;
                        } else {
                            conflicts.push(format!(
                                "{} ({})",
                                local_entry.entry.title, local_entry.entry.id
                            ));
                        }
                        entries.push(merge_usage(local_entry.clone(), remote_entry));
                    }
                }
            }
        }
    }
    for remote_entry in remote_by_id.into_values() {
        if apply_entry_tombstone(&mut tombstones, remote_entry) {
            removed += 1;
            continue;
        }
        pulled += 1;
        entries.push(remote_entry.clone());
    }
    entries.sort_by(|a, b| a.entry.id.cmp(&b.entry.id));

    let mut folders: Vec<crate::vault::FolderDto> = Vec::new();
    for folder in local.folders.iter().chain(remote.folders.iter()) {
        if tombstones.contains_key(&(TOMBSTONE_FOLDER.to_string(), folder.id.clone())) {
            continue;
        }
        if !folders
            .iter()
            .any(|item| item.id == folder.id || item.name == folder.name)
        {
            folders.push(folder.clone());
        }
    }
    let folder_aliases: HashMap<String, String> = local.folders.iter().chain(remote.folders.iter())
        .filter_map(|folder| folders.iter().find(|kept| kept.id == folder.id || kept.name == folder.name)
            .map(|kept| (folder.id.clone(), kept.id.clone())))
        .collect();
    for entry in entries.iter_mut() {
        if let Some(id) = entry.entry.folder_id.clone() {
            if let Some(kept) = folder_aliases.get(&id) { entry.entry.folder_id = Some(kept.clone()); }
            else if let Some(at) = tombstones.get(&(TOMBSTONE_FOLDER.to_string(), id)) {
                entry.entry.folder_id = None;
                if cmp_time(&entry.entry.updated_at, at) == std::cmp::Ordering::Less { entry.entry.updated_at = at.clone(); }
            }
        }
        entry.entry.tags.retain(|tag| !tombstones.contains_key(&("tag".into(), tag.clone())));
    }

    let mut tags = local.tags.clone();
    for tag in &remote.tags {
        if !tags.iter().any(|item| item == tag) {
            tags.push(tag.clone());
        }
    }
    tags.retain(|tag| !tombstones.contains_key(&("tag".into(), tag.clone())));
    let conflict_details = detect_conflicts(local, remote);
    // Legacy summaries retain IDs only. Titles are available in UI-only details.
    conflicts = conflict_details.iter().map(|c| c.id.clone()).collect();
    (
        SyncSnapshot {
            folders,
            tags,
            entries,
            deleted: prune_tombstones(tombstones),
        },
        SyncReport {
            pulled,
            pushed,
            unchanged,
            removed,
            conflicts,
            remote_missing: false,
            phase: if conflict_details.is_empty() { SyncPhase::Preview } else { SyncPhase::Conflicts },
            blocked: None,
            retryable: false,
            conflict_details,
        },
    )
}

fn remap_folders(merged: &mut SyncSnapshot, local: &SyncSnapshot, remote: &SyncSnapshot) {
    for entry in &mut merged.entries {
        if let Some(id) = entry.entry.folder_id.clone() {
            if merged.folders.iter().any(|f| f.id == id) { continue; }
            if let Some(source) = local.folders.iter().chain(remote.folders.iter()).find(|f| f.id == id) {
                if let Some(target) = merged.folders.iter().find(|f| f.name == source.name) {
                    entry.entry.folder_id = Some(target.id.clone());
                } else if merged.deleted.iter().any(|t| t.kind == TOMBSTONE_FOLDER && t.id == id) {
                    entry.entry.folder_id = None;
                }
            }
        }
        entry.entry.tags.retain(|tag| !merged.deleted.iter().any(|t| t.kind == "tag" && &t.id == tag));
    }
}

fn entry_digest(entry: &SyncEntry) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(&normalized_entry(entry)).unwrap_or_default(),
    ))
}

fn cmp_time(left: &str, right: &str) -> std::cmp::Ordering {
    match (parse_time(left), parse_time(right)) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

fn parse_time(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|time| time.with_timezone(&chrono::Utc))
}

struct RemoteClient {
    kind: SyncKind,
    endpoint: String,
    username: String,
    secret: String,
    bucket: String,
    region: String,
    object_key: String,
    conditional_verified: bool,
    /// Tencent COS ignores If-Match/If-None-Match on PUT; writes go through a
    /// create-only lease instead. See `cos_put`.
    cos: bool,
}

impl Drop for RemoteClient {
    fn drop(&mut self) { self.secret.zeroize(); }
}
impl RemoteStore for RemoteClient {
    fn get(&self) -> Result<Option<RemoteObject>, String> { RemoteClient::get(self) }
    fn put(&self, body: &[u8], condition: &WriteCondition) -> Result<(), String> {
        RemoteClient::put(self, body, condition)
    }
}

impl RemoteClient {
    fn new(config: &SyncConfig, secret: &str) -> Result<Self, String> {
        let object_key = if config.prefix.is_empty() {
            OBJECT_NAME.to_string()
        } else {
            format!("{}/{}", config.prefix, OBJECT_NAME)
        };
        Ok(Self {
            kind: config.kind.clone(),
            endpoint: config.endpoint.clone(),
            username: config.username.clone(),
            secret: secret.to_string(),
            bucket: config.bucket.clone(),
            region: config.region.clone(),
            object_key,
            conditional_verified: false,
            cos: config.kind == SyncKind::S3 && is_tencent_cos_endpoint(&config.endpoint),
        })
    }

    fn get(&self) -> Result<Option<RemoteObject>, String> {
        match self.kind {
            SyncKind::Webdav => self.webdav_get(),
            SyncKind::S3 => self.s3_get(),
        }
    }

    fn put(&self, bytes: &[u8], condition: &WriteCondition) -> Result<(), String> {
        if !self.conditional_verified {
            return Err(SYNC_CONDITIONAL_WRITE_UNVERIFIED.into());
        }
        if bytes.len() > MAX_REMOTE_BYTES { return Err("sync snapshot exceeds 64MB".into()); }
        match self.kind {
            SyncKind::Webdav => self.webdav_put(bytes, condition),
            SyncKind::S3 => self.s3_put(bytes, condition),
        }
    }

    fn encoded_key(&self) -> String {
        self.object_key
            .split('/')
            .map(encode_path_segment)
            .collect::<Vec<_>>()
            .join("/")
    }

    fn webdav_url(&self) -> String {
        format!("{}/{}", self.endpoint, self.encoded_key())
    }

    fn webdav_get(&self) -> Result<Option<RemoteObject>, String> {
        match self.agent().get(&self.webdav_url()).call() {
            Ok(response) => read_remote_object(response).map(Some),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(code, response)) => {
                Err(format!("WebDAV HTTP {code}: {}", brief(response)))
            }
            Err(error) => Err(format!("WebDAV connection failed: {error}")),
        }
    }

    fn webdav_put(&self, bytes: &[u8], condition: &WriteCondition) -> Result<(), String> {
        let (name, value) = condition.header();
        match self
            .agent()
            .put(&self.webdav_url())
            .set("Content-Type", "application/octet-stream")
            .set(name, value)
            .send_bytes(bytes)
        {
            Ok(response) if (200..300).contains(&response.status()) => Ok(()),
            Ok(response) => Err(format!("WebDAV write failed: HTTP {}", response.status())),
            Err(ureq::Error::Status(412, _)) => Err("sync_precondition_failed".into()),
            Err(ureq::Error::Status(code, response)) => Err(format!(
                "WebDAV write failed: HTTP {code} {}",
                brief(response)
            )),
            Err(error) => Err(format!("WebDAV write failed: {error}")),
        }
    }

    fn s3_url(&self) -> String {
        self.s3_url_for(&self.object_key)
    }

    fn s3_url_for(&self, key: &str) -> String {
        let encoded = key
            .split('/')
            .map(encode_path_segment)
            .collect::<Vec<_>>()
            .join("/");
        if is_eos_endpoint(&self.endpoint) {
            return format!(
                "{}/{}/{}",
                self.endpoint.trim_end_matches('/'),
                encode_path_segment(&self.bucket),
                encoded
            );
        }
        let host = self
            .endpoint
            .trim_start_matches("https://")
            .trim_end_matches('/');
        let base = if host.starts_with(&format!("{}.", self.bucket)) {
            self.endpoint.clone()
        } else {
            format!("https://{}.{}", self.bucket, host)
        };
        format!("{}/{}", base.trim_end_matches('/'), encoded)
    }

    fn s3_get(&self) -> Result<Option<RemoteObject>, String> {
        self.s3_get_key(&self.object_key)
    }

    fn s3_get_key(&self, key: &str) -> Result<Option<RemoteObject>, String> {
        let url = self.s3_url_for(key);
        let headers = self.s3_headers("GET", &url, &[])?;
        let mut request = self.agent().get(&url);
        for (name, value) in &headers {
            request = request.set(name, value);
        }
        match request.call() {
            Ok(response) => read_remote_object(response).map(Some),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(code, response)) => {
                Err(format!("S3 HTTP {code}: {}", brief(response)))
            }
            Err(error) => Err(format!("S3 connection failed: {error}")),
        }
    }

    fn s3_put(&self, bytes: &[u8], condition: &WriteCondition) -> Result<(), String> {
        if self.cos {
            return self.cos_put(bytes, condition);
        }
        self.s3_put_key(&self.s3_url(), bytes, Some(condition), &[])
    }

    /// Tencent COS ignores `If-Match`/`If-None-Match` on PUT Object, so sync has
    /// to build the same guarantees from `x-cos-forbid-overwrite`, which COS
    /// honors atomically (200 when absent, 409 when the key already exists).
    ///
    /// Create (missing remote) is directly a conditional write. Replace takes a
    /// create-only lease on `<object>.lease`, re-reads the ETag under that lease,
    /// and only then overwrites. Two devices can no longer interleave a
    /// read-modify-write; a holder that pauses past the TTL can still write after
    /// its lease was stolen, which narrows to roughly one request.
    fn cos_put(&self, bytes: &[u8], condition: &WriteCondition) -> Result<(), String> {
        let url = self.s3_url();
        match condition {
            WriteCondition::Missing => self.cos_create_only(&url, bytes),
            WriteCondition::Match(expected) => {
                let nonce = self.cos_lease_acquire(&self.object_key)?;
                let result = match self.s3_get_key(&self.object_key) {
                    Ok(Some(object)) if &object.etag == expected => self.s3_put_key(&url, bytes, None, &[]),
                    Ok(_) => Err("sync_precondition_failed".into()),
                    Err(error) => Err(error),
                };
                self.cos_lease_release(&self.object_key, &nonce);
                result
            }
        }
    }

    fn cos_create_only(&self, url: &str, bytes: &[u8]) -> Result<(), String> {
        self.s3_put_key(url, bytes, None, &[("x-cos-forbid-overwrite", "true")])
    }

    /// Returns the nonce this device now owns. A lease left behind by a crash is
    /// stolen only after its expiry plus a clock-skew margin.
    fn cos_lease_acquire(&self, key: &str) -> Result<String, String> {
        let lease_key = format!("{key}.lease");
        let lease_url = self.s3_url_for(&lease_key);
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(COS_LEASE_TTL_SECS);
        for _ in 0..3 {
            let nonce = uuid::Uuid::new_v4().to_string();
            let body = serde_json::json!({
                "nonce": nonce,
                "expires_at": expires_at.to_rfc3339(),
            })
            .to_string();
            match self.cos_create_only(&lease_url, body.as_bytes()) {
                Ok(()) => return Ok(nonce),
                Err(error) if error == "sync_precondition_failed" => {
                    match self.s3_get_key(&lease_key)? {
                        Some(current) if !cos_lease_expired(&current.body) => {
                            return Err("sync_lease_busy".into());
                        }
                        Some(_) => self.cos_delete_key(&lease_key)?,
                        None => {}
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err("sync_lease_busy".into())
    }

    /// Best effort: a failed release only delays other devices until the TTL.
    fn cos_lease_release(&self, key: &str, nonce: &str) {
        let lease_key = format!("{key}.lease");
        let Ok(Some(current)) = self.s3_get_key(&lease_key) else { return };
        let owned = serde_json::from_slice::<serde_json::Value>(&current.body)
            .ok()
            .and_then(|value| value.get("nonce").and_then(|v| v.as_str()).map(str::to_string))
            .is_some_and(|value| value == nonce);
        if owned {
            let _ = self.cos_delete_key(&lease_key);
        }
    }

    fn cos_delete_key(&self, key: &str) -> Result<(), String> {
        let url = self.s3_url_for(key);
        let headers = self.s3_headers("DELETE", &url, &[])?;
        let mut request = self.agent().delete(&url);
        for (name, value) in &headers {
            request = request.set(name, value);
        }
        match request.call() {
            Ok(response) if (200..300).contains(&response.status()) => Ok(()),
            Err(ureq::Error::Status(404, _)) => Ok(()),
            Ok(response) => Err(format!("S3 delete failed: HTTP {}", response.status())),
            Err(ureq::Error::Status(code, response)) => {
                Err(format!("S3 delete failed: HTTP {code} {}", brief(response)))
            }
            Err(error) => Err(format!("S3 delete failed: {error}")),
        }
    }

    fn s3_put_key(&self, url: &str, bytes: &[u8], condition: Option<&WriteCondition>,
        extra: &[(&str, &str)]) -> Result<(), String> {
        let headers = self.s3_headers_extra("PUT", url, bytes, condition, extra)?;
        let mut request = self.agent().put(url);
        for (name, value) in &headers {
            request = request.set(name, value);
        }
        let create_only = extra
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-cos-forbid-overwrite"));
        match request.send_bytes(bytes) {
            Ok(response) if (200..300).contains(&response.status()) => Ok(()),
            Ok(response) => Err(format!("S3 write failed: HTTP {}", response.status())),
            Err(ureq::Error::Status(412, _)) => Err("sync_precondition_failed".into()),
            Err(ureq::Error::Status(409, _)) if create_only => {
                Err("sync_precondition_failed".into())
            }
            Err(ureq::Error::Status(code, response)) => {
                Err(format!("S3 write failed: HTTP {code} {}", brief(response)))
            }
            Err(error) => Err(format!("S3 write failed: {error}")),
        }
    }

    fn s3_headers(
        &self,
        method: &str,
        url: &str,
        body: &[u8],
    ) -> Result<Vec<(String, String)>, String> {
        self.s3_headers_extra(method, url, body, None, &[])
    }

    /// `extra` headers are part of the signature, so a provider cannot drop them
    /// silently while the request still verifies.
    fn s3_headers_extra(&self, method: &str, url: &str, body: &[u8],
        condition: Option<&WriteCondition>, extra: &[(&str, &str)])
        -> Result<Vec<(String, String)>, String> {
        if is_eos_endpoint(&self.endpoint) {
            return self.eos_headers_conditional(method, url, condition);
        }
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let payload_hash = hex::encode(Sha256::digest(body));
        let (host, canonical_uri, _) = split_url(url)?;
        let mut signing_headers = vec![("host".to_string(), host),
            ("x-amz-content-sha256".into(), payload_hash.clone()), ("x-amz-date".into(), amz_date.clone())];
        if let Some(condition) = condition {
            let (name, value) = condition.header();
            signing_headers.push((name.into(), value.into()));
        }
        for (name, value) in extra {
            signing_headers.push(((*name).to_string(), (*value).to_string()));
        }
        signing_headers.sort_by(|a,b| a.0.cmp(&b.0));
        let canonical_headers = signing_headers.iter().map(|(name,value)| format!("{name}:{value}\n")).collect::<String>();
        let signed_headers = signing_headers.iter().map(|(name,_)| name.as_str()).collect::<Vec<_>>().join(";");
        let canonical_request = format!(
            "{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let scope = format!("{date_stamp}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let signing_key = s3_signing_key(&self.secret, &date_stamp, &self.region)?;
        let mut mac = HmacSha256::new_from_slice(&signing_key).map_err(|_| "S3 signing failed")?;
        mac.update(string_to_sign.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={signed_headers}, Signature={signature}",
            self.username, scope
        );
        let mut headers = vec![
            ("Authorization".into(), authorization),
            ("x-amz-date".into(), amz_date),
            ("x-amz-content-sha256".into(), payload_hash),
            ("Content-Type".into(), "application/octet-stream".into()),
        ];
        if let Some(condition) = condition {
            let (name,value) = condition.header();
            headers.push((name.into(), value.into()));
        }
        for (name, value) in extra {
            headers.push(((*name).into(), (*value).into()));
        }
        Ok(headers)
    }

    fn eos_headers_conditional(&self, method: &str, url: &str,
        condition: Option<&WriteCondition>) -> Result<Vec<(String, String)>, String> {
        let date = chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let content_type = "application/octet-stream";
        let (_, canonical_uri, _) = split_url(url)?;
        let string_to_sign = format!(
            "{method}\n\n{content_type}\n{date}\n{canonical_uri}"
        );
        let signature = base64::engine::general_purpose::STANDARD
            .encode(hmac_sha1(self.secret.as_bytes(), string_to_sign.as_bytes()));
        let mut headers = vec![
            ("Authorization".into(), format!("AWS {}:{signature}", self.username)),
            ("Date".into(), date),
            ("Content-Type".into(), content_type.into()),
        ];
        if let Some(condition) = condition {
            let (name, value) = condition.header();
            headers.push((name.into(), value.into()));
        }
        Ok(headers)
    }

    fn delete_probe(&self) -> Result<(), String> {
        let (_, suffix) = self.object_key.rsplit_once(".probe-").ok_or("sync_not_probe_object")?;
        uuid::Uuid::parse_str(suffix).map_err(|_| "sync_not_probe_object")?;
        if self.cos {
            // A lease left by an aborted probe would block the object forever.
            let _ = self.cos_delete_key(&format!("{}.lease", self.object_key));
        }
        let url = match self.kind { SyncKind::Webdav => self.webdav_url(), SyncKind::S3 => self.s3_url() };
        let mut request = self.agent().delete(&url);
        if self.kind == SyncKind::S3 {
            for (name, value) in self.s3_headers("DELETE", &url, &[])? { request = request.set(&name, &value); }
        }
        match request.call() {
            Ok(response) if (200..300).contains(&response.status()) => Ok(()),
            Err(ureq::Error::Status(404, _)) => Ok(()),
            Ok(response) => Err(format!("probe DELETE HTTP {}", response.status())),
            Err(error) => Err(format!("probe DELETE failed: {error}")),
        }
    }

    fn agent(&self) -> ureq::Agent {
        let mut builder = ureq::builder()
            .redirects(0)
            .timeout(Duration::from_secs(30))
            .timeout_connect(Duration::from_secs(8))
            .resolver(PublicResolver)
            .user_agent(concat!("Sealbox/", env!("CARGO_PKG_VERSION")));
        if self.kind == SyncKind::Webdav {
            let auth = basic_auth(&self.username, &self.secret);
            builder = builder.middleware(move |req: ureq::Request, next: ureq::MiddlewareNext<'_>| {
                next.handle(req.set("Authorization", &auth))
            });
        }
        builder.build()
    }
}

fn basic_auth(username: &str, secret: &str) -> String {
    let raw = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{secret}"));
    format!("Basic {raw}")
}

fn encode_path_segment(segment: &str) -> String {
    let mut out = String::new();
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn is_eos_endpoint(endpoint: &str) -> bool {
    let Ok(target) = parse_http_url(endpoint, true) else {
        return false;
    };
    let host = target.host.trim_end_matches('.').to_ascii_lowercase();
    host == "cmecloud.cn"
        || host
            .strip_suffix(".cmecloud.cn")
            .is_some_and(|prefix| !prefix.is_empty())
}

fn split_url(url: &str) -> Result<(String, String, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| "sync endpoint must use https".to_string())?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    if host.is_empty() {
        return Err("sync endpoint is missing a host".into());
    }
    Ok((host.to_string(), format!("/{path}"), String::new()))
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        key_block[..20].copy_from_slice(&sha1_digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner = [0u8; BLOCK_SIZE];
    let mut outer = [0u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner[index] = key_block[index] ^ 0x36;
        outer[index] = key_block[index] ^ 0x5c;
    }

    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + data.len());
    inner_input.extend_from_slice(&inner);
    inner_input.extend_from_slice(data);
    let inner_digest = sha1_digest(&inner_input);

    let mut outer_input = Vec::with_capacity(BLOCK_SIZE + inner_digest.len());
    outer_input.extend_from_slice(&outer);
    outer_input.extend_from_slice(&inner_digest);
    sha1_digest(&outer_input)
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let padded_len = ((data.len() + 9 + 63) / 64) * 64;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() + 8) % 64 != 0 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = [
        0x67452301u32,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0,
    ];
    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 80];
        for (index, word) in words[..16].iter_mut().enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..80 {
            words[index] = (words[index - 3]
                ^ words[index - 8]
                ^ words[index - 14]
                ^ words[index - 16])
                .rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in words.iter().enumerate() {
            let (function, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut digest = [0u8; 20];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn s3_signing_key(secret: &str, date: &str, region: &str) -> Result<Vec<u8>, String> {
    fn hmac_bytes(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| "S3 signing failed")?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
    let date_key = hmac_bytes(format!("AWS4{secret}").as_bytes(), date.as_bytes())?;
    let region_key = hmac_bytes(&date_key, region.as_bytes())?;
    let service_key = hmac_bytes(&region_key, b"s3")?;
    hmac_bytes(&service_key, b"aws4_request")
}

fn read_remote_object(response: ureq::Response) -> Result<RemoteObject, String> {
    let etag = StrongEtag::parse(response.header("ETag").ok_or("sync_strong_etag_required")?)?;
    Ok(RemoteObject { body: read_limited(response, MAX_REMOTE_BYTES)?, etag })
}

fn read_limited(response: ureq::Response, max: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let mut reader = response.into_reader().take(max as u64 + 1);
    reader
        .read_to_end(&mut body)
        .map_err(|e| format!("failed to read remote response: {e}"))?;
    if body.len() > max {
        return Err("remote file exceeds 64MB".into());
    }
    Ok(body)
}

fn brief(response: ureq::Response) -> String {
    let status = response.status();
    match response.into_string() {
        Ok(text) if !text.is_empty() => text.chars().take(180).collect(),
        _ => format!("HTTP {status}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{EntryKind, FolderDto, SecretPayload, UpsertEntry};
    use std::cell::{Cell, RefCell};

    fn entry(id: &str, title: &str, updated_at: &str, password: &str) -> SyncEntry {
        SyncEntry {
            entry: BackupEntry {
                id: id.into(),
                kind: "website".into(),
                title: title.into(),
                account: Some("a".into()),
                url: Some("https://example.com".into()),
                folder_id: None,
                pinned: false,
                expires_at: None,
                use_count: 0,
                last_used_at: None,
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: updated_at.into(),
                deleted_at: None,
                has_totp: false,
                fingerprint: None,
                secret_blob: Vec::new(),
                notes_blob: None,
                profile_blob: None,
                tags: vec![],
            },
            secret: Some(SecretPayload::Website {
                url: Some("https://example.com".into()),
                username: Some("a".into()),
                password: password.into(),
                totp_secret: None,
            }),
            notes: None,
            profile: None,
        }
    }

    fn snap(entries: Vec<SyncEntry>) -> SyncSnapshot {
        SyncSnapshot {
            folders: vec![FolderDto {
                id: "f1".into(),
                name: "work".into(),
            }],
            tags: vec!["mail".into()],
            entries,
            deleted: Vec::new(),
        }
    }

    #[test]
    fn merge_prefers_newer_and_keeps_both_sides() {
        let local = snap(vec![
            entry("a", "local-new", "2026-02-02T00:00:00Z", "new"),
            entry("b", "local-old", "2026-01-01T00:00:00Z", "old"),
            entry("c", "local-only", "2026-01-03T00:00:00Z", "local"),
        ]);
        let remote = snap(vec![
            entry("a", "remote-old", "2026-01-02T00:00:00Z", "old"),
            entry("b", "remote-new", "2026-03-01T00:00:00Z", "remote"),
            entry("d", "remote-only", "2026-01-04T00:00:00Z", "remote-only"),
        ]);
        let (merged, report) = merge_snapshots(&local, &remote);
        assert_eq!(report.pulled, 2);
        assert_eq!(report.pushed, 2);
        assert_eq!(merged.entries.len(), 4);
        let kept = merged
            .entries
            .iter()
            .find(|item| item.entry.id == "b")
            .unwrap();
        assert_eq!(kept.entry.title, "remote-new");
    }

    #[test]
    fn same_time_different_payload_pauses_for_conflict_without_writing() {
        let local = snap(vec![entry("a", "local", "2026-02-02T00:00:00Z", "one")]);
        let remote = snap(vec![entry("a", "remote", "2026-02-02T00:00:00Z", "two")]);
        let (_, report) = merge_snapshots(&local, &remote);
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(report.conflict_details[0].kind, ConflictKind::EditEdit);
        assert_eq!(report.phase, SyncPhase::Conflicts);
        assert!(report.pushed == 0 && report.pulled == 0);

        // Equal timestamps are a conflict: pause, and do not write either side.
        let (ls, rs) = stores(&local, Some(&remote));
        let remote_before = rs.bytes();
        let mut runtime = SyncRuntime::default();
        let preview = run_preview(&mut runtime, &ls, &rs).unwrap();
        assert_eq!(preview.report.phase, SyncPhase::Conflicts);
        assert_eq!(
            run_commit(&mut runtime, &ls, &rs, &preview.token, &[]).unwrap_err(),
            "sync_all_choices_required"
        );
        assert_no_writes(&ls, &rs);
        assert_eq!(rs.put_calls.get(), 0);
        assert_eq!(rs.bytes(), remote_before);
        assert_eq!(find(&rs.snapshot(), "a").entry.title, "remote");
        assert_eq!(find(&ls.snapshot(), "a").entry.title, "local");
    }

    #[test]
    fn snapshot_roundtrip_rejects_wrong_key() {
        let key = sync_key("correct horse battery");
        let bytes = encode_snapshot(
            &key,
            &snap(vec![entry("a", "x", "2026-01-01T00:00:00Z", "p")]),
            "dev",
        )
        .unwrap();
        let (_, legacy) = decode_snapshot(&key, None, &bytes).unwrap();
        assert!(!legacy);
        assert!(decode_snapshot(&sync_key("other secret"), None, &bytes).is_err());
    }

    #[test]
    fn config_rejects_private_and_plain_http() {
        let webdav = SyncConfig {
            kind: SyncKind::Webdav,
            endpoint: "http://example.com/dav".into(),
            username: "me".into(),
            bucket: String::new(),
            region: String::new(),
            prefix: String::new(),
        };
        assert!(webdav.normalize().is_err());
        let local = SyncConfig {
            kind: SyncKind::S3,
            endpoint: "https://127.0.0.1:9000".into(),
            username: "key".into(),
            bucket: "box".into(),
            region: String::new(),
            prefix: String::new(),
        };
        assert!(local.normalize().is_err());
    }

    fn test_sync_config(endpoint: &str) -> SyncConfig {
        SyncConfig {
            kind: SyncKind::Webdav,
            endpoint: endpoint.into(),
            username: "user".into(),
            bucket: String::new(),
            region: "us-east-1".into(),
            prefix: String::new(),
        }
    }

    fn fresh_sync_vault() -> (Vault, [u8; 32]) {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        save_config(
            &vault,
            &dek,
            test_sync_config("https://dav.example.com"),
            Some("memory-sync-secret"),
        )
        .unwrap();
        (vault, dek)
    }

    #[test]
    fn saving_legacy_sync_secret_migrates_before_missing_check() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let config = test_sync_config("https://dav.example.com");
        vault
            .set_setting("sync_config", &serde_json::to_string(&config).unwrap())
            .unwrap();
        vault
            .set_setting("sync_secret", "legacy-sync-secret")
            .unwrap();

        save_config(&vault, &dek, config, None).unwrap();

        assert!(vault.get_setting("sync_secret_enc").unwrap().is_some());
        assert!(vault.get_setting("sync_secret").unwrap().is_none());
    }

    #[test]
    fn conditional_support_requires_an_exact_binding() {
        let (vault, dek) = fresh_sync_vault();
        assert!(!conditional_support_verified(&vault, &dek).unwrap());

        vault
            .set_setting("sync_conditional_verified", "wrong-binding")
            .unwrap();
        assert!(!conditional_support_verified(&vault, &dek).unwrap());

        let binding = conditional_capability_binding(&vault, &dek).unwrap();
        vault
            .set_setting("sync_conditional_verified", &binding)
            .unwrap();
        assert!(conditional_support_verified(&vault, &dek).unwrap());
    }

    #[test]
    fn unverified_configuration_is_rejected_before_auto_sync_network_work() {
        let (vault, dek) = fresh_sync_vault();
        assert_eq!(
            require_conditional_support(&vault, &dek).unwrap_err(),
            SYNC_CONDITIONAL_WRITE_UNVERIFIED
        );
    }

    #[test]
    fn sync_now_with_runtime_rejects_unverified_before_remote_get() {
        let (vault, dek) = fresh_sync_vault();
        let mut runtime = SyncRuntime::default();
        assert_eq!(
            sync_now_with_runtime(&mut runtime, &vault, &dek, &|| true).unwrap_err(),
            SYNC_CONDITIONAL_WRITE_UNVERIFIED
        );
    }

    #[test]
    fn changing_sync_config_clears_conditional_binding() {
        let (vault, dek) = fresh_sync_vault();
        let binding = conditional_capability_binding(&vault, &dek).unwrap();
        vault
            .set_setting("sync_conditional_verified", &binding)
            .unwrap();

        save_config(
            &vault,
            &dek,
            test_sync_config("https://other-dav.example.com"),
            None,
        )
        .unwrap();

        assert!(vault
            .get_setting("sync_conditional_verified")
            .unwrap()
            .is_none());
    }

    #[test]
    fn saving_unchanged_sync_config_preserves_conditional_binding() {
        let (vault, dek) = fresh_sync_vault();
        let binding = conditional_capability_binding(&vault, &dek).unwrap();
        vault
            .set_setting("sync_conditional_verified", &binding)
            .unwrap();

        save_config(
            &vault,
            &dek,
            test_sync_config("https://dav.example.com"),
            None,
        )
        .unwrap();

        assert_eq!(
            vault
                .get_setting("sync_conditional_verified")
                .unwrap()
                .as_deref(),
            Some(binding.as_str())
        );
    }

    #[test]
    fn changing_sync_secret_clears_conditional_binding() {
        let (vault, dek) = fresh_sync_vault();
        let binding = conditional_capability_binding(&vault, &dek).unwrap();
        vault
            .set_setting("sync_conditional_verified", &binding)
            .unwrap();

        save_config(
            &vault,
            &dek,
            test_sync_config("https://dav.example.com"),
            Some("changed-sync-secret"),
        )
        .unwrap();

        assert!(vault
            .get_setting("sync_conditional_verified")
            .unwrap()
            .is_none());
    }

    #[test]
    fn clearing_sync_config_clears_conditional_binding() {
        let (vault, dek) = fresh_sync_vault();
        let binding = conditional_capability_binding(&vault, &dek).unwrap();
        vault
            .set_setting("sync_conditional_verified", &binding)
            .unwrap();

        clear_config(&vault).unwrap();

        assert!(vault
            .get_setting("sync_conditional_verified")
            .unwrap()
            .is_none());
    }

    #[test]
    fn s3_authorization_contains_access_key() {
        let client = RemoteClient {
            kind: SyncKind::S3,
            endpoint: "https://s3.amazonaws.com".into(),
            username: "AKIAEXAMPLE".into(),
            secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            bucket: "examplebucket".into(),
            region: "us-east-1".into(),
            object_key: "sealbox/vault.sboxsync".into(),
            conditional_verified: false,
            cos: false,
        };
        let headers = client
            .s3_headers(
                "GET",
                "https://examplebucket.s3.amazonaws.com/sealbox/vault.sboxsync",
                b"",
            )
            .unwrap();
        assert!(headers
            .iter()
            .any(|(name, value)| name == "Authorization" && value.contains("AKIAEXAMPLE")));
    }

    #[test]
    fn eos_uses_path_style_and_sigv2_authorization() {
        let client = RemoteClient {
            kind: SyncKind::S3,
            endpoint: "https://eos-beijing-1.cmecloud.cn".into(),
            username: "AK".into(),
            secret: "secret".into(),
            bucket: "vault-bucket".into(),
            region: "beijing-1".into(),
            object_key: "sealbox/vault.sboxsync".into(),
            conditional_verified: false,
            cos: false,
        };
        let url = client.s3_url();
        assert_eq!(
            url,
            "https://eos-beijing-1.cmecloud.cn/vault-bucket/sealbox/vault.sboxsync"
        );
        let headers = client.s3_headers("GET", &url, b"").unwrap();
        assert!(headers.iter().any(|(name, value)| {
            name == "Authorization" && value.starts_with("AWS AK:")
        }));
        assert!(headers.iter().any(|(name, _)| name == "Date"));
        assert!(!headers.iter().any(|(name, _)| name == "x-amz-date"));

        let conditional = client
            .eos_headers_conditional("PUT", &url, Some(&WriteCondition::Missing))
            .unwrap();
        assert!(conditional
            .iter()
            .any(|(name, value)| name == "if-none-match" && value == "*"));
        assert!(conditional
            .iter()
            .any(|(name, value)| name == "Content-Type" && value == "application/octet-stream"));

        assert_eq!(
            hex::encode(hmac_sha1(
                b"key",
                b"The quick brown fox jumps over the lazy dog"
            )),
            "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
        );
    }

    #[test]
    fn replace_snapshot_roundtrip_keeps_secret() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .upsert_entry_with_duplicate_policy(
                &dek,
                UpsertEntry {
                    id: Some("e1".into()),
                    kind: EntryKind::Website,
                    title: "mail".into(),
                    account: Some("a@b.c".into()),
                    url: Some("https://example.com".into()),
                    folder_id: None,
                    tags: vec!["work".into()],
                    pinned: true,
                    expires_at: None,
                    notes: Some("note".into()),
                    secret: SecretPayload::Website {
                        url: Some("https://example.com".into()),
                        username: Some("a@b.c".into()),
                        password: "secret".into(),
                        totp_secret: None,
                    },
                },
                true,
            )
            .unwrap();
        let snapshot = vault.snapshot_for_backup().unwrap();
        vault.replace_snapshot_same_key(&dek, &snapshot).unwrap();
        match vault.get_secret(&dek, "e1").unwrap() {
            SecretPayload::Website { password, .. } => assert_eq!(password, "secret"),
            _ => panic!("kind"),
        }
    }

    #[test]
    fn sync_snapshot_reseals_under_another_vault_key() {
        let (source, source_dek) =
            Vault::create_in_memory("correct horse battery staple extra").unwrap();
        source
            .upsert_entry_with_duplicate_policy(
                &source_dek,
                UpsertEntry {
                    id: Some("e1".into()),
                    kind: EntryKind::Website,
                    title: "mail".into(),
                    account: Some("a@b.c".into()),
                    url: Some("https://example.com".into()),
                    folder_id: None,
                    tags: vec!["work".into()],
                    pinned: false,
                    expires_at: None,
                    notes: Some("note".into()),
                    secret: SecretPayload::Website {
                        url: Some("https://example.com".into()),
                        username: Some("a@b.c".into()),
                        password: "secret".into(),
                        totp_secret: None,
                    },
                },
                true,
            )
            .unwrap();
        let portable = SyncSnapshot::from_vault(&source_dek, &source.snapshot_for_backup().unwrap())
            .unwrap();
        let key = sync_key("sync secret value");
        let bytes = encode_snapshot(&key, &portable, "desktop").unwrap();

        let (dest, dest_dek) =
            Vault::create_in_memory("another horse battery staple extra").unwrap();
        let (decoded, legacy) = decode_snapshot(&key, Some(&dest_dek), &bytes).unwrap();
        assert!(!legacy);
        dest.replace_snapshot_same_key(&dest_dek, &decoded.seal(&dest_dek).unwrap())
            .unwrap();
        match dest.get_secret(&dest_dek, "e1").unwrap() {
            SecretPayload::Website { password, .. } => assert_eq!(password, "secret"),
            _ => panic!("kind"),
        }
        assert_eq!(dest.get_notes(&dest_dek, "e1").unwrap().as_deref(), Some("note"));
    }

    #[test]
    fn legacy_remote_is_flagged_for_rewrite_and_becomes_portable() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .upsert_entry_with_duplicate_policy(
                &dek,
                UpsertEntry {
                    id: Some("e1".into()),
                    kind: EntryKind::Website,
                    title: "mail".into(),
                    account: Some("a@b.c".into()),
                    url: Some("https://example.com".into()),
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::Website {
                        url: Some("https://example.com".into()),
                        username: Some("a@b.c".into()),
                        password: "secret".into(),
                        totp_secret: None,
                    },
                },
                true,
            )
            .unwrap();

        let key = sync_key("sync secret value");
        let json = serde_json::to_vec(&vault.snapshot_for_backup().unwrap()).unwrap();
        let file = SyncFile {
            blob: encrypt(&key, &json).unwrap(),
            device_id: "desktop".into(),
            written_at: "2026-01-01T00:00:00Z".into(),
        };
        let mut bytes = Vec::from(*MAGIC);
        bytes.extend(serde_json::to_vec(&file).unwrap());

        assert!(decode_snapshot(&key, None, &bytes).is_err());
        let (decoded, legacy) = decode_snapshot(&key, Some(&dek), &bytes).unwrap();
        assert!(legacy);

        let rewritten = encode_snapshot(&key, &decoded, "desktop").unwrap();
        let (portable, legacy) = decode_snapshot(&key, None, &rewritten).unwrap();
        assert!(!legacy);
        match &portable.entries[0].secret {
            Some(SecretPayload::Website { password, .. }) => assert_eq!(password, "secret"),
            _ => panic!("secret"),
        }
    }

    fn days_ago(days: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::days(days)).to_rfc3339()
    }

    fn tombstone(kind: &str, id: &str, at: &str) -> Tombstone {
        Tombstone {
            kind: kind.into(),
            id: id.into(),
            deleted_at: at.into(),
        }
    }

    #[test]
    fn tombstone_removes_entry_from_both_sides() {
        let local = snap(vec![entry("a", "gone", &days_ago(60), "p")]);
        let mut remote = snap(vec![]);
        remote.deleted = vec![tombstone(TOMBSTONE_ENTRY, "a", &days_ago(30))];

        let (merged, report) = merge_snapshots(&local, &remote);
        assert!(merged.entries.is_empty());
        assert_eq!(report.removed, 1);
        assert_eq!(merged.deleted.len(), 1);

        let (again, report) = merge_snapshots(&local, &merged);
        assert!(again.entries.is_empty());
        assert_eq!(report.removed, 1);
    }

    #[test]
    fn entry_edited_after_tombstone_survives() {
        let local = snap(vec![entry("a", "kept", &days_ago(1), "p")]);
        let mut remote = snap(vec![]);
        remote.deleted = vec![tombstone(TOMBSTONE_ENTRY, "a", &days_ago(30))];

        let (merged, report) = merge_snapshots(&local, &remote);
        assert_eq!(merged.entries.len(), 1);
        assert_eq!(merged.entries[0].entry.title, "kept");
        assert!(merged.deleted.is_empty());
        assert_eq!(report.removed, 0);
    }

    #[test]
    fn delete_edit_same_timestamp_requires_explicit_resolution() {
        let at = days_ago(5);
        let local = snap(vec![entry("a", "live", &at, "one")]);
        let mut trashed = entry("a", "trashed", &at, "two");
        trashed.entry.deleted_at = Some(at.clone());
        let remote = snap(vec![trashed]);

        let (merged, report) = merge_snapshots(&local, &remote);
        assert_eq!(report.conflict_details.len(), 1);
        assert_eq!(report.conflict_details[0].kind, ConflictKind::DeleteEdit);
        assert_eq!(merged.entries.len(), 1);
        // merge is only a provisional candidate; runtime must not write it.
        assert_eq!(merged.entries[0].entry.deleted_at.as_deref(), Some(at.as_str()));
    }

    #[test]
    fn usage_counters_do_not_conflict() {
        let at = "2026-02-02T00:00:00Z";
        let mut local_entry = entry("a", "same", at, "p");
        local_entry.entry.use_count = 7;
        local_entry.entry.last_used_at = Some("2026-02-02T00:00:00Z".into());
        let mut remote_entry = entry("a", "same", at, "p");
        remote_entry.entry.use_count = 3;
        remote_entry.entry.last_used_at = Some("2026-01-15T00:00:00Z".into());

        let (merged, report) = merge_snapshots(&snap(vec![local_entry]), &snap(vec![remote_entry]));
        assert!(report.conflicts.is_empty());
        assert_eq!(report.unchanged, 1);
        assert_eq!(merged.entries[0].entry.use_count, 7);
        assert_eq!(
            merged.entries[0].entry.last_used_at.as_deref(),
            Some("2026-02-02T00:00:00Z")
        );
    }

    #[test]
    fn snapshot_digest_tracks_folders_tags_and_tombstones() {
        let base = snap(vec![entry("a", "x", "2026-01-01T00:00:00Z", "p")]);

        let mut counters = base.clone();
        counters.entries[0].entry.use_count = 9;
        counters.entries[0].entry.last_used_at = Some("2026-01-02T00:00:00Z".into());
        assert_eq!(snapshot_digest(&base), snapshot_digest(&counters));

        let mut folder = base.clone();
        folder.folders.push(FolderDto {
            id: "f2".into(),
            name: "extra".into(),
        });
        assert_ne!(snapshot_digest(&base), snapshot_digest(&folder));

        let mut tag = base.clone();
        tag.tags.push("other".into());
        assert_ne!(snapshot_digest(&base), snapshot_digest(&tag));

        let mut deleted = base.clone();
        deleted.deleted = vec![tombstone(TOMBSTONE_ENTRY, "b", "2026-01-01T00:00:00Z")];
        assert_ne!(snapshot_digest(&base), snapshot_digest(&deleted));
    }

    #[test]
    fn folder_tombstone_drops_folder_and_clears_reference() {
        let at = days_ago(30);
        let mut local = snap(vec![entry("a", "x", &days_ago(60), "p")]);
        local.entries[0].entry.folder_id = Some("f1".into());
        let mut remote = snap(vec![]);
        remote.folders.clear();
        remote.deleted = vec![tombstone(TOMBSTONE_FOLDER, "f1", &at)];

        let (merged, _) = merge_snapshots(&local, &remote);
        assert!(merged.folders.is_empty());
        assert_eq!(merged.entries[0].entry.folder_id, None);
        assert_eq!(merged.entries[0].entry.updated_at, at);
    }

    #[test]
    fn snapshot_roundtrip_keeps_tombstones() {
        let key = sync_key("correct horse battery");
        let mut snapshot = snap(vec![entry("a", "x", "2026-01-01T00:00:00Z", "p")]);
        snapshot.deleted = vec![tombstone(TOMBSTONE_ENTRY, "z", "2026-01-01T00:00:00Z")];
        let bytes = encode_snapshot(&key, &snapshot, "dev").unwrap();
        let (decoded, _) = decode_snapshot(&key, None, &bytes).unwrap();
        assert_eq!(decoded.deleted, snapshot.deleted);
    }

    #[test]
    fn snapshot_without_tombstones_still_decodes() {
        let raw = serde_json::json!({
            "folders": [],
            "tags": [],
            "entries": []
        });
        let snapshot: SyncSnapshot = serde_json::from_value(raw).unwrap();
        assert!(snapshot.deleted.is_empty());
    }

    fn vault_with_sync() -> Vault {
        let (vault, _dek) =
            Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let config = SyncConfig {
            kind: SyncKind::Webdav,
            endpoint: "https://dav.example.com".into(),
            username: "user".into(),
            bucket: String::new(),
            region: "us-east-1".into(),
            prefix: String::new(),
        };
        vault
            .set_setting("sync_config", &serde_json::to_string(&config).unwrap())
            .unwrap();
        vault
    }

    #[test]
    fn auto_sync_stays_off_without_a_target() {
        let (vault, _dek) =
            Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let auto = auto_settings(&vault).unwrap();
        assert!(!auto.enabled);
        assert_eq!(auto.secs, DEFAULT_AUTO_SYNC_SECS);
        // Even an explicit "on" schedules nothing until a target exists.
        save_auto(&vault, Some(true), None).unwrap();
        assert!(!auto_settings(&vault).unwrap().enabled);
    }

    #[test]
    fn auto_sync_defaults_to_60_seconds_once_configured() {
        let vault = vault_with_sync();
        let auto = auto_settings(&vault).unwrap();
        assert!(auto.enabled);
        assert_eq!(auto.secs, DEFAULT_AUTO_SYNC_SECS);
    }

    #[test]
    fn save_auto_clamps_interval_and_keeps_unspecified_values() {
        let vault = vault_with_sync();
        save_auto(&vault, Some(true), Some(1)).unwrap();
        assert_eq!(auto_settings(&vault).unwrap().secs, MIN_AUTO_SYNC_SECS);
        save_auto(&vault, None, Some(999_999)).unwrap();
        let auto = auto_settings(&vault).unwrap();
        assert!(auto.enabled);
        assert_eq!(auto.secs, MAX_AUTO_SYNC_SECS);
    }

    #[test]
    fn save_auto_can_turn_it_off() {
        let vault = vault_with_sync();
        save_auto(&vault, Some(false), Some(120)).unwrap();
        let view = view(&vault).unwrap();
        assert!(!view.auto_sync);
        assert_eq!(view.auto_sync_secs, 120);
    }

    const SYNC_SECRET: &str = "memory-sync-secret";
    const BINDING: &str = "memory-binding";

    fn test_dek() -> [u8; 32] {
        [4u8; 32]
    }

    fn password(entry: &SyncEntry) -> String {
        match &entry.secret {
            Some(SecretPayload::Website { password, .. }) => password.clone(),
            _ => panic!("expected website secret"),
        }
    }

    fn find<'a>(snapshot: &'a SyncSnapshot, id: &str) -> &'a SyncEntry {
        snapshot
            .entries
            .iter()
            .find(|item| item.entry.id == id)
            .unwrap_or_else(|| panic!("missing entry {id}"))
    }

    /// In-memory vault seam. `seal`/`from_vault` round-trip with `test_dek`, so
    /// tests never touch SQLite. `fail_apply` injects a single local write error.
    struct MemoryLocal {
        current: RefCell<SyncSnapshot>,
        applied: Cell<u32>,
        fail_apply: Cell<u32>,
    }

    impl MemoryLocal {
        fn new(snapshot: SyncSnapshot) -> Self {
            Self {
                current: RefCell::new(snapshot),
                applied: Cell::new(0),
                fail_apply: Cell::new(0),
            }
        }

        fn snapshot(&self) -> SyncSnapshot {
            self.current.borrow().clone()
        }

        fn set_snapshot(&self, snapshot: SyncSnapshot) {
            *self.current.borrow_mut() = snapshot;
        }

        fn fail_next_apply(&self) {
            self.fail_apply.set(self.fail_apply.get() + 1);
        }
    }

    impl LocalSyncStore for MemoryLocal {
        fn read(&self) -> Result<SyncBaseline, String> {
            let snapshot = self.current.borrow().clone();
            Ok(SyncBaseline {
                snapshot: snapshot.seal(&test_dek()).map_err(|e| e.to_string())?,
                tombstones: snapshot.deleted.clone(),
            })
        }

        fn apply(
            &self,
            dek: &[u8; 32],
            expected: &SyncBaseline,
            replacement: &SyncBaseline,
        ) -> Result<(), String> {
            if self.fail_apply.get() > 0 {
                self.fail_apply.set(self.fail_apply.get() - 1);
                return Err("sync_local_apply_failed".into());
            }
            let current = self.current.borrow().clone();
            let mut expected_open =
                SyncSnapshot::from_vault(dek, &expected.snapshot).map_err(|e| e.to_string())?;
            expected_open.deleted = expected.tombstones.clone();
            if full_snapshot_digest(&current) != full_snapshot_digest(&expected_open) {
                return Err(SYNC_LOCAL_CHANGED.into());
            }
            let mut next =
                SyncSnapshot::from_vault(dek, &replacement.snapshot).map_err(|e| e.to_string())?;
            next.deleted = replacement.tombstones.clone();
            *self.current.borrow_mut() = next;
            self.applied.set(self.applied.get() + 1);
            Ok(())
        }
    }

    /// In-memory remote. Weak or absent ETag strings fail closed in `get`, the
    /// same way `read_remote_object` rejects a non-strong validator.
    struct MemoryRemote {
        body: RefCell<Option<Vec<u8>>>,
        etag: RefCell<Option<String>>,
        gets: Cell<u32>,
        puts: Cell<u32>,
        put_calls: Cell<u32>,
        fail_put: Cell<bool>,
    }

    impl MemoryRemote {
        fn new(body: Option<Vec<u8>>) -> Self {
            Self {
                body: RefCell::new(body),
                etag: RefCell::new(Some("\"rev-0\"".to_string())),
                gets: Cell::new(0),
                puts: Cell::new(0),
                put_calls: Cell::new(0),
                fail_put: Cell::new(false),
            }
        }

        fn bytes(&self) -> Vec<u8> {
            self.body.borrow().clone().unwrap_or_default()
        }

        fn snapshot(&self) -> SyncSnapshot {
            let body = self.body.borrow().clone().expect("remote object");
            decode_snapshot(&sync_key(SYNC_SECRET), Some(&test_dek()), &body)
                .unwrap()
                .0
        }

        fn set_etag(&self, etag: Option<&str>) {
            *self.etag.borrow_mut() = etag.map(str::to_string);
        }

        fn fail_next_put(&self) {
            self.fail_put.set(true);
        }

        fn enforce(&self, condition: &WriteCondition) -> Result<(), String> {
            match condition {
                WriteCondition::Match(expected) => {
                    let current = self
                        .etag
                        .borrow()
                        .clone()
                        .ok_or("sync_strong_etag_required")?;
                    if expected.as_str() != current {
                        return Err("sync_precondition_failed".into());
                    }
                }
                WriteCondition::Missing => {
                    if self.body.borrow().is_some() {
                        return Err("sync_precondition_failed".into());
                    }
                }
            }
            Ok(())
        }
    }

    impl RemoteStore for MemoryRemote {
        fn get(&self) -> Result<Option<RemoteObject>, String> {
            self.gets.set(self.gets.get() + 1);
            let Some(body) = self.body.borrow().clone() else {
                return Ok(None);
            };
            let raw = self
                .etag
                .borrow()
                .clone()
                .ok_or("sync_strong_etag_required")?;
            Ok(Some(RemoteObject {
                body,
                etag: StrongEtag::parse(&raw)?,
            }))
        }

        fn put(&self, body: &[u8], condition: &WriteCondition) -> Result<(), String> {
            self.put_calls.set(self.put_calls.get() + 1);
            self.enforce(condition)?;
            if self.fail_put.get() {
                self.fail_put.set(false);
                return Err("sync_precondition_failed".into());
            }
            *self.body.borrow_mut() = Some(body.to_vec());
            *self.etag.borrow_mut() = Some(format!("\"rev-{}\"", self.put_calls.get()));
            self.puts.set(self.puts.get() + 1);
            Ok(())
        }
    }

    /// Remote fixture that writes regardless of the supplied precondition.
    struct IgnoringConditionRemote {
        body: RefCell<Option<Vec<u8>>>,
    }

    impl IgnoringConditionRemote {
        fn new() -> Self {
            Self {
                body: RefCell::new(None),
            }
        }
    }

    impl RemoteStore for IgnoringConditionRemote {
        fn get(&self) -> Result<Option<RemoteObject>, String> {
            let Some(body) = self.body.borrow().clone() else {
                return Ok(None);
            };
            Ok(Some(RemoteObject {
                body,
                etag: StrongEtag::parse(r#""ignored""#)?,
            }))
        }

        fn put(&self, body: &[u8], _condition: &WriteCondition) -> Result<(), String> {
            *self.body.borrow_mut() = Some(body.to_vec());
            Ok(())
        }
    }

    #[test]
    fn tencent_cos_endpoint_matches_normalized_host_only() {
        assert!(is_tencent_cos_endpoint("https://myqcloud.com/"));
        assert!(is_tencent_cos_endpoint(" https://bucket.MYQCloud.com:443/cos "));
        assert!(is_tencent_cos_endpoint(
            "https://cos.ap-beijing.myqcloud.com"
        ));
        assert!(is_tencent_cos_endpoint(
            "https://pass-1450885502.cos.ap-beijing.myqcloud.com/sealbox"
        ));

        assert!(!is_tencent_cos_endpoint("https://myqcloud.com.attacker.example"));
        assert!(!is_tencent_cos_endpoint("https://evil-myqcloud.com"));
        assert!(!is_tencent_cos_endpoint("https://example.com/myqcloud.com"));
        assert!(!is_tencent_cos_endpoint("https://s3.amazonaws.com"));
        assert!(!is_tencent_cos_endpoint("not a url"));
    }

    #[test]
    fn cos_lease_expired_covers_stale_live_and_unreadable() {
        let stale = chrono::Utc::now() - chrono::Duration::seconds(COS_LEASE_SKEW_SECS + 5);
        let live = chrono::Utc::now() + chrono::Duration::seconds(COS_LEASE_TTL_SECS);
        let within_skew = chrono::Utc::now() - chrono::Duration::seconds(COS_LEASE_SKEW_SECS - 5);

        assert!(cos_lease_expired(
            serde_json::json!({ "nonce": "n", "expires_at": stale.to_rfc3339() })
                .to_string()
                .as_bytes()
        ));
        assert!(!cos_lease_expired(
            serde_json::json!({ "nonce": "n", "expires_at": live.to_rfc3339() })
                .to_string()
                .as_bytes()
        ));
        assert!(
            !cos_lease_expired(
                serde_json::json!({ "expires_at": within_skew.to_rfc3339() })
                    .to_string()
                    .as_bytes()
            ),
            "expiry inside the clock-skew margin is still held"
        );
        assert!(cos_lease_expired(b"not-json"));
        assert!(cos_lease_expired(br#"{"nonce":"only"}"#));
        assert!(cos_lease_expired(br#"{"expires_at":"yesterday"}"#));
        assert!(cos_lease_expired(br#"{"expires_at":1}"#));
    }

    #[test]
    fn cos_forbid_overwrite_is_part_of_sigv4_signed_headers() {
        let client = RemoteClient {
            kind: SyncKind::S3,
            endpoint: "https://cos.ap-beijing.myqcloud.com".into(),
            username: "AKIDexample".into(),
            secret: "secret".into(),
            bucket: "pass-1450885502".into(),
            region: "ap-beijing".into(),
            object_key: "sealbox/vault.sboxsync".into(),
            conditional_verified: true,
            cos: true,
        };
        let url = client.s3_url();
        assert_eq!(
            url,
            "https://pass-1450885502.cos.ap-beijing.myqcloud.com/sealbox/vault.sboxsync"
        );
        let headers = client
            .s3_headers_extra(
                "PUT",
                &url,
                b"body",
                None,
                &[("x-cos-forbid-overwrite", "true")],
            )
            .unwrap();
        let authorization = headers
            .iter()
            .find(|(name, _)| name == "Authorization")
            .map(|(_, value)| value.as_str())
            .unwrap();
        assert!(authorization.contains(
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-cos-forbid-overwrite"
        ));
        assert!(headers
            .iter()
            .any(|(name, value)| name == "x-cos-forbid-overwrite" && value == "true"));
    }

    #[test]
    fn probe_rejects_remote_that_ignores_write_condition() {
        let remote = IgnoringConditionRemote::new();

        assert_eq!(
            probe_conditions(&remote, &|| true).unwrap_err(),
            "sync_conditional_write_unsupported"
        );
    }

    fn stores(local: &SyncSnapshot, remote: Option<&SyncSnapshot>) -> (MemoryLocal, MemoryRemote) {
        let body = remote.map(|snapshot| {
            encode_snapshot(&sync_key(SYNC_SECRET), snapshot, "remote-device").unwrap()
        });
        (MemoryLocal::new(local.clone()), MemoryRemote::new(body))
    }

    fn run_preview(
        runtime: &mut SyncRuntime,
        local: &MemoryLocal,
        remote: &MemoryRemote,
    ) -> Result<SyncPreview, String> {
        runtime.preview_with_store(local, remote, &test_dek(), sync_key(SYNC_SECRET), BINDING)
    }

    fn run_commit(
        runtime: &mut SyncRuntime,
        local: &MemoryLocal,
        remote: &MemoryRemote,
        token: &str,
        choices: &[SyncResolution],
    ) -> Result<SyncReport, String> {
        runtime.commit_with_store(local, remote, &test_dek(), BINDING, token, choices, &|| true)
    }

    fn assert_no_writes(local: &MemoryLocal, remote: &MemoryRemote) {
        assert_eq!(local.applied.get(), 0, "local apply wrote");
        assert_eq!(remote.puts.get(), 0, "remote put wrote");
    }

    /// Remote is newer and local has an extra entry, so a real commit must both
    /// put and apply. Use this whenever a test claims a failure prevented a write.
    fn push_and_pull() -> (SyncSnapshot, SyncSnapshot) {
        let local = snap(vec![
            entry("a", "local-old", "2026-01-01T00:00:00Z", "old"),
            entry("b", "local-only", "2026-01-02T00:00:00Z", "side"),
        ]);
        let remote = snap(vec![entry(
            "a",
            "remote-new",
            "2026-02-01T00:00:00Z",
            "new",
        )]);
        (local, remote)
    }

    fn choice_for(choice: ConflictChoice, confirm: bool) -> SyncResolution {
        SyncResolution {
            id: "a".into(),
            choice,
            confirm_delete_edit: confirm,
        }
    }

    #[test]
    fn preview_does_not_write_remote_or_local() {
        let (local, remote) = push_and_pull();
        let (ls, rs) = stores(&local, Some(&remote));
        let remote_before = rs.bytes();
        let local_before = full_snapshot_digest(&ls.snapshot());
        let mut runtime = SyncRuntime::default();

        let preview = run_preview(&mut runtime, &ls, &rs).unwrap();

        assert_eq!(preview.report.phase, SyncPhase::Preview);
        assert!(preview.report.conflict_details.is_empty());
        assert!(rs.gets.get() >= 1);
        assert_eq!(rs.put_calls.get(), 0);
        assert_no_writes(&ls, &rs);
        assert_eq!(rs.bytes(), remote_before);
        assert_eq!(full_snapshot_digest(&ls.snapshot()), local_before);
        assert!(runtime.pending.as_ref().unwrap().uploaded.is_none());
    }

    #[test]
    fn conflict_choices_local_remote_and_both_keep_local_id() {
        let at = "2026-02-02T00:00:00Z";
        let resolve = |choice: ConflictChoice| {
            let local = snap(vec![entry("a", "local", at, "one")]);
            let remote = snap(vec![entry("a", "remote", at, "two")]);
            let (ls, rs) = stores(&local, Some(&remote));
            let mut runtime = SyncRuntime::default();
            let preview = run_preview(&mut runtime, &ls, &rs).unwrap();
            assert_eq!(preview.report.phase, SyncPhase::Conflicts);
            let report = run_commit(
                &mut runtime,
                &ls,
                &rs,
                &preview.token,
                &[choice_for(choice, false)],
            )
            .unwrap();
            assert_eq!(report.phase, SyncPhase::Committed);
            (ls.snapshot(), rs.snapshot())
        };

        let (local_kept, remote_kept) = resolve(ConflictChoice::Local);
        assert_eq!(local_kept.entries.len(), 1);
        assert_eq!(find(&local_kept, "a").entry.title, "local");
        assert_eq!(password(find(&local_kept, "a")), "one");
        assert_eq!(find(&remote_kept, "a").entry.title, "local");
        assert_eq!(password(find(&remote_kept, "a")), "one");

        let (local_taken, remote_taken) = resolve(ConflictChoice::Remote);
        assert_eq!(local_taken.entries.len(), 1);
        assert_eq!(find(&local_taken, "a").entry.title, "remote");
        assert_eq!(password(find(&local_taken, "a")), "two");
        assert_eq!(find(&remote_taken, "a").entry.id, "a");
        assert_eq!(find(&remote_taken, "a").entry.title, "remote");

        let (local_both, remote_both) = resolve(ConflictChoice::Both);
        assert_eq!(local_both.entries.len(), 2);
        assert_eq!(find(&local_both, "a").entry.title, "local");
        assert_eq!(password(find(&local_both, "a")), "one");
        let copies: Vec<_> = local_both
            .entries
            .iter()
            .filter(|item| item.entry.id != "a")
            .collect();
        assert_eq!(copies.len(), 1);
        assert!(uuid::Uuid::parse_str(&copies[0].entry.id).is_ok());
        assert_eq!(copies[0].entry.title, "remote");
        assert_eq!(password(copies[0]), "two");
        assert_eq!(remote_both.entries.len(), 2);
        assert_eq!(find(&remote_both, "a").entry.title, "local");
        assert_eq!(
            find(&remote_both, &copies[0].entry.id).entry.title,
            "remote"
        );
    }

    #[test]
    fn delete_edit_without_confirmation_is_rejected_and_both_keeps_marker() {
        let mut local = snap(vec![]);
        local.deleted = vec![tombstone(TOMBSTONE_ENTRY, "a", &days_ago(30))];
        let remote = snap(vec![entry("a", "edited", &days_ago(1), "two")]);
        let (ls, rs) = stores(&local, Some(&remote));
        let remote_before = rs.bytes();
        let mut runtime = SyncRuntime::default();
        let preview = run_preview(&mut runtime, &ls, &rs).unwrap();
        assert_eq!(preview.report.phase, SyncPhase::Conflicts);
        assert_eq!(
            preview.report.conflict_details[0].kind,
            ConflictKind::DeleteEdit
        );

        for choice in [
            ConflictChoice::Local,
            ConflictChoice::Remote,
            ConflictChoice::Both,
        ] {
            assert_eq!(
                run_commit(
                    &mut runtime,
                    &ls,
                    &rs,
                    &preview.token,
                    &[choice_for(choice, false)],
                )
                .unwrap_err(),
                "sync_delete_edit_confirmation_required"
            );
        }
        assert_no_writes(&ls, &rs);
        assert_eq!(rs.bytes(), remote_before);
        assert!(ls.snapshot().entries.is_empty());

        let report = run_commit(
            &mut runtime,
            &ls,
            &rs,
            &preview.token,
            &[choice_for(ConflictChoice::Both, true)],
        )
        .unwrap();
        assert_eq!(report.phase, SyncPhase::Committed);

        for snapshot in [ls.snapshot(), rs.snapshot()] {
            assert!(snapshot
                .deleted
                .iter()
                .any(|item| item.kind == TOMBSTONE_ENTRY && item.id == "a"));
            assert!(snapshot.entries.iter().all(|item| item.entry.id != "a"));
            let live: Vec<_> = snapshot
                .entries
                .iter()
                .filter(|item| item.entry.deleted_at.is_none())
                .collect();
            assert_eq!(live.len(), 1);
            assert!(uuid::Uuid::parse_str(&live[0].entry.id).is_ok());
            assert_eq!(live[0].entry.title, "edited");
            assert_eq!(password(live[0]), "two");
            assert!(live[0].entry.deleted_at.is_none());
        }
    }

    #[test]
    fn weak_or_missing_etag_fails_commit_without_writes() {
        assert_eq!(
            StrongEtag::parse(r#"W/"weak""#).unwrap_err(),
            "sync_strong_etag_required"
        );
        assert_eq!(
            StrongEtag::parse("").unwrap_err(),
            "sync_strong_etag_required"
        );

        for etag in [Some(r#"W/"weak""#), None] {
            let (local, remote) = push_and_pull();
            assert_ne!(full_snapshot_digest(&local), full_snapshot_digest(&remote));
            let (ls, rs) = stores(&local, Some(&remote));
            let remote_before = rs.bytes();
            let local_before = full_snapshot_digest(&ls.snapshot());
            let mut runtime = SyncRuntime::default();
            let preview = run_preview(&mut runtime, &ls, &rs).unwrap();

            rs.set_etag(etag);
            assert_eq!(
                run_commit(&mut runtime, &ls, &rs, &preview.token, &[]).unwrap_err(),
                "sync_strong_etag_required"
            );
            assert_eq!(rs.put_calls.get(), 0);
            assert_no_writes(&ls, &rs);
            assert_eq!(rs.bytes(), remote_before);
            assert_eq!(full_snapshot_digest(&ls.snapshot()), local_before);
            assert!(runtime.pending.as_ref().unwrap().uploaded.is_none());
        }
    }

    #[test]
    fn conditional_put_failure_does_not_change_local() {
        let (local, remote) = push_and_pull();
        let (ls, rs) = stores(&local, Some(&remote));
        let remote_before = rs.bytes();
        let mut runtime = SyncRuntime::default();
        let preview = run_preview(&mut runtime, &ls, &rs).unwrap();
        rs.fail_next_put();

        assert_eq!(
            run_commit(&mut runtime, &ls, &rs, &preview.token, &[]).unwrap_err(),
            "sync_precondition_failed"
        );
        assert_eq!(rs.put_calls.get(), 1);
        assert_no_writes(&ls, &rs);
        assert_eq!(rs.bytes(), remote_before);
        assert_eq!(find(&ls.snapshot(), "a").entry.title, "local-old");
        assert_eq!(find(&rs.snapshot(), "a").entry.title, "remote-new");
        assert!(rs.snapshot().entries.iter().all(|item| item.entry.id != "b"));
        let pending = runtime.pending.as_ref().unwrap();
        assert_eq!(pending.token, preview.token);
        assert!(pending.uploaded.is_none());
    }

    #[test]
    fn expired_token_and_changed_baseline_do_not_overwrite_local_edits() {
        let fresh = snap(vec![entry(
            "a",
            "local-fresh",
            "2026-03-01T00:00:00Z",
            "fresh",
        )]);

        let (local, remote) = push_and_pull();
        let (ls, rs) = stores(&local, Some(&remote));
        let remote_before = rs.bytes();
        let mut runtime = SyncRuntime::default();
        let preview = run_preview(&mut runtime, &ls, &rs).unwrap();
        ls.set_snapshot(fresh.clone());
        runtime.pending.as_mut().unwrap().created =
            Instant::now() - (PREVIEW_TTL + Duration::from_secs(1));

        assert_eq!(
            run_commit(&mut runtime, &ls, &rs, &preview.token, &[]).unwrap_err(),
            SYNC_TOKEN_EXPIRED
        );
        assert!(runtime.pending.is_none());
        assert_no_writes(&ls, &rs);
        assert_eq!(rs.bytes(), remote_before);
        assert_eq!(find(&ls.snapshot(), "a").entry.title, "local-fresh");
        assert_eq!(password(find(&ls.snapshot(), "a")), "fresh");
        assert_eq!(find(&rs.snapshot(), "a").entry.title, "remote-new");

        let (local, remote) = push_and_pull();
        let (ls, rs) = stores(&local, Some(&remote));
        let remote_before = rs.bytes();
        let mut runtime = SyncRuntime::default();
        let preview = run_preview(&mut runtime, &ls, &rs).unwrap();
        ls.set_snapshot(fresh);
        let report = run_commit(&mut runtime, &ls, &rs, &preview.token, &[]).unwrap();

        assert_eq!(report.phase, SyncPhase::Blocked);
        assert_eq!(report.blocked.as_deref(), Some(SYNC_LOCAL_CHANGED));
        assert!(!report.retryable);
        assert_eq!(rs.put_calls.get(), 0);
        assert_no_writes(&ls, &rs);
        assert_eq!(rs.bytes(), remote_before);
        assert_eq!(find(&ls.snapshot(), "a").entry.title, "local-fresh");
        assert_eq!(password(find(&ls.snapshot(), "a")), "fresh");
        assert!(ls
            .snapshot()
            .entries
            .iter()
            .all(|item| item.entry.id != "b"));
        assert_eq!(find(&rs.snapshot(), "a").entry.title, "remote-new");
        assert!(runtime.pending.as_ref().unwrap().uploaded.is_none());
    }

    #[test]
    fn uploaded_retry_applies_local_without_second_put() {
        let (local, remote) = push_and_pull();
        let (ls, rs) = stores(&local, Some(&remote));
        let remote_before = rs.bytes();
        let mut runtime = SyncRuntime::default();
        let preview = run_preview(&mut runtime, &ls, &rs).unwrap();
        ls.fail_next_apply();

        let pending = run_commit(&mut runtime, &ls, &rs, &preview.token, &[]).unwrap();
        assert_eq!(pending.phase, SyncPhase::LocalPending);
        assert_eq!(pending.blocked.as_deref(), Some("sync_local_apply_pending"));
        assert!(pending.retryable);
        assert_eq!(rs.puts.get(), 1);
        assert_eq!(ls.applied.get(), 0);
        assert_eq!(find(&ls.snapshot(), "a").entry.title, "local-old");
        assert_eq!(find(&rs.snapshot(), "a").entry.title, "remote-new");
        assert_eq!(find(&rs.snapshot(), "b").entry.title, "local-only");
        assert_ne!(rs.bytes(), remote_before);
        assert!(runtime.pending.as_ref().unwrap().uploaded.is_some());
        let remote_after_put = rs.bytes();
        let puts = rs.put_calls.get();

        let committed = run_commit(&mut runtime, &ls, &rs, &preview.token, &[]).unwrap();
        assert_eq!(committed.phase, SyncPhase::Committed);
        assert!(committed.blocked.is_none());
        assert!(!committed.retryable);
        assert_eq!(rs.put_calls.get(), puts);
        assert_eq!(rs.bytes(), remote_after_put);
        assert_eq!(ls.applied.get(), 1);
        assert!(runtime.pending.is_none());
        assert_eq!(find(&ls.snapshot(), "a").entry.title, "remote-new");
        assert_eq!(password(find(&ls.snapshot(), "a")), "new");
        assert_eq!(find(&ls.snapshot(), "b").entry.title, "local-only");
    }

    #[test]
    fn auto_sync_wrapper_on_conflict_writes_nothing() {
        // `sync_now_with_runtime` returns this blocked report and does not commit.
        // That wrapper opens a network client, so the same branch is driven here
        // through the store seam.
        let local = snap(vec![entry("a", "local", "2026-02-02T00:00:00Z", "one")]);
        let remote = snap(vec![entry("a", "remote", "2026-02-02T00:00:00Z", "two")]);
        let (ls, rs) = stores(&local, Some(&remote));
        let remote_before = rs.bytes();
        let mut runtime = SyncRuntime::default();
        let preview = run_preview(&mut runtime, &ls, &rs).unwrap();
        let report = if !preview.report.conflict_details.is_empty() {
            blocked_report(&preview.report, "sync_conflicts_require_resolution", false)
        } else {
            run_commit(&mut runtime, &ls, &rs, &preview.token, &[]).unwrap()
        };

        assert_eq!(report.phase, SyncPhase::Blocked);
        assert_eq!(
            report.blocked.as_deref(),
            Some("sync_conflicts_require_resolution")
        );
        assert!(!report.retryable);
        assert_eq!(report.conflict_details.len(), 1);
        assert_eq!(rs.put_calls.get(), 0);
        assert_no_writes(&ls, &rs);
        assert_eq!(rs.bytes(), remote_before);
        assert_eq!(find(&ls.snapshot(), "a").entry.title, "local");
        assert_eq!(find(&rs.snapshot(), "a").entry.title, "remote");
        assert!(runtime.pending.as_ref().unwrap().uploaded.is_none());
    }

    #[test]
    fn same_name_folders_remap_folder_id_instead_of_clearing() {
        let local = snap(vec![]);
        let mut remote = snap(vec![entry("e", "item", "2026-02-02T00:00:00Z", "pw")]);
        remote.folders = vec![FolderDto {
            id: "f-remote".into(),
            name: "work".into(),
        }];
        remote.entries[0].entry.folder_id = Some("f-remote".into());

        let (merged, report) = merge_snapshots(&local, &remote);
        assert!(report.conflict_details.is_empty());
        assert_eq!(merged.folders.len(), 1);
        assert_eq!(merged.folders[0].id, "f1");
        assert_eq!(merged.entries[0].entry.folder_id.as_deref(), Some("f1"));

        let (ls, rs) = stores(&local, Some(&remote));
        let mut runtime = SyncRuntime::default();
        let preview = run_preview(&mut runtime, &ls, &rs).unwrap();
        let committed = run_commit(&mut runtime, &ls, &rs, &preview.token, &[]).unwrap();
        assert_eq!(committed.phase, SyncPhase::Committed);
        for snapshot in [ls.snapshot(), rs.snapshot()] {
            assert!(snapshot.folders.iter().all(|folder| folder.id != "f-remote"));
            assert_eq!(find(&snapshot, "e").entry.folder_id.as_deref(), Some("f1"));
        }
    }

    #[test]
    fn tag_tombstone_blocks_tag_revival() {
        let mut local = snap(vec![entry("a", "x", "2026-02-01T00:00:00Z", "p")]);
        local.tags = vec!["mail".into(), "keep".into()];
        local.entries[0].entry.tags = vec!["mail".into(), "keep".into()];
        let mut remote = snap(vec![]);
        remote.tags = vec!["mail".into()];
        remote.deleted = vec![tombstone("tag", "mail", &days_ago(3))];

        let (ls, rs) = stores(&local, Some(&remote));
        let mut runtime = SyncRuntime::default();
        let preview = run_preview(&mut runtime, &ls, &rs).unwrap();
        assert!(preview.report.conflict_details.is_empty());
        let committed = run_commit(&mut runtime, &ls, &rs, &preview.token, &[]).unwrap();
        assert_eq!(committed.phase, SyncPhase::Committed);

        for snapshot in [ls.snapshot(), rs.snapshot()] {
            assert!(snapshot.tags.iter().all(|tag| tag != "mail"));
            assert!(snapshot.tags.iter().any(|tag| tag == "keep"));
            assert!(find(&snapshot, "a")
                .entry
                .tags
                .iter()
                .all(|tag| tag != "mail"));
            assert!(find(&snapshot, "a").entry.tags.iter().any(|tag| tag == "keep"));
            assert!(snapshot
                .deleted
                .iter()
                .any(|item| item.kind == "tag" && item.id == "mail"));
        }

        let mut revived = local.clone();
        revived.tags.push("mail".into());
        revived.entries[0].entry.tags.push("mail".into());
        let (again, _) = merge_snapshots(&revived, &ls.snapshot());
        assert!(again.tags.iter().all(|tag| tag != "mail"));
        assert!(find(&again, "a").entry.tags.iter().all(|tag| tag != "mail"));
        assert!(again.tags.iter().any(|tag| tag == "keep"));
        assert!(again
            .deleted
            .iter()
            .any(|item| item.kind == "tag" && item.id == "mail"));
    }
}

