use crate::crypto::{decrypt, encrypt, Encrypted};
use crate::http_guard::{assert_public_target, parse_http_url, PublicResolver};
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
use std::time::Duration;

const MAGIC: &[u8; 6] = b"SBOXS1";
const OBJECT_NAME: &str = "sealbox/vault.sboxsync";
const MAX_REMOTE_BYTES: usize = 64 * 1024 * 1024;
/// How long a deletion keeps being broadcast. Older clients that stayed
/// offline longer than this can still resurrect an item.
const TOMBSTONE_RETENTION_DAYS: i64 = 180;
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
}

#[derive(Clone, Debug, Serialize)]
pub struct SyncReport {
    pub pulled: usize,
    pub pushed: usize,
    pub unchanged: usize,
    pub removed: usize,
    pub conflicts: Vec<String>,
    pub remote_missing: bool,
}

pub fn view(vault: &Vault) -> Result<SyncView, VaultError> {
    let config = load_config(vault)?;
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
    })
}

pub fn save_config(
    vault: &Vault,
    dek: &[u8; 32],
    config: SyncConfig,
    secret: Option<&str>,
) -> Result<(), String> {
    let config = config.normalize()?;
    let secret = secret.map(str::trim).filter(|s| !s.is_empty());
    if secret.is_none()
        && vault
            .get_setting("sync_secret_enc")
            .map_err(|e| e.to_string())?
            .is_none()
    {
        return Err("第一次保存需要填写同步密钥".into());
    }
    let json = serde_json::to_string(&config).map_err(|e| e.to_string())?;
    vault
        .set_setting("sync_config", &json)
        .map_err(|e| e.to_string())?;
    if let Some(secret) = secret {
        if secret.len() < 8 {
            return Err("同步密钥至少 8 位".into());
        }
        let key = sync_key(secret);
        let check = encrypt(&key, b"sealbox-sync-v1").map_err(|e| e.to_string())?;
        vault
            .set_secret_setting(dek, "sync_secret", secret)
            .map_err(|e| e.to_string())?;
        vault
            .set_setting("sync_key_check", &hex::encode(check.to_bytes()))
            .map_err(|e| e.to_string())?;
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
    ] {
        vault.delete_setting(key)?;
    }
    let _ = vault.audit("sync_config", None, "cleared");
    Ok(())
}

pub fn sync_now(vault: &Vault, dek: &[u8; 32]) -> Result<SyncReport, String> {
    let config = load_config(vault)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "还没有配置同步".to_string())?;
    let secret = vault
        .get_secret_setting(dek, "sync_secret")
        .map_err(|e| e.to_string())?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "同步密钥缺失，请重新保存".to_string())?;
    let key = sync_key(&secret);
    let client = RemoteClient::new(&config, &secret)?;
    let remote = client.get().map_err(|e| format!("读取远端失败: {e}"))?;
    let local_raw = vault.snapshot_for_backup().map_err(|e| e.to_string())?;
    let mut local = SyncSnapshot::from_vault(dek, &local_raw)?;
    local.deleted = vault.sync_tombstones().map_err(|e| e.to_string())?;
    let device = device_id(vault).map_err(|e| e.to_string())?;

    let (merged, report, changed) = match remote {
        None => (
            local.clone(),
            SyncReport {
                pulled: 0,
                pushed: local.entries.len(),
                unchanged: 0,
                removed: 0,
                conflicts: Vec::new(),
                remote_missing: true,
            },
            true,
        ),
        Some(bytes) => {
            let (remote_snap, legacy) = decode_snapshot(&key, Some(dek), &bytes)?;
            let (merged, report) = merge_snapshots(&local, &remote_snap);
            let changed = legacy || snapshot_digest(&merged) != snapshot_digest(&remote_snap);
            (merged, report, changed)
        }
    };

    if changed {
        let bytes = encode_snapshot(&key, &merged, &device).map_err(|e| e.to_string())?;
        client
            .put(&bytes)
            .map_err(|e| format!("写入远端失败: {e}"))?;
    }
    let sealed = merged.seal(dek)?;
    vault
        .replace_snapshot_same_key(dek, &sealed)
        .map_err(|e| e.to_string())?;
    vault
        .replace_sync_tombstones(&merged.deleted)
        .map_err(|e| e.to_string())?;
    let summary = format!(
        "pulled={} pushed={} unchanged={} removed={} conflicts={}",
        report.pulled,
        report.pushed,
        report.unchanged,
        report.removed,
        report.conflicts.len()
    );
    let now = chrono::Utc::now().to_rfc3339();
    let _ = vault.set_setting("sync_last_at", &now);
    let _ = vault.set_setting("sync_last_result", &summary);
    let _ = vault.audit("sync", None, &summary);
    Ok(report)
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
        let mut entry = entry.clone();
        entry.secret_blob.clear();
        entry.notes_blob = None;
        Ok(Self {
            entry,
            secret: Some(secret),
            notes,
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
        let mut entry = self.entry.clone();
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
    for entry in entries.iter_mut() {
        let Some(folder_id) = entry.entry.folder_id.clone() else {
            continue;
        };
        if folders.iter().any(|folder| folder.id == folder_id) {
            continue;
        }
        entry.entry.folder_id = None;
        if let Some(at) = tombstones.get(&(TOMBSTONE_FOLDER.to_string(), folder_id)) {
            if cmp_time(&entry.entry.updated_at, at) == std::cmp::Ordering::Less {
                entry.entry.updated_at = at.clone();
            }
        }
    }

    let mut tags = local.tags.clone();
    for tag in &remote.tags {
        if !tags.iter().any(|item| item == tag) {
            tags.push(tag.clone());
        }
    }
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
        },
    )
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
        })
    }

    fn get(&self) -> Result<Option<Vec<u8>>, String> {
        match self.kind {
            SyncKind::Webdav => self.webdav_get(),
            SyncKind::S3 => self.s3_get(),
        }
    }

    fn put(&self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > MAX_REMOTE_BYTES {
            return Err("sync snapshot exceeds 64MB".into());
        }
        match self.kind {
            SyncKind::Webdav => self.webdav_put(bytes),
            SyncKind::S3 => self.s3_put(bytes),
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

    fn webdav_get(&self) -> Result<Option<Vec<u8>>, String> {
        match self.agent().get(&self.webdav_url()).call() {
            Ok(response) => read_limited(response, MAX_REMOTE_BYTES).map(Some),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(code, response)) => {
                Err(format!("WebDAV HTTP {code}: {}", brief(response)))
            }
            Err(error) => Err(format!("WebDAV connection failed: {error}")),
        }
    }

    fn webdav_put(&self, bytes: &[u8]) -> Result<(), String> {
        match self
            .agent()
            .put(&self.webdav_url())
            .set("Content-Type", "application/octet-stream")
            .send_bytes(bytes)
        {
            Ok(response) if (200..300).contains(&response.status()) => Ok(()),
            Ok(response) => Err(format!("WebDAV write failed: HTTP {}", response.status())),
            Err(ureq::Error::Status(code, response)) => Err(format!(
                "WebDAV write failed: HTTP {code} {}",
                brief(response)
            )),
            Err(error) => Err(format!("WebDAV write failed: {error}")),
        }
    }

    fn s3_url(&self) -> String {
        let host = self
            .endpoint
            .trim_start_matches("https://")
            .trim_end_matches('/');
        let base = if host.starts_with(&format!("{}.", self.bucket)) {
            self.endpoint.clone()
        } else {
            format!("https://{}.{}", self.bucket, host)
        };
        format!("{}/{}", base.trim_end_matches('/'), self.encoded_key())
    }

    fn s3_get(&self) -> Result<Option<Vec<u8>>, String> {
        let url = self.s3_url();
        let headers = self.s3_headers("GET", &url, &[])?;
        let mut request = self.agent().get(&url);
        for (name, value) in &headers {
            request = request.set(name, value);
        }
        match request.call() {
            Ok(response) => read_limited(response, MAX_REMOTE_BYTES).map(Some),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(code, response)) => {
                Err(format!("S3 HTTP {code}: {}", brief(response)))
            }
            Err(error) => Err(format!("S3 connection failed: {error}")),
        }
    }

    fn s3_put(&self, bytes: &[u8]) -> Result<(), String> {
        let url = self.s3_url();
        let headers = self.s3_headers("PUT", &url, bytes)?;
        let mut request = self.agent().put(&url);
        for (name, value) in &headers {
            request = request.set(name, value);
        }
        match request.send_bytes(bytes) {
            Ok(response) if (200..300).contains(&response.status()) => Ok(()),
            Ok(response) => Err(format!("S3 write failed: HTTP {}", response.status())),
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
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let payload_hash = hex::encode(Sha256::digest(body));
        let (host, canonical_uri, _) = split_url(url)?;
        let canonical_headers = format!(
            "host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
        );
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
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
        Ok(vec![
            ("Authorization".into(), authorization),
            ("x-amz-date".into(), amz_date),
            ("x-amz-content-sha256".into(), payload_hash),
            ("Content-Type".into(), "application/octet-stream".into()),
        ])
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
                tags: vec![],
            },
            secret: Some(SecretPayload::Website {
                url: Some("https://example.com".into()),
                username: Some("a".into()),
                password: password.into(),
                totp_secret: None,
            }),
            notes: None,
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
    fn same_time_different_payload_is_conflict_and_keeps_local() {
        let local = snap(vec![entry("a", "local", "2026-02-02T00:00:00Z", "one")]);
        let remote = snap(vec![entry("a", "remote", "2026-02-02T00:00:00Z", "two")]);
        let (merged, report) = merge_snapshots(&local, &remote);
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(merged.entries[0].entry.title, "local");
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
    fn deleted_side_wins_when_timestamps_match() {
        let at = days_ago(5);
        let local = snap(vec![entry("a", "live", &at, "one")]);
        let mut trashed = entry("a", "trashed", &at, "two");
        trashed.entry.deleted_at = Some(at.clone());
        let remote = snap(vec![trashed]);

        let (merged, report) = merge_snapshots(&local, &remote);
        assert!(report.conflicts.is_empty());
        assert_eq!(merged.entries.len(), 1);
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
}

