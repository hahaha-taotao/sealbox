//! Portable encrypted backups. Filesystem adapters must not decrypt secrets themselves.
use crate::crypto::{decrypt, derive_kek, encrypt, unwrap_key, wrap_key, ArgonParams, Encrypted};
use crate::vault::{BackupSnapshot, SecretPayload, EntryKind, Tombstone, Vault, VaultError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Default)]
pub struct RestoreOptions {
    pub overwrite: bool,
    pub restore_settings: bool,
}

const MAGIC: &[u8; 5] = b"SBOX1";
pub const MAX_BACKUP_BYTES: usize = 128 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct BackupFile {
    salt: [u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    blob: Encrypted,
}

fn legacy_version() -> u32 { 1 }

/// Extensions live here, not in BackupSnapshot (also consumed by sync).
#[derive(Serialize, Deserialize)]
pub struct BackupEnvelope {
    #[serde(default = "legacy_version")]
    pub version: u32,
    pub wrapped_dek: Encrypted,
    pub snapshot: BackupSnapshot,
    #[serde(default)]
    pub tombstones: Vec<Tombstone>,
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
}

/// Secret-free inspection result. Inspection authenticates and validates every record.
#[derive(Debug, Serialize)]
pub struct BackupInspection {
    pub version: u32,
    pub entries: usize,
    pub trash: usize,
    pub folders: usize,
    pub tags: usize,
    pub tombstones: usize,
    pub includes_settings: bool,
    pub warnings: Vec<String>,
}

pub fn export_envelope(vault: &Vault, dek: &[u8; 32], password: &str) -> Result<Vec<u8>, VaultError> {
    export(vault, dek, password, true)
}

pub fn export(vault: &Vault, dek: &[u8; 32], password: &str, include_settings: bool) -> Result<Vec<u8>, VaultError> {
    if &vault.unlock(password)? != dek { return Err(VaultError::BadPassword); }
    let params = ArgonParams::default();
    let kek = Zeroizing::new(derive_kek(password, &params)?);
    let mut settings = BTreeMap::new();
    if include_settings {
        for key in ["idle_secs", "clipboard_secs"] {
            if let Some(value) = vault.get_setting(key)? { settings.insert(key.to_string(), value); }
        }
    }
    let env = BackupEnvelope {
        version: 2,
        wrapped_dek: wrap_key(&kek, dek)?,
        snapshot: vault.snapshot_for_backup()?,
        tombstones: vault.sync_tombstones()?,
        settings,
    };
    validate(&env, dek)?;
    let blob = encrypt(&kek, &serde_json::to_vec(&env)?)?;
    let file = BackupFile { salt: params.salt, m_cost: params.m_cost, t_cost: params.t_cost, p_cost: params.p_cost, blob };
    let mut out = Vec::from(*MAGIC);
    out.extend(serde_json::to_vec(&file)?);
    if out.len() > MAX_BACKUP_BYTES { return Err(VaultError::CorruptBackup); }
    Ok(out)
}

fn decode(bytes: &[u8], password: &str) -> Result<(BackupEnvelope, Zeroizing<[u8; 32]>), VaultError> {
    if bytes.len() < 6 || bytes.len() > MAX_BACKUP_BYTES || &bytes[..5] != MAGIC { return Err(VaultError::CorruptBackup); }
    let file: BackupFile = serde_json::from_slice(&bytes[5..]).map_err(|_| VaultError::CorruptBackup)?;
    let params = ArgonParams { salt: file.salt, m_cost: file.m_cost, t_cost: file.t_cost, p_cost: file.p_cost };
    params.validate_import_bounds().map_err(|_| VaultError::InvalidBackupKdf)?;
    let kek = Zeroizing::new(derive_kek(password, &params)?);
    let json = Zeroizing::new(decrypt(&kek, &file.blob).map_err(|_| VaultError::BadPassword)?);
    let mut env: BackupEnvelope = serde_json::from_slice(&json).map_err(|_| VaultError::CorruptBackup)?;
    let dek = Zeroizing::new(unwrap_key(&kek, &env.wrapped_dek).map_err(|_| VaultError::CorruptBackup)?);
    if env.version == 1 {
        // Historical desktop snapshots could contain dangling folder references.
        let folders: HashSet<_> = env.snapshot.folders.iter().map(|f| f.id.clone()).collect();
        let mut tags: HashSet<_> = env.snapshot.tags.iter().cloned().collect();
        for e in &mut env.snapshot.entries {
            if e.folder_id.as_ref().map(|id| !folders.contains(id)).unwrap_or(false) { e.folder_id = None; }
            for tag in &e.tags { if tags.insert(tag.clone()) { env.snapshot.tags.push(tag.clone()); } }
        }
    }
    validate(&env, &dek)?;
    Ok((env, dek))
}

fn validate(env: &BackupEnvelope, dek: &[u8; 32]) -> Result<(), VaultError> {
    let corrupt = || VaultError::CorruptBackup;
    if !(1..=2).contains(&env.version) || env.snapshot.entries.len() > 100_000 || env.snapshot.folders.len() > 100_000 || env.snapshot.tags.len() > 100_000 || env.tombstones.len() > 100_000 { return Err(corrupt()); }
    let mut folders = HashSet::new();
    let mut names = HashSet::new();
    for f in &env.snapshot.folders {
        if f.id.is_empty() || f.name.trim().is_empty() || !folders.insert(f.id.as_str()) || !names.insert(f.name.trim()) { return Err(corrupt()); }
    }
    let mut tags = HashSet::new();
    for tag in &env.snapshot.tags { if tag.trim().is_empty() || !tags.insert(tag.as_str()) { return Err(corrupt()); } }
    let mut ids = HashSet::new();
    for e in &env.snapshot.entries {
        if e.id.is_empty() || !ids.insert(e.id.as_str()) || e.folder_id.as_deref().map(|id| !folders.contains(id)).unwrap_or(false) || e.tags.iter().any(|t| !tags.contains(t.as_str())) { return Err(corrupt()); }
        let plain = Zeroizing::new(decrypt(dek, &Encrypted::from_bytes(&e.secret_blob).map_err(|_| corrupt())?).map_err(|_| corrupt())?);
        let payload = Zeroizing::new(serde_json::from_slice::<SecretPayload>(&plain).map_err(|_| corrupt())?);
        if payload.kind() != EntryKind::parse(&e.kind).map_err(|_| corrupt())? { return Err(corrupt()); }
        if let SecretPayload::ClientCert { cert_pem, key_pem, passphrase } = &*payload {
            crate::certificate::validate_client_cert(cert_pem, key_pem, passphrase.as_deref()).map_err(|_| corrupt())?;
        }
        if let Some(blob) = &e.notes_blob {
            let notes = Zeroizing::new(decrypt(dek, &Encrypted::from_bytes(blob).map_err(|_| corrupt())?).map_err(|_| corrupt())?);
            std::str::from_utf8(&notes).map_err(|_| corrupt())?;
        }
    }
    let mut tombstones = HashSet::new();
    for t in &env.tombstones {
        if !matches!(t.kind.as_str(), "entry" | "folder" | "tag") || t.id.trim().is_empty() || chrono::DateTime::parse_from_rfc3339(&t.deleted_at).is_err() || !tombstones.insert((&t.kind, &t.id)) { return Err(corrupt()); }
        // A live folder cannot simultaneously be a deleted folder.
        if (t.kind == "folder" && folders.contains(t.id.as_str())) || (t.kind == "entry" && ids.contains(t.id.as_str())) || (t.kind == "tag" && tags.contains(t.id.as_str())) { return Err(corrupt()); }
    }
    for (key, value) in &env.settings {
        let seconds = value.parse::<u64>().map_err(|_| corrupt())?;
        if !match key.as_str() { "idle_secs" => seconds >= 60, "clipboard_secs" => (5..=120).contains(&seconds), _ => false } { return Err(corrupt()); }
    }
    Ok(())
}

pub fn inspect(bytes: &[u8], password: &str) -> Result<BackupInspection, VaultError> {
    let (env, _) = decode(bytes, password)?;
    Ok(BackupInspection { version: env.version, entries: env.snapshot.entries.len(), trash: env.snapshot.entries.iter().filter(|e| e.deleted_at.is_some()).count(), folders: env.snapshot.folders.len(), tags: env.snapshot.tags.len(), tombstones: env.tombstones.len(), includes_settings: !env.settings.is_empty(), warnings: if env.version == 1 { vec!["旧版备份：缺失文件夹引用按未分类处理，缺失标签声明由条目补齐".into()] } else { vec![] } })
}

pub fn restore_into(vault: &Vault, dest_dek: &[u8; 32], bytes: &[u8], password: &str, overwrite: bool) -> Result<(usize, usize), VaultError> {
    restore_into_with_options(vault, dest_dek, bytes, password, RestoreOptions { overwrite, restore_settings: false })
}

pub fn restore_into_with_options(vault: &Vault, dest_dek: &[u8; 32], bytes: &[u8], password: &str, options: RestoreOptions) -> Result<(usize, usize), VaultError> {
    let (env, source_dek) = decode(bytes, password)?;
    let settings = if options.restore_settings { env.settings } else { BTreeMap::new() };
    vault.import_backup_bundle(&source_dek, dest_dek, &env.snapshot, &env.tombstones, &settings, options.overwrite, false)
}

pub fn import_envelope(vault: &Vault, dest_dek: &[u8; 32], bytes: &[u8], password: &str, overwrite: bool) -> Result<(usize, usize), VaultError> {
    restore_into(vault, dest_dek, bytes, password, overwrite)
}

/// Validate before touching disk; publish a closed, checkpointed DB without overwriting.
/// Hard-link publication is atomic/no-clobber and stays on the destination filesystem.
pub fn restore_new(path: &str, bytes: &[u8], password: &str, new_password: Option<&str>) -> Result<[u8; 32], VaultError> {
    restore_new_with_options(path, bytes, password, new_password, RestoreOptions::default())
}

pub fn restore_new_with_options(path: &str, bytes: &[u8], password: &str, new_password: Option<&str>, options: RestoreOptions) -> Result<[u8; 32], VaultError> {
    let (env, source_dek) = decode(bytes, password)?;
    let password = new_password.unwrap_or(password);
    if password.chars().count() < 10 { return Err(VaultError::PasswordTooShort); }
    let target = Path::new(path);
    if target.exists() { return Err(VaultError::AlreadyExists); }
    let parent = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(".sealbox-restore-{}.db", uuid::Uuid::new_v4()));
    let temp_path = temporary.to_str().ok_or(VaultError::CorruptBackup)?;
    // Reserve exclusively: never clean up a file we did not create ourselves.
    drop(std::fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?);
    let result = (|| {
        let (vault, dek) = Vault::initialize_backup_temp(temp_path, password)?;
        let settings = if options.restore_settings { env.settings.clone() } else { BTreeMap::new() };
        vault.import_backup_bundle(&source_dek, &dek, &env.snapshot, &env.tombstones, &settings, true, true)?;
        vault.prepare_backup_publication()?;
        drop(vault);
        let verified = Vault::open(temp_path)?;
        if verified.unlock(password)? != dek { return Err(VaultError::CorruptBackup); }
        // Reopening may re-enable WAL; close it back into a single durable file.
        verified.prepare_backup_publication()?;
        drop(verified);
        std::fs::OpenOptions::new().read(true).write(true).open(&temporary)?.sync_all()?;
        std::fs::hard_link(&temporary, target).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists { VaultError::AlreadyExists } else { VaultError::Io(error) }
        })?;
        Ok(dek)
    })();
    for suffix in ["", "-wal", "-shm", "-journal"] { let _ = std::fs::remove_file(format!("{temp_path}{suffix}")); }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt, wrap_key, ARGON_M_COST, ARGON_P_COST, ARGON_T_COST};
    use crate::vault::{BackupEntry, BackupSnapshot, EntryKind, SecretPayload, UpsertEntry};

    fn website(id: &str, title: &str, password: &str, folder_id: Option<&str>) -> UpsertEntry {
        UpsertEntry {
            id: Some(id.into()),
            kind: EntryKind::Website,
            title: title.into(),
            account: Some("a@b.c".into()),
            url: None,
            folder_id: folder_id.map(|s| s.into()),
            tags: vec![],
            pinned: false,
            expires_at: None,
            notes: None,
            secret: SecretPayload::Website {
                url: None,
                username: Some("a@b.c".into()),
                password: password.into(),
                totp_secret: None,
            },
        }
    }

    fn tamper_kdf(bytes: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Vec<u8> {
        let mut file: BackupFile = serde_json::from_slice(&bytes[5..]).unwrap();
        file.m_cost = m_cost;
        file.t_cost = t_cost;
        file.p_cost = p_cost;
        let body = serde_json::to_vec(&file).unwrap();
        let mut out = Vec::from(*MAGIC);
        out.extend(body);
        out
    }

    fn envelope_bytes(
        password: &str,
        params: &ArgonParams,
        snapshot: BackupSnapshot,
        dek: &[u8; 32],
    ) -> Vec<u8> {
        let kek = derive_kek(password, params).unwrap();
        let env = BackupEnvelope {
            wrapped_dek: wrap_key(&kek, dek).unwrap(),
            version: 1, tombstones: vec![], settings: BTreeMap::new(), snapshot,
        };
        // Write the exact original SBOX1 envelope shape, without extension fields.
        let mut value = serde_json::to_value(&env).unwrap();
        for key in ["version", "tombstones", "settings"] { value.as_object_mut().unwrap().remove(key); }
        let blob = encrypt(&kek, &serde_json::to_vec(&value).unwrap()).unwrap();
        let file = BackupFile {
            salt: params.salt,
            m_cost: params.m_cost,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            blob,
        };
        let mut out = Vec::from(*MAGIC);
        out.extend(serde_json::to_vec(&file).unwrap());
        out
    }

    #[test]
    fn versioned_backup_all_types_empty_tags_settings_and_new_vault() {
        let password = "export password long";
        let (src, dek) = Vault::create_in_memory(password).unwrap();
        let folder = src.create_folder("保留稳定ID").unwrap();
        let mut seed = website("website", "中文,\"网站\"", "=secret\n密码", Some(&folder.id));
        seed.notes = Some("私密备注\n第二行".into());
        src.upsert_entry(&dek, seed.clone()).unwrap();
        let payloads = vec![
            serde_json::json!({"type":"api_token","service":"svc","account":null,"token":"tok"}),
            serde_json::json!({"type":"ssh","key_type":"ed25519","private_key":"ssh-secret","passphrase":null,"public_fingerprint":null}),
            serde_json::json!({"type":"mailbox","email":"a@b.c","password":"mail","imap_host":null,"imap_port":null,"smtp_host":null,"smtp_port":null}),
            serde_json::json!({"type":"mail_auth","email":"a@b.c","provider":"p","auth_code":"code"}),
            serde_json::json!({"type":"server","host":"example.com","port":22,"protocol":"ssh","username":"u","password":"server"}),
            serde_json::json!({"type":"database","engine":"pg","host":"db","port":5432,"database":"d","username":"u","password":"database"}),
        ];
        for (index, payload) in payloads.into_iter().enumerate() {
            let mut row = seed.clone();
            row.secret = serde_json::from_value(payload).unwrap();
            row.kind = row.secret.kind();
            row.id = Some(format!("variant-{index}"));
            src.upsert_entry(&dek, row).unwrap();
        }
        src.upsert_entry(&dek, client_cert("cert", "证书")).unwrap();
        src.soft_delete(&["variant-0".into()]).unwrap();
        // Unreferenced tags are deliberately not visible through entry DTOs.
        let mut snapshot = src.snapshot_for_backup().unwrap();
        snapshot.tags.push("空标签".into());
        let tombstones = vec![Tombstone { kind: "folder".into(), id: "deleted-folder".into(), deleted_at: "2026-01-01T00:00:00Z".into() }, Tombstone { kind: "tag".into(), id: "deleted-tag".into(), deleted_at: "2026-01-01T00:00:00Z".into() }];
        src.import_backup_bundle(&dek, &dek, &snapshot, &tombstones, &BTreeMap::new(), true, false).unwrap();
        src.set_setting("idle_secs", "600").unwrap();
        src.set_setting("clipboard_secs", "30").unwrap();
        src.set_setting("device_id", "never-export-me").unwrap();
        src.set_setting("sync_secret", "never-export-me").unwrap();
        let bytes = export_envelope(&src, &dek, password).unwrap();
        let summary = inspect(&bytes, password).unwrap();
        assert_eq!(summary.version, 2);
        assert_eq!(summary.entries, 8);
        assert_eq!(summary.trash, 1);
        let (env, _) = decode(&bytes, password).unwrap();
        assert_eq!(env.settings.len(), 2);
        assert!(!env.settings.contains_key("device_id"));
        let path = std::env::temp_dir().join(format!("sealbox-{}.db", uuid::Uuid::new_v4()));
        let path = path.to_str().unwrap();
        let new_dek = restore_new_with_options(path, &bytes, password, Some("new password long"), RestoreOptions { overwrite: true, restore_settings: true }).unwrap();
        let dst = Vault::open(path).unwrap();
        assert_eq!(dst.unlock("new password long").unwrap(), new_dek);
        assert!(dst.unlock(password).is_err());
        assert_eq!(dst.list_folders().unwrap()[0].id, folder.id);
        assert!(dst.snapshot_for_backup().unwrap().tags.contains(&"空标签".to_string()));
        assert!(dst.list_tags().unwrap().contains(&"空标签".to_string()));
        assert_eq!(dst.sync_tombstones().unwrap().len(), 2);
        assert_eq!(dst.get_setting("idle_secs").unwrap().as_deref(), Some("600"));
        assert!(dst.get_setting("device_id").unwrap().is_none());
        assert_eq!(dst.get_notes(&new_dek, "website").unwrap(), seed.notes);
        let actual = dst.snapshot_for_backup().unwrap();
        let original = src.snapshot_for_backup().unwrap();
        for row in actual.entries {
            let from = original.entries.iter().find(|e| e.id == row.id).unwrap();
            assert_eq!(decrypt(&dek, &Encrypted::from_bytes(&from.secret_blob).unwrap()).unwrap(), decrypt(&new_dek, &Encrypted::from_bytes(&row.secret_blob).unwrap()).unwrap());
            assert_eq!(row.deleted_at, from.deleted_at);
        }
        assert!(matches!(restore_new(path, &bytes, password, None), Err(VaultError::AlreadyExists)));
        drop(dst);
        for suffix in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{path}{suffix}")); }
    }

    #[test]
    fn sync_bundle_compare_and_apply_rejects_stale_and_rolls_back() {
        let (vault, dek) = Vault::create_in_memory("correct password long").unwrap();
        let baseline = vault.snapshot_for_backup().unwrap();
        vault.upsert_entry(&dek, website("changed", "changed", "secret", None)).unwrap();
        assert!(matches!(vault.replace_sync_bundle_if_unchanged(&dek, &baseline, &[], &baseline, &[]), Err(VaultError::ConcurrentModification)));
        assert_eq!(vault.snapshot_for_backup().unwrap().entries.len(), 1);
        let current = vault.snapshot_for_backup().unwrap();
        let bad_tombs = vec![Tombstone { kind: "entry".into(), id: "same".into(), deleted_at: "2026-01-01T00:00:00Z".into() }; 2];
        assert!(vault.replace_sync_bundle_if_unchanged(&dek, &current, &[], &baseline, &bad_tombs).is_err());
        assert_eq!(vault.snapshot_for_backup().unwrap().entries.len(), 1);
        vault.replace_sync_bundle_if_unchanged(&dek, &current, &[], &baseline, &[]).unwrap();
        assert!(vault.snapshot_for_backup().unwrap().entries.is_empty());
    }

    #[test]
    fn invalid_restore_never_creates_target_and_settings_are_opt_in() {
        let password = "export password long";
        let (src, dek) = Vault::create_in_memory(password).unwrap();
        src.set_setting("idle_secs", "600").unwrap();
        let bytes = export_envelope(&src, &dek, password).unwrap();
        let path = std::env::temp_dir().join(format!("sealbox-invalid-{}.db", uuid::Uuid::new_v4()));
        let path = path.to_str().unwrap();
        assert!(restore_new(path, &bytes, "wrong password", None).is_err());
        assert!(!Path::new(path).exists());
        assert!(restore_new(path, &bytes[..bytes.len()/2], password, None).is_err());
        assert!(!Path::new(path).exists());
        let (dst, ddek) = Vault::create_in_memory("target password long").unwrap();
        dst.set_setting("idle_secs", "120").unwrap();
        restore_into(&dst, &ddek, &bytes, password, false).unwrap();
        assert_eq!(dst.get_setting("idle_secs").unwrap().as_deref(), Some("120"));
        restore_into_with_options(&dst, &ddek, &bytes, password, RestoreOptions { overwrite: false, restore_settings: true }).unwrap();
        assert_eq!(dst.get_setting("idle_secs").unwrap().as_deref(), Some("600"));
    }

    #[test]
    fn export_import_merge() {
        let (src, dek) = Vault::create_in_memory("export password long").unwrap();
        src.upsert_entry(&dek, website("fixed-id-1", "mail", "p@ss", None))
            .unwrap();
        let bytes = export_envelope(&src, &dek, "export password long").unwrap();

        let (dst, ddek) = Vault::create_in_memory("local password long").unwrap();
        match import_envelope(&dst, &ddek, &bytes, "wrong password extra", false) {
            Err(VaultError::BadPassword) => {}
            other => panic!("expected BadPassword, got {other:?}"),
        }
        let (n, skip) =
            import_envelope(&dst, &ddek, &bytes, "export password long", false).unwrap();
        assert_eq!(n, 1);
        assert_eq!(skip, 0);
        match dst.get_secret(&ddek, "fixed-id-1").unwrap() {
            SecretPayload::Website { password, .. } => assert_eq!(password, "p@ss"),
            _ => panic!("kind"),
        }
        assert!(dst.unlock("export password long").is_err());
        assert!(dst.unlock("local password long").is_ok());
    }

    fn client_cert(id: &str, title: &str) -> UpsertEntry {
        UpsertEntry {
            id: Some(id.into()),
            kind: EntryKind::ClientCert,
            title: title.into(),
            account: None,
            url: None,
            folder_id: None,
            tags: vec![],
            pinned: false,
            expires_at: None,
            notes: None,
            secret: SecretPayload::ClientCert {
                cert_pem: include_str!("../../../src-tauri/tests/data/client-chain.pem").into(),
                key_pem: include_str!("../../../src-tauri/tests/data/client-key.pem").into(),
                passphrase: None,
            },
        }
    }

    #[test]
    fn client_cert_is_stored_encrypted_and_survives_backup() {
        let (src, dek) = Vault::create_in_memory("export password long").unwrap();
        let entry = src
            .upsert_entry(&dek, client_cert("cert-id-1", "ZoomKey 客户端证书"))
            .unwrap();
        assert_eq!(entry.kind, EntryKind::ClientCert);
        assert_eq!(
            src.counts_for(&crate::vault::ListFilter::default())
                .unwrap()
                .client_cert,
            1
        );
        match src.get_secret(&dek, "cert-id-1").unwrap() {
            SecretPayload::ClientCert { key_pem, .. } => {
                assert!(key_pem.contains("BEGIN PRIVATE KEY"))
            }
            _ => panic!("kind"),
        }

        let bytes = export_envelope(&src, &dek, "export password long").unwrap();
        let (dst, ddek) = Vault::create_in_memory("local password long").unwrap();
        let (n, skip) =
            import_envelope(&dst, &ddek, &bytes, "export password long", false).unwrap();
        assert_eq!(n, 1);
        assert_eq!(skip, 0);
        match dst.get_secret(&ddek, "cert-id-1").unwrap() {
            SecretPayload::ClientCert {
                cert_pem,
                key_pem,
                passphrase,
            } => {
                assert!(cert_pem.contains("BEGIN CERTIFICATE"));
                assert!(key_pem.contains("BEGIN PRIVATE KEY"));
                assert!(passphrase.is_none());
            }
            _ => panic!("kind"),
        }
    }

    #[test]
    fn import_rejects_weak_and_huge_kdf_params() {
        let (src, dek) = Vault::create_in_memory("export password long").unwrap();
        src.upsert_entry(&dek, website("fixed-id-1", "mail", "p@ss", None))
            .unwrap();
        let bytes = export_envelope(&src, &dek, "export password long").unwrap();
        let (dst, ddek) = Vault::create_in_memory("local password long").unwrap();

        let weak = tamper_kdf(&bytes, 1, ARGON_T_COST, ARGON_P_COST);
        match import_envelope(&dst, &ddek, &weak, "export password long", false) {
            Err(VaultError::InvalidBackupKdf) => {}
            other => panic!("expected InvalidBackupKdf, got {other:?}"),
        }

        let huge = tamper_kdf(&bytes, 2_000_000, ARGON_T_COST, ARGON_P_COST);
        match import_envelope(&dst, &ddek, &huge, "export password long", false) {
            Err(VaultError::InvalidBackupKdf) => {}
            other => panic!("expected InvalidBackupKdf, got {other:?}"),
        }
        assert!(dst
            .list_entries(&crate::vault::ListFilter::default())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn import_maps_folders_by_name_and_keeps_existing_dest_ids() {
        let (src, dek) = Vault::create_in_memory("export password long").unwrap();
        let src_folder = src.create_folder("work").unwrap();
        src.upsert_entry(
            &dek,
            website("fixed-id-1", "mail", "p@ss", Some(&src_folder.id)),
        )
        .unwrap();
        let bytes = export_envelope(&src, &dek, "export password long").unwrap();

        let (dst, ddek) = Vault::create_in_memory("local password long").unwrap();
        let dest_folder = dst.create_folder("work").unwrap();
        assert_ne!(src_folder.id, dest_folder.id);

        let (n, skip) =
            import_envelope(&dst, &ddek, &bytes, "export password long", false).unwrap();
        assert_eq!(n, 1);
        assert_eq!(skip, 0);
        let listed = dst
            .list_entries(&crate::vault::ListFilter::default())
            .unwrap();
        assert_eq!(
            listed[0].folder_id.as_deref(),
            Some(dest_folder.id.as_str())
        );
        let folders = dst.list_folders().unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].id, dest_folder.id);
    }

    #[test]
    fn import_creates_missing_folder_and_rewrites_entry_folder_id() {
        let (src, dek) = Vault::create_in_memory("export password long").unwrap();
        let src_folder = src.create_folder("personal").unwrap();
        src.upsert_entry(
            &dek,
            website("fixed-id-2", "bank", "p@ss", Some(&src_folder.id)),
        )
        .unwrap();
        let bytes = export_envelope(&src, &dek, "export password long").unwrap();

        let (dst, ddek) = Vault::create_in_memory("local password long").unwrap();
        let (n, skip) =
            import_envelope(&dst, &ddek, &bytes, "export password long", false).unwrap();
        assert_eq!(n, 1);
        assert_eq!(skip, 0);
        let folders = dst.list_folders().unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].name, "personal");
        assert_ne!(folders[0].id, src_folder.id);
        let listed = dst
            .list_entries(&crate::vault::ListFilter::default())
            .unwrap();
        assert_eq!(listed[0].folder_id.as_deref(), Some(folders[0].id.as_str()));
    }

    #[test]
    fn import_rolls_back_when_an_entry_fails_to_decrypt() {
        let password = "export password long";
        let (src, dek) = Vault::create_in_memory(password).unwrap();
        src.upsert_entry(&dek, website("good-id", "mail", "p@ss", None))
            .unwrap();
        let good = src.snapshot_for_backup().unwrap().entries.remove(0);
        let other_dek = [9u8; 32];
        let bad_secret = encrypt(&other_dek, b"not-a-secret").unwrap().to_bytes();
        let snapshot = BackupSnapshot {
            folders: vec![],
            tags: vec![],
            entries: vec![
                good,
                BackupEntry {
                    id: "bad-id".into(),
                    kind: "website".into(),
                    title: "broken".into(),
                    account: None,
                    url: None,
                    folder_id: None,
                    pinned: false,
                    expires_at: None,
                    use_count: 0,
                    last_used_at: None,
                    created_at: "2026-01-01T00:00:00Z".into(),
                    updated_at: "2026-01-01T00:00:00Z".into(),
                    deleted_at: None,
                    has_totp: false,
                    fingerprint: None,
                    secret_blob: bad_secret,
                    notes_blob: None,
                    tags: vec![],
                },
            ],
        };
        let params = ArgonParams {
            salt: [7u8; 16],
            m_cost: ARGON_M_COST,
            t_cost: ARGON_T_COST,
            p_cost: ARGON_P_COST,
        };
        let bytes = envelope_bytes(password, &params, snapshot, &dek);
        let (dst, ddek) = Vault::create_in_memory("local password long").unwrap();
        match import_envelope(&dst, &ddek, &bytes, password, false) {
            Err(VaultError::CorruptBackup) => {}
            other => panic!("expected CorruptBackup, got {other:?}"),
        }
        assert!(dst
            .list_entries(&crate::vault::ListFilter::default())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn import_skips_existing_ids_unless_overwrite_is_set() {
        let (src, dek) = Vault::create_in_memory("export password long").unwrap();
        src.upsert_entry(&dek, website("fixed-id-1", "mail", "from-backup", None))
            .unwrap();
        let bytes = export_envelope(&src, &dek, "export password long").unwrap();

        let (dst, ddek) = Vault::create_in_memory("local password long").unwrap();
        dst.upsert_entry(&ddek, website("fixed-id-1", "mail", "local-secret", None))
            .unwrap();

        let (n, skip) =
            import_envelope(&dst, &ddek, &bytes, "export password long", false).unwrap();
        assert_eq!(n, 0);
        assert_eq!(skip, 1);
        match dst.get_secret(&ddek, "fixed-id-1").unwrap() {
            SecretPayload::Website { password, .. } => assert_eq!(password, "local-secret"),
            _ => panic!("kind"),
        }

        let (n, skip) = import_envelope(&dst, &ddek, &bytes, "export password long", true).unwrap();
        assert_eq!(n, 1);
        assert_eq!(skip, 0);
        match dst.get_secret(&ddek, "fixed-id-1").unwrap() {
            SecretPayload::Website { password, .. } => assert_eq!(password, "from-backup"),
            _ => panic!("kind"),
        }
    }

    #[test]
    fn import_rejects_truncated_or_garbage_as_corrupt() {
        let (dst, ddek) = Vault::create_in_memory("local password long").unwrap();
        match import_envelope(&dst, &ddek, b"nope", "export password long", false) {
            Err(VaultError::CorruptBackup) => {}
            other => panic!("expected CorruptBackup, got {other:?}"),
        }
        let mut almost = Vec::from(*MAGIC);
        almost.extend_from_slice(b"{not-json");
        match import_envelope(&dst, &ddek, &almost, "export password long", false) {
            Err(VaultError::CorruptBackup) => {}
            other => panic!("expected CorruptBackup, got {other:?}"),
        }
    }
}

