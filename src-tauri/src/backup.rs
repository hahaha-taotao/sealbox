use crate::crypto::{decrypt, derive_kek, encrypt, unwrap_key, wrap_key, ArgonParams, Encrypted};
use crate::vault::{BackupSnapshot, Vault, VaultError};
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 5] = b"SBOX1";

#[derive(Serialize, Deserialize)]
struct BackupFile {
    salt: [u8; 16],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    blob: Encrypted,
}

#[derive(Serialize, Deserialize)]
pub struct BackupEnvelope {
    pub wrapped_dek: Encrypted,
    pub snapshot: BackupSnapshot,
}

pub fn export_envelope(
    vault: &Vault,
    dek: &[u8; 32],
    master_password: &str,
) -> Result<Vec<u8>, VaultError> {
    let check = vault.unlock(master_password)?;
    if &check != dek {
        return Err(VaultError::BadPassword);
    }
    let snap = vault.snapshot_for_backup()?;
    let params = ArgonParams::default();
    let kek = derive_kek(master_password, &params)?;
    let wrapped_dek = wrap_key(&kek, dek)?;
    let env = BackupEnvelope {
        wrapped_dek,
        snapshot: snap,
    };
    let json = serde_json::to_vec(&env)?;
    let blob = encrypt(&kek, &json)?;
    let file = BackupFile {
        salt: params.salt,
        m_cost: params.m_cost,
        t_cost: params.t_cost,
        p_cost: params.p_cost,
        blob,
    };
    let body = serde_json::to_vec(&file)?;
    let mut out = Vec::from(*MAGIC);
    out.extend(body);
    Ok(out)
}

pub fn import_envelope(
    vault: &Vault,
    dest_dek: &[u8; 32],
    bytes: &[u8],
    backup_password: &str,
    overwrite: bool,
) -> Result<(usize, usize), VaultError> {
    if bytes.len() < 6 || &bytes[..5] != MAGIC {
        return Err(VaultError::CorruptBackup);
    }
    let file: BackupFile =
        serde_json::from_slice(&bytes[5..]).map_err(|_| VaultError::CorruptBackup)?;
    let params = ArgonParams {
        salt: file.salt,
        m_cost: file.m_cost,
        t_cost: file.t_cost,
        p_cost: file.p_cost,
    };
    params
        .validate_import_bounds()
        .map_err(|_| VaultError::InvalidBackupKdf)?;
    let kek = derive_kek(backup_password, &params)?;
    let json = decrypt(&kek, &file.blob).map_err(|_| VaultError::BadPassword)?;
    let env: BackupEnvelope =
        serde_json::from_slice(&json).map_err(|_| VaultError::CorruptBackup)?;
    let source_dek = unwrap_key(&kek, &env.wrapped_dek).map_err(|_| VaultError::BadPassword)?;
    vault.import_reencrypted_snapshot(&source_dek, dest_dek, &env.snapshot, overwrite)
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
            snapshot,
        };
        let blob = encrypt(&kek, &serde_json::to_vec(&env).unwrap()).unwrap();
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
                cert_pem: include_str!("../tests/data/client-chain.pem").into(),
                key_pem: include_str!("../tests/data/client-key.pem").into(),
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
