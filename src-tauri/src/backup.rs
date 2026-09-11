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

pub fn export_envelope(vault: &Vault, dek: &[u8; 32], master_password: &str) -> Result<Vec<u8>, VaultError> {
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
        return Err(VaultError::BadPassword);
    }
    let file: BackupFile = serde_json::from_slice(&bytes[5..]).map_err(|_| VaultError::BadPassword)?;
    let params = ArgonParams {
        salt: file.salt,
        m_cost: file.m_cost,
        t_cost: file.t_cost,
        p_cost: file.p_cost,
    };
    let kek = derive_kek(backup_password, &params)?;
    let json = decrypt(&kek, &file.blob).map_err(|_| VaultError::BadPassword)?;
    let env: BackupEnvelope = serde_json::from_slice(&json)?;
    let source_dek = unwrap_key(&kek, &env.wrapped_dek).map_err(|_| VaultError::BadPassword)?;
    for folder in &env.snapshot.folders {
        let _ = vault.ensure_folder_named(&folder.name);
    }
    let mut imported = 0usize;
    let mut skipped = 0usize;
    for entry in &env.snapshot.entries {
        match vault.insert_reencrypted_entry(&source_dek, dest_dek, entry, overwrite) {
            Ok(true) => imported += 1,
            Ok(false) => skipped += 1,
            Err(_) => skipped += 1,
        }
    }
    vault.audit(
        "import",
        None,
        &format!("imported={imported} skipped={skipped}"),
    )?;
    Ok((imported, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{EntryKind, SecretPayload, UpsertEntry};

    #[test]
    fn export_import_merge() {
        let (src, dek) = Vault::create_in_memory("export password long").unwrap();
        src.upsert_entry(
            &dek,
            UpsertEntry {
                id: Some("fixed-id-1".into()),
                kind: EntryKind::Website,
                title: "mail".into(),
                account: Some("a@b.c".into()),
                url: None,
                folder_id: None,
                tags: vec![],
                pinned: false,
                expires_at: None,
                notes: None,
                secret: SecretPayload::Website {
                    url: None,
                    username: Some("a@b.c".into()),
                    password: "p@ss".into(),
                    totp_secret: None,
                },
            },
        )
        .unwrap();
        let bytes = export_envelope(&src, &dek, "export password long").unwrap();

        let (dst, ddek) = Vault::create_in_memory("local password long").unwrap();
        let (n, skip) = import_envelope(&dst, &ddek, &bytes, "export password long", false).unwrap();
        assert_eq!(n, 1);
        assert_eq!(skip, 0);
        match dst.get_secret(&ddek, "fixed-id-1").unwrap() {
            SecretPayload::Website { password, .. } => assert_eq!(password, "p@ss"),
            _ => panic!("kind"),
        }
        assert!(dst.unlock("export password long").is_err());
        assert!(dst.unlock("local password long").is_ok());
    }
}
