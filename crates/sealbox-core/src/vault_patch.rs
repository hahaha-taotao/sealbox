use super::*;
use crate::crypto::{decrypt, Encrypted};
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use zeroize::Zeroize;

const PATCH_FIELDS: &[&str] = &[
    "title", "account", "url", "folder_id", "tags", "pinned", "expires_at", "notes",
    "secret",
];

impl Vault {
    pub fn entry_revision(&self, id: &str) -> Result<String, VaultError> {
        let raw = self.raw_revision_value(id)?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(&raw)?)))
    }

    pub fn patch_entry(
        &self,
        dek: &[u8; 32],
        id: &str,
        mut patch: serde_json::Map<String, serde_json::Value>,
        expected_revision: &str,
    ) -> Result<EntryDto, VaultError> {
        let result = (|| {
            self.conn.execute_batch("BEGIN IMMEDIATE")?;
            let applied = self.patch_entry_in_transaction(dek, id, &patch, expected_revision);
            match applied {
                Ok(value) => match self.conn.execute_batch("COMMIT") {
                    Ok(()) => Ok(value),
                    Err(error) => {
                        let _ = self.conn.execute_batch("ROLLBACK");
                        Err(error.into())
                    }
                },
                Err(error) => {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    Err(error)
                }
            }
        })();
        scrub_map(&mut patch);
        result
    }

    fn patch_entry_in_transaction(
        &self,
        dek: &[u8; 32],
        id: &str,
        patch: &serde_json::Map<String, serde_json::Value>,
        expected_revision: &str,
    ) -> Result<EntryDto, VaultError> {
        let actual = self.entry_revision(id)?;
        if actual != expected_revision {
            return Err(VaultError::ConcurrentModification);
        }
        let (kind, title, account, url, folder_id, pinned, expires_at, deleted_at):
            (String, String, Option<String>, Option<String>, Option<String>, i64, Option<String>, Option<String>) =
            self.conn.query_row(
                "SELECT kind,title,account,url,folder_id,pinned,expires_at,deleted_at FROM entries WHERE id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
            ).optional()?.ok_or(VaultError::NotFound)?;
        if deleted_at.is_some() {
            return Err(VaultError::InvalidPatch("deleted entries cannot be patched".into()));
        }
        for key in patch.keys() {
            if key == "id" || key == "kind" || key == "created_at" || key == "updated_at"
                || key == "use_count" || key == "last_used_at" || key == "fingerprint"
                || key == "deleted_at" || !PATCH_FIELDS.contains(&key.as_str())
            {
                return Err(VaultError::InvalidPatch(format!("field {key} is not patchable")));
            }
        }
        let kind = EntryKind::parse(&kind)?;
        if patch.is_empty() {
            return self.get_dto(id);
        }
        let tags = self.tags_for(id)?;
        let (secret_blob, notes_blob): (Vec<u8>, Option<Vec<u8>>) = self.conn.query_row(
            "SELECT secret_blob, notes_blob FROM entries WHERE id=?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let secret_bytes = zeroize::Zeroizing::new(decrypt(dek, &Encrypted::from_bytes(&secret_blob)?)?);
        let secret: SecretPayload = serde_json::from_slice(&secret_bytes)?;
        let mut plain = PlainGuard { secret, notes: None };
        if plain.secret.kind() != kind {
            return Err(VaultError::KindMismatch);
        }
        plain.notes = match notes_blob {
            Some(blob) => {
                let bytes = zeroize::Zeroizing::new(decrypt(dek, &Encrypted::from_bytes(&blob)?)?);
                let text = String::from_utf8_lossy(&bytes).into_owned();
                if text.is_empty() { None } else { Some(text) }
            }
            None => None,
        };

        let mut record = serde_json::Map::new();
        record.insert("id".into(), serde_json::Value::String(id.into()));
        record.insert("kind".into(), serde_json::to_value(&kind)?);
        record.insert("title".into(), serde_json::Value::String(title));
        record.insert("account".into(), serde_json::to_value(account)?);
        record.insert("url".into(), serde_json::to_value(url)?);
        record.insert("folder_id".into(), serde_json::to_value(folder_id)?);
        record.insert("tags".into(), serde_json::to_value(tags)?);
        record.insert("pinned".into(), serde_json::Value::Bool(pinned != 0));
        record.insert("expires_at".into(), serde_json::to_value(expires_at)?);
        record.insert("notes".into(), serde_json::to_value(&plain.notes)?);
        let mut secret_value = serde_json::to_value(&plain.secret)?;
        if let Some(value) = patch.get("secret") {
            let object = value.as_object().ok_or_else(|| invalid("secret must be an object"))?;
            validate_secret_patch(&kind, object)?;
            merge_json(&mut secret_value, value)?;
        }
        record.insert("secret".into(), secret_value);
        for (key, value) in patch {
            if key == "secret" { continue; }
            apply_metadata(&mut record, key, value.clone())?;
        }

        let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&record)?);
        scrub_map(&mut record);
        let mut input: UpsertEntry = serde_json::from_slice(&encoded)
            .map_err(|_| invalid("invalid patch value"))?;
        if input.kind != kind {
            input.secret.zeroize();
            if let Some(notes) = &mut input.notes {
                notes.zeroize();
            }
            return Err(invalid("kind cannot be changed"));
        }
        let result = self.upsert_entry(dek, input)?;
        Ok(result)
    }

    fn raw_revision_value(&self, id: &str) -> Result<serde_json::Value, VaultError> {
        let row = self.conn.query_row(
            "SELECT id,kind,title,account,url,folder_id,pinned,expires_at,use_count,last_used_at,created_at,updated_at,deleted_at,has_totp,fingerprint,secret_blob,notes_blob FROM entries WHERE id=?1",
            params![id],
            |r| Ok((
                r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?, r.get::<_, Option<String>>(4)?, r.get::<_, Option<String>>(5)?,
                r.get::<_, i64>(6)?, r.get::<_, Option<String>>(7)?, r.get::<_, i64>(8)?,
                r.get::<_, Option<String>>(9)?, r.get::<_, String>(10)?, r.get::<_, String>(11)?,
                r.get::<_, Option<String>>(12)?, r.get::<_, i64>(13)?, r.get::<_, Option<String>>(14)?,
                r.get::<_, Vec<u8>>(15)?, r.get::<_, Option<Vec<u8>>>(16)?,
            )),
        ).optional()?.ok_or(VaultError::NotFound)?;
        let mut tags = self.tags_for(id)?;
        tags.sort();
        Ok(serde_json::json!({
            "id": row.0, "kind": row.1, "title": row.2, "account": row.3, "url": row.4,
            "folder_id": row.5, "pinned": row.6, "expires_at": row.7, "use_count": row.8,
            "last_used_at": row.9, "created_at": row.10, "updated_at": row.11, "deleted_at": row.12,
            "has_totp": row.13, "fingerprint": row.14, "secret_blob": row.15,
            "notes_blob": row.16, "tags": tags,
        }))
    }
}

fn invalid(message: impl Into<String>) -> VaultError { VaultError::InvalidPatch(message.into()) }

struct PlainGuard {
    secret: SecretPayload,
    notes: Option<String>,
}

impl Drop for PlainGuard {
    fn drop(&mut self) {
        self.secret.zeroize();
        if let Some(notes) = &mut self.notes {
            notes.zeroize();
        }
    }
}

fn scrub_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                scrub_value(item);
            }
        }
        serde_json::Value::Object(map) => scrub_map(map),
        _ => {}
    }
    *value = serde_json::Value::Null;
}

fn scrub_map(map: &mut serde_json::Map<String, serde_json::Value>) {
    let owned = std::mem::take(map);
    for (mut key, mut value) in owned {
        scrub_value(&mut value);
        key.zeroize();
    }
}

fn apply_metadata(record: &mut serde_json::Map<String, serde_json::Value>, key: &str, value: serde_json::Value) -> Result<(), VaultError> {
    match key {
        "title" | "pinned" => if value.is_null() { Err(invalid(format!("{key} cannot be null"))) } else { record.insert(key.into(), value); Ok(()) },
        "account" | "url" | "folder_id" | "expires_at" | "notes" => {
            if !value.is_null() && !value.is_string() { return Err(invalid(format!("{key} must be a string or null"))); }
            record.insert(key.into(), value); Ok(())
        }
        "tags" => { if !value.as_array().map(|a| a.iter().all(serde_json::Value::is_string)).unwrap_or(false) { return Err(invalid("tags must be an array of strings")); } record.insert(key.into(), value); Ok(()) }
        _ => Err(invalid(format!("field {key} is not patchable"))),
    }
}

fn validate_secret_patch(kind: &EntryKind, patch: &serde_json::Map<String, serde_json::Value>) -> Result<(), VaultError> {
    if patch.contains_key("type") { return Err(invalid("secret type cannot be changed")); }
    let allowed: BTreeSet<&str> = match kind {
        EntryKind::Website => ["url", "username", "password", "totp_secret"].into_iter().collect(),
        EntryKind::ApiToken => ["service", "account", "token"].into_iter().collect(),
        EntryKind::Ssh => ["key_type", "private_key", "passphrase", "public_fingerprint"].into_iter().collect(),
        EntryKind::Mailbox => ["email", "password", "imap_host", "imap_port", "smtp_host", "smtp_port"].into_iter().collect(),
        EntryKind::MailAuth => ["email", "provider", "auth_code"].into_iter().collect(),
        EntryKind::Server => ["host", "port", "protocol", "username", "password"].into_iter().collect(),
        EntryKind::Database => ["engine", "host", "port", "database", "username", "password"].into_iter().collect(),
        EntryKind::ClientCert => ["passphrase"].into_iter().collect(),
    };
    for key in patch.keys() {
        if !allowed.contains(key.as_str()) { return Err(invalid(format!("secret field {key} is not patchable"))); }
    }
    Ok(())
}

fn nullable_secret_field(key: &str) -> bool {
    matches!(
        key,
        "url" | "username" | "totp_secret" | "account" | "passphrase" | "public_fingerprint"
            | "imap_host" | "imap_port" | "smtp_host" | "smtp_port" | "port"
    )
}

fn merge_json(target: &mut serde_json::Value, patch: &serde_json::Value) -> Result<(), VaultError> {
    let Some(patch) = patch.as_object() else { return Err(invalid("secret must be an object")); };
    let Some(target) = target.as_object_mut() else { return Err(invalid("secret must be an object")); };
    for (key, value) in patch {
        if value.is_object() {
            let Some(current) = target.get_mut(key) else {
                return Err(invalid(format!("unknown secret field {key}")));
            };
            if !current.is_object() {
                return Err(invalid(format!("secret field {key} cannot be an object")));
            }
            merge_json(current, value)?;
            continue;
        }
        if value.is_null() {
            let current = target.get(key).ok_or_else(|| invalid(format!("unknown secret field {key}")))?;
            if !current.is_null() && !nullable_secret_field(key) {
                return Err(invalid(format!("secret field {key} cannot be null")));
            }
        }
        if let Some(mut previous) = target.insert(key.clone(), value.clone()) {
            scrub_value(&mut previous);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use zeroize::Zeroize;

    fn vault() -> (Vault, [u8; 32], String) {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let entry = vault.upsert_entry(&dek, UpsertEntry {
            id: None, kind: EntryKind::Mailbox, title: "mail".into(), account: None, url: None,
            folder_id: None, tags: vec!["work".into()], pinned: false, expires_at: Some("2030-01-01".into()), notes: None,
            secret: SecretPayload::Mailbox { email: "a@b.test".into(), password: "pw".into(), imap_host: Some("imap".into()), imap_port: Some(993), smtp_host: Some("smtp".into()), smtp_port: Some(465) },
        }).unwrap();
        (vault, dek, entry.id)
    }

    #[test]
    fn patch_merges_secret_and_preserves_metadata() {
        let (vault, dek, id) = vault(); let revision = vault.entry_revision(&id).unwrap();
        let result = vault.patch_entry(&dek, &id, serde_json::json!({"title":"new", "secret":{"password":"new"}}).as_object().unwrap().clone(), &revision).unwrap();
        assert_eq!(result.title, "new"); assert_eq!(result.expires_at.as_deref(), Some("2030-01-01"));
        assert!(matches!(vault.get_secret(&dek, &id).unwrap(), SecretPayload::Mailbox { imap_host: Some(ref i), smtp_host: Some(ref s), password: ref p, .. } if i == "imap" && s == "smtp" && p == "new"));
    }

    #[test]
    fn patch_rejects_unknown_and_trash_and_stale_revision_without_writes() {
        let (vault, dek, id) = vault(); let revision = vault.entry_revision(&id).unwrap();
        let before: Vec<u8> = vault.conn.query_row("SELECT secret_blob FROM entries WHERE id=?1", params![id], |row| row.get(0)).unwrap();
        assert!(matches!(vault.patch_entry(&dek, &id, serde_json::json!({"nope":1}).as_object().unwrap().clone(), &revision), Err(VaultError::InvalidPatch(_))));
        assert!(matches!(vault.patch_entry(&dek, &id, serde_json::json!({"title":"x"}).as_object().unwrap().clone(), "stale"), Err(VaultError::ConcurrentModification)));
        let after: Vec<u8> = vault.conn.query_row("SELECT secret_blob FROM entries WHERE id=?1", params![id], |row| row.get(0)).unwrap();
        assert_eq!(before, after);
        assert_eq!(vault.entry_revision(&id).unwrap(), revision);
        vault.conn.execute("UPDATE entries SET deleted_at='now' WHERE id=?1", params![id]).unwrap();
        let trashed = vault.entry_revision(&id).unwrap();
        assert!(matches!(vault.patch_entry(&dek, &id, serde_json::Map::new(), &trashed), Err(VaultError::InvalidPatch(_))));
        let deleted: Option<String> = vault.conn.query_row("SELECT deleted_at FROM entries WHERE id=?1", params![id], |row| row.get(0)).unwrap();
        let still: Vec<u8> = vault.conn.query_row("SELECT secret_blob FROM entries WHERE id=?1", params![id], |row| row.get(0)).unwrap();
        assert!(deleted.is_some());
        assert_eq!(still, before);
        assert!(matches!(vault.entry_revision("missing"), Err(VaultError::NotFound)));
    }

    #[test]
    fn generic_patch_cannot_replace_client_cert_material() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut secret = SecretPayload::ClientCert {
            cert_pem: "CERT".into(),
            key_pem: "KEY".into(),
            passphrase: Some("pw".into()),
        };
        let blob = crate::crypto::encrypt(&dek, &serde_json::to_vec(&secret).unwrap()).unwrap().to_bytes();
        secret.zeroize();
        vault.conn.execute(
            "INSERT INTO entries (id,kind,title,account,url,folder_id,pinned,expires_at,use_count,last_used_at,created_at,updated_at,deleted_at,has_totp,fingerprint,secret_blob,notes_blob) VALUES ('cert','client_cert','c',NULL,NULL,NULL,0,NULL,0,NULL,'2020-01-01T00:00:00+00:00','2020-01-01T00:00:00+00:00',NULL,0,NULL,?1,NULL)",
            params![blob],
        ).unwrap();
        let revision = vault.entry_revision("cert").unwrap();
        let before: Vec<u8> = vault.conn.query_row("SELECT secret_blob FROM entries WHERE id='cert'", [], |row| row.get(0)).unwrap();
        for raw in [r#"{"secret":{"cert_pem":"NEW"}}"#, r#"{"secret":{"key_pem":"NEW"}}"#] {
            let patch = serde_json::from_str::<serde_json::Value>(raw).unwrap();
            let err = vault.patch_entry(&dek, "cert", patch.as_object().unwrap().clone(), &revision);
            assert!(matches!(err, Err(VaultError::InvalidPatch(_))), "{raw} -> {err:?}");
        }
        let after: Vec<u8> = vault.conn.query_row("SELECT secret_blob FROM entries WHERE id='cert'", [], |row| row.get(0)).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn empty_patch_does_not_reencrypt_ciphertext() {
        let (vault, dek, id) = vault(); let before: Vec<u8> = vault.conn.query_row("SELECT secret_blob FROM entries WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        vault.patch_entry(&dek, &id, serde_json::Map::new(), &vault.entry_revision(&id).unwrap()).unwrap();
        let after: Vec<u8> = vault.conn.query_row("SELECT secret_blob FROM entries WHERE id=?1", params![id], |r| r.get(0)).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn title_patch_preserves_ssh_fields_and_unknown_server_database_values() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let ssh = vault.upsert_entry(&dek, UpsertEntry {
            id: None, kind: EntryKind::Ssh, title: "ssh".into(), account: None, url: None,
            folder_id: None, tags: vec![], pinned: false, expires_at: None, notes: None,
            secret: SecretPayload::Ssh { key_type: "ed25519-custom".into(), private_key: "key".into(), passphrase: Some("phrase".into()), public_fingerprint: None },
        }).unwrap();
        let revision = vault.entry_revision(&ssh.id).unwrap();
        vault.patch_entry(&dek, &ssh.id, serde_json::json!({"title":"new"}).as_object().unwrap().clone(), &revision).unwrap();
        assert!(matches!(vault.get_secret(&dek, &ssh.id).unwrap(), SecretPayload::Ssh { key_type, passphrase: Some(passphrase), .. } if key_type == "ed25519-custom" && passphrase == "phrase"));

        for (kind, secret) in [
            (EntryKind::Server, SecretPayload::Server { host: "host".into(), port: None, protocol: "future-protocol".into(), username: "u".into(), password: "p".into() }),
            (EntryKind::Database, SecretPayload::Database { engine: "future-engine".into(), host: "host".into(), port: None, database: "db".into(), username: "u".into(), password: "p".into() }),
        ] {
            let entry = vault.upsert_entry(&dek, UpsertEntry { id: None, kind, title: "old".into(), account: None, url: None, folder_id: None, tags: vec![], pinned: false, expires_at: None, notes: None, secret }).unwrap();
            let revision = vault.entry_revision(&entry.id).unwrap();
            vault.patch_entry(&dek, &entry.id, serde_json::json!({"title":"new"}).as_object().unwrap().clone(), &revision).unwrap();
            match vault.get_secret(&dek, &entry.id).unwrap() {
                SecretPayload::Server { protocol, .. } => assert_eq!(protocol, "future-protocol"),
                SecretPayload::Database { engine, .. } => assert_eq!(engine, "future-engine"),
                other => panic!("unexpected secret: {other:?}"),
            }
        }
    }
}
