use crate::crypto::{
    decrypt, derive_kek, encrypt, random_key, unwrap_key, wrap_key, ArgonParams, Encrypted,
};
use crate::db;
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("database error: {0}")]
    Db(#[from] db::DbError),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("vault already exists")]
    AlreadyExists,
    #[error("vault not initialized")]
    NotInitialized,
    #[error("master password incorrect")]
    BadPassword,
    #[error("entry not found")]
    NotFound,
    #[error("invalid kind")]
    InvalidKind,
    #[error("master password too short")]
    PasswordTooShort,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Website,
    ApiToken,
    Ssh,
}

impl EntryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Website => "website",
            Self::ApiToken => "api_token",
            Self::Ssh => "ssh",
        }
    }

    pub fn parse(s: &str) -> Result<Self, VaultError> {
        match s {
            "website" => Ok(Self::Website),
            "api_token" => Ok(Self::ApiToken),
            "ssh" => Ok(Self::Ssh),
            _ => Err(VaultError::InvalidKind),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntryDto {
    pub id: String,
    pub kind: EntryKind,
    pub title: String,
    pub account: Option<String>,
    pub url: Option<String>,
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
    pub pinned: bool,
    pub expires_at: Option<String>,
    pub use_count: i64,
    pub last_used_at: Option<String>,
    pub updated_at: String,
    pub has_totp: bool,
    pub fingerprint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListFilter {
    pub query: Option<String>,
    pub kind: Option<EntryKind>,
    pub folder_id: Option<String>,
    pub uncategorized: bool,
    pub tag: Option<String>,
    pub trash: bool,
    pub sort: SortBy,
}

impl Default for ListFilter {
    fn default() -> Self {
        Self {
            query: None,
            kind: None,
            folder_id: None,
            uncategorized: false,
            tag: None,
            trash: false,
            sort: SortBy::UseCount,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortBy {
    UseCount,
    Updated,
    Title,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpsertEntry {
    pub id: Option<String>,
    pub kind: EntryKind,
    pub title: String,
    pub account: Option<String>,
    pub url: Option<String>,
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
    pub pinned: bool,
    pub expires_at: Option<String>,
    pub notes: Option<String>,
    pub secret: SecretPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretPayload {
    Website {
        url: Option<String>,
        username: Option<String>,
        password: String,
        totp_secret: Option<String>,
    },
    ApiToken {
        service: String,
        account: Option<String>,
        token: String,
    },
    Ssh {
        key_type: String,
        private_key: String,
        passphrase: Option<String>,
        public_fingerprint: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FolderDto {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub at: String,
    pub action: String,
    pub entry_id: Option<String>,
    pub detail: String,
}

pub struct Vault {
    conn: Connection,
}

impl Vault {
    pub fn create(path: &str, master_password: &str) -> Result<[u8; 32], VaultError> {
        if master_password.chars().count() < 10 {
            return Err(VaultError::PasswordTooShort);
        }
        if std::path::Path::new(path).exists() {
            return Err(VaultError::AlreadyExists);
        }
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = db::open(path)?;
        Self::init_meta(&conn, master_password)
    }

    pub fn create_in_memory(master_password: &str) -> Result<(Self, [u8; 32]), VaultError> {
        if master_password.chars().count() < 10 {
            return Err(VaultError::PasswordTooShort);
        }
        let conn = db::open_memory()?;
        let dek = Self::init_meta(&conn, master_password)?;
        Ok((Self { conn }, dek))
    }

    pub fn open(path: &str) -> Result<Self, VaultError> {
        Ok(Self {
            conn: db::open(path)?,
        })
    }

    fn init_meta(conn: &Connection, master_password: &str) -> Result<[u8; 32], VaultError> {
        let params_kdf = ArgonParams::default();
        let kek = derive_kek(master_password, &params_kdf)?;
        let dek = random_key();
        let wrapped = wrap_key(&kek, &dek)?;
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO vault_meta (
                id, schema_version, kdf_salt, kdf_m, kdf_t, kdf_p,
                wrapped_data_key, hello_enabled, wrapped_dek_hello, created_at, updated_at
            ) VALUES (1, 1, ?1, ?2, ?3, ?4, ?5, 0, NULL, ?6, ?6)",
            params![
                params_kdf.salt.as_slice(),
                params_kdf.m_cost as i64,
                params_kdf.t_cost as i64,
                params_kdf.p_cost as i64,
                wrapped.to_bytes(),
                now,
            ],
        )?;
        Ok(dek)
    }

    pub fn exists(path: &str) -> bool {
        std::path::Path::new(path).exists()
    }

    pub fn unlock(&self, master_password: &str) -> Result<[u8; 32], VaultError> {
        let row = self
            .conn
            .query_row(
                "SELECT kdf_salt, kdf_m, kdf_t, kdf_p, wrapped_data_key FROM vault_meta WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(VaultError::NotInitialized)?;
        let mut salt = [0u8; 16];
        if row.0.len() != 16 {
            return Err(VaultError::NotInitialized);
        }
        salt.copy_from_slice(&row.0);
        let params_kdf = ArgonParams {
            salt,
            m_cost: row.1 as u32,
            t_cost: row.2 as u32,
            p_cost: row.3 as u32,
        };
        let kek = derive_kek(master_password, &params_kdf)?;
        let enc = Encrypted::from_bytes(&row.4)?;
        unwrap_key(&kek, &enc).map_err(|_| VaultError::BadPassword)
    }

    pub fn change_master_password(
        &self,
        dek: &[u8; 32],
        old_password: &str,
        new_password: &str,
    ) -> Result<(), VaultError> {
        let current = self.unlock(old_password)?;
        if &current != dek {
            return Err(VaultError::BadPassword);
        }
        if new_password.chars().count() < 10 {
            return Err(VaultError::PasswordTooShort);
        }
        let params_kdf = ArgonParams::default();
        let kek = derive_kek(new_password, &params_kdf)?;
        let wrapped = wrap_key(&kek, dek)?;
        self.conn.execute(
            "UPDATE vault_meta SET kdf_salt=?1, kdf_m=?2, kdf_t=?3, kdf_p=?4, wrapped_data_key=?5, updated_at=?6 WHERE id=1",
            params![
                params_kdf.salt.as_slice(),
                params_kdf.m_cost as i64,
                params_kdf.t_cost as i64,
                params_kdf.p_cost as i64,
                wrapped.to_bytes(),
                now_rfc3339(),
            ],
        )?;
        self.audit("change_master", None, "ok")?;
        Ok(())
    }

    pub fn upsert_entry(&self, dek: &[u8; 32], input: UpsertEntry) -> Result<EntryDto, VaultError> {
        let id = input
            .id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = now_rfc3339();
        let (has_totp, fingerprint, account, url) = match &input.secret {
            SecretPayload::Website {
                url,
                username,
                totp_secret,
                ..
            } => (
                totp_secret.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
                None,
                username.clone().or(input.account.clone()),
                url.clone().or(input.url.clone()),
            ),
            SecretPayload::ApiToken { account, .. } => {
                (false, None, account.clone().or(input.account.clone()), None)
            }
            SecretPayload::Ssh {
                public_fingerprint, ..
            } => (
                false,
                public_fingerprint.clone(),
                input.account.clone(),
                None,
            ),
        };
        let secret_json = serde_json::to_vec(&input.secret)?;
        let secret_blob = encrypt(dek, &secret_json)?.to_bytes();
        let notes_blob = match &input.notes {
            Some(n) if !n.is_empty() => Some(encrypt(dek, n.as_bytes())?.to_bytes()),
            _ => None,
        };

        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT created_at FROM entries WHERE id=?1",
                params![&id],
                |r| r.get(0),
            )
            .optional()?;
        let created_at = existing.unwrap_or_else(|| now.clone());

        self.conn.execute(
            "INSERT INTO entries (
                id, kind, title, account, url, folder_id, pinned, expires_at,
                use_count, last_used_at, created_at, updated_at, deleted_at,
                has_totp, fingerprint, secret_blob, notes_blob
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0,NULL,?9,?10,NULL,?11,?12,?13,?14)
            ON CONFLICT(id) DO UPDATE SET
                kind=excluded.kind,
                title=excluded.title,
                account=excluded.account,
                url=excluded.url,
                folder_id=excluded.folder_id,
                pinned=excluded.pinned,
                expires_at=excluded.expires_at,
                updated_at=excluded.updated_at,
                has_totp=excluded.has_totp,
                fingerprint=excluded.fingerprint,
                secret_blob=excluded.secret_blob,
                notes_blob=excluded.notes_blob,
                deleted_at=NULL
            ",
            params![
                &id,
                input.kind.as_str(),
                &input.title,
                &account,
                &url,
                &input.folder_id,
                input.pinned as i64,
                &input.expires_at,
                &created_at,
                &now,
                has_totp as i64,
                &fingerprint,
                secret_blob,
                notes_blob,
            ],
        )?;
        self.conn
            .execute("DELETE FROM entry_tags WHERE entry_id=?1", params![&id])?;
        for tag in &input.tags {
            let tag_id = self.ensure_tag(tag)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1,?2)",
                params![&id, &tag_id],
            )?;
        }
        let action = if input.id.is_some() {
            "update"
        } else {
            "create"
        };
        self.audit(action, Some(&id), &format!("{} {}", input.kind.as_str(), input.title))?;
        self.get_dto(&id)
    }

    pub fn get_secret(&self, dek: &[u8; 32], id: &str) -> Result<SecretPayload, VaultError> {
        let blob: Vec<u8> = self
            .conn
            .query_row(
                "SELECT secret_blob FROM entries WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(VaultError::NotFound)?;
        let enc = Encrypted::from_bytes(&blob)?;
        let json = decrypt(dek, &enc)?;
        Ok(serde_json::from_slice(&json)?)
    }

    pub fn get_notes(&self, dek: &[u8; 32], id: &str) -> Result<Option<String>, VaultError> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT notes_blob FROM entries WHERE id=?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(VaultError::NotFound)?;
        match blob {
            Some(b) => {
                let enc = Encrypted::from_bytes(&b)?;
                let bytes = decrypt(dek, &enc)?;
                Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
            }
            None => Ok(None),
        }
    }

    pub fn list_entries(&self, filter: &ListFilter) -> Result<Vec<EntryDto>, VaultError> {
        let mut sql = String::from(
            "SELECT e.id, e.kind, e.title, e.account, e.url, e.folder_id, e.pinned,
                    e.expires_at, e.use_count, e.last_used_at, e.updated_at, e.has_totp, e.fingerprint
             FROM entries e",
        );
        if filter.tag.is_some() {
            sql.push_str(" JOIN entry_tags et ON et.entry_id = e.id JOIN tags t ON t.id = et.tag_id");
        }
        sql.push_str(" WHERE ");
        if filter.trash {
            sql.push_str("e.deleted_at IS NOT NULL");
        } else {
            sql.push_str("e.deleted_at IS NULL");
        }
        if filter.kind.is_some() {
            sql.push_str(" AND e.kind = ?");
        }
        if filter.uncategorized {
            sql.push_str(" AND e.folder_id IS NULL");
        } else if filter.folder_id.is_some() {
            sql.push_str(" AND e.folder_id = ?");
        }
        if filter.tag.is_some() {
            sql.push_str(" AND t.name = ?");
        }
        if filter.query.as_ref().map(|q| !q.is_empty()).unwrap_or(false) {
            sql.push_str(
                " AND (e.title LIKE ? OR IFNULL(e.account,'') LIKE ? OR IFNULL(e.url,'') LIKE ?
                       OR e.id IN (
                         SELECT et2.entry_id FROM entry_tags et2 JOIN tags t2 ON t2.id=et2.tag_id WHERE t2.name LIKE ?
                       )
                       OR e.folder_id IN (SELECT id FROM folders WHERE name LIKE ?)
                      )",
            );
        }
        sql.push_str(" ORDER BY e.pinned DESC, ");
        sql.push_str(match filter.sort {
            SortBy::UseCount => "e.use_count DESC, e.updated_at DESC",
            SortBy::Updated => "e.updated_at DESC",
            SortBy::Title => "e.title COLLATE NOCASE ASC",
        });

        let mut stmt = self.conn.prepare(&sql)?;
        let mut bind: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(k) = &filter.kind {
            bind.push(Box::new(k.as_str().to_string()));
        }
        if let Some(fid) = &filter.folder_id {
            if !filter.uncategorized {
                bind.push(Box::new(fid.clone()));
            }
        }
        if let Some(tag) = &filter.tag {
            bind.push(Box::new(tag.clone()));
        }
        if let Some(q) = &filter.query {
            if !q.is_empty() {
                let like = format!("%{q}%");
                bind.push(Box::new(like.clone()));
                bind.push(Box::new(like.clone()));
                bind.push(Box::new(like.clone()));
                bind.push(Box::new(like.clone()));
                bind.push(Box::new(like));
            }
        }
        let bind_refs: Vec<&dyn rusqlite::ToSql> = bind.iter().map(|b| b.as_ref()).collect();
        let rows = stmt.query_map(bind_refs.as_slice(), |r| {
            Ok(EntryDto {
                id: r.get(0)?,
                kind: EntryKind::parse(&r.get::<_, String>(1)?).unwrap_or(EntryKind::Website),
                title: r.get(2)?,
                account: r.get(3)?,
                url: r.get(4)?,
                folder_id: r.get(5)?,
                tags: Vec::new(),
                pinned: r.get::<_, i64>(6)? != 0,
                expires_at: r.get(7)?,
                use_count: r.get(8)?,
                last_used_at: r.get(9)?,
                updated_at: r.get(10)?,
                has_totp: r.get::<_, i64>(11)? != 0,
                fingerprint: r.get(12)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            let mut dto = row?;
            dto.tags = self.tags_for(&dto.id)?;
            out.push(dto);
        }
        Ok(out)
    }

    pub fn soft_delete(&self, ids: &[String]) -> Result<usize, VaultError> {
        let now = now_rfc3339();
        let mut n = 0;
        for id in ids {
            n += self.conn.execute(
                "UPDATE entries SET deleted_at=?1, updated_at=?1 WHERE id=?2 AND deleted_at IS NULL",
                params![&now, id],
            )?;
            self.audit("delete", Some(id), "trash")?;
        }
        Ok(n)
    }

    pub fn restore(&self, ids: &[String]) -> Result<usize, VaultError> {
        let mut n = 0;
        let now = now_rfc3339();
        for id in ids {
            n += self.conn.execute(
                "UPDATE entries SET deleted_at=NULL, updated_at=?1 WHERE id=?2 AND deleted_at IS NOT NULL",
                params![&now, id],
            )?;
            self.audit("restore", Some(id), "ok")?;
        }
        Ok(n)
    }

    pub fn purge_expired_trash(&self, now: DateTime<Utc>, retention_days: i64) -> Result<usize, VaultError> {
        let cutoff = (now - Duration::days(retention_days)).to_rfc3339();
        let n = self.conn.execute(
            "DELETE FROM entries WHERE deleted_at IS NOT NULL AND deleted_at <= ?1",
            params![cutoff],
        )?;
        Ok(n)
    }

    pub fn bump_use(&self, id: &str) -> Result<(), VaultError> {
        let now = now_rfc3339();
        self.conn.execute(
            "UPDATE entries SET use_count = use_count + 1, last_used_at=?1 WHERE id=?2",
            params![&now, id],
        )?;
        Ok(())
    }

    pub fn create_folder(&self, name: &str) -> Result<FolderDto, VaultError> {
        let id = Uuid::new_v4().to_string();
        self.conn.execute(
            "INSERT INTO folders (id, name, parent_id) VALUES (?1,?2,NULL)",
            params![&id, name],
        )?;
        Ok(FolderDto {
            id,
            name: name.to_string(),
        })
    }

    pub fn list_folders(&self) -> Result<Vec<FolderDto>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name FROM folders ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok(FolderDto {
                id: r.get(0)?,
                name: r.get(1)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn list_tags(&self) -> Result<Vec<String>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT name FROM tags ORDER BY name")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn list_audit(&self, limit: i64) -> Result<Vec<AuditEvent>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, at, action, entry_id, detail FROM audit_events ORDER BY at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok(AuditEvent {
                id: r.get(0)?,
                at: r.get(1)?,
                action: r.get(2)?,
                entry_id: r.get(3)?,
                detail: r.get(4)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn audit(&self, action: &str, entry_id: Option<&str>, detail: &str) -> Result<(), VaultError> {
        self.conn.execute(
            "INSERT INTO audit_events (id, at, action, entry_id, detail) VALUES (?1,?2,?3,?4,?5)",
            params![
                Uuid::new_v4().to_string(),
                now_rfc3339(),
                action,
                entry_id,
                detail
            ],
        )?;
        Ok(())
    }

    pub fn hello_enabled(&self) -> Result<bool, VaultError> {
        let v: i64 = self
            .conn
            .query_row("SELECT hello_enabled FROM vault_meta WHERE id=1", [], |r| {
                r.get(0)
            })?;
        Ok(v != 0)
    }

    pub fn set_hello(
        &self,
        dek: &[u8; 32],
        hello_key: Option<&[u8; 32]>,
    ) -> Result<(), VaultError> {
        match hello_key {
            Some(key) => {
                let wrapped = wrap_key(key, dek)?.to_bytes();
                self.conn.execute(
                    "UPDATE vault_meta SET hello_enabled=1, wrapped_dek_hello=?1, updated_at=?2 WHERE id=1",
                    params![wrapped, now_rfc3339()],
                )?;
            }
            None => {
                self.conn.execute(
                    "UPDATE vault_meta SET hello_enabled=0, wrapped_dek_hello=NULL, updated_at=?1 WHERE id=1",
                    params![now_rfc3339()],
                )?;
            }
        }
        Ok(())
    }

    pub fn unlock_with_hello_key(&self, hello_key: &[u8; 32]) -> Result<[u8; 32], VaultError> {
        let blob: Option<Vec<u8>> = self.conn.query_row(
            "SELECT wrapped_dek_hello FROM vault_meta WHERE id=1 AND hello_enabled=1",
            [],
            |r| r.get(0),
        )?;
        let blob = blob.ok_or(VaultError::BadPassword)?;
        let enc = Encrypted::from_bytes(&blob)?;
        unwrap_key(hello_key, &enc).map_err(|_| VaultError::BadPassword)
    }

    pub fn snapshot_for_backup(&self) -> Result<BackupSnapshot, VaultError> {
        let folders = self.list_folders()?;
        let tags = self.list_tags()?;
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, title, account, url, folder_id, pinned, expires_at,
                    use_count, last_used_at, created_at, updated_at, deleted_at,
                    has_totp, fingerprint, secret_blob, notes_blob FROM entries",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(BackupEntry {
                id: r.get(0)?,
                kind: r.get(1)?,
                title: r.get(2)?,
                account: r.get(3)?,
                url: r.get(4)?,
                folder_id: r.get(5)?,
                pinned: r.get::<_, i64>(6)? != 0,
                expires_at: r.get(7)?,
                use_count: r.get(8)?,
                last_used_at: r.get(9)?,
                created_at: r.get(10)?,
                updated_at: r.get(11)?,
                deleted_at: r.get(12)?,
                has_totp: r.get::<_, i64>(13)? != 0,
                fingerprint: r.get(14)?,
                secret_blob: r.get(15)?,
                notes_blob: r.get(16)?,
                tags: Vec::new(),
            })
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let mut e = row?;
            e.tags = self.tags_for(&e.id)?;
            entries.push(e);
        }
        Ok(BackupSnapshot {
            folders,
            tags,
            entries,
        })
    }

    pub fn insert_reencrypted_entry(
        &self,
        source_dek: &[u8; 32],
        dest_dek: &[u8; 32],
        entry: &BackupEntry,
        overwrite: bool,
    ) -> Result<bool, VaultError> {
        let exists: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM entries WHERE id=?1",
                params![&entry.id],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_some() && !overwrite {
            return Ok(false);
        }
        let secret = decrypt(source_dek, &Encrypted::from_bytes(&entry.secret_blob)?)?;
        let new_secret = encrypt(dest_dek, &secret)?.to_bytes();
        let new_notes = match &entry.notes_blob {
            Some(b) => {
                let n = decrypt(source_dek, &Encrypted::from_bytes(b)?)?;
                Some(encrypt(dest_dek, &n)?.to_bytes())
            }
            None => None,
        };
        self.conn.execute(
            "INSERT INTO entries (
                id, kind, title, account, url, folder_id, pinned, expires_at,
                use_count, last_used_at, created_at, updated_at, deleted_at,
                has_totp, fingerprint, secret_blob, notes_blob
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)
            ON CONFLICT(id) DO UPDATE SET
                kind=excluded.kind, title=excluded.title, account=excluded.account,
                url=excluded.url, folder_id=excluded.folder_id, pinned=excluded.pinned,
                expires_at=excluded.expires_at, use_count=excluded.use_count,
                last_used_at=excluded.last_used_at, updated_at=excluded.updated_at,
                deleted_at=excluded.deleted_at, has_totp=excluded.has_totp,
                fingerprint=excluded.fingerprint, secret_blob=excluded.secret_blob,
                notes_blob=excluded.notes_blob",
            params![
                &entry.id,
                &entry.kind,
                &entry.title,
                &entry.account,
                &entry.url,
                &entry.folder_id,
                entry.pinned as i64,
                &entry.expires_at,
                entry.use_count,
                &entry.last_used_at,
                &entry.created_at,
                &entry.updated_at,
                &entry.deleted_at,
                entry.has_totp as i64,
                &entry.fingerprint,
                new_secret,
                new_notes,
            ],
        )?;
        self.conn
            .execute("DELETE FROM entry_tags WHERE entry_id=?1", params![&entry.id])?;
        for tag in &entry.tags {
            let tag_id = self.ensure_tag(tag)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1,?2)",
                params![&entry.id, &tag_id],
            )?;
        }
        Ok(true)
    }

    pub fn ensure_folder_named(&self, name: &str) -> Result<String, VaultError> {
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM folders WHERE name=?1",
                params![name],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            return Ok(id);
        }
        Ok(self.create_folder(name)?.id)
    }

    fn ensure_tag(&self, name: &str) -> Result<String, VaultError> {
        let existing: Option<String> = self
            .conn
            .query_row("SELECT id FROM tags WHERE name=?1", params![name], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(id) = existing {
            return Ok(id);
        }
        let id = Uuid::new_v4().to_string();
        self.conn
            .execute("INSERT INTO tags (id, name) VALUES (?1,?2)", params![&id, name])?;
        Ok(id)
    }

    fn tags_for(&self, entry_id: &str) -> Result<Vec<String>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT t.name FROM tags t JOIN entry_tags et ON et.tag_id=t.id WHERE et.entry_id=?1 ORDER BY t.name",
        )?;
        let rows = stmt.query_map(params![entry_id], |r| r.get::<_, String>(0))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    fn get_dto(&self, id: &str) -> Result<EntryDto, VaultError> {
        let mut dto = self.conn.query_row(
            "SELECT id, kind, title, account, url, folder_id, pinned, expires_at,
                    use_count, last_used_at, updated_at, has_totp, fingerprint
             FROM entries WHERE id=?1",
            params![id],
            |r| {
                Ok(EntryDto {
                    id: r.get(0)?,
                    kind: EntryKind::parse(&r.get::<_, String>(1)?).unwrap_or(EntryKind::Website),
                    title: r.get(2)?,
                    account: r.get(3)?,
                    url: r.get(4)?,
                    folder_id: r.get(5)?,
                    tags: Vec::new(),
                    pinned: r.get::<_, i64>(6)? != 0,
                    expires_at: r.get(7)?,
                    use_count: r.get(8)?,
                    last_used_at: r.get(9)?,
                    updated_at: r.get(10)?,
                    has_totp: r.get::<_, i64>(11)? != 0,
                    fingerprint: r.get(12)?,
                })
            },
        )?;
        dto.tags = self.tags_for(id)?;
        Ok(dto)
    }

    pub fn counts(&self) -> Result<Counts, VaultError> {
        let total: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE deleted_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        let website: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE deleted_at IS NULL AND kind='website'",
            [],
            |r| r.get(0),
        )?;
        let api_token: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE deleted_at IS NULL AND kind='api_token'",
            [],
            |r| r.get(0),
        )?;
        let ssh: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE deleted_at IS NULL AND kind='ssh'",
            [],
            |r| r.get(0),
        )?;
        let trash: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE deleted_at IS NOT NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(Counts {
            total,
            website,
            api_token,
            ssh,
            trash,
        })
    }

    pub fn recent_entries(&self, limit: i64) -> Result<Vec<EntryDto>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM entries WHERE deleted_at IS NULL AND last_used_at IS NOT NULL
             ORDER BY last_used_at DESC LIMIT ?1",
        )?;
        let ids: Vec<String> = stmt
            .query_map(params![limit], |r| r.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        ids.into_iter().map(|id| self.get_dto(&id)).collect()
    }

    pub fn expiring_entries(&self, within_days: i64) -> Result<Vec<EntryDto>, VaultError> {
        let until = (Utc::now() + Duration::days(within_days)).to_rfc3339();
        let mut stmt = self.conn.prepare(
            "SELECT id FROM entries WHERE deleted_at IS NULL AND expires_at IS NOT NULL
             AND expires_at <= ?1 ORDER BY expires_at ASC LIMIT 20",
        )?;
        let ids: Vec<String> = stmt
            .query_map(params![until], |r| r.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        ids.into_iter().map(|id| self.get_dto(&id)).collect()
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>, VaultError> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key=?1",
                params![key],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), VaultError> {
        self.conn.execute(
            "INSERT INTO settings(key, value) VALUES(?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counts {
    pub total: i64,
    pub website: i64,
    pub api_token: i64,
    pub ssh: i64,
    pub trash: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupSnapshot {
    pub folders: Vec<FolderDto>,
    pub tags: Vec<String>,
    pub entries: Vec<BackupEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupEntry {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub account: Option<String>,
    pub url: Option<String>,
    pub folder_id: Option<String>,
    pub pinned: bool,
    pub expires_at: Option<String>,
    pub use_count: i64,
    pub last_used_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
    pub has_totp: bool,
    pub fingerprint: Option<String>,
    pub secret_blob: Vec<u8>,
    pub notes_blob: Option<Vec<u8>>,
    pub tags: Vec<String>,
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}
