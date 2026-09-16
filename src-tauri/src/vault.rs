use crate::crypto::{
    decrypt, derive_kek, encrypt, random_key, unwrap_key, wrap_key, ArgonParams, Encrypted,
};
use crate::db;
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    #[error("金库已锁定")]
    Locked,
    #[error("master password incorrect")]
    BadPassword,
    #[error("entry not found")]
    NotFound,
    #[error("invalid kind")]
    InvalidKind,
    #[error("master password too short")]
    PasswordTooShort,
    #[error("备份文件损坏或格式不正确")]
    CorruptBackup,
    #[error("备份密钥拉伸参数超出允许范围")]
    InvalidBackupKdf,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Website,
    ApiToken,
    Ssh,
    Mailbox,
    MailAuth,
    Server,
    Database,
}

impl EntryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Website => "website",
            Self::ApiToken => "api_token",
            Self::Ssh => "ssh",
            Self::Mailbox => "mailbox",
            Self::MailAuth => "mail_auth",
            Self::Server => "server",
            Self::Database => "database",
        }
    }

    pub fn parse(s: &str) -> Result<Self, VaultError> {
        match s {
            "website" => Ok(Self::Website),
            "api_token" => Ok(Self::ApiToken),
            "ssh" => Ok(Self::Ssh),
            "mailbox" => Ok(Self::Mailbox),
            "mail_auth" => Ok(Self::MailAuth),
            "server" => Ok(Self::Server),
            "database" => Ok(Self::Database),
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
#[serde(default)]
pub struct ListFilter {
    pub query: Option<String>,
    pub kind: Option<EntryKind>,
    #[serde(default)]
    pub kinds: Vec<EntryKind>,
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
            kinds: Vec::new(),
            folder_id: None,
            uncategorized: false,
            tag: None,
            trash: false,
            sort: SortBy::UseCount,
        }
    }
}

impl ListFilter {
    pub fn selected_kinds(&self) -> Vec<EntryKind> {
        let mut out = self.kinds.clone();
        if let Some(kind) = &self.kind {
            if !out.iter().any(|item| item == kind) {
                out.push(kind.clone());
            }
        }
        out
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortBy {
    #[default]
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
    Mailbox {
        email: String,
        password: String,
        imap_host: Option<String>,
        imap_port: Option<u16>,
        smtp_host: Option<String>,
        smtp_port: Option<u16>,
    },
    MailAuth {
        email: String,
        provider: String,
        auth_code: String,
    },
    Server {
        host: String,
        port: Option<u16>,
        protocol: String,
        username: String,
        password: String,
    },
    Database {
        engine: String,
        host: String,
        port: Option<u16>,
        database: String,
        username: String,
        password: String,
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
        if Self::is_initialized(path) {
            return Err(VaultError::AlreadyExists);
        }
        remove_db_files(path);
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
        if !std::path::Path::new(path).exists() {
            return Err(VaultError::NotInitialized);
        }
        let conn = match db::open_existing(path) {
            Ok(conn) => conn,
            Err(_) if !std::path::Path::new(path).exists() => {
                return Err(VaultError::NotInitialized);
            }
            Err(e) => return Err(e.into()),
        };
        let vault = Self { conn };
        if !vault.has_meta() {
            return Err(VaultError::NotInitialized);
        }
        Ok(vault)
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

    pub fn is_initialized(path: &str) -> bool {
        if !std::path::Path::new(path).exists() {
            return false;
        }
        match Self::open(path) {
            Ok(_) => true,
            Err(VaultError::NotInitialized) => false,
            Err(_) => true,
        }
    }

    fn has_meta(&self) -> bool {
        self.conn
            .query_row("SELECT 1 FROM vault_meta WHERE id = 1", [], |_| Ok(()))
            .optional()
            .ok()
            .flatten()
            .is_some()
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
            SecretPayload::ApiToken { account, .. } => (
                false,
                None,
                account.clone().or(input.account.clone()),
                input.url.clone(),
            ),
            SecretPayload::Ssh {
                public_fingerprint, ..
            } => (
                false,
                public_fingerprint.clone(),
                input.account.clone(),
                None,
            ),
            SecretPayload::Mailbox {
                email,
                imap_host,
                smtp_host,
                ..
            } => {
                let host = imap_host.clone().or(smtp_host.clone());
                (false, None, Some(email.clone()), host)
            }
            SecretPayload::MailAuth { email, .. } => (false, None, Some(email.clone()), None),
            SecretPayload::Server {
                host,
                username,
                port,
                protocol,
                ..
            } => {
                let loc = match port {
                    Some(p) => format!("{protocol}://{host}:{p}"),
                    None => format!("{protocol}://{host}"),
                };
                (false, None, Some(username.clone()), Some(loc))
            }
            SecretPayload::Database {
                engine,
                host,
                port,
                database,
                username,
                ..
            } => {
                let loc = match (host.is_empty(), port, database.is_empty()) {
                    (true, _, false) => format!("{engine}:{database}"),
                    (true, _, true) => engine.clone(),
                    (false, Some(p), false) => format!("{engine}://{host}:{p}/{database}"),
                    (false, Some(p), true) => format!("{engine}://{host}:{p}"),
                    (false, None, false) => format!("{engine}://{host}/{database}"),
                    (false, None, true) => format!("{engine}://{host}"),
                };
                (
                    false,
                    Some(engine.clone()),
                    Some(username.clone()),
                    Some(loc),
                )
            }
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
        self.audit(
            action,
            Some(&id),
            &format!("{} {}", input.kind.as_str(), input.title),
        )?;
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

    fn list_from_sql(&self, select: &str) -> String {
        let mut sql = String::from(select);
        sql.push_str(" FROM entries e");
        sql
    }

    fn apply_list_scope(
        &self,
        sql: &mut String,
        bind: &mut Vec<Box<dyn rusqlite::ToSql>>,
        filter: &ListFilter,
        kinds: &[EntryKind],
    ) {
        if filter.tag.is_some() {
            sql.push_str(
                " JOIN entry_tags et ON et.entry_id = e.id JOIN tags t ON t.id = et.tag_id",
            );
        }
        sql.push_str(" WHERE ");
        if filter.trash {
            sql.push_str("e.deleted_at IS NOT NULL");
        } else {
            sql.push_str("e.deleted_at IS NULL");
        }
        if kinds.len() == 1 {
            sql.push_str(" AND e.kind = ?");
        } else if kinds.len() > 1 {
            sql.push_str(" AND e.kind IN (");
            sql.push_str(&vec!["?"; kinds.len()].join(","));
            sql.push(')');
        }
        for kind in kinds {
            bind.push(Box::new(kind.as_str().to_string()));
        }
        if filter.uncategorized {
            sql.push_str(" AND e.folder_id IS NULL");
        } else if filter.folder_id.is_some() {
            sql.push_str(" AND e.folder_id = ?");
        }
        if let Some(fid) = &filter.folder_id {
            if !filter.uncategorized {
                bind.push(Box::new(fid.clone()));
            }
        }
        if filter.tag.is_some() {
            sql.push_str(" AND t.name = ?");
        }
        if let Some(tag) = &filter.tag {
            bind.push(Box::new(tag.clone()));
        }
        if filter
            .query
            .as_ref()
            .map(|q| !q.is_empty())
            .unwrap_or(false)
        {
            sql.push_str(
                " AND (e.title LIKE ? OR IFNULL(e.account,'') LIKE ? OR IFNULL(e.url,'') LIKE ?
                       OR e.id IN (
                         SELECT et2.entry_id FROM entry_tags et2 JOIN tags t2 ON t2.id=et2.tag_id WHERE t2.name LIKE ?
                       )
                       OR e.folder_id IN (SELECT id FROM folders WHERE name LIKE ?)
                      )",
            );
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
    }

    pub fn list_entries(&self, filter: &ListFilter) -> Result<Vec<EntryDto>, VaultError> {
        let kinds = filter.selected_kinds();
        let mut sql = self.list_from_sql(
            "SELECT e.id, e.kind, e.title, e.account, e.url, e.folder_id, e.pinned,
                    e.expires_at, e.use_count, e.last_used_at, e.updated_at, e.has_totp, e.fingerprint",
        );
        let mut bind: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        self.apply_list_scope(&mut sql, &mut bind, filter, &kinds);
        sql.push_str(" ORDER BY e.pinned DESC, ");
        sql.push_str(match filter.sort {
            SortBy::UseCount => "e.use_count DESC, e.updated_at DESC",
            SortBy::Updated => "e.updated_at DESC",
            SortBy::Title => "e.title COLLATE NOCASE ASC",
        });

        let mut stmt = self.conn.prepare(&sql)?;
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

    pub fn empty_trash(&self) -> Result<usize, VaultError> {
        let n = self
            .conn
            .execute("DELETE FROM entries WHERE deleted_at IS NOT NULL", [])?;
        self.audit("empty_trash", None, &format!("purged={n}"))?;
        Ok(n)
    }

    pub fn set_pinned(&self, id: &str, pinned: bool) -> Result<(), VaultError> {
        self.conn.execute(
            "UPDATE entries SET pinned=?1, updated_at=?2 WHERE id=?3",
            params![pinned as i64, now_rfc3339(), id],
        )?;
        Ok(())
    }

    pub fn purge_expired_trash(
        &self,
        now: DateTime<Utc>,
        retention_days: i64,
    ) -> Result<usize, VaultError> {
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
        let mut stmt = self.conn.prepare("SELECT name FROM tags ORDER BY name")?;
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

    pub fn audit(
        &self,
        action: &str,
        entry_id: Option<&str>,
        detail: &str,
    ) -> Result<(), VaultError> {
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
        let v: i64 =
            self.conn
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

    fn insert_reencrypted_entry(
        &self,
        source_dek: &[u8; 32],
        dest_dek: &[u8; 32],
        entry: &BackupEntry,
        folder_id: Option<&str>,
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
                folder_id,
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
        self.conn.execute(
            "DELETE FROM entry_tags WHERE entry_id=?1",
            params![&entry.id],
        )?;
        for tag in &entry.tags {
            let tag_id = self.ensure_tag(tag)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1,?2)",
                params![&entry.id, &tag_id],
            )?;
        }
        Ok(true)
    }

    pub fn import_reencrypted_snapshot(
        &self,
        source_dek: &[u8; 32],
        dest_dek: &[u8; 32],
        snapshot: &BackupSnapshot,
        overwrite: bool,
    ) -> Result<(usize, usize), VaultError> {
        struct TxGuard<'a> {
            conn: &'a Connection,
            finished: bool,
        }
        impl Drop for TxGuard<'_> {
            fn drop(&mut self) {
                if !self.finished {
                    let _ = self.conn.execute_batch("ROLLBACK");
                }
            }
        }

        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let mut tx = TxGuard {
            conn: &self.conn,
            finished: false,
        };

        let mut folder_map = HashMap::new();
        for folder in &snapshot.folders {
            let dest_id = self.ensure_folder_named(&folder.name)?;
            folder_map.insert(folder.id.clone(), dest_id);
        }

        let mut imported = 0usize;
        let mut skipped = 0usize;
        for entry in &snapshot.entries {
            let folder_id = entry
                .folder_id
                .as_ref()
                .and_then(|id| folder_map.get(id).map(String::as_str));
            match self.insert_reencrypted_entry(source_dek, dest_dek, entry, folder_id, overwrite) {
                Ok(true) => imported += 1,
                Ok(false) => skipped += 1,
                Err(VaultError::Crypto(_) | VaultError::Json(_)) => {
                    return Err(VaultError::CorruptBackup);
                }
                Err(e) => return Err(e),
            }
        }
        self.audit(
            "import",
            None,
            &format!("imported={imported} skipped={skipped} overwrite={overwrite}"),
        )?;
        self.conn.execute_batch("COMMIT")?;
        tx.finished = true;
        Ok((imported, skipped))
    }

    fn ensure_folder_named(&self, name: &str) -> Result<String, VaultError> {
        let existing: Option<String> = self
            .conn
            .query_row("SELECT id FROM folders WHERE name=?1", params![name], |r| {
                r.get(0)
            })
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
        self.conn.execute(
            "INSERT INTO tags (id, name) VALUES (?1,?2)",
            params![&id, name],
        )?;
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
        self.counts_for(&ListFilter::default())
    }

    pub fn counts_for(&self, filter: &ListFilter) -> Result<Counts, VaultError> {
        let mut scoped = filter.clone();
        scoped.kind = None;
        scoped.kinds.clear();
        let mut sql = self.list_from_sql("SELECT e.kind, COUNT(*)");
        let mut bind: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        self.apply_list_scope(&mut sql, &mut bind, &scoped, &[]);
        sql.push_str(" GROUP BY e.kind");

        let mut stmt = self.conn.prepare(&sql)?;
        let bind_refs: Vec<&dyn rusqlite::ToSql> = bind.iter().map(|b| b.as_ref()).collect();
        let rows = stmt.query_map(bind_refs.as_slice(), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        let mut counts = Counts::default();
        for row in rows {
            let (kind, n) = row?;
            match kind.as_str() {
                "website" => counts.website = n,
                "api_token" => counts.api_token = n,
                "ssh" => counts.ssh = n,
                "mailbox" => counts.mailbox = n,
                "mail_auth" => counts.mail_auth = n,
                "server" => counts.server = n,
                "database" => counts.database = n,
                _ => {}
            }
            counts.total += n;
        }
        counts.trash = self.conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE deleted_at IS NOT NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(counts)
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

    fn looks_like_encrypted_setting(value: &str) -> bool {
        hex::decode(value)
            .ok()
            .and_then(|bytes| Encrypted::from_bytes(&bytes).ok())
            .is_some()
    }

    fn decrypt_setting_value(&self, dek: &[u8; 32], value: &str) -> Result<String, VaultError> {
        let bytes = hex::decode(value)
            .map_err(|_| VaultError::Crypto(crate::crypto::CryptoError::Truncated))?;
        let enc = Encrypted::from_bytes(&bytes)?;
        let plain = decrypt(dek, &enc)?;
        String::from_utf8(plain)
            .map_err(|_| VaultError::Crypto(crate::crypto::CryptoError::Decrypt))
    }

    pub fn get_secret_setting(
        &self,
        dek: &[u8; 32],
        key: &str,
    ) -> Result<Option<String>, VaultError> {
        let enc_key = format!("{key}_enc");
        if let Some(value) = self.get_setting(&enc_key)? {
            if let Ok(plain) = self.decrypt_setting_value(dek, &value) {
                if !plain.is_empty() {
                    let _ = self
                        .conn
                        .execute("DELETE FROM settings WHERE key=?1", params![key]);
                    return Ok(Some(plain));
                }
            }
        }
        let Some(legacy) = self.get_setting(key)? else {
            return Ok(None);
        };
        if legacy.is_empty() {
            return Ok(None);
        }
        if Self::looks_like_encrypted_setting(&legacy) {
            if let Ok(plain) = self.decrypt_setting_value(dek, &legacy) {
                if !plain.is_empty() {
                    self.set_secret_setting(dek, key, &plain)?;
                    return Ok(Some(plain));
                }
            }
            return Ok(None);
        }
        self.set_secret_setting(dek, key, &legacy)?;
        Ok(Some(legacy))
    }

    pub fn set_secret_setting(
        &self,
        dek: &[u8; 32],
        key: &str,
        value: &str,
    ) -> Result<(), VaultError> {
        let enc = encrypt(dek, value.as_bytes())?;
        self.set_setting(&format!("{key}_enc"), &hex::encode(enc.to_bytes()))?;
        self.conn
            .execute("DELETE FROM settings WHERE key=?1", params![key])?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counts {
    pub total: i64,
    pub website: i64,
    pub api_token: i64,
    pub ssh: i64,
    pub mailbox: i64,
    pub mail_auth: i64,
    pub server: i64,
    pub database: i64,
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

fn remove_db_files(path: &str) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let _ = std::fs::remove_file(format!("{path}{suffix}"));
    }
}
