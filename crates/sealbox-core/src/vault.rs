use crate::certificate;
use crate::crypto::{
    decrypt, derive_kek, encrypt, random_key, unwrap_key, wrap_key, ArgonParams, Encrypted,
};
use crate::db;
use chrono::{DateTime, Duration, Utc};
use rusqlite::types::Type;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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
    #[error("entry kind and secret payload do not match")]
    KindMismatch,
    #[error("certificate: {0}")]
    Certificate(#[from] certificate::CertificateError),
    #[error("master password too short")]
    PasswordTooShort,
    #[error("{0}")]
    InvalidTotp(String),
    #[error("备份文件损坏或格式不正确")]
    CorruptBackup,
    #[error("备份密钥拉伸参数超出允许范围")]
    InvalidBackupKdf,
    #[error("文件夹名称不能为空")]
    FolderNameEmpty,
    #[error("文件夹已存在")]
    FolderAlreadyExists,
    #[error("文件夹不存在")]
    FolderNotFound,
    #[error("标签名称不能为空")]
    TagNameEmpty,
    #[error("标签已存在")]
    TagAlreadyExists,
    #[error("标签不存在")]
    TagNotFound,
    #[error("已有同站同账号条目，请选择“仍然新建”后重试")]
    DuplicateWebsite,
    #[error("来源和目标不能相同")]
    SameOrganizationTarget,
    #[error("审计查询参数无效：分页须为 1–100 条、非负偏移，日期须为有效且递增的 RFC3339 时间")]
    InvalidAuditQuery,
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
    ClientCert,
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
            Self::ClientCert => "client_cert",
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
            "client_cert" => Ok(Self::ClientCert),
            _ => Err(VaultError::InvalidKind),
        }
    }
}

impl SecretPayload {
    pub fn kind(&self) -> EntryKind {
        match self {
            Self::Website { .. } => EntryKind::Website,
            Self::ApiToken { .. } => EntryKind::ApiToken,
            Self::Ssh { .. } => EntryKind::Ssh,
            Self::Mailbox { .. } => EntryKind::Mailbox,
            Self::MailAuth { .. } => EntryKind::MailAuth,
            Self::Server { .. } => EntryKind::Server,
            Self::Database { .. } => EntryKind::Database,
            Self::ClientCert { .. } => EntryKind::ClientCert,
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
pub struct EntryField {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntryProfile {
    pub entry: EntryDto,
    pub notes: Option<String>,
    pub fields: Vec<EntryField>,
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
    /// 客户端证书（mTLS）。私钥随证书一起加密存放，不落磁盘明文。
    ClientCert {
        cert_pem: String,
        key_pem: String,
        passphrase: Option<String>,
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
                wrapped_data_key, created_at, updated_at
            ) VALUES (1, 1, ?1, ?2, ?3, ?4, ?5, ?6, ?6)",
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

    /// True only when this path holds a vault that can be opened.
    ///
    /// Setup and unlock both trust this answer. A file that exists but cannot
    /// be opened (locked, corrupt, or not a database) must stay false: treating
    /// it as initialized sends the lock screen down the create path, and
    /// `create` then refuses with "vault already exists".
    pub fn is_initialized(path: &str) -> bool {
        matches!(Self::open(path), Ok(_))
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

    /// Confirms a candidate DEK can open this vault without returning a secret.
    ///
    /// `sync_key_check` is sealed with the sync passphrase, not the vault DEK.
    /// Using it here makes fingerprint unlock fail as soon as sync is saved,
    /// and on an empty vault that is the only ciphertext `dek_matches` sees.
    pub fn dek_matches(&self, dek: &[u8; 32]) -> Result<(), VaultError> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT secret_blob FROM entries ORDER BY id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(blob) = blob {
            decrypt(dek, &Encrypted::from_bytes(&blob)?).map_err(|_| VaultError::BadPassword)?;
        }
        Ok(())
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
        self.upsert_entry_with_duplicate_policy(dek, input, true)
    }

    pub fn upsert_entry_with_duplicate_policy(
        &self,
        dek: &[u8; 32],
        mut input: UpsertEntry,
        allow_duplicate: bool,
    ) -> Result<EntryDto, VaultError> {
        if input.kind != input.secret.kind() {
            return Err(VaultError::KindMismatch);
        }
        input.folder_id = input
            .folder_id
            .and_then(|value| normalize_optional_id(&value));
        self.validate_folder_id(input.folder_id.as_deref())?;
        input.tags = normalize_tag_names(&input.tags);
        if let SecretPayload::Website {
            totp_secret: Some(raw),
            ..
        } = &mut input.secret
        {
            if raw.trim().is_empty() {
                *raw = String::new();
            } else {
                *raw = crate::totp::normalize_totp_secret(raw).map_err(VaultError::InvalidTotp)?;
            }
        }
        if let SecretPayload::Website {
            totp_secret: Some(raw),
            ..
        } = &input.secret
        {
            if raw.is_empty() {
                if let SecretPayload::Website { totp_secret, .. } = &mut input.secret {
                    *totp_secret = None;
                }
            }
        }
        if !allow_duplicate {
            if let SecretPayload::Website { url, username, .. } = &input.secret {
                let candidate_url = url.as_deref().or(input.url.as_deref());
                let candidate_username = username.as_deref().or(input.account.as_deref());
                if let (Some(url), Some(username)) = (candidate_url, candidate_username) {
                    if !self
                        .find_website_duplicates(url, username, input.id.as_deref())?
                        .is_empty()
                    {
                        return Err(VaultError::DuplicateWebsite);
                    }
                }
            }
        }
        let certificate_metadata = if let SecretPayload::ClientCert {
            cert_pem,
            key_pem,
            passphrase,
        } = &mut input.secret
        {
            let (normalized_cert, normalized_key, normalized_passphrase, metadata) =
                certificate::prepare_client_cert(cert_pem, key_pem, passphrase.as_deref())?;
            *cert_pem = normalized_cert;
            *key_pem = normalized_key;
            *passphrase = normalized_passphrase;
            Some(metadata)
        } else {
            None
        };
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
            SecretPayload::ClientCert { .. } => (
                false,
                certificate_metadata
                    .as_ref()
                    .map(|metadata| metadata.fingerprint.clone()),
                input.account.clone(),
                input.url.clone(),
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
        self.audit(
            action,
            Some(&id),
            &format!("{} {}", input.kind.as_str(), input.title),
        )?;
        self.get_dto(&id)
    }

    pub fn find_website_duplicates(
        &self,
        url: &str,
        username: &str,
        exclude_id: Option<&str>,
    ) -> Result<Vec<EntryDto>, VaultError> {
        let Some(key) = crate::identity::website_identity_key(url, username) else {
            return Ok(Vec::new());
        };
        let entries = self.list_entries(&ListFilter {
            kind: Some(EntryKind::Website),
            kinds: vec![EntryKind::Website],
            sort: SortBy::Updated,
            ..Default::default()
        })?;
        Ok(entries
            .into_iter()
            .filter(|entry| exclude_id != Some(entry.id.as_str()))
            .filter(|entry| {
                entry
                    .url
                    .as_deref()
                    .and_then(|stored| {
                        crate::identity::website_identity_key(
                            stored,
                            entry.account.as_deref().unwrap_or(""),
                        )
                    })
                    .as_ref()
                    == Some(&key)
            })
            .collect())
    }

    pub fn get_secret(&self, dek: &[u8; 32], id: &str) -> Result<SecretPayload, VaultError> {
        self.get_secret_with_scope(dek, id, true)
    }

    pub fn get_active_secret(&self, dek: &[u8; 32], id: &str) -> Result<SecretPayload, VaultError> {
        self.get_secret_with_scope(dek, id, true)
    }

    fn get_secret_with_scope(
        &self,
        dek: &[u8; 32],
        id: &str,
        active_only: bool,
    ) -> Result<SecretPayload, VaultError> {
        let sql = if active_only {
            "SELECT kind, secret_blob FROM entries WHERE id=?1 AND deleted_at IS NULL"
        } else {
            "SELECT kind, secret_blob FROM entries WHERE id=?1"
        };
        let (kind_raw, blob): (String, Vec<u8>) = self
            .conn
            .query_row(sql, params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?
            .ok_or(VaultError::NotFound)?;
        let kind = EntryKind::parse(&kind_raw)?;
        let enc = Encrypted::from_bytes(&blob)?;
        let json = decrypt(dek, &enc)?;
        let payload: SecretPayload = serde_json::from_slice(&json)?;
        if payload.kind() != kind {
            return Err(VaultError::KindMismatch);
        }
        Ok(payload)
    }

    pub fn update_entry_metadata(
        &self,
        dek: &[u8; 32],
        id: &str,
        title: &str,
        account: Option<&str>,
        url: Option<&str>,
        folder_id: Option<&str>,
        tags: &[String],
        pinned: bool,
        expires_at: Option<&str>,
        notes: Option<&str>,
    ) -> Result<EntryDto, VaultError> {
        let kind: String = self
            .conn
            .query_row(
                "SELECT kind FROM entries WHERE id=?1 AND deleted_at IS NULL",
                params![id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(VaultError::NotFound)?;
        if EntryKind::parse(&kind)? != EntryKind::ClientCert {
            return Err(VaultError::KindMismatch);
        }
        let folder_id = folder_id.and_then(normalize_optional_id);
        self.validate_folder_id(folder_id.as_deref())?;
        let tags = normalize_tag_names(tags);
        let notes_blob = match notes {
            Some(value) if !value.is_empty() => Some(encrypt(dek, value.as_bytes())?.to_bytes()),
            _ => None,
        };
        let now = now_rfc3339();
        self.conn.execute(
            "UPDATE entries SET title=?1, account=?2, url=?3, folder_id=?4, pinned=?5,
             expires_at=?6, updated_at=?7, notes_blob=?8 WHERE id=?9 AND deleted_at IS NULL",
            params![
                title,
                account,
                url,
                folder_id,
                pinned as i64,
                expires_at,
                &now,
                notes_blob,
                id
            ],
        )?;
        self.conn
            .execute("DELETE FROM entry_tags WHERE entry_id=?1", params![id])?;
        for tag in &tags {
            let tag_id = self.ensure_tag(tag)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1,?2)",
                params![id, tag_id],
            )?;
        }
        self.audit("update", Some(id), &format!("client_cert {title}"))?;
        self.get_dto(id)
    }

    pub fn get_notes(&self, dek: &[u8; 32], id: &str) -> Result<Option<String>, VaultError> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT notes_blob FROM entries WHERE id=?1 AND deleted_at IS NULL",
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
            let kind_raw: String = r.get(1)?;
            let kind = EntryKind::parse(&kind_raw).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid entry kind",
                    )),
                )
            })?;
            Ok(EntryDto {
                id: r.get(0)?,
                kind,
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
        self.with_transaction(|conn| {
            let n: usize = conn.query_row(
                "SELECT COUNT(*) FROM entries WHERE deleted_at IS NOT NULL",
                [],
                |row| row.get::<_, i64>(0),
            )? as usize;
            conn.execute(
                "INSERT INTO sync_tombstones (kind, id, deleted_at)
                 SELECT ?1, id, deleted_at FROM entries WHERE deleted_at IS NOT NULL
                 ON CONFLICT(kind, id) DO UPDATE SET deleted_at=excluded.deleted_at",
                params![TOMBSTONE_ENTRY],
            )?;
            conn.execute(
                "DELETE FROM entry_tags WHERE entry_id IN (
                    SELECT id FROM entries WHERE deleted_at IS NOT NULL
                )",
                [],
            )?;
            conn.execute("DELETE FROM entries WHERE deleted_at IS NOT NULL", [])?;
            cleanup_orphan_tags(conn)?;
            audit_on(conn, "empty_trash", None, &format!("purged={n}"))?;
            Ok(n)
        })
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
        self.with_transaction(|conn| {
            let n: usize = conn.query_row(
                "SELECT COUNT(*) FROM entries WHERE deleted_at IS NOT NULL AND deleted_at <= ?1",
                params![&cutoff],
                |row| row.get::<_, i64>(0),
            )? as usize;
            conn.execute(
                "INSERT INTO sync_tombstones (kind, id, deleted_at)
                 SELECT ?1, id, deleted_at FROM entries
                 WHERE deleted_at IS NOT NULL AND deleted_at <= ?2
                 ON CONFLICT(kind, id) DO UPDATE SET deleted_at=excluded.deleted_at",
                params![TOMBSTONE_ENTRY, &cutoff],
            )?;
            conn.execute(
                "DELETE FROM entry_tags WHERE entry_id IN (
                    SELECT id FROM entries WHERE deleted_at IS NOT NULL AND deleted_at <= ?1
                )",
                params![&cutoff],
            )?;
            conn.execute(
                "DELETE FROM entries WHERE deleted_at IS NOT NULL AND deleted_at <= ?1",
                params![&cutoff],
            )?;
            cleanup_orphan_tags(conn)?;
            Ok(n)
        })
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
        let name = normalize_name(name, true)?;
        self.with_transaction(|conn| {
            if folder_id_by_name(conn, &name)?.is_some() {
                return Err(VaultError::FolderAlreadyExists);
            }
            let folder = insert_folder(conn, &name)?;
            audit_on(conn, "create_folder", None, &format!("{name}"))?;
            Ok(folder)
        })
    }

    pub fn rename_folder(&self, id: &str, name: &str) -> Result<FolderDto, VaultError> {
        let name = normalize_name(name, true)?;
        self.with_transaction(|conn| {
            let current_name: Option<String> = conn
                .query_row("SELECT name FROM folders WHERE id=?1", params![id], |row| {
                    row.get(0)
                })
                .optional()?;
            let current_name = current_name.ok_or(VaultError::FolderNotFound)?;
            if let Some(existing_id) = folder_id_by_name(conn, &name)? {
                if existing_id != id {
                    return Err(VaultError::FolderAlreadyExists);
                }
            }
            conn.execute("UPDATE folders SET name=?1 WHERE id=?2", params![&name, id])?;
            audit_on(
                conn,
                "rename_folder",
                None,
                &format!("{current_name} -> {name}"),
            )?;
            Ok(FolderDto {
                id: id.to_string(),
                name,
            })
        })
    }

    pub fn delete_folder(&self, id: &str) -> Result<usize, VaultError> {
        self.with_transaction(|conn| {
            let name: Option<String> = conn
                .query_row("SELECT name FROM folders WHERE id=?1", params![id], |row| {
                    row.get(0)
                })
                .optional()?;
            let name = name.ok_or(VaultError::FolderNotFound)?;
            let now = now_rfc3339();
            let moved = conn.execute(
                "UPDATE entries SET folder_id=NULL, updated_at=?1 WHERE folder_id=?2",
                params![&now, id],
            )?;
            conn.execute(
                "INSERT INTO sync_tombstones (kind, id, deleted_at) VALUES (?1,?2,?3)
                 ON CONFLICT(kind, id) DO UPDATE SET deleted_at=excluded.deleted_at",
                params![TOMBSTONE_FOLDER, id, &now],
            )?;
            conn.execute("DELETE FROM folders WHERE id=?1", params![id])?;
            audit_on(
                conn,
                "delete_folder",
                None,
                &format!("{name} moved={moved}"),
            )?;
            Ok(moved)
        })
    }

    pub fn merge_folders(&self, source_id: &str, target_id: &str) -> Result<usize, VaultError> {
        if source_id == target_id {
            return Err(VaultError::SameOrganizationTarget);
        }
        self.with_transaction(|conn| {
            let source_name: Option<String> = conn
                .query_row(
                    "SELECT name FROM folders WHERE id=?1",
                    params![source_id],
                    |row| row.get(0),
                )
                .optional()?;
            let target_name: Option<String> = conn
                .query_row(
                    "SELECT name FROM folders WHERE id=?1",
                    params![target_id],
                    |row| row.get(0),
                )
                .optional()?;
            let source_name = source_name.ok_or(VaultError::FolderNotFound)?;
            let target_name = target_name.ok_or(VaultError::FolderNotFound)?;
            let now = now_rfc3339();
            let moved = conn.execute(
                "UPDATE entries SET folder_id=?1, updated_at=?2 WHERE folder_id=?3",
                params![target_id, &now, source_id],
            )?;
            conn.execute(
                "INSERT INTO sync_tombstones (kind, id, deleted_at) VALUES (?1,?2,?3)
                 ON CONFLICT(kind, id) DO UPDATE SET deleted_at=excluded.deleted_at",
                params![TOMBSTONE_FOLDER, source_id, &now],
            )?;
            conn.execute("DELETE FROM folders WHERE id=?1", params![source_id])?;
            audit_on(
                conn,
                "merge_folders",
                None,
                &format!("{source_name} -> {target_name} moved={moved}"),
            )?;
            Ok(moved)
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
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(VaultError::from)
    }

    pub fn rename_tag(&self, old_name: &str, new_name: &str) -> Result<(), VaultError> {
        let old_name = normalize_name(old_name, false)?;
        let new_name = normalize_name(new_name, false)?;
        self.with_transaction(|conn| {
            let tag_id: Option<String> = conn
                .query_row(
                    "SELECT id FROM tags WHERE name=?1",
                    params![&old_name],
                    |row| row.get(0),
                )
                .optional()?;
            let tag_id = tag_id.ok_or(VaultError::TagNotFound)?;
            let conflict: Option<String> = conn
                .query_row(
                    "SELECT id FROM tags WHERE name=?1",
                    params![&new_name],
                    |row| row.get(0),
                )
                .optional()?;
            if conflict.is_some() && new_name != old_name {
                return Err(VaultError::TagAlreadyExists);
            }
            conn.execute(
                "UPDATE tags SET name=?1 WHERE id=?2",
                params![&new_name, &tag_id],
            )?;
            conn.execute(
                "UPDATE entries SET updated_at=?1 WHERE id IN (
                    SELECT entry_id FROM entry_tags WHERE tag_id=?2
                )",
                params![now_rfc3339(), &tag_id],
            )?;
            audit_on(
                conn,
                "rename_tag",
                None,
                &format!("{old_name} -> {new_name}"),
            )?;
            Ok(())
        })
    }

    pub fn delete_tag(&self, name: &str) -> Result<usize, VaultError> {
        let name = normalize_name(name, false)?;
        self.with_transaction(|conn| {
            let tag_id: Option<String> = conn
                .query_row("SELECT id FROM tags WHERE name=?1", params![&name], |row| {
                    row.get(0)
                })
                .optional()?;
            let tag_id = tag_id.ok_or(VaultError::TagNotFound)?;
            conn.execute(
                "UPDATE entries SET updated_at=?1 WHERE id IN (
                    SELECT entry_id FROM entry_tags WHERE tag_id=?2
                )",
                params![now_rfc3339(), &tag_id],
            )?;
            let removed =
                conn.execute("DELETE FROM entry_tags WHERE tag_id=?1", params![&tag_id])?;
            conn.execute("DELETE FROM tags WHERE id=?1", params![&tag_id])?;
            audit_on(conn, "delete_tag", None, &format!("{name} links={removed}"))?;
            Ok(removed)
        })
    }

    pub fn merge_tags(&self, source_name: &str, target_name: &str) -> Result<usize, VaultError> {
        let source_name = normalize_name(source_name, false)?;
        let target_name = normalize_name(target_name, false)?;
        if source_name == target_name {
            return Err(VaultError::SameOrganizationTarget);
        }
        self.with_transaction(|conn| {
            let source_id: Option<String> = conn
                .query_row(
                    "SELECT id FROM tags WHERE name=?1",
                    params![&source_name],
                    |row| row.get(0),
                )
                .optional()?;
            let target_id: Option<String> = conn
                .query_row(
                    "SELECT id FROM tags WHERE name=?1",
                    params![&target_name],
                    |row| row.get(0),
                )
                .optional()?;
            let source_id = source_id.ok_or(VaultError::TagNotFound)?;
            let target_id = target_id.ok_or(VaultError::TagNotFound)?;
            conn.execute(
                "UPDATE entries SET updated_at=?1 WHERE id IN (
                    SELECT entry_id FROM entry_tags WHERE tag_id=?2
                )",
                params![now_rfc3339(), &source_id],
            )?;
            let moved = conn.execute(
                "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id)
                 SELECT entry_id, ?1 FROM entry_tags WHERE tag_id=?2",
                params![&target_id, &source_id],
            )?;
            conn.execute(
                "DELETE FROM entry_tags WHERE tag_id=?1",
                params![&source_id],
            )?;
            conn.execute("DELETE FROM tags WHERE id=?1", params![&source_id])?;
            audit_on(
                conn,
                "merge_tags",
                None,
                &format!("{source_name} -> {target_name} links={moved}"),
            )?;
            Ok(moved)
        })
    }

    pub fn list_tags(&self) -> Result<Vec<String>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT t.name FROM tags t
             JOIN entry_tags et ON et.tag_id=t.id
             JOIN entries e ON e.id=et.entry_id
             ORDER BY t.name",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(VaultError::from)
    }

    pub fn list_audit(&self, limit: i64) -> Result<Vec<AuditEvent>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, at, action, entry_id, detail FROM audit_events ORDER BY at DESC, id DESC LIMIT ?1",
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
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(VaultError::from)
    }

    pub fn query_audit(
        &self,
        query: &crate::audit::AuditQuery,
    ) -> Result<crate::audit::AuditPage, VaultError> {
        use crate::audit::{format_event, AuditPage, ACTIONS, RESULTS};
        let invalid = || VaultError::InvalidAuditQuery;
        if !(1..=100).contains(&query.limit)
            || query.offset < 0
            || query.keyword.len() > 2000
            || query.actions.len() > 100
            || (!query.result.is_empty() && !RESULTS.iter().any(|(key, _)| *key == query.result))
        {
            return Err(invalid());
        }
        let parse_date = |s: &str| -> Result<DateTime<Utc>, VaultError> {
            DateTime::parse_from_rfc3339(s)
                .map(|v| v.with_timezone(&Utc))
                .map_err(|_| invalid())
        };
        let from = query.from.as_deref().map(parse_date).transpose()?;
        let to = query.to.as_deref().map(parse_date).transpose()?;
        if from.zip(to).is_some_and(|(a, b)| a >= b) {
            return Err(invalid());
        }
        let keywords: Vec<String> = query
            .keyword
            .split_whitespace()
            .map(str::to_lowercase)
            .collect();
        let mut sql = "SELECT id, at, action, entry_id, detail FROM audit_events".to_string();
        let values: Vec<rusqlite::types::Value> =
            query.actions.iter().cloned().map(Into::into).collect();
        if !values.is_empty() {
            sql.push_str(&format!(
                " WHERE action IN ({})",
                vec!["?"; values.len()].join(",")
            ));
        }
        sql.push_str(" ORDER BY at DESC, id DESC");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(values))?;
        let mut items = Vec::new();
        let mut total = 0;
        // Stream the full history through the same formatter used for display. Memory is bounded
        // by the requested page; a single read cursor keeps count and page on the same snapshot.
        while let Some(row) = rows.next()? {
            let raw = AuditEvent {
                id: row.get(0)?,
                at: row.get(1)?,
                action: row.get(2)?,
                entry_id: row.get(3)?,
                detail: row.get(4)?,
            };
            if from.is_some() || to.is_some() {
                let Ok(at) = DateTime::parse_from_rfc3339(&raw.at) else {
                    continue;
                };
                if from.is_some_and(|v| at < v) || to.is_some_and(|v| at >= v) {
                    continue;
                }
            }
            let display = format_event(raw);
            if !query.result.is_empty() && display.result != query.result {
                continue;
            }
            if !keywords.is_empty() {
                let text = format!(
                    "{} {} {} {} {} {}",
                    display.raw.action,
                    display.raw.detail,
                    display.raw.entry_id.as_deref().unwrap_or(""),
                    display.operation,
                    display.result_label,
                    display.description
                )
                .to_lowercase();
                if !keywords.iter().all(|word| text.contains(word)) {
                    continue;
                }
            }
            if total >= query.offset && items.len() < query.limit as usize {
                items.push(display);
            }
            total += 1;
        }
        Ok(AuditPage {
            items,
            total,
            actions: ACTIONS.to_vec(),
            results: RESULTS.to_vec(),
        })
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
        let payload: SecretPayload =
            serde_json::from_slice(&secret).map_err(|_| VaultError::CorruptBackup)?;
        let expected_kind = EntryKind::parse(&entry.kind).map_err(|_| VaultError::CorruptBackup)?;
        if payload.kind() != expected_kind {
            return Err(VaultError::CorruptBackup);
        }
        if let SecretPayload::ClientCert {
            cert_pem,
            key_pem,
            passphrase,
        } = &payload
        {
            certificate::validate_client_cert(cert_pem, key_pem, passphrase.as_deref())
                .map_err(|_| VaultError::CorruptBackup)?;
        }
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
        for tag in normalize_tag_names(&entry.tags) {
            let tag_id = self.ensure_tag(&tag)?;
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
        let name = normalize_name(name, true)?;
        if let Some(id) = folder_id_by_name(&self.conn, &name)? {
            return Ok(id);
        }
        Ok(insert_folder(&self.conn, &name)?.id)
    }

    fn ensure_tag(&self, name: &str) -> Result<String, VaultError> {
        let Some(name) = normalize_optional_name(name) else {
            return Err(VaultError::TagNameEmpty);
        };
        let existing: Option<String> = self
            .conn
            .query_row("SELECT id FROM tags WHERE name=?1", params![&name], |r| {
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

    fn validate_folder_id(&self, folder_id: Option<&str>) -> Result<(), VaultError> {
        if let Some(folder_id) = folder_id {
            let exists: Option<String> = self
                .conn
                .query_row(
                    "SELECT id FROM folders WHERE id=?1",
                    params![folder_id],
                    |row| row.get(0),
                )
                .optional()?;
            if exists.is_none() {
                return Err(VaultError::FolderNotFound);
            }
        }
        Ok(())
    }

    fn with_transaction<T>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, VaultError>,
    ) -> Result<T, VaultError> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = operation(&self.conn);
        match result {
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
                let kind_raw: String = r.get(1)?;
                let kind = EntryKind::parse(&kind_raw).map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        Type::Text,
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid entry kind",
                        )),
                    )
                })?;
                Ok(EntryDto {
                    id: r.get(0)?,
                    kind,
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
                "client_cert" => counts.client_cert = n,
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

    fn query_text(filter: &ListFilter) -> Option<&str> {
        filter
            .query
            .as_deref()
            .map(str::trim)
            .filter(|query| !query.is_empty())
    }

    fn contains_query(haystack: &str, query: &str) -> bool {
        haystack.to_lowercase().contains(&query.to_lowercase())
    }

    fn folder_name_map(&self) -> Result<HashMap<String, String>, VaultError> {
        Ok(self
            .list_folders()?
            .into_iter()
            .map(|folder| (folder.id, folder.name))
            .collect())
    }

    fn notes_plain(&self, dek: &[u8; 32], id: &str) -> Result<Option<String>, VaultError> {
        let blob = self
            .conn
            .query_row(
                "SELECT notes_blob FROM entries WHERE id=?1",
                params![id],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .ok_or(VaultError::NotFound)?;
        match blob {
            Some(bytes) => {
                let enc = Encrypted::from_bytes(&bytes)?;
                let plain = decrypt(dek, &enc)?;
                Ok(Some(String::from_utf8_lossy(&plain).into_owned()))
            }
            None => Ok(None),
        }
    }

    fn entry_matches_query(
        &self,
        dek: &[u8; 32],
        entry: &EntryDto,
        query: &str,
        folders: &HashMap<String, String>,
    ) -> Result<bool, VaultError> {
        let folder = entry
            .folder_id
            .as_ref()
            .and_then(|id| folders.get(id))
            .map(String::as_str)
            .unwrap_or("");
        let tags = entry.tags.join(" ");
        let notes = self.notes_plain(dek, &entry.id)?.unwrap_or_default();
        let fields = [
            entry.title.as_str(),
            entry.account.as_deref().unwrap_or(""),
            entry.url.as_deref().unwrap_or(""),
            tags.as_str(),
            folder,
            entry.fingerprint.as_deref().unwrap_or(""),
            notes.as_str(),
        ];
        Ok(fields
            .iter()
            .any(|field| Self::contains_query(field, query)))
    }

    pub fn search_entries(
        &self,
        dek: &[u8; 32],
        filter: &ListFilter,
    ) -> Result<Vec<EntryDto>, VaultError> {
        let Some(query) = Self::query_text(filter) else {
            return self.list_entries(filter);
        };
        let mut scoped = filter.clone();
        scoped.query = None;
        let folders = self.folder_name_map()?;
        let mut out = Vec::new();
        for entry in self.list_entries(&scoped)? {
            if self.entry_matches_query(dek, &entry, query, &folders)? {
                out.push(entry);
            }
        }
        Ok(out)
    }

    pub fn counts_for_search(
        &self,
        dek: &[u8; 32],
        filter: &ListFilter,
    ) -> Result<Counts, VaultError> {
        if Self::query_text(filter).is_none() {
            return self.counts_for(filter);
        }
        let mut scoped = filter.clone();
        scoped.kind = None;
        scoped.kinds.clear();
        let mut counts = Counts::default();
        for entry in self.search_entries(dek, &scoped)? {
            match entry.kind {
                EntryKind::Website => counts.website += 1,
                EntryKind::ApiToken => counts.api_token += 1,
                EntryKind::Ssh => counts.ssh += 1,
                EntryKind::Mailbox => counts.mailbox += 1,
                EntryKind::MailAuth => counts.mail_auth += 1,
                EntryKind::Server => counts.server += 1,
                EntryKind::Database => counts.database += 1,
                EntryKind::ClientCert => counts.client_cert += 1,
            }
            counts.total += 1;
        }
        counts.trash = self.conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE deleted_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(counts)
    }

    fn push_field(fields: &mut Vec<EntryField>, label: &str, value: Option<&str>) {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return;
        };
        fields.push(EntryField {
            label: label.to_string(),
            value: value.to_string(),
        });
    }

    fn push_port(fields: &mut Vec<EntryField>, label: &str, port: Option<u16>) {
        if let Some(port) = port {
            fields.push(EntryField {
                label: label.to_string(),
                value: port.to_string(),
            });
        }
    }

    pub fn entry_profile(&self, dek: &[u8; 32], id: &str) -> Result<EntryProfile, VaultError> {
        let entry = self.get_dto(id)?;
        let notes = self.notes_plain(dek, id)?;
        let deleted_at = self
            .conn
            .query_row(
                "SELECT deleted_at FROM entries WHERE id=?1",
                params![id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .ok_or(VaultError::NotFound)?;
        let mut fields = Vec::new();
        if deleted_at.is_some() {
            Self::push_field(&mut fields, "网址", entry.url.as_deref());
            Self::push_field(&mut fields, "账号", entry.account.as_deref());
            return Ok(EntryProfile { entry, notes, fields });
        }
        let secret = self.get_active_secret(dek, id)?;
        match secret {
            SecretPayload::Website { url, username, .. } => {
                Self::push_field(&mut fields, "网址", url.as_deref().or(entry.url.as_deref()));
                Self::push_field(
                    &mut fields,
                    "账号",
                    username.as_deref().or(entry.account.as_deref()),
                );
            }
            SecretPayload::ApiToken { service, account, .. } => {
                Self::push_field(&mut fields, "服务", Some(service.as_str()));
                Self::push_field(
                    &mut fields,
                    "账号",
                    account.as_deref().or(entry.account.as_deref()),
                );
                Self::push_field(&mut fields, "允许的网址", entry.url.as_deref());
            }
            SecretPayload::Ssh {
                key_type,
                public_fingerprint,
                ..
            } => {
                Self::push_field(&mut fields, "密钥类型", Some(key_type.as_str()));
                Self::push_field(
                    &mut fields,
                    "指纹",
                    entry
                        .fingerprint
                        .as_deref()
                        .or(public_fingerprint.as_deref()),
                );
            }
            SecretPayload::Mailbox {
                email,
                imap_host,
                imap_port,
                smtp_host,
                smtp_port,
                ..
            } => {
                Self::push_field(&mut fields, "邮箱", Some(email.as_str()));
                Self::push_field(&mut fields, "IMAP 主机", imap_host.as_deref());
                Self::push_port(&mut fields, "IMAP 端口", imap_port);
                Self::push_field(&mut fields, "SMTP 主机", smtp_host.as_deref());
                Self::push_port(&mut fields, "SMTP 端口", smtp_port);
            }
            SecretPayload::MailAuth { email, provider, .. } => {
                Self::push_field(&mut fields, "邮箱", Some(email.as_str()));
                Self::push_field(&mut fields, "服务商", Some(provider.as_str()));
            }
            SecretPayload::Server {
                host,
                port,
                protocol,
                username,
                ..
            } => {
                Self::push_field(&mut fields, "协议", Some(protocol.as_str()));
                Self::push_field(&mut fields, "主机", Some(host.as_str()));
                Self::push_port(&mut fields, "端口", port);
                Self::push_field(&mut fields, "用户名", Some(username.as_str()));
            }
            SecretPayload::Database {
                engine,
                host,
                port,
                database,
                username,
                ..
            } => {
                Self::push_field(&mut fields, "数据库类型", Some(engine.as_str()));
                Self::push_field(&mut fields, "主机", Some(host.as_str()));
                Self::push_port(&mut fields, "端口", port);
                Self::push_field(&mut fields, "库名", Some(database.as_str()));
                Self::push_field(&mut fields, "用户名", Some(username.as_str()));
            }
            SecretPayload::ClientCert {
                cert_pem,
                key_pem,
                passphrase,
            } => {
                let metadata =
                    certificate::validate_client_cert(&cert_pem, &key_pem, passphrase.as_deref())
                        .ok();
                Self::push_field(
                    &mut fields,
                    "指纹",
                    entry.fingerprint.as_deref().or_else(|| {
                        metadata
                            .as_ref()
                            .map(|value| value.fingerprint.as_str())
                    }),
                );
                if let Some(metadata) = metadata.as_ref() {
                    fields.push(EntryField {
                        label: "证书链张数".into(),
                        value: metadata.certificate_count.to_string(),
                    });
                }
                if passphrase.is_some() {
                    fields.push(EntryField {
                        label: "含私钥口令".into(),
                        value: "是".into(),
                    });
                }
            }
        }
        Ok(EntryProfile { entry, notes, fields })
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

    pub fn delete_setting(&self, key: &str) -> Result<(), VaultError> {
        self.conn
            .execute("DELETE FROM settings WHERE key=?1", params![key])?;
        Ok(())
    }

    /// Ids of entries and folders that were deleted for good. Sync carries
    /// them to other devices, otherwise "missing here, present there" reads
    /// as a new item and the deletion comes back.
    pub fn sync_tombstones(&self) -> Result<Vec<Tombstone>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT kind, id, deleted_at FROM sync_tombstones ORDER BY kind, id")?;
        let rows = stmt.query_map([], |r| {
            Ok(Tombstone {
                kind: r.get(0)?,
                id: r.get(1)?,
                deleted_at: r.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(VaultError::from)
    }

    pub fn replace_sync_tombstones(&self, tombstones: &[Tombstone]) -> Result<(), VaultError> {
        self.with_transaction(|conn| {
            conn.execute("DELETE FROM sync_tombstones", [])?;
            let mut stmt = conn
                .prepare("INSERT INTO sync_tombstones (kind, id, deleted_at) VALUES (?1,?2,?3)")?;
            for item in tombstones {
                stmt.execute(params![&item.kind, &item.id, &item.deleted_at])?;
            }
            Ok(())
        })
    }

    /// Replace folders, tags and entries with a snapshot whose secret blobs
    /// are already encrypted with this vault's DEK. Settings and audit stay.
    pub fn replace_snapshot_same_key(
        &self,
        dek: &[u8; 32],
        snapshot: &BackupSnapshot,
    ) -> Result<(), VaultError> {
        self.replace_snapshot_reencrypted(dek, dek, snapshot)
    }

    /// Same as `replace_snapshot_same_key`, but each blob is decrypted with
    /// `source_dek` and stored again under `dest_dek`. Sync uses this because
    /// two devices encrypt their snapshots with different vault keys.
    pub fn replace_snapshot_reencrypted(
        &self,
        source_dek: &[u8; 32],
        dest_dek: &[u8; 32],
        snapshot: &BackupSnapshot,
    ) -> Result<(), VaultError> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.conn.execute("DELETE FROM entry_tags", [])?;
            self.conn.execute("DELETE FROM entries", [])?;
            self.conn.execute("DELETE FROM folders", [])?;
            self.conn.execute("DELETE FROM tags", [])?;
            for folder in &snapshot.folders {
                let name = normalize_name(&folder.name, true)?;
                self.conn.execute(
                    "INSERT INTO folders (id, name, parent_id) VALUES (?1,?2,NULL)",
                    params![&folder.id, &name],
                )?;
            }
            for entry in &snapshot.entries {
                let secret = decrypt(source_dek, &Encrypted::from_bytes(&entry.secret_blob)?)?;
                let notes = match &entry.notes_blob {
                    Some(blob) => Some(decrypt(source_dek, &Encrypted::from_bytes(blob)?)?),
                    None => None,
                };
                let secret_blob = encrypt(dest_dek, &secret)?.to_bytes();
                let notes_blob = notes
                    .as_ref()
                    .map(|plain| encrypt(dest_dek, plain).map(|enc| enc.to_bytes()))
                    .transpose()?;
                let folder_id = entry
                    .folder_id
                    .as_ref()
                    .filter(|id| snapshot.folders.iter().any(|folder| folder.id == **id));
                self.conn.execute(
                    "INSERT INTO entries (
                        id, kind, title, account, url, folder_id, pinned, expires_at,
                        use_count, last_used_at, created_at, updated_at, deleted_at,
                        has_totp, fingerprint, secret_blob, notes_blob
                    ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
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
                        &secret_blob,
                        &notes_blob,
                    ],
                )?;
                for tag in normalize_tag_names(&entry.tags) {
                    let tag_id = self.ensure_tag(&tag)?;
                    self.conn.execute(
                        "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1,?2)",
                        params![&entry.id, &tag_id],
                    )?;
                }
            }
            self.audit(
                "sync_apply",
                None,
                &format!("entries={}", snapshot.entries.len()),
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
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
    pub client_cert: i64,
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tombstone {
    pub kind: String,
    pub id: String,
    pub deleted_at: String,
}

pub const TOMBSTONE_ENTRY: &str = "entry";
pub const TOMBSTONE_FOLDER: &str = "folder";

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn normalize_optional_name(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn normalize_name(value: &str, folder: bool) -> Result<String, VaultError> {
    normalize_optional_name(value).ok_or(if folder {
        VaultError::FolderNameEmpty
    } else {
        VaultError::TagNameEmpty
    })
}

fn normalize_optional_id(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn normalize_tag_names(values: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .iter()
        .filter_map(|value| normalize_optional_name(value))
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn folder_id_by_name(conn: &Connection, name: &str) -> Result<Option<String>, VaultError> {
    conn.query_row(
        "SELECT id FROM folders WHERE name=?1",
        params![name],
        |row| row.get(0),
    )
    .optional()
    .map_err(VaultError::from)
}

fn insert_folder(conn: &Connection, name: &str) -> Result<FolderDto, VaultError> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO folders (id, name, parent_id) VALUES (?1,?2,NULL)",
        params![&id, name],
    )?;
    Ok(FolderDto {
        id,
        name: name.to_string(),
    })
}

fn cleanup_orphan_tags(conn: &Connection) -> Result<(), VaultError> {
    conn.execute(
        "DELETE FROM entry_tags
         WHERE entry_id NOT IN (SELECT id FROM entries)
            OR tag_id NOT IN (SELECT id FROM tags)",
        [],
    )?;
    conn.execute(
        "DELETE FROM tags WHERE id NOT IN (SELECT DISTINCT tag_id FROM entry_tags)",
        [],
    )?;
    Ok(())
}

fn audit_on(
    conn: &Connection,
    action: &str,
    entry_id: Option<&str>,
    detail: &str,
) -> Result<(), VaultError> {
    conn.execute(
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

fn remove_db_files(path: &str) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let _ = std::fs::remove_file(format!("{path}{suffix}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_queries_cover_full_history_and_literal_chinese_search() {
        use crate::audit::AuditQuery;
        let (vault, _) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        for i in 0..260 {
            vault
                .conn
                .execute(
                    "INSERT INTO audit_events VALUES (?1,?2,?3,?4,?5)",
                    params![
                        format!("{i:04}"),
                        if i < 5 {
                            "2025-01-01T08:00:00+08:00"
                        } else {
                            "2026-01-01T00:00:00Z"
                        },
                        if i < 5 { "copy" } else { "unlock" },
                        "entry-needle",
                        if i < 5 { "totp" } else { "ok" }
                    ],
                )
                .unwrap();
        }
        let mut q = AuditQuery {
            limit: 50,
            ..Default::default()
        };
        let page = vault.query_audit(&q).unwrap();
        assert_eq!(page.total, 260);
        assert_eq!(page.items[0].raw.id, "0259");
        q.offset = 250;
        assert_eq!(vault.query_audit(&q).unwrap().items.len(), 10);
        q.offset = 0;
        q.keyword = "复制 动态验证码".into();
        let page = vault.query_audit(&q).unwrap();
        assert_eq!(page.total, 5);
        assert_eq!(page.items[0].raw.id, "0004");
        q.actions = vec!["copy".into(), "unknown".into()];
        q.result = "recorded".into();
        q.from = Some("2025-01-01T00:00:00Z".into());
        q.to = Some("2025-01-02T00:00:00Z".into());
        q.limit = 2;
        q.offset = 2;
        let page = vault.query_audit(&q).unwrap();
        assert_eq!(page.total, 5);
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].raw.id, "0002");
        q.result = "success".into();
        assert_eq!(vault.query_audit(&q).unwrap().total, 0);
        vault
            .audit("new_future_action", None, "100%_ ' OR 1=1 --")
            .unwrap();
        q = AuditQuery {
            keyword: "100%_".into(),
            limit: 50,
            ..Default::default()
        };
        assert_eq!(vault.query_audit(&q).unwrap().total, 1);
        q.keyword = "OR 1=1 --".into();
        assert_eq!(vault.query_audit(&q).unwrap().total, 1);
        q.actions = vec!["' OR 1=1 --".into()];
        assert_eq!(vault.query_audit(&q).unwrap().total, 0);
        q.limit = 0;
        assert!(vault.query_audit(&q).is_err());
        q.limit = 101;
        assert!(vault.query_audit(&q).is_err());
        q.limit = 50;
        q.offset = -1;
        assert!(vault.query_audit(&q).is_err());
        q.offset = 0;
        q.from = Some("not a date".into());
        assert!(vault.query_audit(&q).is_err());
        q.from = Some("2026-01-01T00:00:00Z".into());
        q.to = q.from.clone();
        assert!(vault.query_audit(&q).is_err());
        vault.conn.execute("INSERT INTO audit_events VALUES (?1,?2,?3,NULL,?4)", params![
            "older-mcp", "2024-01-01T00:00:00Z", "mcp_zoomkey_denied",
            "operation=zoomkey_crm_project_members decision=deny reason=network endpoint=crm detail=project=a b key=value status=- count=- credential=abc"
        ]).unwrap();
        q = AuditQuery {
            keyword: "项目成员 网络失败".into(),
            result: "network".into(),
            limit: 50,
            ..Default::default()
        };
        let page = vault.query_audit(&q).unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].raw.id, "older-mcp");
        q.result = "denied".into();
        assert_eq!(vault.query_audit(&q).unwrap().total, 0);
        // Corrupt rows must not silently disappear from count or compatibility reads.
        vault
            .conn
            .execute("UPDATE audit_events SET detail=x'00' WHERE id='0000'", [])
            .unwrap();
        q = AuditQuery {
            limit: 50,
            ..Default::default()
        };
        assert!(vault.query_audit(&q).is_err());
        assert!(vault.list_audit(1000).is_err());
    }

    #[test]
    fn dek_matches_rejects_a_different_key_and_accepts_the_real_one() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .upsert_entry(
                &dek,
                UpsertEntry {
                    id: None,
                    kind: EntryKind::ApiToken,
                    title: "api".into(),
                    account: None,
                    url: None,
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::ApiToken {
                        service: "example".into(),
                        account: None,
                        token: "secret-token".into(),
                    },
                },
            )
            .unwrap();
        assert!(vault.dek_matches(&dek).is_ok());
        assert!(vault.dek_matches(&[9u8; 32]).is_err());
    }

    #[test]
    fn dek_matches_ignores_sync_key_check_sealed_with_the_sync_passphrase() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut sync_key = [0u8; 32];
        sync_key[0] = 7;
        let check = encrypt(&sync_key, b"sealbox-sync-v1").unwrap();
        vault
            .set_setting("sync_key_check", &hex::encode(check.to_bytes()))
            .unwrap();
        assert!(vault.dek_matches(&dek).is_ok());
        assert!(vault.dek_matches(&[9u8; 32]).is_ok());

        vault
            .upsert_entry(
                &dek,
                UpsertEntry {
                    id: None,
                    kind: EntryKind::ApiToken,
                    title: "api".into(),
                    account: None,
                    url: None,
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::ApiToken {
                        service: "example".into(),
                        account: None,
                        token: "secret-token".into(),
                    },
                },
            )
            .unwrap();
        assert!(vault.dek_matches(&dek).is_ok());
        assert!(vault.dek_matches(&[9u8; 32]).is_err());
    }

    #[test]
    fn upsert_normalizes_website_totp() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let entry = vault
            .upsert_entry(
                &dek,
                UpsertEntry {
                    id: None,
                    kind: EntryKind::Website,
                    title: "GitHub".into(),
                    account: Some("octocat".into()),
                    url: Some("https://github.com".into()),
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::Website {
                        url: Some("https://github.com".into()),
                        username: Some("octocat".into()),
                        password: "pw".into(),
                        totp_secret: Some(
                            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP".into(),
                        ),
                    },
                },
            )
            .unwrap();
        match vault.get_secret(&dek, &entry.id).unwrap() {
            SecretPayload::Website {
                totp_secret: Some(secret),
                ..
            } => assert_eq!(secret, "JBSWY3DPEHPK3PXP"),
            other => panic!("{other:?}"),
        }
        assert!(entry.has_totp);
    }

    #[test]
    fn upsert_treats_blank_totp_as_unconfigured() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let entry = vault
            .upsert_entry(
                &dek,
                UpsertEntry {
                    id: None,
                    kind: EntryKind::Website,
                    title: "GitHub".into(),
                    account: Some("octocat".into()),
                    url: Some("https://github.com".into()),
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::Website {
                        url: Some("https://github.com".into()),
                        username: Some("octocat".into()),
                        password: "pw".into(),
                        totp_secret: Some("  ".into()),
                    },
                },
            )
            .unwrap();
        assert!(!entry.has_totp);
        assert!(matches!(
            vault.get_secret(&dek, &entry.id).unwrap(),
            SecretPayload::Website {
                totp_secret: None,
                ..
            }
        ));
    }
}
