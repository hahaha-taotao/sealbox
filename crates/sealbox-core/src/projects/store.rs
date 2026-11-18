//! Encrypted project tables inside the vault SQLite database.
//!
//! - `pm_workspaces`: workspace id + format version + DEK-wrapped business key (AAD-bound).
//! - `pm_records`: per-record encrypted payload (AAD binds workspace/record/type/schema/revision).
//!
//! Schema creation is idempotent (`CREATE IF NOT EXISTS`) so desktop and Android opening the
//! same vault never strip project data.

use rusqlite::{params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{
    decrypt_with_aad, encrypt_with_aad, random_key, unwrap_key_with_aad, wrap_key_with_aad,
    Encrypted,
};
use crate::db::DbError;

use super::model::{
    JiraRangeOrigin, JiraRangeRelation, JiraSupplementRelation, SourceBinding,
    DEFAULT_ENTITY_SCHEMA_VERSION, ENTITY_JIRA_RANGE, ENTITY_JIRA_SUPPLEMENT, MODULE_ID,
    WORKSPACE_FORMAT_VERSION,
};

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("database error: {0}")]
    Db(#[from] DbError),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("workspace or record not found")]
    NotFound,
    #[error("revision conflict")]
    Conflict,
    #[error("duplicate unique relation")]
    Duplicate,
    #[error("corrupt project record")]
    Corrupt,
    #[error("invalid project input: {0}")]
    InvalidInput(String),
}

#[derive(Clone, Debug)]
pub struct WorkspaceRow {
    pub id: String,
    pub format_version: u32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug)]
pub struct RecordMeta {
    pub workspace_id: String,
    pub id: String,
    pub entity_type: String,
    pub schema_version: u32,
    pub revision: u64,
}

/// Arguments for [`put_record`].
pub struct PutRecord<'a> {
    pub workspace_id: &'a str,
    /// `None` allocates a new UUID and starts at revision 1.
    pub record_id: Option<&'a str>,
    pub entity_type: &'a str,
    pub schema_version: u32,
    /// Required when updating an existing row: must equal the stored revision.
    /// Ignored (must be `None`) when creating.
    pub expected_revision: Option<u64>,
}

pub fn ensure_schema(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS pm_workspaces (
          id TEXT PRIMARY KEY NOT NULL,
          format_version INTEGER NOT NULL,
          wrapped_business_key BLOB NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pm_records (
          workspace_id TEXT NOT NULL,
          id TEXT NOT NULL,
          entity_type TEXT NOT NULL,
          schema_version INTEGER NOT NULL,
          revision INTEGER NOT NULL,
          payload BLOB NOT NULL,
          PRIMARY KEY (workspace_id, id),
          FOREIGN KEY (workspace_id) REFERENCES pm_workspaces(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS pm_records_workspace_type
          ON pm_records(workspace_id, entity_type);
        "#,
    )?;
    Ok(())
}

fn key_wrap_aad(workspace_id: &str, format_version: u32) -> String {
    format!("{MODULE_ID}|keywrap|{workspace_id}|v{format_version}")
}

fn record_aad(
    workspace_id: &str,
    record_id: &str,
    entity_type: &str,
    schema_version: u32,
    revision: u64,
) -> String {
    format!(
        "{MODULE_ID}|record|{workspace_id}|{record_id}|{entity_type}|{schema_version}|{revision}"
    )
}

/// Create a workspace with a fresh random 256-bit business key wrapped by `dek`.
pub fn create_workspace(conn: &Connection, dek: &[u8; 32]) -> Result<WorkspaceRow, ProjectError> {
    let id = Uuid::new_v4().to_string();
    let format_version = WORKSPACE_FORMAT_VERSION;
    let business = Zeroizing::new(random_key());
    let aad = key_wrap_aad(&id, format_version);
    let wrapped = wrap_key_with_aad(dek, &business, aad.as_bytes())?;
    let now = now_rfc3339();
    conn.execute(
        "INSERT INTO pm_workspaces (id, format_version, wrapped_business_key, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?4)",
        params![&id, format_version as i64, wrapped.to_bytes(), &now],
    )?;
    Ok(WorkspaceRow {
        id,
        format_version,
        created_at: now.clone(),
        updated_at: now,
    })
}

pub fn get_workspace(conn: &Connection, workspace_id: &str) -> Result<WorkspaceRow, ProjectError> {
    conn.query_row(
        "SELECT id, format_version, created_at, updated_at FROM pm_workspaces WHERE id=?1",
        params![workspace_id],
        |row| {
            Ok(WorkspaceRow {
                id: row.get(0)?,
                format_version: row.get::<_, i64>(1)? as u32,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
            })
        },
    )
    .optional()?
    .ok_or(ProjectError::NotFound)
}

/// List workspaces oldest-first (MVP uses the first as the default vault workspace).
pub fn list_workspaces(conn: &Connection) -> Result<Vec<WorkspaceRow>, ProjectError> {
    let mut stmt = conn.prepare(
        "SELECT id, format_version, created_at, updated_at FROM pm_workspaces
         ORDER BY created_at ASC, id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(WorkspaceRow {
            id: row.get(0)?,
            format_version: row.get::<_, i64>(1)? as u32,
            created_at: row.get(2)?,
            updated_at: row.get(3)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Delete one encrypted record. Missing id → [`ProjectError::NotFound`].
pub fn delete_record(
    conn: &Connection,
    workspace_id: &str,
    record_id: &str,
) -> Result<(), ProjectError> {
    let n = conn.execute(
        "DELETE FROM pm_records WHERE workspace_id=?1 AND id=?2",
        params![workspace_id, record_id],
    )?;
    if n == 0 {
        return Err(ProjectError::NotFound);
    }
    Ok(())
}

/// Unwrap the per-workspace business key using the vault DEK and AAD.
pub fn unwrap_business_key(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
) -> Result<[u8; 32], ProjectError> {
    let (format_version, blob): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT format_version, wrapped_business_key FROM pm_workspaces WHERE id=?1",
            params![workspace_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(ProjectError::NotFound)?;
    let enc = Encrypted::from_bytes(&blob).map_err(|_| ProjectError::Corrupt)?;
    let aad = key_wrap_aad(workspace_id, format_version as u32);
    Ok(unwrap_key_with_aad(dek, &enc, aad.as_bytes())?)
}

/// Re-wrap a workspace business key under a new DEK (backup restore into another vault).
pub fn rewrap_workspace_key(
    conn: &Connection,
    source_dek: &[u8; 32],
    dest_dek: &[u8; 32],
    workspace_id: &str,
) -> Result<(), ProjectError> {
    let business = Zeroizing::new(unwrap_business_key(conn, source_dek, workspace_id)?);
    let row = get_workspace(conn, workspace_id)?;
    let aad = key_wrap_aad(workspace_id, row.format_version);
    let wrapped = wrap_key_with_aad(dest_dek, &business, aad.as_bytes())?;
    let now = now_rfc3339();
    let n = conn.execute(
        "UPDATE pm_workspaces SET wrapped_business_key=?1, updated_at=?2 WHERE id=?3",
        params![wrapped.to_bytes(), &now, workspace_id],
    )?;
    if n == 0 {
        return Err(ProjectError::NotFound);
    }
    Ok(())
}

/// Insert or update an encrypted record.
///
/// - Create: `record_id = None`, `expected_revision = None` → revision 1.
/// - Update: pass existing id and `expected_revision = Some(current)`; stores `current + 1`.
///   Mismatch → [`ProjectError::Conflict`] (no silent overwrite).
pub fn put_record<T: Serialize>(
    conn: &Connection,
    dek: &[u8; 32],
    args: PutRecord<'_>,
    payload: &T,
) -> Result<RecordMeta, ProjectError> {
    if args.entity_type.trim().is_empty() {
        return Err(ProjectError::InvalidInput("entity_type required".into()));
    }
    let business = Zeroizing::new(unwrap_business_key(conn, dek, args.workspace_id)?);

    let (record_id, new_revision, is_insert) = match (args.record_id, args.expected_revision) {
        (None, None) => (Uuid::new_v4().to_string(), 1u64, true),
        (Some(id), Some(expected)) => {
            let current: Option<i64> = conn
                .query_row(
                    "SELECT revision FROM pm_records WHERE workspace_id=?1 AND id=?2",
                    params![args.workspace_id, id],
                    |row| row.get(0),
                )
                .optional()?;
            match current {
                Some(rev) if rev as u64 == expected => (id.to_string(), expected + 1, false),
                Some(_) => return Err(ProjectError::Conflict),
                None => return Err(ProjectError::NotFound),
            }
        }
        (Some(id), None) => {
            // Explicit create with caller-chosen id (e.g. restore).
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM pm_records WHERE workspace_id=?1 AND id=?2)",
                params![args.workspace_id, id],
                |row| row.get(0),
            )?;
            if exists {
                return Err(ProjectError::Conflict);
            }
            (id.to_string(), 1u64, true)
        }
        (None, Some(_)) => {
            return Err(ProjectError::InvalidInput(
                "expected_revision requires record_id".into(),
            ));
        }
    };

    let plain = serde_json::to_vec(payload)?;
    let aad = record_aad(
        args.workspace_id,
        &record_id,
        args.entity_type,
        args.schema_version,
        new_revision,
    );
    let enc = encrypt_with_aad(&business, &plain, aad.as_bytes())?;

    if is_insert {
        conn.execute(
            "INSERT INTO pm_records
               (workspace_id, id, entity_type, schema_version, revision, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                args.workspace_id,
                &record_id,
                args.entity_type,
                args.schema_version as i64,
                new_revision as i64,
                enc.to_bytes(),
            ],
        )?;
    } else {
        let n = conn.execute(
            "UPDATE pm_records
             SET entity_type=?1, schema_version=?2, revision=?3, payload=?4
             WHERE workspace_id=?5 AND id=?6 AND revision=?7",
            params![
                args.entity_type,
                args.schema_version as i64,
                new_revision as i64,
                enc.to_bytes(),
                args.workspace_id,
                &record_id,
                (new_revision - 1) as i64,
            ],
        )?;
        if n != 1 {
            return Err(ProjectError::Conflict);
        }
    }

    Ok(RecordMeta {
        workspace_id: args.workspace_id.to_string(),
        id: record_id,
        entity_type: args.entity_type.to_string(),
        schema_version: args.schema_version,
        revision: new_revision,
    })
}

pub fn get_record<T: DeserializeOwned>(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    record_id: &str,
) -> Result<(RecordMeta, T), ProjectError> {
    let row = conn
        .query_row(
            "SELECT entity_type, schema_version, revision, payload
             FROM pm_records WHERE workspace_id=?1 AND id=?2",
            params![workspace_id, record_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u32,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(ProjectError::NotFound)?;
    let (entity_type, schema_version, revision, blob) = row;
    let business = Zeroizing::new(unwrap_business_key(conn, dek, workspace_id)?);
    let enc = Encrypted::from_bytes(&blob).map_err(|_| ProjectError::Corrupt)?;
    let aad = record_aad(
        workspace_id,
        record_id,
        &entity_type,
        schema_version,
        revision,
    );
    let plain = decrypt_with_aad(&business, &enc, aad.as_bytes()).map_err(|_| ProjectError::Corrupt)?;
    let value = serde_json::from_slice(&plain).map_err(|_| ProjectError::Corrupt)?;
    Ok((
        RecordMeta {
            workspace_id: workspace_id.to_string(),
            id: record_id.to_string(),
            entity_type,
            schema_version,
            revision,
        },
        value,
    ))
}

pub fn list_records_by_type<T: DeserializeOwned>(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    entity_type: &str,
) -> Result<Vec<(RecordMeta, T)>, ProjectError> {
    let mut stmt = conn.prepare(
        "SELECT id, schema_version, revision, payload FROM pm_records
         WHERE workspace_id=?1 AND entity_type=?2 ORDER BY id",
    )?;
    let rows = stmt.query_map(params![workspace_id, entity_type], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)? as u32,
            row.get::<_, i64>(2)? as u64,
            row.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    let business = Zeroizing::new(unwrap_business_key(conn, dek, workspace_id)?);
    let mut out = Vec::new();
    for row in rows {
        let (id, schema_version, revision, blob) = row?;
        let enc = Encrypted::from_bytes(&blob).map_err(|_| ProjectError::Corrupt)?;
        let aad = record_aad(workspace_id, &id, entity_type, schema_version, revision);
        let plain =
            decrypt_with_aad(&business, &enc, aad.as_bytes()).map_err(|_| ProjectError::Corrupt)?;
        let value: T = serde_json::from_slice(&plain).map_err(|_| ProjectError::Corrupt)?;
        out.push((
            RecordMeta {
                workspace_id: workspace_id.to_string(),
                id,
                entity_type: entity_type.to_string(),
                schema_version,
                revision,
            },
            value,
        ));
    }
    Ok(out)
}

fn binding_scope(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    source_binding_id: &str,
) -> Result<(String, String), ProjectError> {
    let (_meta, binding): (_, SourceBinding) =
        get_record(conn, dek, workspace_id, source_binding_id)?;
    Ok((binding.site, binding.account_scope))
}

/// Find an existing Jira range row for uniqueness key
/// `(local_project, jira site/account, jira_project_id)`.
pub fn find_jira_range(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    local_project_id: &str,
    source_binding_id: &str,
    jira_project_id: &str,
) -> Result<Option<(RecordMeta, JiraRangeRelation)>, ProjectError> {
    let (site, account) = binding_scope(conn, dek, workspace_id, source_binding_id)?;
    let rows: Vec<(RecordMeta, JiraRangeRelation)> =
        list_records_by_type(conn, dek, workspace_id, ENTITY_JIRA_RANGE)?;
    for (meta, rel) in rows {
        if rel.local_project_id != local_project_id || rel.jira_project_id != jira_project_id {
            continue;
        }
        let (rel_site, rel_account) = binding_scope(conn, dek, workspace_id, &rel.source_binding_id)?;
        if rel_site == site && rel_account == account {
            return Ok(Some((meta, rel)));
        }
    }
    Ok(None)
}

/// Find an existing local Jira supplement for
/// `(local_project, jira site/account, issue_id)`.
pub fn find_jira_supplement(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    local_project_id: &str,
    source_binding_id: &str,
    issue_id: &str,
) -> Result<Option<(RecordMeta, JiraSupplementRelation)>, ProjectError> {
    let (site, account) = binding_scope(conn, dek, workspace_id, source_binding_id)?;
    let rows: Vec<(RecordMeta, JiraSupplementRelation)> =
        list_records_by_type(conn, dek, workspace_id, ENTITY_JIRA_SUPPLEMENT)?;
    for (meta, rel) in rows {
        if rel.local_project_id != local_project_id || rel.issue_id != issue_id {
            continue;
        }
        let (rel_site, rel_account) = binding_scope(conn, dek, workspace_id, &rel.source_binding_id)?;
        if rel_site == site && rel_account == account {
            return Ok(Some((meta, rel)));
        }
    }
    Ok(None)
}

/// Idempotent add/update of a Jira range relation. Same unique key returns the
/// existing row (merging `origin` into `origins`). Concurrent revision edits conflict.
pub fn put_jira_range_idempotent(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    mut relation: JiraRangeRelation,
    origin: JiraRangeOrigin,
) -> Result<(RecordMeta, JiraRangeRelation), ProjectError> {
    if relation.local_project_id.is_empty() || relation.jira_project_id.is_empty() {
        return Err(ProjectError::InvalidInput(
            "local_project_id and jira_project_id required".into(),
        ));
    }
    if let Some((meta, mut existing)) = find_jira_range(
        conn,
        dek,
        workspace_id,
        &relation.local_project_id,
        &relation.source_binding_id,
        &relation.jira_project_id,
    )? {
        if !existing.origins.contains(&origin) {
            existing.origins.push(origin);
            if relation.project_key.is_some() {
                existing.project_key = relation.project_key.clone();
            }
            if relation.project_name.is_some() {
                existing.project_name = relation.project_name.clone();
            }
            existing.updated_at = now_rfc3339();
            let meta = put_record(
                conn,
                dek,
                PutRecord {
                    workspace_id,
                    record_id: Some(&meta.id),
                    entity_type: ENTITY_JIRA_RANGE,
                    schema_version: meta.schema_version,
                    expected_revision: Some(meta.revision),
                },
                &existing,
            )?;
            return Ok((meta, existing));
        }
        return Ok((meta, existing));
    }

    if !relation.origins.contains(&origin) {
        relation.origins.push(origin);
    }
    if relation.id.is_empty() {
        relation.id = Uuid::new_v4().to_string();
    }
    relation.workspace_id = workspace_id.to_string();
    let meta = put_record(
        conn,
        dek,
        PutRecord {
            workspace_id,
            record_id: Some(&relation.id),
            entity_type: ENTITY_JIRA_RANGE,
            schema_version: DEFAULT_ENTITY_SCHEMA_VERSION,
            expected_revision: None,
        },
        &relation,
    )?;
    Ok((meta, relation))
}

/// Idempotent add of a local Jira supplement. Same unique key returns the existing row.
pub fn put_jira_supplement_idempotent(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    mut relation: JiraSupplementRelation,
) -> Result<(RecordMeta, JiraSupplementRelation), ProjectError> {
    if relation.local_project_id.is_empty() || relation.issue_id.is_empty() {
        return Err(ProjectError::InvalidInput(
            "local_project_id and issue_id required".into(),
        ));
    }
    if let Some(existing) = find_jira_supplement(
        conn,
        dek,
        workspace_id,
        &relation.local_project_id,
        &relation.source_binding_id,
        &relation.issue_id,
    )? {
        return Ok(existing);
    }
    if relation.id.is_empty() {
        relation.id = Uuid::new_v4().to_string();
    }
    relation.workspace_id = workspace_id.to_string();
    let meta = put_record(
        conn,
        dek,
        PutRecord {
            workspace_id,
            record_id: Some(&relation.id),
            entity_type: ENTITY_JIRA_SUPPLEMENT,
            schema_version: DEFAULT_ENTITY_SCHEMA_VERSION,
            expected_revision: None,
        },
        &relation,
    )?;
    Ok((meta, relation))
}

/// Low-level helpers used by backup import/export.
pub(crate) mod raw {
    use super::*;

    #[derive(Clone, Debug)]
    pub struct WorkspaceExport {
        pub id: String,
        pub format_version: u32,
        pub wrapped_business_key: Encrypted,
        pub created_at: String,
        pub updated_at: String,
    }

    #[derive(Clone, Debug)]
    pub struct RecordExport {
        pub workspace_id: String,
        pub id: String,
        pub entity_type: String,
        pub schema_version: u32,
        pub revision: u64,
        pub payload: Encrypted,
    }

    pub fn list_workspaces(conn: &Connection) -> Result<Vec<WorkspaceExport>, ProjectError> {
        let mut stmt = conn.prepare(
            "SELECT id, format_version, wrapped_business_key, created_at, updated_at
             FROM pm_workspaces ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u32,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, format_version, blob, created_at, updated_at) = row?;
            let wrapped = Encrypted::from_bytes(&blob).map_err(|_| ProjectError::Corrupt)?;
            out.push(WorkspaceExport {
                id,
                format_version,
                wrapped_business_key: wrapped,
                created_at,
                updated_at,
            });
        }
        Ok(out)
    }

    pub fn list_all_records(conn: &Connection) -> Result<Vec<RecordExport>, ProjectError> {
        let mut stmt = conn.prepare(
            "SELECT workspace_id, id, entity_type, schema_version, revision, payload
             FROM pm_records ORDER BY workspace_id, id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)? as u32,
                row.get::<_, i64>(4)? as u64,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (workspace_id, id, entity_type, schema_version, revision, blob) = row?;
            let payload = Encrypted::from_bytes(&blob).map_err(|_| ProjectError::Corrupt)?;
            out.push(RecordExport {
                workspace_id,
                id,
                entity_type,
                schema_version,
                revision,
                payload,
            });
        }
        Ok(out)
    }

    /// Insert a workspace whose business key is already wrapped for `dest_dek`.
    pub fn insert_workspace(
        conn: &Connection,
        row: &WorkspaceExport,
    ) -> Result<(), ProjectError> {
        conn.execute(
            "INSERT INTO pm_workspaces (id, format_version, wrapped_business_key, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &row.id,
                row.format_version as i64,
                row.wrapped_business_key.to_bytes(),
                &row.created_at,
                &row.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn delete_workspace_cascade(
        conn: &Connection,
        workspace_id: &str,
    ) -> Result<(), ProjectError> {
        conn.execute(
            "DELETE FROM pm_records WHERE workspace_id=?1",
            params![workspace_id],
        )?;
        conn.execute(
            "DELETE FROM pm_workspaces WHERE id=?1",
            params![workspace_id],
        )?;
        Ok(())
    }

    pub fn insert_record(conn: &Connection, row: &RecordExport) -> Result<(), ProjectError> {
        conn.execute(
            "INSERT INTO pm_records
               (workspace_id, id, entity_type, schema_version, revision, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &row.workspace_id,
                &row.id,
                &row.entity_type,
                row.schema_version as i64,
                row.revision as i64,
                row.payload.to_bytes(),
            ],
        )?;
        Ok(())
    }

    pub fn workspace_exists(conn: &Connection, workspace_id: &str) -> Result<bool, ProjectError> {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pm_workspaces WHERE id=?1)",
            params![workspace_id],
            |row| row.get(0),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;
    use crate::projects::model::{
        LocalProject, PlatformKind, BindingStatus, ENTITY_LOCAL_PROJECT, ENTITY_SOURCE_BINDING,
    };

    fn setup() -> (Connection, [u8; 32]) {
        let conn = open_memory().unwrap();
        let dek = random_key();
        (conn, dek)
    }

    #[test]
    fn create_workspace_put_get_and_revision_conflict() {
        let (conn, dek) = setup();
        let ws = create_workspace(&conn, &dek).unwrap();
        let project = LocalProject {
            id: String::new(),
            workspace_id: ws.id.clone(),
            short_name: Some("XKRL".into()),
            alias: Some("城南".into()),
            owner: None,
            archived: false,
            revision: 0,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
        };
        let meta = put_record(
            &conn,
            &dek,
            PutRecord {
                workspace_id: &ws.id,
                record_id: None,
                entity_type: ENTITY_LOCAL_PROJECT,
                schema_version: 1,
                expected_revision: None,
            },
            &project,
        )
        .unwrap();
        assert_eq!(meta.revision, 1);

        let (got_meta, got): (_, LocalProject) =
            get_record(&conn, &dek, &ws.id, &meta.id).unwrap();
        assert_eq!(got_meta.revision, 1);
        assert_eq!(got.short_name.as_deref(), Some("XKRL"));

        let mut updated = got;
        updated.alias = Some("新城南".into());
        updated.updated_at = now_rfc3339();
        let meta2 = put_record(
            &conn,
            &dek,
            PutRecord {
                workspace_id: &ws.id,
                record_id: Some(&meta.id),
                entity_type: ENTITY_LOCAL_PROJECT,
                schema_version: 1,
                expected_revision: Some(1),
            },
            &updated,
        )
        .unwrap();
        assert_eq!(meta2.revision, 2);

        // Stale expected revision must conflict.
        let err = put_record(
            &conn,
            &dek,
            PutRecord {
                workspace_id: &ws.id,
                record_id: Some(&meta.id),
                entity_type: ENTITY_LOCAL_PROJECT,
                schema_version: 1,
                expected_revision: Some(1),
            },
            &updated,
        )
        .unwrap_err();
        assert!(matches!(err, ProjectError::Conflict));
    }

    #[test]
    fn wrong_aad_context_fails_to_decrypt() {
        let (conn, dek) = setup();
        let ws = create_workspace(&conn, &dek).unwrap();
        let meta = put_record(
            &conn,
            &dek,
            PutRecord {
                workspace_id: &ws.id,
                record_id: None,
                entity_type: ENTITY_LOCAL_PROJECT,
                schema_version: 1,
                expected_revision: None,
            },
            &LocalProject {
                id: "x".into(),
                workspace_id: ws.id.clone(),
                short_name: None,
                alias: None,
                owner: None,
                archived: false,
                revision: 0,
                created_at: now_rfc3339(),
                updated_at: now_rfc3339(),
            },
        )
        .unwrap();
        // Tamper plaintext revision column → AAD mismatch on read.
        conn.execute(
            "UPDATE pm_records SET revision=99 WHERE workspace_id=?1 AND id=?2",
            params![&ws.id, &meta.id],
        )
        .unwrap();
        let err = get_record::<LocalProject>(&conn, &dek, &ws.id, &meta.id).unwrap_err();
        assert!(matches!(err, ProjectError::Corrupt));
    }

    #[test]
    fn jira_range_and_supplement_uniqueness_helpers() {
        let (conn, dek) = setup();
        let ws = create_workspace(&conn, &dek).unwrap();
        let binding = SourceBinding {
            id: Uuid::new_v4().to_string(),
            workspace_id: ws.id.clone(),
            platform: PlatformKind::ZoomkeyJira,
            site: "https://jira.example/".into(),
            account_scope: "user-1".into(),
            credential_entry_id: "cred-1".into(),
            auth_revision: 1,
            status: BindingStatus::Active,
            revision: 0,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
        };
        put_record(
            &conn,
            &dek,
            PutRecord {
                workspace_id: &ws.id,
                record_id: Some(&binding.id),
                entity_type: ENTITY_SOURCE_BINDING,
                schema_version: 1,
                expected_revision: None,
            },
            &binding,
        )
        .unwrap();

        let range = JiraRangeRelation {
            id: String::new(),
            workspace_id: ws.id.clone(),
            local_project_id: "proj-1".into(),
            source_binding_id: binding.id.clone(),
            jira_project_id: "10001".into(),
            project_key: Some("XKRL".into()),
            project_name: Some("城南".into()),
            origins: vec![],
            revision: 0,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
        };
        let (m1, r1) = put_jira_range_idempotent(
            &conn,
            &dek,
            &ws.id,
            range.clone(),
            JiraRangeOrigin::Auto,
        )
        .unwrap();
        assert!(r1.origins.contains(&JiraRangeOrigin::Auto));
        let (m2, r2) = put_jira_range_idempotent(
            &conn,
            &dek,
            &ws.id,
            range,
            JiraRangeOrigin::Manual,
        )
        .unwrap();
        assert_eq!(m1.id, m2.id);
        assert!(r2.origins.contains(&JiraRangeOrigin::Auto));
        assert!(r2.origins.contains(&JiraRangeOrigin::Manual));

        let supp = JiraSupplementRelation {
            id: String::new(),
            workspace_id: ws.id.clone(),
            local_project_id: "proj-1".into(),
            source_binding_id: binding.id.clone(),
            issue_id: "20001".into(),
            issue_key: Some("XKRL-1".into()),
            revision: 0,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
        };
        let (s1, _) = put_jira_supplement_idempotent(&conn, &dek, &ws.id, supp.clone()).unwrap();
        let (s2, _) = put_jira_supplement_idempotent(&conn, &dek, &ws.id, supp).unwrap();
        assert_eq!(s1.id, s2.id);
    }

    #[test]
    fn ensure_schema_is_idempotent() {
        let conn = open_memory().unwrap();
        ensure_schema(&conn).unwrap();
        ensure_schema(&conn).unwrap();
        let dek = random_key();
        create_workspace(&conn, &dek).unwrap();
    }
}
