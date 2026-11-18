//! Projects extension for [`crate::backup::BackupEnvelope`] v3.
//!
//! Record payloads stay encrypted under the per-workspace business key. On restore
//! into a vault with a different DEK, only the workspace key wrap is re-sealed —
//! record ciphertext is copied as-is (AAD still binds workspace/record metadata).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{unwrap_key_with_aad, wrap_key_with_aad, Encrypted};
use rusqlite::Connection;

use super::model::{MODULE_ID, WORKSPACE_FORMAT_VERSION};
use super::store::{raw, ProjectError};

/// Independent schema version for the projects backup extension (not envelope version).
pub const PROJECTS_BACKUP_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceBackup {
    pub id: String,
    pub format_version: u32,
    pub wrapped_business_key: Encrypted,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecordBackup {
    pub workspace_id: String,
    pub id: String,
    pub entity_type: String,
    pub schema_version: u32,
    pub revision: u64,
    pub payload: Encrypted,
}

/// Optional projects block inside BackupEnvelope v3.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectsBackupExtension {
    pub schema_version: u32,
    pub workspaces: Vec<WorkspaceBackup>,
    pub records: Vec<RecordBackup>,
}

impl ProjectsBackupExtension {
    pub fn is_empty(&self) -> bool {
        self.workspaces.is_empty() && self.records.is_empty()
    }
}

fn key_wrap_aad(workspace_id: &str, format_version: u32) -> String {
    format!("{MODULE_ID}|keywrap|{workspace_id}|v{format_version}")
}

/// Snapshot all project tables. Returns `None` when the vault has no workspaces
/// (caller may still emit envelope v3 with `projects: None`).
pub fn export_extension(
    conn: &Connection,
    dek: &[u8; 32],
) -> Result<Option<ProjectsBackupExtension>, ProjectError> {
    let workspaces = raw::list_workspaces(conn)?;
    if workspaces.is_empty() {
        return Ok(None);
    }
    // Verify every wrapped key opens under the export DEK before shipping.
    for ws in &workspaces {
        let aad = key_wrap_aad(&ws.id, ws.format_version);
        let _ = Zeroizing::new(unwrap_key_with_aad(
            dek,
            &ws.wrapped_business_key,
            aad.as_bytes(),
        )?);
    }
    let records = raw::list_all_records(conn)?;
    for rec in &records {
        if !workspaces.iter().any(|w| w.id == rec.workspace_id) {
            return Err(ProjectError::Corrupt);
        }
    }
    Ok(Some(ProjectsBackupExtension {
        schema_version: PROJECTS_BACKUP_SCHEMA_VERSION,
        workspaces: workspaces
            .into_iter()
            .map(|w| WorkspaceBackup {
                id: w.id,
                format_version: w.format_version,
                wrapped_business_key: w.wrapped_business_key,
                created_at: w.created_at,
                updated_at: w.updated_at,
            })
            .collect(),
        records: records
            .into_iter()
            .map(|r| RecordBackup {
                workspace_id: r.workspace_id,
                id: r.id,
                entity_type: r.entity_type,
                schema_version: r.schema_version,
                revision: r.revision,
                payload: r.payload,
            })
            .collect(),
    }))
}

/// Validate ciphertext wrappers and referential integrity without writing.
pub fn validate_extension(
    ext: &ProjectsBackupExtension,
    source_dek: &[u8; 32],
) -> Result<(), ProjectError> {
    if ext.schema_version == 0 || ext.schema_version > PROJECTS_BACKUP_SCHEMA_VERSION {
        return Err(ProjectError::Corrupt);
    }
    if ext.workspaces.len() > 10_000 || ext.records.len() > 500_000 {
        return Err(ProjectError::Corrupt);
    }
    let mut ids = std::collections::HashSet::new();
    for ws in &ext.workspaces {
        if ws.id.trim().is_empty() || !ids.insert(ws.id.as_str()) {
            return Err(ProjectError::Corrupt);
        }
        if ws.format_version == 0 || ws.format_version > WORKSPACE_FORMAT_VERSION + 8 {
            return Err(ProjectError::Corrupt);
        }
        let aad = key_wrap_aad(&ws.id, ws.format_version);
        let _ = Zeroizing::new(unwrap_key_with_aad(
            source_dek,
            &ws.wrapped_business_key,
            aad.as_bytes(),
        )?);
    }
    let mut record_ids = std::collections::HashSet::new();
    for rec in &ext.records {
        if rec.id.trim().is_empty()
            || rec.entity_type.trim().is_empty()
            || !ids.contains(rec.workspace_id.as_str())
            || !record_ids.insert((rec.workspace_id.as_str(), rec.id.as_str()))
            || rec.revision == 0
        {
            return Err(ProjectError::Corrupt);
        }
        // Ensure nonce||ciphertext shape; content authenticated later by business key AAD.
        if rec.payload.ciphertext.len() < 16 {
            return Err(ProjectError::Corrupt);
        }
    }
    Ok(())
}

/// Import projects into `conn`, re-wrapping business keys from `source_dek` to `dest_dek`.
///
/// - `replace_existing`: when true, delete a colliding workspace (and its records) first.
/// - when false, skip workspaces that already exist (and skip their records).
///
/// A missing extension must not call this — callers leave target projects untouched.
pub fn import_extension(
    conn: &Connection,
    source_dek: &[u8; 32],
    dest_dek: &[u8; 32],
    ext: &ProjectsBackupExtension,
    replace_existing: bool,
) -> Result<(usize, usize), ProjectError> {
    validate_extension(ext, source_dek)?;
    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut accepted_workspaces = std::collections::HashSet::new();

    for ws in &ext.workspaces {
        let exists = raw::workspace_exists(conn, &ws.id)?;
        if exists && !replace_existing {
            skipped += 1;
            continue;
        }
        if exists && replace_existing {
            raw::delete_workspace_cascade(conn, &ws.id)?;
        }
        let aad = key_wrap_aad(&ws.id, ws.format_version);
        let business = Zeroizing::new(unwrap_key_with_aad(
            source_dek,
            &ws.wrapped_business_key,
            aad.as_bytes(),
        )?);
        let rewrapped = wrap_key_with_aad(dest_dek, &business, aad.as_bytes())?;
        raw::insert_workspace(
            conn,
            &raw::WorkspaceExport {
                id: ws.id.clone(),
                format_version: ws.format_version,
                wrapped_business_key: rewrapped,
                created_at: ws.created_at.clone(),
                updated_at: ws.updated_at.clone(),
            },
        )?;
        accepted_workspaces.insert(ws.id.clone());
        imported += 1;
    }

    for rec in &ext.records {
        if !accepted_workspaces.contains(&rec.workspace_id) {
            // Workspace was skipped (already present, no replace) — skip its records too.
            skipped += 1;
            continue;
        }
        raw::insert_record(
            conn,
            &raw::RecordExport {
                workspace_id: rec.workspace_id.clone(),
                id: rec.id.clone(),
                entity_type: rec.entity_type.clone(),
                schema_version: rec.schema_version,
                revision: rec.revision,
                payload: rec.payload.clone(),
            },
        )?;
        imported += 1;
    }
    Ok((imported, skipped))
}
