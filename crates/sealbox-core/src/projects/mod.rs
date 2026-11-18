//! Project workbench storage: encrypted local project records inside the vault DB.
//!
//! Stage A1 only — models, SQLite schema, AAD-bound crypto, and BackupEnvelope v3
//! extension. CRM/Jira adapters and Vue UI live elsewhere.

pub mod backup;
pub mod model;
pub mod store;

pub use backup::{
    ProjectsBackupExtension, RecordBackup, WorkspaceBackup, PROJECTS_BACKUP_SCHEMA_VERSION,
};
pub use model::*;
pub use store::{
    create_workspace, delete_record, ensure_schema, find_jira_range, find_jira_supplement,
    get_record, get_workspace, list_records_by_type, list_workspaces, put_jira_range_idempotent,
    put_jira_supplement_idempotent, put_record, rewrap_workspace_key, unwrap_business_key,
    ProjectError, PutRecord, RecordMeta, WorkspaceRow,
};
