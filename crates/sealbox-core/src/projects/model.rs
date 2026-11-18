//! Product-facing project workbench types for the query MVP.
//!
//! UI copy says "ERP"; adapter identifiers may still use `zoomkey_crm` / CRM module
//! names from the existing ZoomKey integration. Remote IDs are always strings and
//! must be paired with site + account scope — never numbers or display names alone.

use serde::{Deserialize, Serialize};

/// Logical module id used in AAD and backup comments.
pub const MODULE_ID: &str = "sealbox-projects";

/// Current `pm_workspaces.format_version` written by this build.
pub const WORKSPACE_FORMAT_VERSION: u32 = 1;

/// Default schema_version for newly written entity payloads.
pub const DEFAULT_ENTITY_SCHEMA_VERSION: u32 = 1;

// --- entity_type values stored in pm_records ---------------------------------

pub const ENTITY_SOURCE_BINDING: &str = "source_binding";
pub const ENTITY_LOCAL_PROJECT: &str = "local_project";
pub const ENTITY_PROJECT_SOURCE_LINK: &str = "project_source_link";
pub const ENTITY_LOCAL_CUSTOMER_LINK: &str = "local_customer_link";
pub const ENTITY_JIRA_RANGE: &str = "jira_range";
pub const ENTITY_JIRA_SUPPLEMENT: &str = "jira_supplement";
pub const ENTITY_SYNC_STATE: &str = "sync_state";
pub const ENTITY_REMOTE_CACHE: &str = "remote_cache";

/// Platform kind on a [`SourceBinding`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformKind {
    /// ZoomKey CRM / ERP. Stored value stays `zoomkey_crm` for adapter continuity.
    ZoomkeyCrm,
    ZoomkeyJira,
    #[serde(other)]
    Unknown,
}

/// Capability / auth status for a source binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingStatus {
    Active,
    NeedsRebind,
    Disabled,
    #[serde(other)]
    Unknown,
}

/// Customer role on ERP snapshot / local customer link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomerRole {
    /// 签约客户
    Contracting,
    /// 实际使用方
    EndUser,
    #[serde(other)]
    Unknown,
}

/// How a Jira project entered the effective range (auto ∩ manual may coexist).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JiraRangeOrigin {
    Auto,
    Manual,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    pub id: String,
    pub timezone: String,
    /// Optional calendar preference id / name; encrypted with other workspace settings later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar: Option<String>,
    pub schema_version: u32,
    pub created_at: String,
    pub updated_at: String,
}

/// Authorized connection to one ERP or Jira site/account scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceBinding {
    pub id: String,
    pub workspace_id: String,
    pub platform: PlatformKind,
    /// Normalized site URL; keep business-meaningful instance path.
    pub site: String,
    /// Verified account scope identity (not a display name).
    pub account_scope: String,
    /// Vault entry id holding credentials — never the secret itself.
    pub credential_entry_id: String,
    /// Profile / binding revision observed when authorized.
    pub auth_revision: u64,
    pub status: BindingStatus,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// Local project adopted into "我的项目".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalProject {
    pub id: String,
    pub workspace_id: String,
    /// Optional short code used for Jira project-key auto match (e.g. `XKRL`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    /// Local display alias; platform name lives on the source link / cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub archived: bool,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// Link from a local project to one remote ERP/CRM project identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSourceLink {
    pub id: String,
    pub workspace_id: String,
    pub local_project_id: String,
    pub source_binding_id: String,
    /// Remote module name, e.g. `Project`.
    pub remote_module: String,
    /// String remote id (e.g. `30x564318`).
    pub remote_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_name: Option<String>,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// Target of a local customer association: ERP customer ref or hand-entered name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LocalCustomerTarget {
    Erp {
        source_binding_id: String,
        remote_module: String,
        remote_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_name: Option<String>,
    },
    Manual {
        name: String,
    },
}

/// Local customer association for one role on a local project.
/// MVP: at most one current link per (local_project, role).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalCustomerLink {
    pub id: String,
    pub workspace_id: String,
    pub local_project_id: String,
    pub role: CustomerRole,
    pub target: LocalCustomerTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// One Jira project in a local project's effective query range.
///
/// Uniqueness key: `(local_project_id, jira site/account scope, jira_project_id)`.
/// Origins may include both auto and manual for the same project.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraRangeRelation {
    pub id: String,
    pub workspace_id: String,
    pub local_project_id: String,
    pub source_binding_id: String,
    /// Stable Jira project id (not the key).
    pub jira_project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
    /// Non-empty; both Auto and Manual may be present after an idempotent add.
    pub origins: Vec<JiraRangeOrigin>,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// Locally supplemented Jira issue that ERP did not already associate.
///
/// Uniqueness key: `(local_project_id, jira site/account scope, issue_id)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraSupplementRelation {
    pub id: String,
    pub workspace_id: String,
    pub local_project_id: String,
    pub source_binding_id: String,
    /// Stable issue id; key is a snapshot for display.
    pub issue_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_key: Option<String>,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// Sync cursor / success timestamps for one binding + query kind (stub for A1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncState {
    pub id: String,
    pub workspace_id: String,
    pub source_binding_id: String,
    pub query_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_full_success_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<String>,
    #[serde(default)]
    pub partition_status: String,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// Encrypted remote cache envelope (stub). Body is opaque JSON bytes inside this payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteCache {
    pub id: String,
    pub workspace_id: String,
    pub source_binding_id: String,
    pub cache_kind: String,
    pub cache_key: String,
    /// Opaque cached document (already part of the encrypted record payload).
    pub body: serde_json::Value,
    pub fetched_at: String,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// Normalize a project short name for Jira key substring matching:
/// `trim` then uppercase. Empty result means no auto-match items.
pub fn normalize_short_name(short: &str) -> String {
    short.trim().to_uppercase()
}

/// Whether `project_key` is matched by a normalized short name (substring, case-insensitive).
pub fn short_name_matches_project_key(normalized_short: &str, project_key: &str) -> bool {
    if normalized_short.is_empty() {
        return false;
    }
    project_key.to_uppercase().contains(normalized_short)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_name_normalize_and_match() {
        assert_eq!(normalize_short_name("  xkrl "), "XKRL");
        assert!(short_name_matches_project_key("XKRL", "XKRL"));
        assert!(short_name_matches_project_key("XKRL", "XKRLWXM"));
        assert!(!short_name_matches_project_key("", "XKRL"));
        assert!(!short_name_matches_project_key("XKRL", "OTHER"));
    }
}
