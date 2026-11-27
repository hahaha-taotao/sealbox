//! Project workbench service: vault session + sealbox-core encrypted store.
//!
//! Remote reads use structured ZoomKey adapters when a real SourceBinding /
//! credential is available (MCP switch not required). Without credentials the
//! offline PROJ3733 fixture is used. Live bindings never silently fall back to
//! the fixture on network/auth failure.

use std::sync::Mutex;

use rusqlite::Connection;
use sealbox_core::projects::{
    create_workspace, delete_record, find_jira_range, get_record, list_records_by_type,
    list_workspaces, normalize_short_name, put_jira_range_idempotent,
    put_jira_supplement_idempotent, put_record, short_name_matches_project_key, BindingStatus,
    CustomerRole, JiraRangeOrigin, JiraRangeRelation, JiraSupplementRelation, LocalCustomerLink,
    LocalCustomerTarget, LocalProject, PlatformKind, ProjectError, ProjectSourceLink, PutRecord,
    SourceBinding, DEFAULT_ENTITY_SCHEMA_VERSION, ENTITY_JIRA_RANGE, ENTITY_JIRA_SUPPLEMENT,
    ENTITY_LOCAL_CUSTOMER_LINK, ENTITY_LOCAL_PROJECT, ENTITY_PROJECT_SOURCE_LINK,
    ENTITY_SOURCE_BINDING,
};
use uuid::Uuid;

use crate::session::Session;
use crate::vault::SecretPayload;
use crate::zoomkey;

use super::adapters::{self, crm as crm_adapter, jira as jira_adapter};
use super::dto::{
    AdoptRequest, AdoptResultDto, BindCustomerRequest, CustomerRoleDto, DevTaskDto,
    FactCustomersDto, JiraIssueRequest, JiraRangeRequest, LocalCustomerBindingDto,
    LocalCustomerKind, LocalCustomersDto, LocalProjectDto, MutationMessageDto, ProjectDetailDto,
    ProjectSummaryDto, RemoteSearchPageDto, SearchRemoteRequest, SetShortNameRequest,
    SourceBindingSummaryDto, UnbindCustomerRequest,
};
use super::fixture::{self, FIXTURE_ACCOUNT_SCOPE, FIXTURE_CREDENTIAL_REF, FIXTURE_CRM_SITE,
    FIXTURE_JIRA_SITE};

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn map_err(e: ProjectError) -> String {
    match e {
        ProjectError::NotFound => "项目记录不存在".into(),
        ProjectError::Conflict => "项目版本冲突，请刷新后重试".into(),
        ProjectError::Duplicate => "项目关系已存在".into(),
        ProjectError::InvalidInput(msg) => format!("参数无效：{msg}"),
        ProjectError::Corrupt => "项目数据损坏".into(),
        other => other.to_string(),
    }
}

/// Session-scoped workspace id cache — cleared on vault lock.
static CACHED_WORKSPACE: Mutex<Option<String>> = Mutex::new(None);

pub fn clear_session_cache() {
    if let Ok(mut guard) = CACHED_WORKSPACE.lock() {
        *guard = None;
    }
}

fn cache_workspace(id: &str) {
    if let Ok(mut guard) = CACHED_WORKSPACE.lock() {
        *guard = Some(id.to_string());
    }
}

fn cached_workspace() -> Option<String> {
    CACHED_WORKSPACE.lock().ok().and_then(|g| g.clone())
}

fn role_core(role: &CustomerRoleDto) -> CustomerRole {
    match role {
        CustomerRoleDto::Contract => CustomerRole::Contracting,
        CustomerRoleDto::User => CustomerRole::EndUser,
    }
}

fn role_matches(stored: &CustomerRole, want: &CustomerRoleDto) -> bool {
    matches!(
        (stored, want),
        (CustomerRole::Contracting, CustomerRoleDto::Contract)
            | (CustomerRole::EndUser, CustomerRoleDto::User)
    )
}

/// Ensure one workspace exists for this vault (MVP: single workspace).
pub fn ensure_workspace(conn: &Connection, dek: &[u8; 32]) -> Result<String, String> {
    if let Some(id) = cached_workspace() {
        if list_workspaces(conn)
            .map_err(map_err)?
            .iter()
            .any(|w| w.id == id)
        {
            return Ok(id);
        }
    }
    let existing = list_workspaces(conn).map_err(map_err)?;
    if let Some(first) = existing.into_iter().next() {
        cache_workspace(&first.id);
        return Ok(first.id);
    }
    let ws = create_workspace(conn, dek).map_err(map_err)?;
    cache_workspace(&ws.id);
    Ok(ws.id)
}

struct WorkspaceBindings {
    crm: SourceBinding,
    jira: SourceBinding,
}

/// Instance identity, retaining any CRM installation path before webservice.php.
fn site_from_base(base_url: &str) -> String {
    let base = base_url
        .trim()
        .split(['#', '?'])
        .next()
        .unwrap_or_default()
        .trim_end_matches('/');
    base.strip_suffix("/webservice.php")
        .unwrap_or(base)
        .to_string()
}

fn account_scope_for(
    session: &Session,
    credential_id: &str,
    candidate_account: Option<&str>,
) -> String {
    if let Some(account) = candidate_account.map(str::trim).filter(|s| !s.is_empty()) {
        return account.to_string();
    }
    if let (Ok(vault), Ok(dek)) = (session.vault(), session.dek()) {
        if let Ok(SecretPayload::ApiToken {
            account: Some(account),
            ..
        }) = vault.get_active_secret(dek, credential_id)
        {
            let account = account.trim();
            if !account.is_empty() {
                return account.to_string();
            }
        }
    }
    format!("cred:{credential_id}")
}

fn find_platform_binding<'a>(
    bindings: &'a [SourceBinding],
    platform: PlatformKind,
) -> Option<&'a SourceBinding> {
    let matched: Vec<&'a SourceBinding> = bindings
        .iter()
        .filter(|b| b.platform == platform)
        .collect();
    matched
        .iter()
        .copied()
        .find(|b| !adapters::is_fixture_binding(b) && b.status == BindingStatus::Active)
        .or_else(|| {
            matched
                .iter()
                .copied()
                .find(|b| !adapters::is_fixture_binding(b))
        })
        .or_else(|| {
            matched
                .iter()
                .copied()
                .find(|b| adapters::is_fixture_binding(b))
        })
}

fn upsert_live_binding(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    platform: PlatformKind,
    site: &str,
    account_scope: &str,
    credential_entry_id: &str,
) -> Result<SourceBinding, String> {
    let listed: Vec<(sealbox_core::projects::RecordMeta, SourceBinding)> =
        list_records_by_type(conn, dek, workspace_id, ENTITY_SOURCE_BINDING).map_err(map_err)?;

    if let Some((meta, mut existing)) = listed.into_iter().find(|(_, b)| {
        b.platform == platform
            && !adapters::is_fixture_binding(b)
            && b.site == site
            && b.account_scope == account_scope
    }) {
        let dirty = existing.credential_entry_id != credential_entry_id
            || existing.status != BindingStatus::Active;
        if dirty {
            existing.credential_entry_id = credential_entry_id.to_string();
            existing.status = BindingStatus::Active;
            existing.updated_at = now_rfc3339();
            put_record(
                conn,
                dek,
                PutRecord {
                    workspace_id,
                    record_id: Some(&meta.id),
                    entity_type: ENTITY_SOURCE_BINDING,
                    schema_version: meta.schema_version,
                    expected_revision: Some(meta.revision),
                },
                &existing,
            )
            .map_err(map_err)?;
        }
        return Ok(existing);
    }

    let now = now_rfc3339();
    let binding = SourceBinding {
        id: Uuid::new_v4().to_string(),
        workspace_id: workspace_id.to_string(),
        platform,
        site: site.to_string(),
        account_scope: account_scope.to_string(),
        credential_entry_id: credential_entry_id.to_string(),
        auth_revision: 1,
        status: BindingStatus::Active,
        revision: 0,
        created_at: now.clone(),
        updated_at: now,
    };
    put_record(
        conn,
        dek,
        PutRecord {
            workspace_id,
            record_id: Some(&binding.id),
            entity_type: ENTITY_SOURCE_BINDING,
            schema_version: DEFAULT_ENTITY_SCHEMA_VERSION,
            expected_revision: None,
        },
        &binding,
    )
    .map_err(map_err)?;
    Ok(binding)
}

fn ensure_fixture_platform(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    platform: PlatformKind,
) -> Result<SourceBinding, String> {
    let (site, _) = match platform {
        PlatformKind::ZoomkeyCrm => (FIXTURE_CRM_SITE, FIXTURE_ACCOUNT_SCOPE),
        PlatformKind::ZoomkeyJira => (FIXTURE_JIRA_SITE, FIXTURE_ACCOUNT_SCOPE),
        PlatformKind::Unknown => {
            return Err("未知平台，无法创建夹具绑定".into());
        }
    };
    let listed: Vec<(_, SourceBinding)> =
        list_records_by_type(conn, dek, workspace_id, ENTITY_SOURCE_BINDING).map_err(map_err)?;
    if let Some((_, existing)) = listed.iter().find(|(_, b)| {
        b.platform == platform
            && b.site == site
            && b.account_scope == FIXTURE_ACCOUNT_SCOPE
            && adapters::is_fixture_binding(b)
    }) {
        return Ok(existing.clone());
    }

    let now = now_rfc3339();
    let binding = SourceBinding {
        id: Uuid::new_v4().to_string(),
        workspace_id: workspace_id.to_string(),
        platform,
        site: site.into(),
        account_scope: FIXTURE_ACCOUNT_SCOPE.into(),
        credential_entry_id: FIXTURE_CREDENTIAL_REF.into(),
        auth_revision: 1,
        status: BindingStatus::Active,
        revision: 0,
        created_at: now.clone(),
        updated_at: now,
    };
    put_record(
        conn,
        dek,
        PutRecord {
            workspace_id,
            record_id: Some(&binding.id),
            entity_type: ENTITY_SOURCE_BINDING,
            schema_version: DEFAULT_ENTITY_SCHEMA_VERSION,
            expected_revision: None,
        },
        &binding,
    )
    .map_err(map_err)?;
    Ok(binding)
}

fn pick_credential(
    policy_credential_id: &str,
    candidates: &[zoomkey::ZoomkeyCredentialOption],
) -> Option<(String, Option<String>)> {
    let policy_id = policy_credential_id.trim();
    if !policy_id.is_empty() {
        let account = candidates
            .iter()
            .find(|c| c.id == policy_id)
            .and_then(|c| c.account.clone());
        return Some((policy_id.to_string(), account));
    }
    candidates
        .first()
        .map(|c| (c.id.clone(), c.account.clone()))
}

fn select_crm_credential<'a>(
    policy_id: &str,
    candidates: &'a [zoomkey::ZoomkeyCredentialOption],
    mut profile_origin: impl FnMut(&str) -> Result<Option<String>, String>,
) -> Result<Option<(&'a zoomkey::ZoomkeyCredentialOption, Option<String>)>, String> {
    let policy_id = policy_id.trim();
    if !policy_id.is_empty() {
        let selected = candidates
            .iter()
            .find(|c| c.id == policy_id)
            .ok_or_else(|| "已选 ZoomKey CRM 凭据已失效或服务类型不符，请重新选择".to_string())?;
        return Ok(Some((selected, profile_origin(&selected.id)?)));
    }
    let mut selected = None;
    for candidate in candidates {
        if let Some(origin) = profile_origin(&candidate.id)? {
            if selected.is_some() {
                return Err(
                    "有多条已配置的 ZoomKey CRM 凭据，请在 ZoomKey 设置中明确选择一条".into(),
                );
            }
            selected = Some((candidate, Some(origin)));
        }
    }
    if selected.is_none() && !candidates.is_empty() {
        return Err("请为 ZoomKey CRM 凭据配置 Profile，或在 ZoomKey 设置中选择凭据和证书".into());
    }
    Ok(selected)
}

/// Resolve CRM/Jira SourceBindings from ZoomKey policy + vault candidates.
/// A live configuration error is not an excuse to switch CRM accounts or use a fixture.
fn resolve_bindings(session: &Session) -> Result<WorkspaceBindings, String> {
    let dek = *session.dek().map_err(|e| e.to_string())?;
    let (workspace_id, policy) = {
        let vault = session.vault().map_err(|e| e.to_string())?;
        let workspace_id = ensure_workspace(vault.project_conn(), &dek)?;
        let policy = zoomkey::load_policy(vault, &dek);
        (workspace_id, policy)
    };
    let candidates = zoomkey::list_candidates(session)?;

    let vault = session.vault().map_err(|e| e.to_string())?;
    let crm_plan = select_crm_credential(
        &policy.crm.credential_id,
        &candidates.crm_credentials,
        |id| {
            let profile = vault
                .credential_profile(&dek, id)
                .map_err(|_| "无法读取 ZoomKey CRM 凭据的 Profile".to_string())?;
            Ok(profile
                .filter(|p| p.adapter == "zoomkey_crm")
                .map(|p| p.origin))
        },
    )?
    .map(|(credential, origin)| {
        let site = site_from_base(origin.as_deref().unwrap_or(&policy.crm.base_url));
        let scope = account_scope_for(session, &credential.id, credential.account.as_deref());
        (site, scope, credential.id.clone())
    });
    let jira_plan =
        pick_credential(&policy.jira.credential_id, &candidates.jira_credentials).map(
            |(cred_id, account)| {
                let mut site = site_from_base(&policy.jira.base_url);
                if site.is_empty() {
                    site = site_from_base(zoomkey::DEFAULT_JIRA_BASE);
                }
                let scope = account_scope_for(session, &cred_id, account.as_deref());
                (site, scope, cred_id)
            },
        );

    let vault = session.vault().map_err(|e| e.to_string())?;
    let conn = vault.project_conn();

    let crm = if let Some((site, scope, cred_id)) = crm_plan {
        upsert_live_binding(
            conn,
            &dek,
            &workspace_id,
            PlatformKind::ZoomkeyCrm,
            &site,
            &scope,
            &cred_id,
        )?
    } else {
        ensure_fixture_platform(conn, &dek, &workspace_id, PlatformKind::ZoomkeyCrm)?
    };

    let jira = if let Some((site, scope, cred_id)) = jira_plan {
        upsert_live_binding(
            conn,
            &dek,
            &workspace_id,
            PlatformKind::ZoomkeyJira,
            &site,
            &scope,
            &cred_id,
        )?
    } else {
        ensure_fixture_platform(conn, &dek, &workspace_id, PlatformKind::ZoomkeyJira)?
    };

    Ok(WorkspaceBindings { crm, jira })
}

/// Prefer an existing live binding, else fixture — for adopt/mutations that only have conn.
fn load_workspace_bindings(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
) -> Result<WorkspaceBindings, String> {
    let listed: Vec<(_, SourceBinding)> =
        list_records_by_type(conn, dek, workspace_id, ENTITY_SOURCE_BINDING).map_err(map_err)?;
    let bindings: Vec<SourceBinding> = listed.into_iter().map(|(_, b)| b).collect();

    let crm = match find_platform_binding(&bindings, PlatformKind::ZoomkeyCrm) {
        Some(b) => b.clone(),
        None => ensure_fixture_platform(conn, dek, workspace_id, PlatformKind::ZoomkeyCrm)?,
    };
    let jira = match find_platform_binding(&bindings, PlatformKind::ZoomkeyJira) {
        Some(b) => b.clone(),
        None => ensure_fixture_platform(conn, dek, workspace_id, PlatformKind::ZoomkeyJira)?,
    };
    Ok(WorkspaceBindings { crm, jira })
}

fn binding_summary(b: &SourceBinding) -> SourceBindingSummaryDto {
    let platform = match b.platform {
        PlatformKind::ZoomkeyCrm => "zoomkey_crm",
        PlatformKind::ZoomkeyJira => "zoomkey_jira",
        PlatformKind::Unknown => "unknown",
    };
    let status = match b.status {
        BindingStatus::Active => "active",
        BindingStatus::NeedsRebind => "needs_rebind",
        BindingStatus::Disabled => "disabled",
        BindingStatus::Unknown => "unknown",
    };
    SourceBindingSummaryDto {
        id: b.id.clone(),
        platform: platform.into(),
        site: b.site.clone(),
        account_scope: b.account_scope.clone(),
        status: status.into(),
        credential_entry_id: b.credential_entry_id.clone(),
        is_fixture: adapters::is_fixture_binding(b),
    }
}

pub fn sources_list(session: &Session) -> Result<Vec<SourceBindingSummaryDto>, String> {
    let bindings = resolve_bindings(session)?;
    Ok(vec![
        binding_summary(&bindings.crm),
        binding_summary(&bindings.jira),
    ])
}

struct AdoptedRef {
    local_project_id: String,
    remote_id: String,
    short_name: String,
    revision: u64,
}

fn same_crm_source(left: &SourceBinding, right: &SourceBinding) -> bool {
    left.platform == PlatformKind::ZoomkeyCrm
        && right.platform == PlatformKind::ZoomkeyCrm
        && left.site == right.site
        && left.account_scope == right.account_scope
        && adapters::is_fixture_binding(left) == adapters::is_fixture_binding(right)
}

fn find_adopted_by_remote(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    crm_binding: &SourceBinding,
    remote_id: &str,
) -> Result<Option<AdoptedRef>, String> {
    let links: Vec<(_, ProjectSourceLink)> =
        list_records_by_type(conn, dek, workspace_id, ENTITY_PROJECT_SOURCE_LINK)
            .map_err(map_err)?;
    for (_link_meta, link) in links {
        if link.remote_id != remote_id {
            continue;
        }
        let Ok((_, binding)): Result<(sealbox_core::projects::RecordMeta, SourceBinding), _> =
            get_record(conn, dek, workspace_id, &link.source_binding_id)
        else {
            continue;
        };
        if !same_crm_source(&binding, crm_binding) {
            continue;
        }
        let (proj_meta, project): (_, LocalProject) =
            get_record(conn, dek, workspace_id, &link.local_project_id).map_err(map_err)?;
        return Ok(Some(AdoptedRef {
            local_project_id: link.local_project_id,
            remote_id: link.remote_id,
            short_name: project.short_name.unwrap_or_default(),
            revision: proj_meta.revision,
        }));
    }
    Ok(None)
}

fn list_adopted(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
) -> Result<Vec<AdoptedRef>, String> {
    let links: Vec<(_, ProjectSourceLink)> =
        list_records_by_type(conn, dek, workspace_id, ENTITY_PROJECT_SOURCE_LINK)
            .map_err(map_err)?;
    let mut out = Vec::new();
    for (_link_meta, link) in links {
        let Ok((proj_meta, project)): Result<(sealbox_core::projects::RecordMeta, LocalProject), _> =
            get_record(conn, dek, workspace_id, &link.local_project_id)
        else {
            continue;
        };
        out.push(AdoptedRef {
            local_project_id: link.local_project_id,
            remote_id: link.remote_id,
            short_name: project
                .short_name
                .unwrap_or_else(|| fixture::DEFAULT_SHORT_NAME.into()),
            revision: proj_meta.revision,
        });
    }
    Ok(out)
}

/// Live CRM search without touching the project store (avoids Session/conn borrow overlap).
fn search_remote_live_fetch(
    session: &Session,
    crm_binding: &SourceBinding,
    keyword: &str,
) -> Result<(Vec<serde_json::Value>, Vec<String>), String> {
    if adapters::is_fixture_binding(crm_binding) {
        return Err("fixture binding".into());
    }
    let runtime =
        adapters::open_desktop_runtime(session, crm_binding).map_err(|e| e.message)?;
    crm_adapter::search_projects(&runtime, keyword, 50).map_err(|e| e.message)
}

fn stamp_search_adopted(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    crm: &SourceBinding,
    records: &[serde_json::Value],
    mut warnings: Vec<String>,
) -> Result<(Vec<ProjectSummaryDto>, Vec<String>), String> {
    let mut items = Vec::new();
    for record in records {
        let mapped = match crm_adapter::map_project(record) {
            Ok(mapped) => mapped,
            Err(e) => {
                if !warnings.contains(&e) {
                    warnings.push(e);
                }
                continue;
            }
        };
        let adopted =
            find_adopted_by_remote(conn, dek, workspace_id, crm, &mapped.remote_id)?;
        let short = adopted
            .as_ref()
            .map(|a| a.short_name.clone())
            .unwrap_or_default();
        items.push(crm_adapter::map_project_summary(
            &mapped,
            adopted.is_some(),
            adopted.as_ref().map(|a| a.local_project_id.clone()),
            &short,
        ));
    }
    Ok((items, warnings))
}

fn search_remote_fixture(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    crm: &SourceBinding,
    keyword: &str,
) -> Result<(Vec<ProjectSummaryDto>, Vec<String>), String> {
    let adopted =
        find_adopted_by_remote(conn, dek, workspace_id, crm, fixture::REMOTE_ID)?;
    let items = if fixture::keyword_matches(keyword) {
        let short = adopted
            .as_ref()
            .map(|a| a.short_name.as_str())
            .unwrap_or(fixture::DEFAULT_SHORT_NAME);
        vec![fixture::to_summary(
            adopted.is_some(),
            adopted.as_ref().map(|a| a.local_project_id.clone()),
            short,
        )]
    } else {
        vec![]
    };
    let warnings = if items.is_empty() {
        vec!["离线演示数据中没有匹配项目".into()]
    } else {
        vec![]
    };
    Ok((items, warnings))
}

/// Desktop remote search. Live bindings never fall back to the fixture on error.
pub fn search_remote(
    session: &Session,
    request: SearchRemoteRequest,
) -> Result<RemoteSearchPageDto, String> {
    let dek = *session.dek().map_err(|e| e.to_string())?;
    let bindings = resolve_bindings(session)?;
    let workspace_id = {
        let vault = session.vault().map_err(|e| e.to_string())?;
        ensure_workspace(vault.project_conn(), &dek)?
    };
    let source_binding_id = bindings.crm.id.clone();
    if request
        .source_binding_id
        .as_deref()
        .is_some_and(|id| id != source_binding_id)
    {
        return Err("所选 ERP 来源已变更，请重新查询".into());
    }
    let fetched_at = now_rfc3339();

    if request.cursor.as_deref() == Some("done") {
        return Ok(RemoteSearchPageDto {
            items: vec![],
            next_cursor: None,
            complete: true,
            fetched_at,
            source_binding_id,
            warnings: vec![],
        });
    }

    let is_fixture = adapters::is_fixture_binding(&bindings.crm);
    if is_fixture {
        let vault = session.vault().map_err(|e| e.to_string())?;
        let (items, warnings) = search_remote_fixture(
            vault.project_conn(),
            &dek,
            &workspace_id,
            &bindings.crm,
            &request.keyword,
        )?;
        return Ok(RemoteSearchPageDto {
            items,
            next_cursor: None,
            complete: true,
            fetched_at,
            source_binding_id,
            warnings,
        });
    }

    match search_remote_live_fetch(session, &bindings.crm, &request.keyword) {
        Ok((records, warnings)) => {
            let vault = session.vault().map_err(|e| e.to_string())?;
            let (items, warnings) = stamp_search_adopted(
                vault.project_conn(),
                &dek,
                &workspace_id,
                &bindings.crm,
                &records,
                warnings,
            )?;
            Ok(RemoteSearchPageDto {
                items,
                next_cursor: None,
                complete: true,
                fetched_at,
                source_binding_id,
                warnings,
            })
        }
        Err(err) => Ok(RemoteSearchPageDto {
            items: vec![],
            next_cursor: None,
            complete: true,
            fetched_at,
            source_binding_id,
            warnings: vec![format!("实时 ERP 查询失败：{err}")],
        }),
    }
}

pub fn adopt_from_session(
    session: &Session,
    request: AdoptRequest,
) -> Result<AdoptResultDto, String> {
    let bindings = resolve_bindings(session)?;
    if request
        .source_binding_id
        .as_deref()
        .is_some_and(|id| id != bindings.crm.id)
    {
        return Err("所选 ERP 来源已变更，请重新查询后绑定".into());
    }
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    adopt(
        vault.project_conn(),
        dek,
        &bindings,
        &request.remote_id,
        request.remote_key.as_deref(),
        request.remote_name.as_deref(),
        request.owner.as_deref(),
        request.short_name.as_deref(),
        request.stage.as_deref(),
    )
}

fn adopt(
    conn: &Connection,
    dek: &[u8; 32],
    bindings: &WorkspaceBindings,
    remote_id: &str,
    remote_key: Option<&str>,
    remote_name: Option<&str>,
    owner: Option<&str>,
    short_name: Option<&str>,
    _stage: Option<&str>,
) -> Result<AdoptResultDto, String> {
    let workspace_id = ensure_workspace(conn, dek)?;
    let fixture = if adapters::is_fixture_binding(&bindings.crm) {
        Some(fixture::find_remote(remote_id).ok_or_else(|| "离线夹具中没有该项目".to_string())?)
    } else {
        None
    };
    let resolved_remote_id = fixture
        .as_ref()
        .map(|f| f.remote_id)
        .unwrap_or_else(|| remote_id.trim())
        .to_string();
    if !zoomkey::crm::valid_record_id(&resolved_remote_id) {
        return Err("绑定 ERP 需要有效的 CRM 记录 ID，请重新查询并选择项目".into());
    }

    if let Some(existing) =
        find_adopted_by_remote(conn, dek, &workspace_id, &bindings.crm, &resolved_remote_id)?
    {
        return Ok(AdoptResultDto {
            local_project_id: existing.local_project_id,
            remote_id: existing.remote_id,
            created: false,
        });
    }

    let number = fixture
        .as_ref()
        .map(|f| f.number.to_string())
        .or_else(|| remote_key.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
        .unwrap_or_else(|| resolved_remote_id.clone());
    let title = fixture
        .as_ref()
        .map(|f| f.title.to_string())
        .or_else(|| remote_name.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
        .unwrap_or_else(|| number.clone());
    let owner_val = fixture
        .as_ref()
        .map(|f| f.owner.to_string())
        .or_else(|| owner.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    let short = fixture
        .as_ref()
        .map(|f| f.short_name.to_string())
        .or_else(|| short_name.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
        .unwrap_or_default();

    let now = now_rfc3339();
    let local_id = Uuid::new_v4().to_string();
    let project = LocalProject {
        id: local_id.clone(),
        workspace_id: workspace_id.clone(),
        short_name: if short.is_empty() { None } else { Some(short.clone()) },
        alias: Some(title.clone()),
        owner: owner_val.clone(),
        archived: false,
        revision: 0,
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    put_record(
        conn,
        dek,
        PutRecord {
            workspace_id: &workspace_id,
            record_id: Some(&local_id),
            entity_type: ENTITY_LOCAL_PROJECT,
            schema_version: DEFAULT_ENTITY_SCHEMA_VERSION,
            expected_revision: None,
        },
        &project,
    )
    .map_err(map_err)?;

    let link = ProjectSourceLink {
        id: Uuid::new_v4().to_string(),
        workspace_id: workspace_id.clone(),
        local_project_id: local_id.clone(),
        source_binding_id: bindings.crm.id.clone(),
        remote_module: "Project".into(),
        remote_id: resolved_remote_id.clone(),
        remote_key: Some(number),
        remote_name: Some(title),
        revision: 0,
        created_at: now.clone(),
        updated_at: now,
    };
    put_record(
        conn,
        dek,
        PutRecord {
            workspace_id: &workspace_id,
            record_id: Some(&link.id),
            entity_type: ENTITY_PROJECT_SOURCE_LINK,
            schema_version: DEFAULT_ENTITY_SCHEMA_VERSION,
            expected_revision: None,
        },
        &link,
    )
    .map_err(map_err)?;

    if !short.is_empty() {
        recompute_auto_ranges(conn, dek, &workspace_id, &local_id, &short, &bindings.jira)?;
    }

    Ok(AdoptResultDto {
        local_project_id: local_id,
        remote_id: resolved_remote_id,
        created: true,
    })
}

pub fn create_local_project(
    conn: &Connection,
    dek: &[u8; 32],
    title: &str,
    short_name: Option<&str>,
) -> Result<AdoptResultDto, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("项目名称不能为空".into());
    }
    let workspace_id = ensure_workspace(conn, dek)?;
    let now = now_rfc3339();
    let local_id = Uuid::new_v4().to_string();
    let short = short_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let project = LocalProject {
        id: local_id.clone(),
        workspace_id: workspace_id.clone(),
        short_name: short.clone(),
        alias: Some(title.to_string()),
        owner: None,
        archived: false,
        revision: 0,
        created_at: now.clone(),
        updated_at: now,
    };
    put_record(
        conn,
        dek,
        PutRecord {
            workspace_id: &workspace_id,
            record_id: Some(&local_id),
            entity_type: ENTITY_LOCAL_PROJECT,
            schema_version: DEFAULT_ENTITY_SCHEMA_VERSION,
            expected_revision: None,
        },
        &project,
    )
    .map_err(map_err)?;

    if let Some(ref s) = short {
        let bindings = load_workspace_bindings(conn, dek, &workspace_id)?;
        recompute_auto_ranges(conn, dek, &workspace_id, &local_id, s, &bindings.jira)?;
    }

    Ok(AdoptResultDto {
        local_project_id: local_id,
        remote_id: String::new(),
        created: true,
    })
}

pub fn list_local(conn: &Connection, dek: &[u8; 32]) -> Result<Vec<LocalProjectDto>, String> {
    let summaries = list_summaries(conn, dek)?;
    Ok(summaries
        .into_iter()
        .filter_map(|s| {
            let local_id = s.local_project_id?;
            Some(LocalProjectDto {
                local_project_id: local_id,
                remote_id: s.crm_id,
                title: s.title,
                short_name: s.short_name,
                revision: 0,
            })
        })
        .collect())
}

fn resolve_adopted(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    crm: &SourceBinding,
    id: &str,
) -> Result<Option<AdoptedRef>, String> {
    let needle = id.trim();
    if needle.is_empty() {
        return Ok(None);
    }
    if Uuid::parse_str(needle).is_ok() {
        let adopted = list_adopted(conn, dek, workspace_id)?;
        return Ok(adopted.into_iter().find(|a| a.local_project_id == needle));
    }
    if adapters::is_fixture_binding(crm) {
        if let Some(remote) = fixture::find_remote(needle) {
            return find_adopted_by_remote(conn, dek, workspace_id, crm, remote.remote_id);
        }
    }
    find_adopted_by_remote(conn, dek, workspace_id, crm, needle)
}

fn load_local_overlays(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    local_project_id: &str,
) -> Result<(LocalCustomersDto, Vec<String>, Vec<String>), String> {
    let customers: Vec<(_, LocalCustomerLink)> =
        list_records_by_type(conn, dek, workspace_id, ENTITY_LOCAL_CUSTOMER_LINK)
            .map_err(map_err)?;
    let mut local = LocalCustomersDto {
        contract: LocalCustomerBindingDto::default(),
        user: LocalCustomerBindingDto::default(),
    };
    for (_, link) in customers {
        if link.local_project_id != local_project_id {
            continue;
        }
        let binding = match link.target {
            LocalCustomerTarget::Erp {
                remote_id,
                display_name,
                ..
            } => LocalCustomerBindingDto {
                kind: LocalCustomerKind::Erp,
                client_id: Some(remote_id.clone()),
                name: display_name.or_else(|| {
                    fixture::client_name(&remote_id).map(str::to_string)
                }),
            },
            LocalCustomerTarget::Manual { name } => LocalCustomerBindingDto {
                kind: LocalCustomerKind::Manual,
                client_id: None,
                name: Some(name),
            },
        };
        match link.role {
            CustomerRole::Contracting => local.contract = binding,
            CustomerRole::EndUser => local.user = binding,
            CustomerRole::Unknown => {}
        }
    }

    let ranges: Vec<(_, JiraRangeRelation)> =
        list_records_by_type(conn, dek, workspace_id, ENTITY_JIRA_RANGE).map_err(map_err)?;
    let mut manual_ranges = Vec::new();
    for (_, rel) in ranges {
        if rel.local_project_id != local_project_id {
            continue;
        }
        if rel.origins.contains(&JiraRangeOrigin::Manual) {
            if let Some(key) = rel.project_key {
                manual_ranges.push(key);
            }
        }
    }
    manual_ranges.sort();
    manual_ranges.dedup();

    let supplements: Vec<(_, JiraSupplementRelation)> =
        list_records_by_type(conn, dek, workspace_id, ENTITY_JIRA_SUPPLEMENT).map_err(map_err)?;
    let mut local_issues = Vec::new();
    for (_, rel) in supplements {
        if rel.local_project_id != local_project_id {
            continue;
        }
        if let Some(key) = rel.issue_key {
            local_issues.push(key);
        } else {
            local_issues.push(rel.issue_id);
        }
    }
    local_issues.sort();
    local_issues.dedup();

    Ok((local, manual_ranges, local_issues))
}

fn overlays_for_adopted(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    crm: &SourceBinding,
    remote_id: &str,
    default_short: &str,
) -> Result<(String, LocalCustomersDto, Vec<String>, Vec<String>, u64, Option<String>, bool), String>
{
    let adopted = find_adopted_by_remote(conn, dek, workspace_id, crm, remote_id)?;
    if let Some(a) = adopted {
        let (local, manual, issues) =
            load_local_overlays(conn, dek, workspace_id, &a.local_project_id)?;
        Ok((
            a.short_name,
            local,
            manual,
            issues,
            a.revision,
            Some(a.local_project_id),
            true,
        ))
    } else {
        Ok((
            default_short.to_string(),
            LocalCustomersDto {
                contract: LocalCustomerBindingDto::default(),
                user: LocalCustomerBindingDto::default(),
            },
            vec![],
            vec![],
            0,
            None,
            false,
        ))
    }
}

fn build_detail_fixture(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    crm: &SourceBinding,
    id: &str,
) -> Result<Option<ProjectDetailDto>, String> {
    let remote = match fixture::find_remote(id) {
        Some(r) => r,
        None => {
            let adopted = resolve_adopted(conn, dek, workspace_id, crm, id)?;
            match adopted {
                Some(a) => fixture::find_remote(&a.remote_id)
                    .ok_or_else(|| format!("项目不存在：{id}"))?,
                None => return Ok(None),
            }
        }
    };

    let (short_name, local, manual_ranges, local_issues, revision, local_project_id, is_adopted) =
        overlays_for_adopted(
            conn,
            dek,
            workspace_id,
            crm,
            remote.remote_id,
            remote.short_name,
        )?;

    Ok(Some(ProjectDetailDto {
        id: remote.number.into(),
        crm_id: remote.remote_id.into(),
        title: remote.title.into(),
        stage: remote.stage.into(),
        owner: remote.owner.into(),
        start: remote.start.into(),
        plan_online: remote.plan_online.into(),
        plan_delivery: remote.plan_delivery.into(),
        actual_end: remote.actual_end.map(str::to_string),
        short_name,
        fact: remote.fact,
        local,
        manual_ranges,
        local_issues,
        staff: fixture::staff(),
        amounts: fixture::amounts(),
        hours: fixture::hours(),
        jira_catalog: fixture::jira_catalog(),
        jira_status_defaults: fixture::jira_status_defaults(),
        erp_issues: fixture::erp_issues(),
        dev_tasks: fixture::dev_tasks(),
        snapshot_date: fixture::SNAPSHOT_DATE.into(),
        adopted: is_adopted,
        local_project_id,
        revision,
        data_source: "fixture".into(),
        warnings: vec![],
    }))
}

struct LiveDetailParts {
    mapped: crm_adapter::MappedProject,
    staff: Vec<super::dto::ProjectStaffDto>,
    amounts: super::dto::ProjectAmountsDto,
    hours: super::dto::ProjectHoursDto,
    erp_issues: Vec<super::dto::JiraTaskDto>,
    jira_catalog: std::collections::BTreeMap<String, super::dto::JiraCatalogEntryDto>,
    jira_status_defaults: Vec<String>,
    snapshot_date: String,
    warnings: Vec<String>,
}

/// Network-only live fetch (Session borrow). Local overlays applied afterwards.
fn fetch_live_detail_parts(
    session: &Session,
    crm: &SourceBinding,
    jira: &SourceBinding,
    reference: &str,
) -> Result<LiveDetailParts, String> {
    if adapters::is_fixture_binding(crm) {
        return Err("fixture binding".into());
    }
    let crm_runtime =
        adapters::open_desktop_runtime(session, crm).map_err(|e| e.message)?;
    let remote_id = if zoomkey::crm::valid_record_id(reference) {
        reference.to_string()
    } else {
        crm_adapter::project_id_by_number(&crm_runtime, reference).map_err(|e| e.message)?
    };
    let snapshot_date = chrono::Utc::now().date_naive().to_string();
    let bundle = crm_adapter::fetch_project_bundle(&crm_runtime, &remote_id, &snapshot_date)
        .map_err(|e| e.message)?;
    let mapped = bundle
        .project
        .ok_or_else(|| "CRM 未返回项目".to_string())?;

    let mut erp_issues = bundle.erp_issues;
    let mut warnings = bundle.warnings;
    let mut jira_catalog = std::collections::BTreeMap::new();
    let mut jira_status_defaults = Vec::new();

    if !adapters::is_fixture_binding(jira) {
        match adapters::open_desktop_runtime(session, jira) {
            Ok(jira_runtime) => {
                match jira_adapter::list_projects(&jira_runtime) {
                    Ok(projects) => {
                        jira_catalog = jira_adapter::projects_to_catalog(&projects);
                    }
                    Err(e) => warnings.push(format!("Jira 项目列表失败：{}", e.message)),
                }
                warnings.extend(jira_adapter::enrich_erp_issues(&jira_runtime, &mut erp_issues));
                if let Some(first_key) = jira_catalog.keys().next().cloned() {
                    if let Ok(statuses) =
                        jira_adapter::list_status_names(&jira_runtime, &first_key)
                    {
                        if !statuses.is_empty() {
                            jira_status_defaults = statuses;
                        }
                    }
                }
            }
            Err(e) => warnings.push(format!("Jira runtime unavailable：{}", e.message)),
        }
    }

    let amounts = bundle
        .amounts
        .ok_or_else(|| "ERP 项目金额未返回".to_string())?;
    let hours = bundle
        .hours
        .ok_or_else(|| "ERP 项目工时未返回".to_string())?;
    let staff = bundle.staff;

    Ok(LiveDetailParts {
        mapped,
        staff,
        amounts,
        hours,
        erp_issues,
        jira_catalog,
        jira_status_defaults,
        snapshot_date,
        warnings,
    })
}

fn assemble_live_detail(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    crm: &SourceBinding,
    parts: LiveDetailParts,
    stored_remote_id: Option<&str>,
) -> Result<ProjectDetailDto, String> {
    let (short_name, local, manual_ranges, local_issues, revision, local_project_id, is_adopted) =
        overlays_for_adopted(
            conn,
            dek,
            workspace_id,
            crm,
            stored_remote_id.unwrap_or(&parts.mapped.remote_id),
            "",
        )?;
    let warnings = parts.warnings;
    let dev_tasks: Vec<DevTaskDto> = parts
        .erp_issues
        .iter()
        .filter_map(|t| {
            Some(DevTaskDto {
                key: t.key.clone(),
                title: t.title.clone(),
                project: parts
                    .jira_catalog
                    .get(&t.jira_project_key)
                    .map(|e| e.name.clone())
                    .unwrap_or_else(|| t.jira_project_key.clone()),
                hours: t.hours?,
                amount: t.amount?,
                kind: t.kind.clone().unwrap_or_default(),
            })
        })
        .collect();

    Ok(ProjectDetailDto {
        id: parts.mapped.number,
        crm_id: parts.mapped.remote_id,
        title: parts.mapped.title,
        stage: parts.mapped.stage,
        owner: parts.mapped.owner,
        start: parts.mapped.start,
        plan_online: parts.mapped.plan_online,
        plan_delivery: parts.mapped.plan_delivery,
        actual_end: parts.mapped.actual_end,
        short_name,
        fact: parts.mapped.fact,
        local,
        manual_ranges,
        local_issues,
        staff: parts.staff,
        amounts: parts.amounts,
        hours: parts.hours,
        jira_catalog: parts.jira_catalog,
        jira_status_defaults: parts.jira_status_defaults,
        erp_issues: parts.erp_issues,
        dev_tasks,
        snapshot_date: parts.snapshot_date,
        adopted: is_adopted,
        local_project_id,
        revision,
        data_source: "live".into(),
        warnings,
    })
}

fn build_detail(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    crm: &SourceBinding,
    id: &str,
) -> Result<Option<ProjectDetailDto>, String> {
    build_detail_fixture(conn, dek, workspace_id, crm, id)
}

fn live_project_reference<'a>(
    id: &'a str,
    link: Option<&'a ProjectSourceLink>,
) -> Result<&'a str, String> {
    let Some(link) = link else {
        return Ok(id);
    };
    let remote_id = link.remote_id.trim();
    if zoomkey::crm::valid_record_id(remote_id) {
        return Ok(remote_id);
    }
    // Old links may carry a project number (or a raw DB ID) as remote_id.
    // Only use a known project number to recover the canonical ID from CRM.
    let number = link
        .remote_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !zoomkey::crm::valid_record_id(s));
    let legacy_number = remote_id
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("PROJ"))
        && remote_id.len() > 4
        && remote_id[4..].bytes().all(|b| b.is_ascii_digit());
    number
        .or(legacy_number.then_some(remote_id))
        .ok_or_else(|| "已绑定项目缺少有效的 CRM 记录 ID 和项目编号，请重新查询并绑定".to_string())
}

pub fn get_detail(session: &Session, id: &str) -> Result<Option<ProjectDetailDto>, String> {
    let dek = *session.dek().map_err(|e| e.to_string())?;
    let id = id.trim();
    if id.is_empty() {
        return Ok(None);
    }
    let (workspace_id, link) = {
        let vault = session.vault().map_err(|e| e.to_string())?;
        let conn = vault.project_conn();
        let workspace_id = ensure_workspace(conn, &dek)?;
        let links: Vec<(_, ProjectSourceLink)> =
            list_records_by_type(conn, &dek, &workspace_id, ENTITY_PROJECT_SOURCE_LINK)
                .map_err(map_err)?;
        let link = links
            .into_iter()
            .map(|(_, link)| link)
            .find(|l| l.local_project_id == id);
        (workspace_id, link)
    };

    // Local-only follow (no ERP link).
    {
        let vault = session.vault().map_err(|e| e.to_string())?;
        let conn = vault.project_conn();
        if link.is_none() {
            if let Ok((meta, project)) =
                get_record::<LocalProject>(conn, &dek, &workspace_id, id.trim())
            {
                let title = project
                    .alias
                    .clone()
                    .unwrap_or_else(|| "未命名项目".into());
                return Ok(Some(ProjectDetailDto {
                    id: project.id.clone(),
                    crm_id: String::new(),
                    title,
                    stage: "本地".into(),
                    owner: project.owner.clone().unwrap_or_default(),
                    start: String::new(),
                    plan_online: String::new(),
                    plan_delivery: String::new(),
                    actual_end: None,
                    short_name: project.short_name.clone().unwrap_or_default(),
                    fact: FactCustomersDto {
                        contract: None,
                        user: None,
                    },
                    local: LocalCustomersDto {
                        contract: LocalCustomerBindingDto::default(),
                        user: LocalCustomerBindingDto::default(),
                    },
                    manual_ranges: Vec::new(),
                    local_issues: Vec::new(),
                    staff: Vec::new(),
                    amounts: fixture::amounts(),
                    hours: fixture::hours(),
                    jira_catalog: std::collections::BTreeMap::new(),
                    jira_status_defaults: Vec::new(),
                    erp_issues: Vec::new(),
                    dev_tasks: Vec::new(),
                    snapshot_date: String::new(),
                    adopted: true,
                    local_project_id: Some(project.id),
                    revision: meta.revision,
                    data_source: "local".into(),
                    warnings: vec![
                        "这是本地关注项，尚未绑定 ERP。请先在 MCP→ZoomKey 配置 CRM 凭据与客户端证书，再用「绑定 ERP」关联。".into(),
                    ],
                }));
            }
        }
    }

    let vault = session.vault().map_err(|e| e.to_string())?;
    let conn = vault.project_conn();
    let linked_source = link
        .as_ref()
        .map(|link| {
            get_record::<SourceBinding>(conn, &dek, &workspace_id, &link.source_binding_id)
                .map(|(_, binding)| binding)
                .map_err(|_| "此项目的 ERP 来源记录不可用，请重新绑定".to_string())
        })
        .transpose()?;
    if let Some(source) = linked_source
        .as_ref()
        .filter(|b| adapters::is_fixture_binding(b))
    {
        return build_detail_fixture(conn, &dek, &workspace_id, source, id);
    }
    if link.is_none() && Uuid::parse_str(id).is_ok() {
        return Ok(None);
    }

    let bindings = resolve_bindings(session)?;
    if linked_source
        .as_ref()
        .is_some_and(|source| !same_crm_source(source, &bindings.crm))
    {
        return Err(
            "此项目绑定的 ERP 来源与当前配置不一致，请切回原来源或在当前来源中重新查询绑定".into(),
        );
    }
    if adapters::is_fixture_binding(&bindings.crm) {
        return build_detail_fixture(conn, &dek, &workspace_id, &bindings.crm, id);
    }

    let reference = live_project_reference(id, link.as_ref())?;
    match fetch_live_detail_parts(session, &bindings.crm, &bindings.jira, reference) {
        Ok(parts) => {
            let vault = session.vault().map_err(|e| e.to_string())?;
            Ok(Some(assemble_live_detail(
                vault.project_conn(),
                &dek,
                &workspace_id,
                &bindings.crm,
                parts,
                link.as_ref().map(|link| link.remote_id.as_str()),
            )?))
        }
        Err(err) => Err(format!("实时 ERP 项目详情加载失败：{err}")),
    }
}

fn require_adopted(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    crm: &SourceBinding,
    id: &str,
) -> Result<AdoptedRef, String> {
    resolve_adopted(conn, dek, workspace_id, crm, id)?
        .ok_or_else(|| "请先纳入我的项目".into())
}

fn update_local_project(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    local_project_id: &str,
    mutate: impl FnOnce(&mut LocalProject),
) -> Result<u64, String> {
    let (meta, mut project): (_, LocalProject) =
        get_record(conn, dek, workspace_id, local_project_id).map_err(map_err)?;
    mutate(&mut project);
    project.updated_at = now_rfc3339();
    let meta = put_record(
        conn,
        dek,
        PutRecord {
            workspace_id,
            record_id: Some(local_project_id),
            entity_type: ENTITY_LOCAL_PROJECT,
            schema_version: meta.schema_version,
            expected_revision: Some(meta.revision),
        },
        &project,
    )
    .map_err(map_err)?;
    Ok(meta.revision)
}

fn recompute_auto_ranges(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    local_project_id: &str,
    short_name: &str,
    jira_binding: &SourceBinding,
) -> Result<(), String> {
    let normalized = normalize_short_name(short_name);
    let catalog = fixture::jira_catalog();
    let now = now_rfc3339();

    // Collect existing ranges for this local project + jira scope.
    let existing: Vec<(sealbox_core::projects::RecordMeta, JiraRangeRelation)> =
        list_records_by_type(conn, dek, workspace_id, ENTITY_JIRA_RANGE).map_err(map_err)?;

    for (meta, mut rel) in existing {
        if rel.local_project_id != local_project_id {
            continue;
        }
        let Ok((_, binding)): Result<(sealbox_core::projects::RecordMeta, SourceBinding), _> =
            get_record(conn, dek, workspace_id, &rel.source_binding_id)
        else {
            continue;
        };
        if binding.site != jira_binding.site || binding.account_scope != jira_binding.account_scope
        {
            continue;
        }
        let key = rel.project_key.clone().unwrap_or_default();
        let should_auto = short_name_matches_project_key(&normalized, &key);
        let had_auto = rel.origins.contains(&JiraRangeOrigin::Auto);
        if should_auto && !had_auto {
            rel.origins.push(JiraRangeOrigin::Auto);
            rel.updated_at = now.clone();
            put_record(
                conn,
                dek,
                PutRecord {
                    workspace_id,
                    record_id: Some(&meta.id),
                    entity_type: ENTITY_JIRA_RANGE,
                    schema_version: meta.schema_version,
                    expected_revision: Some(meta.revision),
                },
                &rel,
            )
            .map_err(map_err)?;
        } else if !should_auto && had_auto {
            rel.origins.retain(|o| o != &JiraRangeOrigin::Auto);
            if rel.origins.is_empty() {
                delete_record(conn, workspace_id, &meta.id).map_err(map_err)?;
            } else {
                rel.updated_at = now.clone();
                put_record(
                    conn,
                    dek,
                    PutRecord {
                        workspace_id,
                        record_id: Some(&meta.id),
                        entity_type: ENTITY_JIRA_RANGE,
                        schema_version: meta.schema_version,
                        expected_revision: Some(meta.revision),
                    },
                    &rel,
                )
                .map_err(map_err)?;
            }
        }
    }

    // Add missing auto matches.
    for key in catalog.keys() {
        if !short_name_matches_project_key(&normalized, key) {
            continue;
        }
        let relation = JiraRangeRelation {
            id: String::new(),
            workspace_id: workspace_id.to_string(),
            local_project_id: local_project_id.to_string(),
            source_binding_id: jira_binding.id.clone(),
            jira_project_id: fixture::jira_project_stable_id(key),
            project_key: Some(key.clone()),
            project_name: catalog.get(key).map(|e| e.name.clone()),
            origins: vec![],
            revision: 0,
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        put_jira_range_idempotent(conn, dek, workspace_id, relation, JiraRangeOrigin::Auto)
            .map_err(map_err)?;
    }
    Ok(())
}

pub fn set_short_name(
    conn: &Connection,
    dek: &[u8; 32],
    request: SetShortNameRequest,
) -> Result<ProjectDetailDto, String> {
    let workspace_id = ensure_workspace(conn, dek)?;
    let bindings = load_workspace_bindings(conn, dek, &workspace_id)?;
    let adopted = require_adopted(conn, dek, &workspace_id, &bindings.crm, &request.id)?;
    let short = request.short_name.trim().to_string();
    update_local_project(conn, dek, &workspace_id, &adopted.local_project_id, |p| {
        p.short_name = if short.is_empty() {
            None
        } else {
            Some(short.clone())
        };
    })?;
    recompute_auto_ranges(
        conn,
        dek,
        &workspace_id,
        &adopted.local_project_id,
        &short,
        &bindings.jira,
    )?;
    build_detail(conn, dek, &workspace_id, &bindings.crm, &adopted.remote_id)?
        .ok_or_else(|| "项目不存在".to_string())
}

fn upsert_customer_link(
    conn: &Connection,
    dek: &[u8; 32],
    workspace_id: &str,
    local_project_id: &str,
    role: &CustomerRoleDto,
    binding: &LocalCustomerBindingDto,
    crm_binding: &SourceBinding,
) -> Result<(), String> {
    let customers: Vec<(sealbox_core::projects::RecordMeta, LocalCustomerLink)> =
        list_records_by_type(conn, dek, workspace_id, ENTITY_LOCAL_CUSTOMER_LINK)
            .map_err(map_err)?;
    let existing = customers
        .into_iter()
        .find(|(_, link)| {
            link.local_project_id == local_project_id && role_matches(&link.role, role)
        });

    if matches!(binding.kind, LocalCustomerKind::None) {
        if let Some((meta, _)) = existing {
            delete_record(conn, workspace_id, &meta.id).map_err(map_err)?;
        }
        return Ok(());
    }

    let target = match binding.kind {
        LocalCustomerKind::Erp => {
            let client_id = binding
                .client_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "请选择 ERP 客户".to_string())?;
            LocalCustomerTarget::Erp {
                source_binding_id: crm_binding.id.clone(),
                remote_module: "Accounts".into(),
                remote_id: client_id.to_string(),
                display_name: binding
                    .name
                    .clone()
                    .or_else(|| fixture::client_name(client_id).map(str::to_string)),
            }
        }
        LocalCustomerKind::Manual => {
            let name = binding
                .name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "请输入手工客户名称".to_string())?;
            LocalCustomerTarget::Manual {
                name: name.to_string(),
            }
        }
        LocalCustomerKind::None => unreachable!(),
    };

    let now = now_rfc3339();
    if let Some((meta, mut link)) = existing {
        link.target = target;
        link.updated_at = now;
        put_record(
            conn,
            dek,
            PutRecord {
                workspace_id,
                record_id: Some(&meta.id),
                entity_type: ENTITY_LOCAL_CUSTOMER_LINK,
                schema_version: meta.schema_version,
                expected_revision: Some(meta.revision),
            },
            &link,
        )
        .map_err(map_err)?;
    } else {
        let link = LocalCustomerLink {
            id: Uuid::new_v4().to_string(),
            workspace_id: workspace_id.to_string(),
            local_project_id: local_project_id.to_string(),
            role: role_core(role),
            target,
            note: None,
            revision: 0,
            created_at: now.clone(),
            updated_at: now,
        };
        put_record(
            conn,
            dek,
            PutRecord {
                workspace_id,
                record_id: Some(&link.id),
                entity_type: ENTITY_LOCAL_CUSTOMER_LINK,
                schema_version: DEFAULT_ENTITY_SCHEMA_VERSION,
                expected_revision: None,
            },
            &link,
        )
        .map_err(map_err)?;
    }
    Ok(())
}

pub fn bind_customer(
    conn: &Connection,
    dek: &[u8; 32],
    request: BindCustomerRequest,
) -> Result<ProjectDetailDto, String> {
    let workspace_id = ensure_workspace(conn, dek)?;
    let bindings = load_workspace_bindings(conn, dek, &workspace_id)?;
    let adopted = require_adopted(conn, dek, &workspace_id, &bindings.crm, &request.id)?;
    upsert_customer_link(
        conn,
        dek,
        &workspace_id,
        &adopted.local_project_id,
        &request.role,
        &request.binding,
        &bindings.crm,
    )?;
    update_local_project(conn, dek, &workspace_id, &adopted.local_project_id, |_| {})?;
    build_detail(conn, dek, &workspace_id, &bindings.crm, &adopted.remote_id)?
        .ok_or_else(|| "项目不存在".to_string())
}

pub fn unbind_customer(
    conn: &Connection,
    dek: &[u8; 32],
    request: UnbindCustomerRequest,
) -> Result<ProjectDetailDto, String> {
    bind_customer(
        conn,
        dek,
        BindCustomerRequest {
            id: request.id,
            role: request.role,
            binding: LocalCustomerBindingDto::default(),
        },
    )
}

pub fn add_jira_range(
    conn: &Connection,
    dek: &[u8; 32],
    request: JiraRangeRequest,
) -> Result<MutationMessageDto, String> {
    let workspace_id = ensure_workspace(conn, dek)?;
    let bindings = load_workspace_bindings(conn, dek, &workspace_id)?;
    let adopted = require_adopted(conn, dek, &workspace_id, &bindings.crm, &request.id)?;
    let key = normalize_short_name(&request.key);
    if key.is_empty() {
        return Err("请选择或输入 Jira 项目 key".into());
    }
    let catalog = fixture::jira_catalog();
    let meta = catalog.get(&key);
    let already_auto = short_name_matches_project_key(
        &normalize_short_name(&adopted.short_name),
        &key,
    );
    let existing = find_jira_range(
        conn,
        dek,
        &workspace_id,
        &adopted.local_project_id,
        &bindings.jira.id,
        &fixture::jira_project_stable_id(&key),
    )
    .map_err(map_err)?;
    let already_manual = existing
        .as_ref()
        .map(|(_, r)| r.origins.contains(&JiraRangeOrigin::Manual))
        .unwrap_or(false);

    if already_manual {
        let detail = build_detail(conn, dek, &workspace_id, &bindings.crm, &adopted.remote_id)?
            .ok_or_else(|| "项目不存在".to_string())?;
        let message = format!(
            "{key} 已在手动范围中（幂等）{}",
            if already_auto {
                "；同时由简称自动命中，故仍在范围内"
            } else {
                ""
            }
        );
        return Ok(MutationMessageDto {
            detail,
            message,
            still_auto: None,
        });
    }

    let now = now_rfc3339();
    let relation = JiraRangeRelation {
        id: String::new(),
        workspace_id: workspace_id.clone(),
        local_project_id: adopted.local_project_id.clone(),
        source_binding_id: bindings.jira.id.clone(),
        jira_project_id: fixture::jira_project_stable_id(&key),
        project_key: Some(key.clone()),
        project_name: meta.map(|e| e.name.clone()),
        origins: vec![],
        revision: 0,
        created_at: now.clone(),
        updated_at: now,
    };
    put_jira_range_idempotent(
        conn,
        dek,
        &workspace_id,
        relation,
        JiraRangeOrigin::Manual,
    )
    .map_err(map_err)?;
    update_local_project(conn, dek, &workspace_id, &adopted.local_project_id, |_| {})?;

    let suffix = match meta.map(|e| e.status.as_str()) {
        Some("pending") => " · 待验证（原型可移除）",
        Some("example") => " · 规则示例，无任务",
        _ => "",
    };
    let message = if already_auto {
        format!("已记录 {key} 为手动补充；该项目同时由简称自动命中，仍在范围内（未重复建项）")
    } else {
        format!("已添加手动范围 {key}{suffix}")
    };
    let detail = build_detail(conn, dek, &workspace_id, &bindings.crm, &adopted.remote_id)?
        .ok_or_else(|| "项目不存在".to_string())?;
    Ok(MutationMessageDto {
        detail,
        message,
        still_auto: None,
    })
}

pub fn remove_jira_range(
    conn: &Connection,
    dek: &[u8; 32],
    request: JiraRangeRequest,
) -> Result<MutationMessageDto, String> {
    let workspace_id = ensure_workspace(conn, dek)?;
    let bindings = load_workspace_bindings(conn, dek, &workspace_id)?;
    let adopted = require_adopted(conn, dek, &workspace_id, &bindings.crm, &request.id)?;
    let key = normalize_short_name(&request.key);
    let still_auto =
        short_name_matches_project_key(&normalize_short_name(&adopted.short_name), &key);

    if let Some((meta, mut rel)) = find_jira_range(
        conn,
        dek,
        &workspace_id,
        &adopted.local_project_id,
        &bindings.jira.id,
        &fixture::jira_project_stable_id(&key),
    )
    .map_err(map_err)?
    {
        // Remove only the manual mark — never touch task supplements / ERP links.
        rel.origins.retain(|o| o != &JiraRangeOrigin::Manual);
        if rel.origins.is_empty() {
            delete_record(conn, &workspace_id, &meta.id).map_err(map_err)?;
        } else {
            rel.updated_at = now_rfc3339();
            put_record(
                conn,
                dek,
                PutRecord {
                    workspace_id: &workspace_id,
                    record_id: Some(&meta.id),
                    entity_type: ENTITY_JIRA_RANGE,
                    schema_version: meta.schema_version,
                    expected_revision: Some(meta.revision),
                },
                &rel,
            )
            .map_err(map_err)?;
        }
    }

    update_local_project(conn, dek, &workspace_id, &adopted.local_project_id, |_| {})?;
    let message = if still_auto {
        format!("已移除 {key} 的手动标记；因简称仍命中，保留在自动范围")
    } else {
        format!("已移除手动范围 {key}")
    };
    let detail = build_detail(conn, dek, &workspace_id, &bindings.crm, &adopted.remote_id)?
        .ok_or_else(|| "项目不存在".to_string())?;
    Ok(MutationMessageDto {
        detail,
        message,
        still_auto: Some(still_auto),
    })
}

pub fn add_jira_issue(
    conn: &Connection,
    dek: &[u8; 32],
    request: JiraIssueRequest,
) -> Result<MutationMessageDto, String> {
    let workspace_id = ensure_workspace(conn, dek)?;
    let bindings = load_workspace_bindings(conn, dek, &workspace_id)?;
    let adopted = require_adopted(conn, dek, &workspace_id, &bindings.crm, &request.id)?;
    let key = request.issue_key.trim().to_uppercase();
    if key.is_empty() {
        return Err("请输入 Issue key".into());
    }
    if fixture::is_erp_issue(&key) {
        let detail = build_detail(conn, dek, &workspace_id, &bindings.crm, &adopted.remote_id)?
            .ok_or_else(|| "项目不存在".to_string())?;
        return Ok(MutationMessageDto {
            detail,
            message: format!("{key} 已由 ERP 关联，无需重复绑定"),
            still_auto: None,
        });
    }

    let now = now_rfc3339();
    let relation = JiraSupplementRelation {
        id: String::new(),
        workspace_id: workspace_id.clone(),
        local_project_id: adopted.local_project_id.clone(),
        source_binding_id: bindings.jira.id.clone(),
        // Fixture: use key as stable issue id until real Jira adapter supplies ids.
        issue_id: format!("fixture-issue:{key}"),
        issue_key: Some(key.clone()),
        revision: 0,
        created_at: now.clone(),
        updated_at: now,
    };
    let (meta_before, _) = (
        list_records_by_type::<JiraSupplementRelation>(
            conn,
            dek,
            &workspace_id,
            ENTITY_JIRA_SUPPLEMENT,
        )
        .map_err(map_err)?
        .into_iter()
        .filter(|(_, r)| {
            r.local_project_id == adopted.local_project_id
                && r.issue_key
                    .as_deref()
                    .map(|k| k.eq_ignore_ascii_case(&key))
                    .unwrap_or(false)
        })
        .count(),
        (),
    );
    put_jira_supplement_idempotent(conn, dek, &workspace_id, relation).map_err(map_err)?;
    let already = meta_before > 0;
    if !already {
        update_local_project(conn, dek, &workspace_id, &adopted.local_project_id, |_| {})?;
    }
    let message = if already {
        format!("{key} 已在本地补充中（幂等）")
    } else {
        format!("已本地补充 {key}（模拟 · 无正文快照）")
    };
    let detail = build_detail(conn, dek, &workspace_id, &bindings.crm, &adopted.remote_id)?
        .ok_or_else(|| "项目不存在".to_string())?;
    Ok(MutationMessageDto {
        detail,
        message,
        still_auto: None,
    })
}

pub fn unbind_jira_issue(
    conn: &Connection,
    dek: &[u8; 32],
    request: JiraIssueRequest,
) -> Result<ProjectDetailDto, String> {
    let workspace_id = ensure_workspace(conn, dek)?;
    let bindings = load_workspace_bindings(conn, dek, &workspace_id)?;
    let adopted = require_adopted(conn, dek, &workspace_id, &bindings.crm, &request.id)?;
    let key = request.issue_key.trim().to_uppercase();
    if fixture::is_erp_issue(&key) {
        // ERP associations cannot be removed via local unbind.
        let (_, local_issues) = {
            let overlays = load_local_overlays(conn, dek, &workspace_id, &adopted.local_project_id)?;
            (overlays.0, overlays.2)
        };
        if !local_issues.iter().any(|k| k.eq_ignore_ascii_case(&key)) {
            return Err(format!("{key} 为 ERP 既有关联，不能通过本地解绑移除"));
        }
    }

    let supplements: Vec<(sealbox_core::projects::RecordMeta, JiraSupplementRelation)> =
        list_records_by_type(conn, dek, &workspace_id, ENTITY_JIRA_SUPPLEMENT).map_err(map_err)?;
    for (meta, rel) in supplements {
        if rel.local_project_id != adopted.local_project_id {
            continue;
        }
        let matches = rel
            .issue_key
            .as_deref()
            .map(|k| k.eq_ignore_ascii_case(&key))
            .unwrap_or(false)
            || rel.issue_id.eq_ignore_ascii_case(&key)
            || rel.issue_id == format!("fixture-issue:{key}");
        if matches {
            delete_record(conn, &workspace_id, &meta.id).map_err(map_err)?;
        }
    }
    update_local_project(conn, dek, &workspace_id, &adopted.local_project_id, |_| {})?;
    build_detail(conn, dek, &workspace_id, &bindings.crm, &adopted.remote_id)?
        .ok_or_else(|| "项目不存在".to_string())
}

/// Summaries for followed projects: ERP-bound + local-only shells.
pub fn list_summaries(
    conn: &Connection,
    dek: &[u8; 32],
) -> Result<Vec<ProjectSummaryDto>, String> {
    let workspace_id = ensure_workspace(conn, dek)?;
    let projects: Vec<(_, LocalProject)> =
        list_records_by_type(conn, dek, &workspace_id, ENTITY_LOCAL_PROJECT).map_err(map_err)?;
    let links: Vec<(_, ProjectSourceLink)> =
        list_records_by_type(conn, dek, &workspace_id, ENTITY_PROJECT_SOURCE_LINK).map_err(map_err)?;

    let mut out = Vec::new();
    for (_meta, project) in projects {
        if project.archived { continue; }
        let link = links
            .iter()
            .find(|(_, l)| l.local_project_id == project.id)
            .map(|(_, l)| l.clone());
        if let Some(ref link) = link {
            let from_fixture =
                get_record::<SourceBinding>(conn, dek, &workspace_id, &link.source_binding_id)
                    .ok()
                    .is_some_and(|(_, binding)| adapters::is_fixture_binding(&binding));
            if from_fixture && fixture::find_remote(&link.remote_id).is_some() {
                out.push(fixture::to_summary(
                    true,
                    Some(project.id.clone()),
                    project.short_name.as_deref().unwrap_or(fixture::DEFAULT_SHORT_NAME),
                ));
                continue;
            }
            let number = link.remote_key.clone().unwrap_or_else(|| link.remote_id.clone());
            let title = project
                .alias
                .clone()
                .or_else(|| link.remote_name.clone())
                .unwrap_or_else(|| number.clone());
            out.push(ProjectSummaryDto {
                id: number,
                crm_id: link.remote_id.clone(),
                title,
                stage: "已关注".into(),
                owner: project.owner.clone().unwrap_or_default(),
                contract_customer_id: None,
                contract_customer_name: None,
                user_customer_id: None,
                user_customer_name: None,
                short_name: project.short_name.clone().unwrap_or_default(),
                adopted: true,
                local_project_id: Some(project.id.clone()),
            });
        } else {
            let title = project.alias.clone().unwrap_or_else(|| "未命名项目".into());
            out.push(ProjectSummaryDto {
                id: project.id.clone(),
                crm_id: String::new(),
                title,
                stage: "本地".into(),
                owner: project.owner.clone().unwrap_or_default(),
                contract_customer_id: None,
                contract_customer_name: None,
                user_customer_id: None,
                user_customer_name: None,
                short_name: project.short_name.clone().unwrap_or_default(),
                adopted: true,
                local_project_id: Some(project.id.clone()),
            });
        }
    }
    out.sort_by(|a, b| a.title.cmp(&b.title));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealbox_core::vault::Vault;

    fn open_vault() -> (Vault, [u8; 32]) {
        Vault::create_in_memory("correct horse battery staple extra projects")
            .expect("in-memory vault")
    }

    #[test]
    fn adopt_is_idempotent_per_remote_identity() {
        let (vault, dek) = open_vault();
        let conn = vault.project_conn();
        let workspace_id = ensure_workspace(conn, &dek).unwrap();
        let bindings = load_workspace_bindings(conn, &dek, &workspace_id).unwrap();
        let first = adopt(
            conn,
            &dek,
            &bindings,
            fixture::REMOTE_ID,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(first.created);
        let second = adopt(
            conn,
            &dek,
            &bindings,
            fixture::PROJECT_NUMBER,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!second.created);
        assert_eq!(first.local_project_id, second.local_project_id);
        assert_eq!(first.remote_id, fixture::REMOTE_ID);

        let listed = list_local(conn, &dek).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].local_project_id, first.local_project_id);
    }

    #[test]
    fn live_project_summary_keeps_number_and_crm_id_separate() {
        let (vault, dek) = open_vault();
        let conn = vault.project_conn();
        let workspace = ensure_workspace(conn, &dek).unwrap();
        let mut bindings = load_workspace_bindings(conn, &dek, &workspace).unwrap();
        bindings.crm = upsert_live_binding(
            conn,
            &dek,
            &workspace,
            PlatformKind::ZoomkeyCrm,
            "https://crm.example.test",
            "read-only",
            "test-credential",
        )
        .unwrap();
        assert!(adopt(conn, &dek, &bindings, "PROJ42", None, None, None, None, None).is_err());
        let adopted = adopt(
            conn,
            &dek,
            &bindings,
            "30x721",
            Some("PROJ42"),
            Some("Test project"),
            None,
            None,
            None,
        )
        .unwrap();
        let summaries = list_summaries(conn, &dek).unwrap();
        assert_eq!(summaries[0].id, "PROJ42");
        assert_eq!(summaries[0].crm_id, "30x721");
        assert_eq!(
            summaries[0].local_project_id.as_deref(),
            Some(adopted.local_project_id.as_str())
        );
        let mut links: Vec<(_, ProjectSourceLink)> =
            list_records_by_type(conn, &dek, &workspace, ENTITY_PROJECT_SOURCE_LINK).unwrap();
        let (_, mut link) = links.pop().unwrap();
        assert_eq!(link.source_binding_id, bindings.crm.id);
        assert_eq!(
            live_project_reference(&adopted.local_project_id, Some(&link)).unwrap(),
            "30x721"
        );
        link.remote_id = "721".into();
        assert_eq!(
            live_project_reference(&adopted.local_project_id, Some(&link)).unwrap(),
            "PROJ42"
        );
        link.remote_key = None;
        assert!(live_project_reference(&adopted.local_project_id, Some(&link)).is_err());
        link.remote_id = "PROJ42".into();
        assert_eq!(
            live_project_reference(&adopted.local_project_id, Some(&link)).unwrap(),
            "PROJ42"
        );

        let other = upsert_live_binding(
            conn,
            &dek,
            &workspace,
            PlatformKind::ZoomkeyCrm,
            "https://crm.example.test/another-instance",
            "read-only",
            "test-credential",
        )
        .unwrap();
        assert_ne!(other.id, link.source_binding_id);
        assert!(!same_crm_source(&other, &bindings.crm));
        assert_eq!(
            site_from_base("https://crm.example.test/crm/webservice.php"),
            "https://crm.example.test/crm"
        );
    }

    #[test]
    fn crm_selection_prefers_explicit_then_the_only_configured_profile() {
        let candidates =
            ["unconfigured", "configured"].map(|id| zoomkey::ZoomkeyCredentialOption {
                id: id.into(),
                title: String::new(),
                account: None,
            });
        let profile =
            |id: &str| Ok((id == "configured").then(|| "https://crm.example.test".to_string()));
        let (selected, origin) = select_crm_credential("", &candidates, profile)
            .unwrap()
            .unwrap();
        assert_eq!(selected.id, "configured");
        assert_eq!(origin.as_deref(), Some("https://crm.example.test"));
        let (selected, origin) = select_crm_credential("unconfigured", &candidates, profile)
            .unwrap()
            .unwrap();
        assert_eq!(selected.id, "unconfigured");
        assert_eq!(origin, None); // explicitly selected legacy endpoint
        assert!(select_crm_credential("deleted", &candidates, profile).is_err());
        assert!(select_crm_credential("", &candidates, |_| Ok(Some(
            "https://crm.example.test".into()
        )))
        .is_err());
    }

    #[test]
    fn search_fixture_keyword_and_detail_overlays() {
        let (vault, dek) = open_vault();
        let conn = vault.project_conn();
        // Fixture-path unit test (no live Session credentials).
        let workspace_id = ensure_workspace(conn, &dek).unwrap();
        let bindings = load_workspace_bindings(conn, &dek, &workspace_id).unwrap();
        let (items, warnings) =
            search_remote_fixture(conn, &dek, &workspace_id, &bindings.crm, "徐矿").unwrap();
        assert_eq!(items.len(), 1);
        assert!(!items[0].adopted);
        assert!(warnings.is_empty());

        let adopted = adopt(
            conn,
            &dek,
            &bindings,
            fixture::PROJECT_NUMBER,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(adopted.created);

        set_short_name(
            conn,
            &dek,
            SetShortNameRequest {
                id: fixture::REMOTE_ID.into(),
                short_name: "XKRL".into(),
            },
        )
        .unwrap();

        bind_customer(
            conn,
            &dek,
            BindCustomerRequest {
                id: fixture::REMOTE_ID.into(),
                role: CustomerRoleDto::Contract,
                binding: LocalCustomerBindingDto {
                    kind: LocalCustomerKind::Erp,
                    client_id: Some(fixture::CONTRACT_CLIENT_ID.into()),
                    name: Some(fixture::CONTRACT_CLIENT_NAME.into()),
                },
            },
        )
        .unwrap();

        let detail = build_detail(conn, &dek, &workspace_id, &bindings.crm, "PROJ3733")
            .unwrap()
            .unwrap();
        assert!(detail.adopted);
        assert_eq!(detail.short_name, "XKRL");
        assert!(matches!(detail.local.contract.kind, LocalCustomerKind::Erp));
        assert!(!detail.erp_issues.is_empty());
    }
}
