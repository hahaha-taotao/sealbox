//! Tauri command handlers for the project workbench.

use tauri::State;

use crate::commands::AppState;
use crate::lock::lock_session;

use super::dto::{
    AdoptRequest, AdoptResultDto, BindCustomerRequest, CreateLocalProjectRequest, JiraIssueRequest, JiraRangeRequest,
    LocalProjectDto, MutationMessageDto, ProjectDetailDto, ProjectRefRequest, ProjectSummaryDto,
    RemoteSearchPageDto, SearchRemoteRequest, SetShortNameRequest, SourceBindingSummaryDto,
    UnbindCustomerRequest,
};
use super::service;

fn with_project_store<T>(
    state: &AppState,
    f: impl FnOnce(&rusqlite::Connection, &[u8; 32]) -> Result<T, String>,
) -> Result<T, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(|e| e.to_string())?;
    let dek = *session.dek().map_err(|e| e.to_string())?;
    let vault = session.vault().map_err(|e| e.to_string())?;
    f(vault.project_conn(), &dek)
}

/// Remote reads may need ZoomKey credentials from the Session. Network I/O runs
/// first (borrow Session), then local store overlays use vault.project_conn.
fn with_remote_session<T>(
    state: &AppState,
    f: impl FnOnce(&crate::session::Session) -> Result<T, String>,
) -> Result<T, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(|e| e.to_string())?;
    f(&session)
}

#[tauri::command]
pub fn project_sources_list(
    state: State<'_, AppState>,
) -> Result<Vec<SourceBindingSummaryDto>, String> {
    with_remote_session(&state, |session| service::sources_list(session))
}

#[tauri::command]
pub fn project_search_remote(
    state: State<'_, AppState>,
    request: SearchRemoteRequest,
) -> Result<RemoteSearchPageDto, String> {
    with_remote_session(&state, |session| service::search_remote(session, request))
}

#[tauri::command]
pub fn project_adopt(
    state: State<'_, AppState>,
    request: AdoptRequest,
) -> Result<AdoptResultDto, String> {
    with_remote_session(&state, |session| {
        service::adopt_from_session(session, request)
    })
}

#[tauri::command]
pub fn project_create_local(
    state: State<'_, AppState>,
    request: CreateLocalProjectRequest,
) -> Result<AdoptResultDto, String> {
    with_project_store(&state, |conn, dek| {
        service::create_local_project(conn, dek, &request.title, request.short_name.as_deref())
    })
}

#[tauri::command]
pub fn project_list(state: State<'_, AppState>) -> Result<Vec<ProjectSummaryDto>, String> {
    with_project_store(&state, service::list_summaries)
}

#[tauri::command]
pub fn project_list_local(state: State<'_, AppState>) -> Result<Vec<LocalProjectDto>, String> {
    with_project_store(&state, service::list_local)
}

#[tauri::command]
pub fn project_get(
    state: State<'_, AppState>,
    request: ProjectRefRequest,
) -> Result<Option<ProjectDetailDto>, String> {
    with_remote_session(&state, |session| service::get_detail(session, &request.id))
}

#[tauri::command]
pub fn project_set_short_name(
    state: State<'_, AppState>,
    request: SetShortNameRequest,
) -> Result<ProjectDetailDto, String> {
    with_project_store(&state, |conn, dek| service::set_short_name(conn, dek, request))
}

#[tauri::command]
pub fn project_bind_customer(
    state: State<'_, AppState>,
    request: BindCustomerRequest,
) -> Result<ProjectDetailDto, String> {
    with_project_store(&state, |conn, dek| service::bind_customer(conn, dek, request))
}

#[tauri::command]
pub fn project_unbind_customer(
    state: State<'_, AppState>,
    request: UnbindCustomerRequest,
) -> Result<ProjectDetailDto, String> {
    with_project_store(&state, |conn, dek| service::unbind_customer(conn, dek, request))
}

#[tauri::command]
pub fn project_add_jira_range(
    state: State<'_, AppState>,
    request: JiraRangeRequest,
) -> Result<MutationMessageDto, String> {
    with_project_store(&state, |conn, dek| service::add_jira_range(conn, dek, request))
}

#[tauri::command]
pub fn project_remove_jira_range(
    state: State<'_, AppState>,
    request: JiraRangeRequest,
) -> Result<MutationMessageDto, String> {
    with_project_store(&state, |conn, dek| {
        service::remove_jira_range(conn, dek, request)
    })
}

#[tauri::command]
pub fn project_add_jira_issue(
    state: State<'_, AppState>,
    request: JiraIssueRequest,
) -> Result<MutationMessageDto, String> {
    with_project_store(&state, |conn, dek| service::add_jira_issue(conn, dek, request))
}

#[tauri::command]
pub fn project_unbind_jira_issue(
    state: State<'_, AppState>,
    request: JiraIssueRequest,
) -> Result<ProjectDetailDto, String> {
    with_project_store(&state, |conn, dek| {
        service::unbind_jira_issue(conn, dek, request)
    })
}
