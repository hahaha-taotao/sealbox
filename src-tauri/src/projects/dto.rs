//! Wire DTOs shared between Tauri commands and the Vue `project-api` layer.
//! Field names stay camelCase to match the frontend.

use serde::{Deserialize, Serialize};

/// Vue role keys (`contract` / `user`), mapped to core `CustomerRole` in the service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CustomerRoleDto {
    Contract,
    User,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LocalCustomerKind {
    Erp,
    Manual,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalCustomerBindingDto {
    pub kind: LocalCustomerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Default for LocalCustomerBindingDto {
    fn default() -> Self {
        Self {
            kind: LocalCustomerKind::None,
            client_id: None,
            name: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceBindingSummaryDto {
    pub id: String,
    pub platform: String,
    pub site: String,
    pub account_scope: String,
    pub status: String,
    /// Credential entry id only — never the secret.
    pub credential_entry_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSummaryDto {
    pub id: String,
    pub crm_id: String,
    pub title: String,
    pub stage: String,
    pub owner: String,
    pub contract_customer_id: Option<String>,
    pub contract_customer_name: Option<String>,
    pub user_customer_id: Option<String>,
    pub user_customer_name: Option<String>,
    pub short_name: String,
    pub adopted: bool,
    pub local_project_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteSearchPageDto {
    pub items: Vec<ProjectSummaryDto>,
    pub next_cursor: Option<String>,
    pub complete: bool,
    pub fetched_at: String,
    pub source_binding_id: String,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectStaffDto {
    pub name: String,
    pub role: String,
    pub source: String,
    pub hours: String,
    pub status: String,
    pub start: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoneyItemDto {
    pub key: String,
    pub amount: Option<f64>,
    pub source: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectAmountsDto {
    pub contract_amount: f64,
    pub budget_total: f64,
    pub cost_total: f64,
    pub budget_diff: f64,
    pub budget_profit: f64,
    pub operating: OperatingMetricsDto,
    pub budget_items: Vec<MoneyItemDto>,
    pub cost_items: Vec<MoneyItemDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatingMetricsDto {
    pub contract_amount: f64,
    pub total_payment: f64,
    pub payment_profit: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HourSummaryDto {
    pub total: f64,
    /// ERP 实施工时 — JSON key must stay `impl` to match Vue.
    #[serde(rename = "impl")]
    pub impl_hours: f64,
    pub dev: f64,
    pub travel_days: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HourDetailSumDto {
    pub hours: f64,
    pub days: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HourRowDto {
    pub date: String,
    pub id: String,
    pub hours: f64,
    pub days: f64,
    pub member: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectHoursDto {
    pub summary: HourSummaryDto,
    pub detail_sum: HourDetailSumDto,
    pub rows: Vec<HourRowDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraCatalogEntryDto {
    pub name: String,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraTaskDto {
    pub key: String,
    pub title: String,
    pub jira_project_key: String,
    pub status: String,
    pub priority: String,
    pub batch: String,
    pub due_date: String,
    pub assignee: String,
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hours: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_date: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevTaskDto {
    pub key: String,
    pub title: String,
    pub project: String,
    pub hours: f64,
    pub amount: f64,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectDetailDto {
    pub id: String,
    pub crm_id: String,
    pub title: String,
    pub stage: String,
    pub owner: String,
    pub start: String,
    pub plan_online: String,
    pub plan_delivery: String,
    pub actual_end: Option<String>,
    pub short_name: String,
    pub fact: FactCustomersDto,
    pub local: LocalCustomersDto,
    pub manual_ranges: Vec<String>,
    pub local_issues: Vec<String>,
    pub staff: Vec<ProjectStaffDto>,
    pub amounts: ProjectAmountsDto,
    pub hours: ProjectHoursDto,
    pub jira_catalog: std::collections::BTreeMap<String, JiraCatalogEntryDto>,
    pub jira_status_defaults: Vec<String>,
    pub erp_issues: Vec<JiraTaskDto>,
    pub dev_tasks: Vec<DevTaskDto>,
    pub snapshot_date: String,
    pub adopted: bool,
    pub local_project_id: Option<String>,
    pub revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FactCustomersDto {
    pub contract: Option<String>,
    pub user: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalCustomersDto {
    pub contract: LocalCustomerBindingDto,
    pub user: LocalCustomerBindingDto,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdoptResultDto {
    pub local_project_id: String,
    pub remote_id: String,
    pub created: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalProjectDto {
    pub local_project_id: String,
    pub remote_id: String,
    pub short_name: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationMessageDto {
    pub detail: ProjectDetailDto,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub still_auto: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchRemoteRequest {
    #[serde(default)]
    pub keyword: String,
    #[serde(default)]
    pub source_binding_id: Option<String>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdoptRequest {
    pub remote_id: String,
    #[serde(default)]
    pub source_binding_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRefRequest {
    /// Remote CRM id, project number, or local project UUID.
    pub id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetShortNameRequest {
    pub id: String,
    pub short_name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BindCustomerRequest {
    pub id: String,
    pub role: CustomerRoleDto,
    pub binding: LocalCustomerBindingDto,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnbindCustomerRequest {
    pub id: String,
    pub role: CustomerRoleDto,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraRangeRequest {
    pub id: String,
    pub key: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraIssueRequest {
    pub id: String,
    pub issue_key: String,
}
