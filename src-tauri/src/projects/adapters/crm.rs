//! Structured ZoomKey CRM (ERP) adapter.
//!
//! Field IDs follow design §4 / §5.1. Missing values become empty / unread /
//! explicit zero — never invented numbers.

use serde_json::Value;

use crate::projects::dto::{
    FactCustomersDto, HourDetailSumDto, HourRowDto, HourSummaryDto, JiraTaskDto, MoneyItemDto,
    OperatingMetricsDto, ProjectAmountsDto, ProjectHoursDto, ProjectStaffDto, ProjectSummaryDto,
};
use crate::zoomkey::{crm as zoomkey_crm, EndpointRuntime, ToolFailure};

/// Verified ERP Project amount / workload field ids (design §4, §5.1).
pub mod fields {
    pub const PROJECT_NO: &str = "project_no";
    pub const PROJECT_NAME: &str = "projectname";
    pub const PROJECT_STATUS: &str = "projectstatus";
    pub const START_DATE: &str = "startdate";
    /// Provisional: Vtiger standard planned end — used as plan delivery until live
    /// confirmation splits 计划上线 / 计划交付 into distinct custom fields.
    pub const TARGET_END_DATE: &str = "targetenddate";
    pub const ACTUAL_END_DATE: &str = "actualenddate";
    pub const CONTRACT_CUSTOMER: &str = "linktoaccountscontacts";
    pub const USER_CUSTOMER: &str = "cf_nrl_accounts271_id";
    pub const ASSIGNED_USER: &str = "assigned_user_id";

    pub const TARGET_BUDGET: &str = "targetbudget";
    pub const COST_TOTAL: &str = "cf_2697";
    pub const CONTRACT_AMOUNT_CF9778: &str = "cf_9778";
    pub const BUDGET_PROFIT: &str = "cf_9758";
    pub const OP_CONTRACT: &str = "cf_1486";
    pub const OP_PAYMENT: &str = "cf_2932";
    pub const OP_PAYMENT_PROFIT: &str = "cf_1488";

    pub const BUDGET_IMPL: &str = "cf_8931";
    pub const BUDGET_DEV: &str = "cf_8927";
    pub const BUDGET_TRAVEL: &str = "cf_8935";
    pub const BUDGET_MGMT: &str = "cf_9782";
    pub const BUDGET_OUTSOURCE: &str = "cf_9780";
    // Tax budget field id still unverified (design §4).

    pub const COST_IMPL: &str = "cf_1570";
    pub const COST_DEV: &str = "cf_1350";
    pub const COST_TRAVEL: &str = "cf_1348";
    pub const COST_MGMT: &str = "cf_2197";
    pub const COST_HW: &str = "cf_1342";
    pub const COST_TAX: &str = "cf_1344";

    pub const HOURS_TOTAL: &str = "cf_1634";
    pub const HOURS_IMPL: &str = "cf_1630";
    pub const HOURS_DEV: &str = "cf_1632";
    pub const TRAVEL_DAYS: &str = "cf_2199";

    // Members
    pub const MEMBER_NAME: &str = "name";
    pub const MEMBER_ROLE: &str = "cf_5646";
    pub const MEMBER_STATUS: &str = "cf_7620";
    pub const MEMBER_HOURS: &str = "cf_5659";
    pub const MEMBER_START: &str = "cf_5655";

    // Hour rows
    pub const HOUR_DATE: &str = "cf_7543";
    pub const HOUR_HOURS: &str = "cf_6057";
    pub const HOUR_DAYS: &str = "cf_6059";
    pub const HOUR_MEMBER: &str = "cf_members_id";

    // JIRATask links
    pub const JIRA_KEY: &str = "cf_7907";
    pub const JIRA_LINK: &str = "cf_7921";
    pub const JIRA_DEV_HOURS: &str = "cf_8804";
    pub const JIRA_DEV_COST: &str = "cf_9798";
    pub const JIRA_PROJECT_ID: &str = "cf_project_id";
}

#[derive(Clone, Debug)]
pub struct MappedProject {
    pub remote_id: String,
    pub number: String,
    pub title: String,
    pub stage: String,
    pub owner: String,
    pub start: String,
    pub plan_online: String,
    pub plan_delivery: String,
    pub actual_end: Option<String>,
    pub fact: FactCustomersDto,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ProjectBundle {
    pub project: Option<MappedProject>,
    pub staff: Vec<ProjectStaffDto>,
    pub amounts: Option<ProjectAmountsDto>,
    pub hours: Option<ProjectHoursDto>,
    pub erp_issues: Vec<JiraTaskDto>,
    pub warnings: Vec<String>,
}

fn str_field(record: &Value, key: &str) -> Option<String> {
    match record.get(key)? {
        Value::Null => None,
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        other => {
            // Related records sometimes arrive as { "id": "11x…", "label": "…" }
            if let Some(id) = other.get("id").and_then(Value::as_str) {
                let t = id.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
            if let Some(label) = other
                .get("label")
                .or_else(|| other.get("name"))
                .and_then(Value::as_str)
            {
                let t = label.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
            None
        }
    }
}

/// Parse a money/hours field. Empty / missing → None. Explicit `0` → Some(0.0).
pub(crate) fn parse_number(record: &Value, key: &str) -> Option<f64> {
    let value = record.get(key)?;
    match value {
        Value::Null => None,
        Value::Number(n) => n.as_f64(),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                t.replace(',', "").parse::<f64>().ok()
            }
        }
        _ => None,
    }
}

fn money_item(key: &str, amount: Option<f64>, source: &str) -> MoneyItemDto {
    MoneyItemDto {
        key: key.into(),
        amount,
        source: source.into(),
    }
}

/// Map a raw CRM Project JSON record into a summary DTO.
pub(crate) fn map_project_summary(
    record: &Value,
    adopted: bool,
    local_project_id: Option<String>,
    short_name: &str,
) -> Result<ProjectSummaryDto, String> {
    let mapped = map_project(record)?;
    Ok(ProjectSummaryDto {
        id: mapped.number.clone(),
        crm_id: mapped.remote_id.clone(),
        title: mapped.title.clone(),
        stage: mapped.stage.clone(),
        owner: mapped.owner.clone(),
        contract_customer_id: mapped.fact.contract.clone(),
        contract_customer_name: None,
        user_customer_id: mapped.fact.user.clone(),
        user_customer_name: None,
        short_name: short_name.to_string(),
        adopted,
        local_project_id,
    })
}

pub(crate) fn map_project(record: &Value) -> Result<MappedProject, String> {
    let remote_id = str_field(record, "id").ok_or_else(|| "Project 缺少 id".to_string())?;
    let number = str_field(record, fields::PROJECT_NO).unwrap_or_default();
    let title = str_field(record, fields::PROJECT_NAME).unwrap_or_default();
    if number.is_empty() && title.is_empty() {
        return Err("Project 缺少 project_no / projectname".into());
    }
    let mut warnings = Vec::new();
    let plan_delivery = str_field(record, fields::TARGET_END_DATE).unwrap_or_default();
    // 计划上线 field id not yet confirmed in the source catalog — leave empty
    // rather than inventing a value or reusing plan_delivery.
    let plan_online = String::new();
    if plan_online.is_empty() {
        warnings.push(
            "ERP 计划上线字段 ID 待确认；当前仅映射 startdate / targetenddate / actualenddate"
                .into(),
        );
    }
    Ok(MappedProject {
        remote_id,
        number,
        title,
        stage: str_field(record, fields::PROJECT_STATUS).unwrap_or_default(),
        owner: str_field(record, fields::ASSIGNED_USER).unwrap_or_default(),
        start: str_field(record, fields::START_DATE).unwrap_or_default(),
        plan_online,
        plan_delivery,
        actual_end: str_field(record, fields::ACTUAL_END_DATE),
        fact: FactCustomersDto {
            contract: str_field(record, fields::CONTRACT_CUSTOMER),
            user: str_field(record, fields::USER_CUSTOMER),
        },
        warnings,
    })
}

pub(crate) fn map_amounts(record: &Value) -> ProjectAmountsDto {
    let budget_total = parse_number(record, fields::TARGET_BUDGET);
    let cost_total = parse_number(record, fields::COST_TOTAL);
    let budget_diff = match (budget_total, cost_total) {
        (Some(b), Some(c)) => Some(((b - c) * 100.0).round() / 100.0),
        _ => None,
    };
    ProjectAmountsDto {
        contract_amount: parse_number(record, fields::CONTRACT_AMOUNT_CF9778).unwrap_or(0.0),
        budget_total: budget_total.unwrap_or(0.0),
        cost_total: cost_total.unwrap_or(0.0),
        budget_diff: budget_diff.unwrap_or(0.0),
        budget_profit: parse_number(record, fields::BUDGET_PROFIT).unwrap_or(0.0),
        operating: OperatingMetricsDto {
            contract_amount: parse_number(record, fields::OP_CONTRACT).unwrap_or(0.0),
            total_payment: parse_number(record, fields::OP_PAYMENT).unwrap_or(0.0),
            payment_profit: parse_number(record, fields::OP_PAYMENT_PROFIT).unwrap_or(0.0),
        },
        budget_items: vec![
            money_item(
                "实施",
                parse_number(record, fields::BUDGET_IMPL),
                "ERP Project · 实施预算 · cf_8931",
            ),
            money_item(
                "研发",
                parse_number(record, fields::BUDGET_DEV),
                "ERP Project · 研发预算 · cf_8927",
            ),
            money_item(
                "差旅",
                parse_number(record, fields::BUDGET_TRAVEL),
                "ERP Project · 差旅预算 · cf_8935",
            ),
            money_item(
                "管理",
                parse_number(record, fields::BUDGET_MGMT),
                "ERP Project · 管理预算 · cf_9782",
            ),
            money_item(
                "外采",
                parse_number(record, fields::BUDGET_OUTSOURCE),
                "ERP Project · 外采预算 · cf_9780",
            ),
            money_item(
                "税费",
                None,
                "ERP Project · 税费预算字段暂无值（待核实）",
            ),
        ],
        cost_items: vec![
            money_item(
                "实施",
                parse_number(record, fields::COST_IMPL),
                "ERP Project · 实施成本 · cf_1570",
            ),
            money_item(
                "开发",
                parse_number(record, fields::COST_DEV),
                "ERP Project · 开发成本 · cf_1350",
            ),
            money_item(
                "差旅",
                parse_number(record, fields::COST_TRAVEL),
                "ERP Project · 差旅成本 · cf_1348",
            ),
            money_item(
                "管理",
                parse_number(record, fields::COST_MGMT),
                "ERP Project · 管理成本 · cf_2197",
            ),
            money_item(
                "硬件外采",
                parse_number(record, fields::COST_HW),
                "ERP Project · 硬件外采成本 · cf_1342",
            ),
            money_item(
                "税费",
                parse_number(record, fields::COST_TAX),
                "ERP Project · 税费成本 · cf_1344",
            ),
        ],
    }
}

pub(crate) fn map_hours_summary(project: &Value, hour_rows: &[Value]) -> ProjectHoursDto {
    let rows: Vec<HourRowDto> = hour_rows
        .iter()
        .filter_map(|row| {
            Some(HourRowDto {
                date: str_field(row, fields::HOUR_DATE).unwrap_or_default(),
                id: str_field(row, "id")
                    .or_else(|| str_field(row, "hour_no"))
                    .unwrap_or_default(),
                hours: parse_number(row, fields::HOUR_HOURS).unwrap_or(0.0),
                days: parse_number(row, fields::HOUR_DAYS).unwrap_or(0.0),
                member: str_field(row, fields::HOUR_MEMBER).unwrap_or_default(),
            })
        })
        .collect();
    let detail_hours: f64 = rows.iter().map(|r| r.hours).sum();
    let detail_days: f64 = rows.iter().map(|r| r.days).sum();
    ProjectHoursDto {
        summary: HourSummaryDto {
            total: parse_number(project, fields::HOURS_TOTAL).unwrap_or(0.0),
            impl_hours: parse_number(project, fields::HOURS_IMPL).unwrap_or(0.0),
            dev: parse_number(project, fields::HOURS_DEV).unwrap_or(0.0),
            travel_days: parse_number(project, fields::TRAVEL_DAYS).unwrap_or(0.0),
        },
        detail_sum: HourDetailSumDto {
            hours: detail_hours,
            days: detail_days,
        },
        rows,
    }
}

pub(crate) fn map_members(records: &[Value]) -> Vec<ProjectStaffDto> {
    records
        .iter()
        .map(|row| ProjectStaffDto {
            name: str_field(row, fields::MEMBER_NAME).unwrap_or_default(),
            role: str_field(row, fields::MEMBER_ROLE).unwrap_or_default(),
            source: "ERP Members".into(),
            hours: parse_number(row, fields::MEMBER_HOURS)
                .map(|h| format!("{h:.2}"))
                .unwrap_or_else(|| "0.00".into()),
            status: str_field(row, fields::MEMBER_STATUS).unwrap_or_default(),
            start: str_field(row, fields::MEMBER_START).unwrap_or_default(),
        })
        .collect()
}

/// Map ERP JIRATask rows. Jira priority/due/assignee filled later by the Jira adapter.
pub(crate) fn map_jira_task_links(records: &[Value], snapshot_date: &str) -> Vec<JiraTaskDto> {
    records
        .iter()
        .filter_map(|row| {
            let key = str_field(row, fields::JIRA_KEY)?;
            let project_key = match key.rfind('-') {
                Some(i) => key[..i].to_string(),
                None => key.clone(),
            };
            Some(JiraTaskDto {
                key,
                title: str_field(row, "name")
                    .or_else(|| str_field(row, "jira_task_title"))
                    .unwrap_or_default(),
                jira_project_key: project_key,
                status: String::new(),
                priority: "—".into(),
                batch: "—".into(), // batch custom field id not yet confirmed
                due_date: "—".into(),
                assignee: String::new(),
                origin: "erp".into(),
                hours: parse_number(row, fields::JIRA_DEV_HOURS),
                amount: parse_number(row, fields::JIRA_DEV_COST),
                kind: str_field(row, "cf_8802").or_else(|| str_field(row, "jira_issue_type")),
                snapshot_date: Some(snapshot_date.to_string()),
            })
        })
        .collect()
}

fn sql_eq(field: &str, value: &str) -> String {
    format!(
        "{} = '{}'",
        field,
        zoomkey_crm::escape_sql_literal(value)
    )
}

/// Search projects by exact project_no / id / name (design: exact match baseline).
pub(crate) fn search_projects(
    runtime: &EndpointRuntime,
    keyword: &str,
    limit: u64,
) -> Result<(Vec<Value>, Vec<String>), ToolFailure> {
    let q = keyword.trim();
    let limit = limit.clamp(1, 100);
    let mut warnings = Vec::new();
    if q.is_empty() {
        warnings.push("请输入项目编号或名称后再查询".into());
        return Ok((Vec::new(), warnings));
    }

    // Prefer exact project_no, then id, then name.
    let by_no = format!(
        "select * from Project where {} limit {limit};",
        sql_eq(fields::PROJECT_NO, q)
    );
    let mut records = zoomkey_crm::run_query_inner(runtime, &by_no)?;
    if records.is_empty() && q.contains('x') {
        let by_id = format!(
            "select * from Project where {} limit {limit};",
            sql_eq("id", q)
        );
        records = zoomkey_crm::run_query_inner(runtime, &by_id)?;
    }
    if records.is_empty() {
        let by_name = format!(
            "select * from Project where {} limit {limit};",
            sql_eq(fields::PROJECT_NAME, q)
        );
        records = zoomkey_crm::run_query_inner(runtime, &by_name)?;
    }
    if records.is_empty() {
        warnings.push("ERP 精确匹配无结果（project_no / id / projectname）".into());
    }
    Ok((records, warnings))
}

pub(crate) fn retrieve_project(
    runtime: &EndpointRuntime,
    remote_id: &str,
) -> Result<Value, ToolFailure> {
    zoomkey_crm::retrieve_inner(runtime, remote_id)
}

pub(crate) fn query_members(
    runtime: &EndpointRuntime,
    project_id: &str,
    limit: u64,
) -> Result<Vec<Value>, ToolFailure> {
    let limit = limit.clamp(1, 100);
    let sql = format!(
        "select * from Members where {} limit {limit};",
        sql_eq(fields::JIRA_PROJECT_ID, project_id)
    );
    zoomkey_crm::run_query_inner(runtime, &sql)
}

pub(crate) fn query_hours(
    runtime: &EndpointRuntime,
    project_id: &str,
    limit: u64,
) -> Result<Vec<Value>, ToolFailure> {
    let limit = limit.clamp(1, 200);
    let sql = format!(
        "select * from Hour where {} limit {limit};",
        sql_eq(fields::JIRA_PROJECT_ID, project_id)
    );
    zoomkey_crm::run_query_inner(runtime, &sql)
}

pub(crate) fn query_jira_tasks(
    runtime: &EndpointRuntime,
    project_id: &str,
    limit: u64,
) -> Result<Vec<Value>, ToolFailure> {
    let limit = limit.clamp(1, 200);
    let sql = format!(
        "select * from JIRATask where {} limit {limit};",
        sql_eq(fields::JIRA_PROJECT_ID, project_id)
    );
    zoomkey_crm::run_query_inner(runtime, &sql)
}

/// Fetch a full project bundle over a live runtime (structured JSON only).
pub(crate) fn fetch_project_bundle(
    runtime: &EndpointRuntime,
    remote_id: &str,
    snapshot_date: &str,
) -> Result<ProjectBundle, ToolFailure> {
    let mut warnings = Vec::new();
    let project_json = retrieve_project(runtime, remote_id)?;
    let mapped = map_project(&project_json).map_err(ToolFailure::validation)?;
    warnings.extend(mapped.warnings.iter().cloned());

    let staff = match query_members(runtime, remote_id, 100) {
        Ok(rows) => map_members(&rows),
        Err(e) => {
            warnings.push(format!("Members 读取失败：{}", e.message));
            Vec::new()
        }
    };
    let hour_rows = match query_hours(runtime, remote_id, 100) {
        Ok(rows) => rows,
        Err(e) => {
            warnings.push(format!("Hour 读取失败：{}", e.message));
            Vec::new()
        }
    };
    let hours = map_hours_summary(&project_json, &hour_rows);
    let erp_issues = match query_jira_tasks(runtime, remote_id, 100) {
        Ok(rows) => map_jira_task_links(&rows, snapshot_date),
        Err(e) => {
            warnings.push(format!("JIRATask 读取失败：{}", e.message));
            Vec::new()
        }
    };

    Ok(ProjectBundle {
        amounts: Some(map_amounts(&project_json)),
        hours: Some(hours),
        project: Some(mapped),
        staff,
        erp_issues,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Recorded-shaped PROJ3733 Project JSON (design §4 / §5.1).
    fn sample_project() -> Value {
        json!({
            "id": "30x564318",
            "project_no": "PROJ3733",
            "projectname": "2026-徐矿-新增子公司-城南分公司",
            "projectstatus": "启动",
            "startdate": "2026-08-24",
            "targetenddate": "2026-10-31",
            "actualenddate": "",
            "linktoaccountscontacts": "11x148029",
            "cf_nrl_accounts271_id": "11x564023",
            "assigned_user_id": "19x1",
            "targetbudget": "25100",
            "cf_2697": "21552.73",
            "cf_9778": "60000",
            "cf_9758": "3580.87",
            "cf_1486": "60000",
            "cf_2932": "60000",
            "cf_1488": "38447.27",
            "cf_8931": "7500",
            "cf_8927": "6000",
            "cf_8935": "2000",
            "cf_9782": "9600",
            "cf_9780": "0",
            "cf_1570": "8594",
            "cf_1350": "1353.13",
            "cf_1348": "1972",
            "cf_2197": "9593.60",
            "cf_1342": "40",
            "cf_1344": "0",
            "cf_1634": "61.60",
            "cf_1630": "55",
            "cf_1632": "6.60",
            "cf_2199": "5",
        })
    }

    #[test]
    fn maps_proj3733_amounts_without_inventing() {
        let amounts = map_amounts(&sample_project());
        assert_eq!(amounts.contract_amount, 60000.0);
        assert_eq!(amounts.budget_total, 25100.0);
        assert_eq!(amounts.cost_total, 21552.73);
        assert_eq!(amounts.budget_diff, 3547.27);
        assert_eq!(amounts.budget_profit, 3580.87);
        assert_eq!(amounts.operating.payment_profit, 38447.27);
        let outsource = amounts
            .budget_items
            .iter()
            .find(|i| i.key == "外采")
            .unwrap();
        assert_eq!(outsource.amount, Some(0.0));
        let tax_budget = amounts
            .budget_items
            .iter()
            .find(|i| i.key == "税费")
            .unwrap();
        assert!(tax_budget.amount.is_none());
        let tax_cost = amounts.cost_items.iter().find(|i| i.key == "税费").unwrap();
        assert_eq!(tax_cost.amount, Some(0.0));
    }

    #[test]
    fn missing_amount_fields_stay_empty() {
        let record = json!({
            "id": "30x1",
            "project_no": "PROJ1",
            "projectname": "empty",
            "cf_9780": "",
            "cf_1342": null,
        });
        let amounts = map_amounts(&record);
        assert_eq!(amounts.budget_total, 0.0);
        assert_eq!(amounts.cost_total, 0.0);
        assert_eq!(amounts.budget_diff, 0.0);
        let outsource = amounts
            .budget_items
            .iter()
            .find(|i| i.key == "外采")
            .unwrap();
        assert!(outsource.amount.is_none());
        let hw = amounts
            .cost_items
            .iter()
            .find(|i| i.key == "硬件外采")
            .unwrap();
        assert!(hw.amount.is_none());
    }

    #[test]
    fn maps_jira_task_links() {
        let rows = vec![json!({
            "id": "99x1",
            "cf_project_id": "30x564318",
            "cf_7907": "XKRLWXM-56",
            "cf_7921": "https://jira.example/browse/XKRLWXM-56",
            "cf_8804": "5",
            "cf_9798": "1093.75",
            "name": "新增城南子公司走银联支付接口",
        })];
        let tasks = map_jira_task_links(&rows, "2026-11-18");
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].key, "XKRLWXM-56");
        assert_eq!(tasks[0].jira_project_key, "XKRLWXM");
        assert_eq!(tasks[0].hours, Some(5.0));
        assert_eq!(tasks[0].amount, Some(1093.75));
        assert_eq!(tasks[0].batch, "—");
        assert_eq!(tasks[0].priority, "—");
        assert_eq!(tasks[0].origin, "erp");
    }

    #[test]
    fn maps_members_and_hours() {
        let members = map_members(&[json!({
            "name": "Alice",
            "cf_5646": "项目经理",
            "cf_7620": "参与中",
            "cf_5659": "55",
            "cf_5655": "2026-08-19",
        })]);
        assert_eq!(members[0].hours, "55.00");
        let hours = map_hours_summary(
            &sample_project(),
            &[json!({
                "id": "HO15473",
                "cf_7543": "2026-08-28",
                "cf_6057": "5",
                "cf_6059": "0",
                "cf_members_id": "Alice",
            })],
        );
        assert_eq!(hours.summary.total, 61.6);
        assert_eq!(hours.detail_sum.hours, 5.0);
        assert_eq!(hours.rows.len(), 1);
    }

    #[test]
    fn map_project_preserves_customer_roles() {
        let mapped = map_project(&sample_project()).unwrap();
        assert_eq!(mapped.number, "PROJ3733");
        assert_eq!(mapped.fact.contract.as_deref(), Some("11x148029"));
        assert_eq!(mapped.fact.user.as_deref(), Some("11x564023"));
        assert_eq!(mapped.plan_delivery, "2026-10-31");
        assert!(mapped.actual_end.is_none());
        assert!(mapped.plan_online.is_empty());
    }
}
