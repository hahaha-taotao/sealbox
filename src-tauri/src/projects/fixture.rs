//! Offline PROJ3733 snapshot used when no real SourceBinding / profile is
//! available, or when the structured ZoomKey adapter fails.
//!
//! Live reads go through [`crate::projects::adapters`] (JSON → DTO). This module
//! remains the regression fixture and service fallback — never scrape
//! ToolOutcome text.

use std::collections::BTreeMap;

use super::dto::{
    DevTaskDto, FactCustomersDto, HourDetailSumDto, HourRowDto, HourSummaryDto, JiraCatalogEntryDto,
    JiraTaskDto, MoneyItemDto, OperatingMetricsDto, ProjectAmountsDto, ProjectHoursDto,
    ProjectStaffDto, ProjectSummaryDto,
};

pub const SNAPSHOT_DATE: &str = "2026-11-18";
pub const PROJECT_NUMBER: &str = "PROJ3733";
pub const REMOTE_ID: &str = "30x564318";
pub const DEFAULT_SHORT_NAME: &str = "XKRL";
pub const TITLE: &str = "2026-徐矿-新增子公司-城南分公司";
pub const STAGE: &str = "启动";
pub const OWNER: &str = "张文宇";

pub const FIXTURE_CRM_SITE: &str = "https://fixture.sealbox.local/zoomkey-crm";
pub const FIXTURE_JIRA_SITE: &str = "https://fixture.sealbox.local/zoomkey-jira";
pub const FIXTURE_ACCOUNT_SCOPE: &str = "fixture-readonly";
/// Placeholder credential ref — never a secret. Real binds use vault entry ids.
pub const FIXTURE_CREDENTIAL_REF: &str = "fixture:proj3733";

pub const CONTRACT_CLIENT_ID: &str = "11x148029";
pub const CONTRACT_CLIENT_NAME: &str = "江苏徐矿热力有限公司";
pub const USER_CLIENT_ID: &str = "11x564023";
pub const USER_CLIENT_NAME: &str = "江苏徐矿城南热力有限公司";

#[derive(Clone, Debug)]
pub struct FixtureRemoteProject {
    pub number: &'static str,
    pub remote_id: &'static str,
    pub title: &'static str,
    pub stage: &'static str,
    pub owner: &'static str,
    pub start: &'static str,
    pub plan_online: &'static str,
    pub plan_delivery: &'static str,
    pub actual_end: Option<&'static str>,
    pub short_name: &'static str,
    pub fact: FactCustomersDto,
}

pub fn remote_project() -> FixtureRemoteProject {
    FixtureRemoteProject {
        number: PROJECT_NUMBER,
        remote_id: REMOTE_ID,
        title: TITLE,
        stage: STAGE,
        owner: OWNER,
        start: "2026-08-24",
        plan_online: "2026-09-15",
        plan_delivery: "2026-10-31",
        actual_end: None,
        short_name: DEFAULT_SHORT_NAME,
        fact: FactCustomersDto {
            contract: Some(CONTRACT_CLIENT_ID.into()),
            user: Some(USER_CLIENT_ID.into()),
        },
    }
}

pub fn client_name(id: &str) -> Option<&'static str> {
    match id {
        CONTRACT_CLIENT_ID => Some(CONTRACT_CLIENT_NAME),
        USER_CLIENT_ID => Some(USER_CLIENT_NAME),
        _ => None,
    }
}

pub fn clients() -> Vec<(String, String)> {
    vec![
        (CONTRACT_CLIENT_ID.into(), CONTRACT_CLIENT_NAME.into()),
        (USER_CLIENT_ID.into(), USER_CLIENT_NAME.into()),
    ]
}

/// Keyword hit for the single fixture project (PROJ3733 / 30x564318 / 徐矿…).
pub fn keyword_matches(keyword: &str) -> bool {
    let q = keyword.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    let haystack = [
        PROJECT_NUMBER,
        REMOTE_ID,
        TITLE,
        DEFAULT_SHORT_NAME,
        OWNER,
        CONTRACT_CLIENT_ID,
        USER_CLIENT_ID,
        CONTRACT_CLIENT_NAME,
        USER_CLIENT_NAME,
        "徐矿",
        "城南",
    ];
    haystack
        .iter()
        .any(|part| part.to_lowercase().contains(&q) || q.contains(&part.to_lowercase()))
}

pub fn to_summary(
    adopted: bool,
    local_project_id: Option<String>,
    short_name: &str,
) -> ProjectSummaryDto {
    let remote = remote_project();
    ProjectSummaryDto {
        id: remote.number.into(),
        crm_id: remote.remote_id.into(),
        title: remote.title.into(),
        stage: remote.stage.into(),
        owner: remote.owner.into(),
        contract_customer_id: remote.fact.contract.clone(),
        contract_customer_name: remote
            .fact
            .contract
            .as_deref()
            .and_then(client_name)
            .map(str::to_string),
        user_customer_id: remote.fact.user.clone(),
        user_customer_name: remote
            .fact
            .user
            .as_deref()
            .and_then(client_name)
            .map(str::to_string),
        short_name: short_name.to_string(),
        adopted,
        local_project_id,
    }
}

pub fn staff() -> Vec<ProjectStaffDto> {
    vec![
        ProjectStaffDto {
            name: "张文宇".into(),
            role: "项目经理".into(),
            source: "ERP Members".into(),
            hours: "55.00".into(),
            status: "参与中".into(),
            start: "2026-08-19".into(),
        },
        ProjectStaffDto {
            name: "曹惠峰".into(),
            role: "研发工程师".into(),
            source: "ERP Members".into(),
            hours: "0.00".into(),
            status: "参与中".into(),
            start: "2026-08-19".into(),
        },
    ]
}

pub fn amounts() -> ProjectAmountsDto {
    ProjectAmountsDto {
        contract_amount: 60000.0,
        budget_total: 25100.0,
        cost_total: 21552.73,
        budget_diff: 3547.27,
        budget_profit: 3580.87,
        operating: OperatingMetricsDto {
            contract_amount: 60000.0,
            total_payment: 60000.0,
            payment_profit: 38447.27,
        },
        budget_items: vec![
            money("实施", Some(7500.0), "ERP Project · 实施预算"),
            money("研发", Some(6000.0), "ERP Project · 研发预算"),
            money("差旅", Some(2000.0), "ERP Project · 差旅预算"),
            money("管理", Some(9600.0), "ERP Project · 管理预算"),
            money("外采", Some(0.0), "ERP Project · 外采预算"),
            money("税费", None, "ERP Project · 税费预算字段暂无值"),
        ],
        cost_items: vec![
            money("实施", Some(8594.0), "ERP Project · 实施成本"),
            money("开发", Some(1353.13), "ERP Project · 开发成本"),
            money("差旅", Some(1972.0), "ERP Project · 差旅成本"),
            money("管理", Some(9593.6), "ERP Project · 管理成本"),
            money("硬件外采", Some(40.0), "ERP Project · 硬件外采成本"),
            money("税费", Some(0.0), "ERP Project · 税费成本"),
        ],
    }
}

fn money(key: &str, amount: Option<f64>, source: &str) -> MoneyItemDto {
    MoneyItemDto {
        key: key.into(),
        amount,
        source: source.into(),
    }
}

pub fn hours() -> ProjectHoursDto {
    ProjectHoursDto {
        summary: HourSummaryDto {
            total: 61.6,
            impl_hours: 55.0,
            dev: 6.6,
            travel_days: 5.0,
        },
        detail_sum: HourDetailSumDto {
            hours: 55.0,
            days: 3.0,
        },
        rows: vec![
            hour_row("2026-08-28", "HO15473", 5.0, 0.0),
            hour_row("2026-09-04", "HO15562", 10.0, 0.0),
            hour_row("2026-09-11", "HO15619", 8.0, 0.0),
            hour_row("2026-09-18", "HO15680", 8.0, 0.0),
            hour_row("2026-09-26", "HO15829", 4.0, 0.0),
            hour_row("2026-10-04", "HO15920", 3.0, 0.0),
            hour_row("2026-10-10", "HO16277", 0.0, 0.0),
            hour_row("2026-10-18", "HO16381", 0.0, 0.0),
            hour_row("2026-10-25", "HO16454", 0.0, 0.0),
            hour_row("2026-11-01", "HO16523", 0.0, 0.0),
            hour_row("2026-11-08", "HO16584", 16.0, 3.0),
            hour_row("2026-11-15", "HO16633", 1.0, 0.0),
        ],
    }
}

fn hour_row(date: &str, id: &str, hours: f64, days: f64) -> HourRowDto {
    HourRowDto {
        date: date.into(),
        id: id.into(),
        hours,
        days,
        member: "张文宇".into(),
    }
}

pub fn jira_catalog() -> BTreeMap<String, JiraCatalogEntryDto> {
    let mut map = BTreeMap::new();
    map.insert(
        "XKRLWXM".into(),
        JiraCatalogEntryDto {
            name: "【微信管理】徐矿热力".into(),
            status: "verified".into(),
        },
    );
    map.insert(
        "XKRL".into(),
        JiraCatalogEntryDto {
            name: "徐矿热力".into(),
            status: "verified".into(),
        },
    );
    map.insert(
        "XKRLWXV".into(),
        JiraCatalogEntryDto {
            name: "徐矿热力·规则示例（待验证，无任务）".into(),
            status: "example".into(),
        },
    );
    map
}

/// Fixture-stable Jira project id (key-scoped until real adapter supplies numeric ids).
pub fn jira_project_stable_id(project_key: &str) -> String {
    format!("fixture-jira:{project_key}")
}

pub fn jira_status_defaults() -> Vec<String> {
    [
        "开放",
        "已优选",
        "待开发设计",
        "需求设计完成",
        "需求设计未通过",
        "待开发",
        "处理中",
        "重新打开",
        "开发完成",
        "未通过开发评审",
        "待测试",
        "测试未通过",
        "提测退回",
        "待验证",
        "验证未通过",
        "待合并",
        "待交付客户",
        "已关闭",
        "Done",
        "Closed",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

pub fn erp_issues() -> Vec<JiraTaskDto> {
    let fields: &[(&str, &str, &str)] = &[
        ("XKRLWXM-56", "新增城南子公司走银联支付接口", "王 子沐"),
        ("XKRL-269", "城南公司收据底图替换", "曹 惠峰"),
        ("XKRL-270", "新增城南子公司合同章", "曹 惠峰"),
        ("XKRL-271", "技术日志文件未授权访问漏洞修复", "杨 依逵"),
    ];
    let meta: &[(&str, f64, f64, &str)] = &[
        ("XKRLWXM-56", 5.0, 1093.75, "合同内定制"),
        ("XKRL-269", 0.5, 78.13, "合同内定制"),
        ("XKRL-270", 1.0, 156.25, "合同内定制"),
        ("XKRL-271", 0.1, 25.0, "产品缺陷"),
    ];
    fields
        .iter()
        .zip(meta.iter())
        .map(|((key, title, assignee), (_, hours, amount, kind))| {
            let project_key = issue_project_key(key);
            JiraTaskDto {
                key: (*key).into(),
                title: (*title).into(),
                jira_project_key: project_key,
                status: "已关闭".into(),
                priority: "—".into(),
                batch: "—".into(),
                due_date: "—".into(),
                assignee: (*assignee).into(),
                origin: "erp".into(),
                hours: Some(*hours),
                amount: Some(*amount),
                kind: Some((*kind).into()),
                snapshot_date: Some(SNAPSHOT_DATE.into()),
            }
        })
        .collect()
}

pub fn is_erp_issue(key: &str) -> bool {
    erp_issues().iter().any(|t| t.key.eq_ignore_ascii_case(key))
}

pub fn dev_tasks() -> Vec<DevTaskDto> {
    erp_issues()
        .into_iter()
        .filter_map(|t| {
            Some(DevTaskDto {
                key: t.key.clone(),
                title: t.title.clone(),
                project: jira_catalog()
                    .get(&t.jira_project_key)
                    .map(|e| e.name.clone())
                    .unwrap_or_else(|| t.jira_project_key.clone()),
                hours: t.hours?,
                amount: t.amount?,
                kind: t.kind.unwrap_or_default(),
            })
        })
        .collect()
}

pub fn issue_project_key(issue: &str) -> String {
    match issue.rfind('-') {
        Some(i) => issue[..i].to_string(),
        None => issue.to_string(),
    }
}

pub fn find_remote(remote_or_number: &str) -> Option<FixtureRemoteProject> {
    let needle = remote_or_number.trim();
    if needle.is_empty() {
        return None;
    }
    let remote = remote_project();
    if needle.eq_ignore_ascii_case(remote.number)
        || needle.eq_ignore_ascii_case(remote.remote_id)
    {
        Some(remote)
    } else {
        None
    }
}
