//! Structured ZoomKey Jira adapter.
//!
//! Reads issue fields (`priority.name`, `duedate`, `assignee.displayName`) and
//! project lists for shortName matching. Batch stays "—" until the custom field
//! id is confirmed (design v0.7).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::projects::dto::{JiraCatalogEntryDto, JiraTaskDto};
use crate::zoomkey::{jira as zoomkey_jira, EndpointRuntime, ToolFailure};

#[derive(Clone, Debug)]
pub struct JiraProjectInfo {
    pub id: String,
    pub key: String,
    pub name: String,
}

/// Map a raw `/rest/api/2/project` item.
pub(crate) fn map_project(item: &Value) -> Option<JiraProjectInfo> {
    let key = item.get("key").and_then(Value::as_str)?.trim();
    if key.is_empty() {
        return None;
    }
    let id = item
        .get("id")
        .and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string())))
        .unwrap_or_else(|| format!("jira-key:{key}"));
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(key)
        .to_string();
    Some(JiraProjectInfo {
        id,
        key: key.to_string(),
        name,
    })
}

pub(crate) fn projects_to_catalog(projects: &[JiraProjectInfo]) -> BTreeMap<String, JiraCatalogEntryDto> {
    let mut map = BTreeMap::new();
    for p in projects {
        map.insert(
            p.key.clone(),
            JiraCatalogEntryDto {
                name: p.name.clone(),
                status: "verified".into(),
            },
        );
    }
    map
}

fn fields_obj(issue: &Value) -> &Value {
    issue.get("fields").unwrap_or(&Value::Null)
}

fn named(value: Option<&Value>) -> Option<String> {
    value
        .and_then(|v| v.get("name").or_else(|| v.get("displayName")))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Enrich an ERP-linked / local JiraTaskDto from a raw Jira issue JSON.
/// Batch remains "—" until the custom field id is confirmed.
pub(crate) fn enrich_task_from_issue(task: &mut JiraTaskDto, issue: &Value) {
    let fields = fields_obj(issue);
    if let Some(key) = issue.get("key").and_then(Value::as_str) {
        task.key = key.to_string();
        if let Some(i) = key.rfind('-') {
            task.jira_project_key = key[..i].to_string();
        }
    }
    if let Some(summary) = fields.get("summary").and_then(Value::as_str) {
        if !summary.trim().is_empty() {
            task.title = summary.trim().to_string();
        }
    }
    if let Some(status) = named(fields.get("status")) {
        task.status = status;
    }
    task.priority = named(fields.get("priority")).unwrap_or_else(|| "—".into());
    task.assignee = fields
        .get("assignee")
        .and_then(|v| {
            v.get("displayName")
                .or_else(|| v.get("name"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("未指派")
        .to_string();
    task.due_date = fields
        .get("duedate")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("—")
        .to_string();
    // Batch custom field id not confirmed — keep em dash.
    task.batch = "—".into();
    if let Some(project_key) = fields
        .get("project")
        .and_then(|p| p.get("key"))
        .and_then(Value::as_str)
    {
        task.jira_project_key = project_key.to_string();
    }
}

/// Build a standalone task DTO from a raw issue (e.g. local supplement lookup).
pub(crate) fn map_issue_to_task(issue: &Value, origin: &str) -> JiraTaskDto {
    let mut task = JiraTaskDto {
        key: String::new(),
        title: String::new(),
        jira_project_key: String::new(),
        status: String::new(),
        priority: "—".into(),
        batch: "—".into(),
        due_date: "—".into(),
        assignee: String::new(),
        origin: origin.into(),
        hours: None,
        amount: None,
        kind: None,
        snapshot_date: None,
    };
    enrich_task_from_issue(&mut task, issue);
    task
}

/// Flatten `/project/{key}/statuses` into unique status names (stable order).
pub(crate) fn flatten_status_names(types: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for issue_type in types {
        let Some(statuses) = issue_type.get("statuses").and_then(Value::as_array) else {
            continue;
        };
        for status in statuses {
            let Some(name) = status.get("name").and_then(Value::as_str) else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            if !out.iter().any(|s: &String| s == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

pub(crate) fn list_projects(runtime: &EndpointRuntime) -> Result<Vec<JiraProjectInfo>, ToolFailure> {
    let raw = zoomkey_jira::list_projects_raw(runtime)?;
    Ok(raw.iter().filter_map(map_project).collect())
}

pub(crate) fn get_issue(runtime: &EndpointRuntime, issue_key: &str) -> Result<Value, ToolFailure> {
    zoomkey_jira::get_issue_desktop(runtime, issue_key)
}

pub(crate) fn list_status_names(
    runtime: &EndpointRuntime,
    project_key: &str,
) -> Result<Vec<String>, ToolFailure> {
    let raw = zoomkey_jira::project_statuses_raw(runtime, project_key)?;
    Ok(flatten_status_names(&raw))
}

/// Enrich ERP-linked tasks by fetching each issue key (best-effort).
pub(crate) fn enrich_erp_issues(
    runtime: &EndpointRuntime,
    tasks: &mut [JiraTaskDto],
) -> Vec<String> {
    let mut warnings = Vec::new();
    for task in tasks.iter_mut() {
        match get_issue(runtime, &task.key) {
            Ok(issue) => enrich_task_from_issue(task, &issue),
            Err(e) => {
                warnings.push(format!(
                    "Jira issue {} 读取失败：{}",
                    task.key, e.message
                ));
                if task.priority.is_empty() {
                    task.priority = "—".into();
                }
                if task.due_date.is_empty() {
                    task.due_date = "—".into();
                }
                if task.batch.is_empty() {
                    task.batch = "—".into();
                }
            }
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_project_and_catalog() {
        let item = json!({"id": "10001", "key": "XKRL", "name": "徐矿热力"});
        let info = map_project(&item).unwrap();
        assert_eq!(info.id, "10001");
        assert_eq!(info.key, "XKRL");
        let catalog = projects_to_catalog(&[info]);
        assert_eq!(catalog["XKRL"].name, "徐矿热力");
        assert_eq!(catalog["XKRL"].status, "verified");
    }

    #[test]
    fn enriches_issue_priority_due_assignee() {
        let issue = json!({
            "key": "XKRL-269",
            "fields": {
                "summary": "城南公司收据底图替换",
                "status": {"name": "已关闭"},
                "priority": {"name": "重要"},
                "duedate": "2026-09-30",
                "assignee": {"displayName": "Alice"},
                "project": {"key": "XKRL", "name": "徐矿热力"},
            }
        });
        let mut task = JiraTaskDto {
            key: "XKRL-269".into(),
            title: String::new(),
            jira_project_key: String::new(),
            status: String::new(),
            priority: "—".into(),
            batch: "—".into(),
            due_date: "—".into(),
            assignee: String::new(),
            origin: "erp".into(),
            hours: Some(0.5),
            amount: Some(78.13),
            kind: Some("合同内定制".into()),
            snapshot_date: Some("2026-11-18".into()),
        };
        enrich_task_from_issue(&mut task, &issue);
        assert_eq!(task.title, "城南公司收据底图替换");
        assert_eq!(task.status, "已关闭");
        assert_eq!(task.priority, "重要");
        assert_eq!(task.due_date, "2026-09-30");
        assert_eq!(task.assignee, "Alice");
        assert_eq!(task.batch, "—");
        assert_eq!(task.jira_project_key, "XKRL");
        assert_eq!(task.hours, Some(0.5));
    }

    #[test]
    fn missing_due_and_assignee_use_placeholders() {
        let issue = json!({
            "key": "XKRL-271",
            "fields": {
                "summary": "漏洞修复",
                "status": {"name": "已关闭"},
                "priority": null,
                "duedate": null,
                "assignee": null,
            }
        });
        let task = map_issue_to_task(&issue, "local");
        assert_eq!(task.priority, "—");
        assert_eq!(task.due_date, "—");
        assert_eq!(task.assignee, "未指派");
        assert_eq!(task.batch, "—");
        assert_eq!(task.origin, "local");
    }

    #[test]
    fn flattens_statuses_deduped() {
        let types = vec![json!({
            "name": "任务",
            "statuses": [
                {"name": "开放"},
                {"name": "已关闭"},
            ]
        }), json!({
            "name": "缺陷",
            "statuses": [
                {"name": "开放"},
                {"name": "处理中"},
            ]
        })];
        assert_eq!(
            flatten_status_names(&types),
            vec!["开放", "已关闭", "处理中"]
        );
    }
}
