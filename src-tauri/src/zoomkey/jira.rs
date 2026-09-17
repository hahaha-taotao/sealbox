//! ZoomKey JIRA 只读客户端。
//!
//! 对应 `plugins/zoomkey-jira/tools/*.js` 的 10 个只读工具（`configure` 不移植）。
//! 只访问策略里配置的 `base_url`，只发 GET，路径由代码按固定模板拼装，
//! 不接受模型传入 URL / Header / 方法。

use super::{
    as_string, as_u64, read_capped, to_pretty, trim_json, EndpointRuntime, ToolFailure, ToolOutcome,
};
use crate::session::Session;
use base64::Engine;
use serde_json::{json, Map, Value};

const DEFAULT_FIELDS: [&str; 8] = [
    "key",
    "summary",
    "status",
    "assignee",
    "priority",
    "created",
    "issuetype",
    "updated",
];
const DONE_STATUSES: [&str; 2] = ["Done", "Closed"];

/// get_issue 的默认字段：常用字段 + description/reporter（与插件一致）。
const GET_ISSUE_FIELDS: &str =
    "summary,status,assignee,priority,created,issuetype,updated,description,reporter";
const MAX_DESCRIPTION_BYTES: usize = 4096;

/// 业务预设，与插件保持一致。
const HSRR_PROJECTS: [&str; 11] = [
    "HSRR",
    "HSRRIAM",
    "HSRRHMAPP",
    "HSRRVS",
    "HSRRCSM",
    "HSRRWXM",
    "HSRRWXV",
    "HSRRERPAPP",
    "HSRRERPH5",
    "HSRRERP",
    "HSRRBACS",
];

pub fn tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "zoomkey_jira_nav",
            "JIRA 导航首页：一次返回服务端版本、当前账号、我的未完成清单与呼市燃热未完成数，避免多轮试探。",
            schema(
                &[
                    ("includeHsrr", json!({"type":"boolean","default":true})),
                    ("maxResults", json!({"type":"integer","minimum":1,"maximum":20,"default":8})),
                ],
                &[],
            ),
        ),
        tool(
            "zoomkey_jira_connection_status",
            "检查 JIRA 连通性与 TLS 链路。ping=true 时会额外调用 /myself 验证账号。",
            schema(
                &[("ping", json!({"type":"boolean","default":false}))],
                &[],
            ),
        ),
        tool(
            "zoomkey_jira_list_projects",
            "列出 JIRA 上可见的项目 Key 与名称，可按 key 或名称模糊过滤。",
            schema(&[("query", string_schema(1, 128))], &[]),
        ),
        tool(
            "zoomkey_jira_project_statuses",
            "查看某个项目的状态清单，用于确认中文状态名的准确写法。",
            schema(&[("project", string_schema(1, 64))], &["project"]),
        ),
        tool(
            "zoomkey_jira_field_map",
            "JIRA 任务字段与关联导航（先结构后查询）。默认返回状态/类型/核心字段/预设/查询剧本；live=true 时在线拉字段元数据。",
            schema(
                &[
                    (
                        "section",
                        json!({
                            "type": "string",
                            "enum": ["overview", "status", "issuetype", "fields", "presets", "playbooks", "crm-bridge"],
                            "default": "overview"
                        }),
                    ),
                    ("live", json!({"type":"boolean","default":false})),
                ],
                &[],
            ),
        ),
        tool(
            "zoomkey_jira_search_issues",
            "用 JQL 搜索 JIRA 任务。适合自定义条件；常见未完成/我的任务/呼市燃热请优先用专用工具。此 JIRA 无 Resolved 状态；中文状态名异常时先查项目状态。maxResults 最大 100，更多结果用 startAt 分页。fields 可自定义返回字段（逗号分隔）。",
            schema(
                &[
                    ("jql", string_schema(1, 2000)),
                    ("maxResults", json!({"type":"integer","minimum":1,"maximum":100,"default":50})),
                    ("startAt", json!({"type":"integer","minimum":0,"maximum":100000,"default":0})),
                    ("fields", string_schema(1, 500)),
                ],
                &["jql"],
            ),
        ),
        tool(
            "zoomkey_jira_get_issue",
            "按编号读取单个 JIRA 任务详情，含描述与报告人。fields 可自定义返回字段（逗号分隔）。",
            schema(
                &[
                    ("issueKey", string_schema(1, 64)),
                    ("fields", string_schema(1, 500)),
                ],
                &["issueKey"],
            ),
        ),
        tool(
            "zoomkey_jira_my_open_issues",
            "查询我的未完成任务（status not in Done/Closed）。默认 assignee = currentUser()，可用 project 收窄。",
            schema(
                &[
                    ("assignee", string_schema(1, 128)),
                    ("project", string_schema(1, 64)),
                    ("maxResults", json!({"type":"integer","minimum":1,"maximum":100,"default":50})),
                    ("startAt", json!({"type":"integer","minimum":0,"maximum":100000,"default":0})),
                ],
                &[],
            ),
        ),
        tool(
            "zoomkey_jira_project_unfinished",
            "查询某个项目下的未完成任务（status not in Done/Closed）。",
            schema(
                &[
                    ("project", string_schema(1, 64)),
                    ("assignee", string_schema(1, 128)),
                    ("extraJql", string_schema(1, 500)),
                    ("maxResults", json!({"type":"integer","minimum":1,"maximum":100,"default":50})),
                    ("startAt", json!({"type":"integer","minimum":0,"maximum":100000,"default":0})),
                ],
                &["project"],
            ),
        ),
        tool(
            "zoomkey_jira_preset_unfinished",
            "按业务预设查询跨项目未完成任务。当前内置预设 hsrr（呼市燃热，含 HSRR/HSRRIAM/HSRRERP 等 11 个项目）。",
            schema(
                &[
                    ("preset", json!({"type":"string","minLength":1,"maxLength":64,"default":"hsrr"})),
                    ("assignee", string_schema(1, 128)),
                    ("maxResults", json!({"type":"integer","minimum":1,"maximum":100,"default":50})),
                    ("startAt", json!({"type":"integer","minimum":0,"maximum":100000,"default":0})),
                ],
                &[],
            ),
        ),
    ]
}

fn string_schema(minimum: u64, maximum: u64) -> Value {
    json!({"type":"string","minLength":minimum,"maxLength":maximum})
}

fn schema(properties: &[(&str, Value)], required: &[&str]) -> Value {
    let mut props = Map::new();
    for (name, value) in properties {
        props.insert((*name).to_string(), value.clone());
    }
    json!({
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": false
    })
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "readOnly": true,
        "risk": "low"
    })
}

pub(crate) fn call(
    session: &Session,
    name: &str,
    args: &Value,
) -> Result<ToolOutcome, ToolFailure> {
    match name {
        "zoomkey_jira_nav"
        | "zoomkey_jira_connection_status"
        | "zoomkey_jira_list_projects"
        | "zoomkey_jira_project_statuses"
        | "zoomkey_jira_field_map"
        | "zoomkey_jira_search_issues"
        | "zoomkey_jira_get_issue"
        | "zoomkey_jira_my_open_issues"
        | "zoomkey_jira_project_unfinished"
        | "zoomkey_jira_preset_unfinished" => {}
        _ => return Err(ToolFailure::validation(format!("未知 JIRA 工具 {name}"))),
    }
    let runtime = super::build_runtime(session, "jira")?;
    match name {
        "zoomkey_jira_nav" => nav(&runtime, args),
        "zoomkey_jira_connection_status" => connection_status(&runtime, args),
        "zoomkey_jira_list_projects" => list_projects(&runtime, args),
        "zoomkey_jira_project_statuses" => project_statuses(&runtime, args),
        "zoomkey_jira_field_map" => field_map(&runtime, args),
        "zoomkey_jira_search_issues" => search(&runtime, args, SearchMode::Raw),
        "zoomkey_jira_get_issue" => get_issue(&runtime, args),
        "zoomkey_jira_my_open_issues" => search(&runtime, args, SearchMode::MyOpen),
        "zoomkey_jira_project_unfinished" => search(&runtime, args, SearchMode::ProjectUnfinished),
        "zoomkey_jira_preset_unfinished" => search(&runtime, args, SearchMode::Preset),
        _ => Err(ToolFailure::validation("未知 JIRA 工具")),
    }
}

fn nav(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let max_results = as_u64(args, "maxResults", 8, 1, 20);
    // 与插件一致：includeHsrr 默认 true，显式传 false 时跳过呼市燃热统计。
    let include_hsrr = match args.get("includeHsrr") {
        Some(Value::Bool(value)) => *value,
        _ => true,
    };

    let server = get_json(runtime, "/rest/api/2/serverInfo")?;
    let myself = get_json(runtime, "/rest/api/2/myself")?;

    let jql = format!(
        "{} ORDER BY updated DESC",
        unfinished_jql(None, &[], Some("currentUser()"), None)
    );
    let search = get_json(
        runtime,
        &search_path(&jql, max_results, 0, &DEFAULT_FIELDS.join(",")),
    )?;
    let issues: Vec<Value> = search
        .get("issues")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(summarize_issue).collect())
        .unwrap_or_default();
    let open_total = search.get("total").and_then(Value::as_i64).unwrap_or(0);

    let user = myself
        .get("displayName")
        .or_else(|| myself.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("-");
    let version = server.get("version").and_then(Value::as_str).unwrap_or("-");

    let mut lines = vec![
        "JIRA 概况".to_string(),
        format!(
            "服务端: {} ({version})",
            server
                .get("serverTitle")
                .and_then(Value::as_str)
                .unwrap_or("-")
        ),
        format!("当前账号: {user}"),
        format!("我的未完成: {open_total} 条"),
    ];
    let mut detail = format!("user={user} open={open_total}");

    if include_hsrr {
        let projects: Vec<String> = HSRR_PROJECTS.iter().map(|p| p.to_string()).collect();
        let hsrr_jql = format!(
            "{} ORDER BY updated DESC",
            unfinished_jql(None, &projects, None, None)
        );
        match get_json(
            runtime,
            &search_path(&hsrr_jql, 1, 0, &DEFAULT_FIELDS.join(",")),
        ) {
            Ok(value) => {
                let total = value.get("total").and_then(Value::as_i64).unwrap_or(0);
                lines.push(format!("呼市燃热未完成: {total} 条"));
                detail.push_str(&format!(" hsrr={total}"));
            }
            Err(error) => {
                // 呼市燃热统计失败不影响导航主体，只降级提示。
                lines.push(format!("呼市燃热未完成: 统计失败（{}）", error.message));
                detail.push_str(" hsrr=failed");
            }
        }
    } else {
        lines.push("呼市燃热未完成: 未统计".to_string());
    }

    lines.push(String::new());
    lines.push(format!("我的最近更新（最多 {max_results} 条）:"));
    if issues.is_empty() {
        lines.push("（无）".into());
    } else {
        for issue in &issues {
            lines.push(format_issue_line(issue));
        }
    }
    lines.push(String::new());
    lines.push("下一步可选：".into());
    lines.push("- zoomkey_jira_my_open_issues  我的未完成清单".into());
    lines.push("- zoomkey_jira_preset_unfinished  呼市燃热跨项目未完成".into());
    lines.push("- zoomkey_jira_search_issues  自定义 JQL".into());

    Ok(ToolOutcome {
        text: lines.join("\n"),
        count: Some(open_total.max(0) as usize),
        detail,
    })
}

fn connection_status(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let server = get_json(runtime, "/rest/api/2/serverInfo")?;
    let version = server.get("version").and_then(Value::as_str).unwrap_or("-");
    let mut lines = vec![
        "JIRA 连通正常".to_string(),
        format!("地址: {}", runtime.origin),
        format!("服务端版本: {version}"),
    ];
    let mut detail = format!("origin={} version={version}", runtime.origin);
    if super::as_bool(args, "ping") {
        let myself = get_json(runtime, "/rest/api/2/myself")?;
        let user = myself
            .get("displayName")
            .or_else(|| myself.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("-");
        lines.push(format!("账号校验通过: {user}"));
        detail = format!("{detail} user={user}");
    }
    Ok(ToolOutcome {
        text: lines.join("\n"),
        count: None,
        detail,
    })
}

fn list_projects(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let query = as_string(args, "query").to_lowercase();
    let value = get_json(runtime, "/rest/api/2/project")?;
    let projects = value
        .as_array()
        .ok_or_else(|| ToolFailure::request("JIRA 响应格式不正确", Some(200)))?;
    let total = projects.len();
    let items: Vec<Value> = projects
        .iter()
        .take(500)
        .map(|item| {
            json!({
                "key": item.get("key").and_then(Value::as_str),
                "name": item.get("name").and_then(Value::as_str),
            })
        })
        .filter(|item| {
            if query.is_empty() {
                return true;
            }
            let key = item["key"].as_str().unwrap_or("").to_lowercase();
            let name = item["name"].as_str().unwrap_or("").to_lowercase();
            key.contains(&query) || name.contains(&query)
        })
        .collect();
    let mut text = vec![
        format!("JIRA 项目 共 {total} 个（匹配 {}）", items.len()),
        String::new(),
    ];
    for item in &items {
        text.push(format!(
            "- {} {}",
            item["key"].as_str().unwrap_or("-"),
            item["name"].as_str().unwrap_or("")
        ));
    }
    if items.is_empty() {
        text.push("（无匹配项目）".into());
    }
    Ok(ToolOutcome {
        text: text.join("\n"),
        count: Some(items.len()),
        detail: format!("total={total} matched={}", items.len()),
    })
}

fn project_statuses(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let project = as_string(args, "project");
    if project.is_empty() {
        return Err(ToolFailure::validation("project 不能为空"));
    }
    let path = format!(
        "/rest/api/2/project/{}/statuses",
        encode_component(&project)
    );
    let value = get_json(runtime, &path)?;
    let types = value
        .as_array()
        .ok_or_else(|| ToolFailure::request("JIRA 响应格式不正确", Some(200)))?;
    let mut lines = vec![format!("项目 {project} 状态清单"), String::new()];
    let mut detail = format!("project={project}");
    for issue_type in types.iter().take(50) {
        let type_name = issue_type
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("-");
        let statuses: Vec<&str> = issue_type
            .get("statuses")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|s| s.get("name").and_then(Value::as_str))
                    .collect()
            })
            .unwrap_or_default();
        detail.push_str(&format!(" {type_name}={}", statuses.len()));
        lines.push(format!("- {type_name}: {}", statuses.join(" / ")));
    }
    Ok(ToolOutcome {
        text: lines.join("\n"),
        count: Some(types.len()),
        detail,
    })
}

/// 内置状态清单：(名称, 分类, 是否算未完成)。数据与插件 field_map 保持一致。
const STATUS_MAP: [(&str, &str, bool); 20] = [
    ("开放", "待办", true),
    ("已优选", "待办", true),
    ("待开发设计", "处理中", true),
    ("需求设计完成", "处理中", true),
    ("需求设计未通过", "待办", true),
    ("待开发", "处理中", true),
    ("处理中", "处理中", true),
    ("重新打开", "处理中", true),
    ("开发完成", "处理中", true),
    ("未通过开发评审", "处理中", true),
    ("待测试", "完成向", true),
    ("测试未通过", "处理中", true),
    ("提测退回", "处理中", true),
    ("待验证", "完成向", true),
    ("验证未通过", "处理中", true),
    ("待合并", "完成向", true),
    ("待交付客户", "完成向", true),
    ("已关闭", "完成", false),
    ("Done", "完成", false),
    ("Closed", "完成", false),
];

/// 问题类型簇。
const ISSUE_TYPE_CLUSTERS: [(&str, &[&str]); 4] = [
    (
        "业务研发",
        &[
            "任务",
            "故事",
            "史诗",
            "新功能",
            "改进",
            "合同内定制",
            "合同外定制",
            "产品优化",
            "运维",
            "故障",
        ],
    ),
    ("缺陷", &["缺陷", "项目缺陷", "产品缺陷"]),
    (
        "测试Xray",
        &[
            "测试用例",
            "测试集",
            "测试计划",
            "测试执行",
            "测试",
            "测试前置条件",
        ],
    ),
    ("子任务", &["Sub-Task", "Sub-Bug", "Sub-Custom", "子任务"]),
];

/// 核心系统字段。
const CORE_FIELD_MAP: [(&str, &str); 14] = [
    ("key", "关键字 KEY-123"),
    ("summary", "概要"),
    ("status", "状态"),
    ("assignee", "经办人"),
    ("reporter", "报告人"),
    ("priority", "优先级：紧急/严重/重要/次要/微小"),
    ("issuetype", "问题类型"),
    ("project", "项目 Key"),
    ("created/updated", "创建/更新"),
    ("description", "描述"),
    ("components", "模块"),
    ("labels", "标签"),
    ("parent/subtasks", "父任务/子任务"),
    ("issuelinks", "问题链接"),
];

/// 业务自定义字段：(id, 名称, 备注)。
const BIZ_CUSTOM_FIELDS: [(&str, &str, &str); 20] = [
    ("customfield_12521", "ERP项目", "对接业务/ERP 项目"),
    ("customfield_14521", "ERP应用软件", ""),
    ("customfield_10100", "问题或需求描述", "长文本"),
    ("customfield_11023", "投入工时", "数字"),
    ("customfield_14120", "工作量", "数字"),
    ("customfield_12621", "测试人时", ""),
    ("customfield_14020", "需求设计人时", ""),
    ("customfield_12721", "开发设计人时", ""),
    ("customfield_14820", "运维人时", ""),
    ("customfield_11522", "需求设计", "文本"),
    ("customfield_11528", "开发设计", "文本"),
    ("customfield_13720", "需求设计人", "用户"),
    ("customfield_12720", "开发设计人", "用户"),
    ("customfield_12337", "系统测试人", "用户"),
    ("customfield_10323/10324", "计划开始/结束", "日期时间"),
    ("customfield_10321/10322", "实际开始/结束", "日期时间"),
    ("customfield_12121", "严重性", "选项"),
    ("customfield_11820", "Bug原因类型", ""),
    ("customfield_10221", "冲刺", "Sprint"),
    ("customfield_10226", "史诗链接", "Epic"),
];

/// 关联链接类型。
const LINK_TYPE_MAP: [(&str, &str); 4] = [
    ("相关问题", "可能的相关问题"),
    ("同一问题", "同一问题"),
    ("Tests", "tests / tested by"),
    ("Defect", "关联主/从任务"),
];

/// 内置查询剧本。
const FIELD_PLAYBOOKS: [(&str, &[&str]); 4] = [
    (
        "我的未完成",
        &[
            "zoomkey_jira_my_open_issues",
            "zoomkey_jira_get_issue { issueKey }",
        ],
    ),
    (
        "呼市燃热",
        &["zoomkey_jira_preset_unfinished { preset: hsrr }"],
    ),
    (
        "单项目未完成",
        &[
            "zoomkey_jira_project_unfinished { project: HSRR }",
            "异常时 zoomkey_jira_project_statuses { project: HSRR }",
        ],
    ),
    (
        "已知单号",
        &["zoomkey_jira_get_issue { issueKey: BCCR-107 }"],
    ),
];

fn field_map(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let section = {
        let value = as_string(args, "section").to_lowercase();
        if value.is_empty() {
            "overview".to_string()
        } else {
            value
        }
    };
    // live=true 才联网；默认返回内置地图，离线也能先看清结构。
    if super::as_bool(args, "live") {
        return field_map_live(runtime);
    }

    let lines = field_map_static(&section);
    Ok(ToolOutcome {
        text: lines.join("\n"),
        count: None,
        detail: format!("section={section} mode=static"),
    })
}

/// 内置地图正文（纯静态，不联网）。抽成独立函数便于单测。
fn field_map_static(section: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    match section {
        "status" => {
            lines.push("JIRA 状态导航".into());
            lines.push("未完成 = status not in (Done, Closed)".into());
            lines.push(String::new());
            for (name, category, open) in STATUS_MAP {
                lines.push(format!(
                    "- {} {name} · {category}",
                    if open { "[未完成]" } else { "[完成]" }
                ));
            }
        }
        "issuetype" => {
            lines.push("JIRA 问题类型".into());
            for (cluster, items) in ISSUE_TYPE_CLUSTERS {
                lines.push(String::new());
                lines.push(format!("## {cluster}"));
                for item in items {
                    lines.push(format!("- {item}"));
                }
            }
        }
        "fields" => {
            lines.push("JIRA 字段导航".into());
            lines.push("## 系统".into());
            for (key, note) in CORE_FIELD_MAP {
                lines.push(format!("- {key}: {note}"));
            }
            lines.push(String::new());
            lines.push("## 业务自定义".into());
            for (id, name, note) in BIZ_CUSTOM_FIELDS {
                if note.is_empty() {
                    lines.push(format!("- {id}: {name}"));
                } else {
                    lines.push(format!("- {id}: {name} · {note}"));
                }
            }
        }
        "presets" => {
            lines.push("JIRA 项目预设".into());
            lines.push("## hsrr 呼市燃热".into());
            for key in HSRR_PROJECTS {
                lines.push(format!("- {key}"));
            }
            lines.push(String::new());
            lines.push("工具: zoomkey_jira_preset_unfinished preset=hsrr".into());
            lines.push("全站项目 1000+，不要无过滤 list_projects 当导航".into());
        }
        "playbooks" => {
            lines.push("JIRA 查询剧本".into());
            for (name, steps) in FIELD_PLAYBOOKS {
                lines.push(String::new());
                lines.push(format!("## {name}"));
                for step in steps {
                    lines.push(format!("- {step}"));
                }
            }
        }
        "crm-bridge" => {
            lines.push("JIRA ↔ CRM".into());
            lines.push("- JIRA Project Key（HSRR）≠ CRM project_no（PROJ3096）".into());
            lines.push("- Issue Key 可与 CRM HelpDesk.cf_jiratask_id 对照".into());
            lines.push("- customfield_12521 ERP项目：业务项目侧编号/引用".into());
            lines.push("- 推荐：CRM 锁定项目与成员 → JIRA 用 Key/我的未完成/呼市预设".into());
            lines.push("- CRM 结构: zoomkey_crm_field_map".into());
        }
        _ => {
            lines.push("JIRA 任务字段与关联导航（内置）".into());
            lines.push("未完成约定: status not in (Done, Closed)  // 无 Resolved".into());
            lines.push("优先级: 紧急 > 严重 > 重要 > 次要 > 微小".into());
            lines.push(String::new());
            lines.push("对象: Project(key) → Issue(KEY-n) → links/subtasks/customfields".into());
            lines.push(String::new());
            lines.push("关联链接类型:".into());
            for (name, note) in LINK_TYPE_MAP {
                lines.push(format!("- {name}: {note}"));
            }
            lines.push(String::new());
            lines.push("呼市预设 hsrr:".into());
            lines.push(format!("  {}", HSRR_PROJECTS.join(", ")));
            lines.push(String::new());
            lines.push("查询剧本:".into());
            for (name, steps) in FIELD_PLAYBOOKS {
                lines.push(format!("【{name}】"));
                for step in steps {
                    lines.push(format!("  · {step}"));
                }
            }
            lines.push(String::new());
            lines.push("核心系统字段:".into());
            for (key, note) in CORE_FIELD_MAP {
                lines.push(format!("- {key}: {note}"));
            }
            lines.push(String::new());
            lines.push("业务自定义字段（节选）:".into());
            for (id, name, note) in BIZ_CUSTOM_FIELDS {
                if note.is_empty() {
                    lines.push(format!("- {id} {name}"));
                } else {
                    lines.push(format!("- {id} {name} · {note}"));
                }
            }
            lines.push(String::new());
            lines.push("状态（* = 未完成）:".into());
            for (name, category, open) in STATUS_MAP {
                lines.push(format!(
                    "- {} {name} ({category})",
                    if open { "*" } else { " " }
                ));
            }
            lines.push(String::new());
            lines.push("问题类型簇:".into());
            for (cluster, items) in ISSUE_TYPE_CLUSTERS {
                lines.push(format!("- {cluster}: {}", items.join(" / ")));
            }
            lines.push(String::new());
            lines.push("CRM 桥:".into());
            lines.push("- JIRA Project Key ≠ CRM project_no".into());
            lines.push("- customfield_12521 ERP项目 可对齐业务项目侧".into());
            lines.push("- 有单号先 get_issue；有 PROJ 先走 CRM field_map/find_project".into());
            lines.push(String::new());
            lines.push(
                "section=status|issuetype|fields|presets|playbooks|crm-bridge 可分段查看".into(),
            );
            lines.push("live=true 在线拉 field/status/issuetype（需连通）".into());
        }
    }
    lines
}

/// live=true：在线拉取字段元数据（与插件 live 模式一致）。
fn field_map_live(runtime: &EndpointRuntime) -> Result<ToolOutcome, ToolFailure> {
    let value = get_json(runtime, "/rest/api/2/field")?;
    let fields = value
        .as_array()
        .ok_or_else(|| ToolFailure::request("JIRA 响应格式不正确", Some(200)))?;
    let mut standard = Vec::new();
    let mut custom = Vec::new();
    for field in fields {
        let name = field.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let id = field.get("id").and_then(Value::as_str).unwrap_or("-");
        let custom_field = field
            .get("custom")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let entry = format!("- {id}: {name}");
        if custom_field {
            if custom.len() < 60 {
                custom.push(entry);
            }
        } else {
            standard.push(entry);
        }
    }
    let mut text = vec![
        format!(
            "JIRA 字段 标准 {} 个 · 自定义 {} 个",
            standard.len(),
            custom.len()
        ),
        String::new(),
        "标准字段:".into(),
    ];
    text.extend(standard);
    if !custom.is_empty() {
        text.push(String::new());
        text.push("自定义字段（前 60 个）:".into());
        text.extend(custom);
    }
    let count = fields.len();
    Ok(ToolOutcome {
        text: text.join("\n"),
        count: Some(count),
        detail: format!("fields={count} mode=live"),
    })
}

fn get_issue(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let key = as_string(args, "issueKey").to_uppercase();
    if key.is_empty() {
        return Err(ToolFailure::validation("issueKey 不能为空"));
    }
    if !valid_issue_key(&key) {
        return Err(ToolFailure::validation("issueKey 格式不合法"));
    }
    let requested = as_string(args, "fields");
    let fields = if requested.trim().is_empty() {
        GET_ISSUE_FIELDS.to_string()
    } else {
        sanitize_fields(&requested)?
    };
    let path = format!(
        "/rest/api/2/issue/{}?fields={}",
        encode_component(&key),
        encode_component(&fields)
    );
    let value = get_json(runtime, &path)?;
    let mut summary = summarize_issue(&value);
    if let Some(description) = value
        .get("fields")
        .and_then(|f| f.get("description"))
        .and_then(Value::as_str)
    {
        let mut trimmed = description.to_string();
        if trimmed.len() > MAX_DESCRIPTION_BYTES {
            let mut end = MAX_DESCRIPTION_BYTES;
            while end > 0 && !trimmed.is_char_boundary(end) {
                end -= 1;
            }
            trimmed.truncate(end);
            trimmed.push('…');
        }
        summary["description"] = Value::String(trimmed);
    }
    let mut payload = summary.clone();
    trim_json(&mut payload, 512);
    Ok(ToolOutcome {
        text: format!("{}\n\n{}", format_issue_line(&summary), to_pretty(&payload)),
        count: None,
        detail: format!("key={key}"),
    })
}

#[derive(Clone, Copy)]
enum SearchMode {
    Raw,
    MyOpen,
    ProjectUnfinished,
    Preset,
}

fn search(
    runtime: &EndpointRuntime,
    args: &Value,
    mode: SearchMode,
) -> Result<ToolOutcome, ToolFailure> {
    let max_results = as_u64(args, "maxResults", 50, 1, 100);
    let start_at = as_u64(args, "startAt", 0, 0, 100_000);
    let (jql, title, detail_extra) = match mode {
        SearchMode::Raw => {
            let jql = as_string(args, "jql");
            if jql.is_empty() {
                return Err(ToolFailure::validation("jql 不能为空"));
            }
            (jql, "JIRA JQL 搜索".to_string(), String::new())
        }
        SearchMode::MyOpen => {
            let assignee = {
                let value = as_string(args, "assignee");
                if value.is_empty() {
                    "currentUser()".to_string()
                } else {
                    value
                }
            };
            let project = as_string(args, "project");
            let project = if project.is_empty() {
                None
            } else {
                Some(project.as_str())
            };
            let jql = format!(
                "{} ORDER BY updated DESC",
                unfinished_jql(project, &[], Some(&assignee), None)
            );
            let title = match project {
                Some(project) => format!("我的未完成任务（{project}）"),
                None => "我的未完成任务".to_string(),
            };
            (jql, title, format!("assignee={assignee}"))
        }
        SearchMode::ProjectUnfinished => {
            let project = as_string(args, "project");
            if project.is_empty() {
                return Err(ToolFailure::validation("project 不能为空"));
            }
            let assignee = as_string(args, "assignee");
            let extra = as_string(args, "extraJql");
            let jql = format!(
                "{} ORDER BY updated DESC",
                unfinished_jql(
                    Some(&project),
                    &[],
                    if assignee.is_empty() {
                        None
                    } else {
                        Some(&assignee)
                    },
                    if extra.is_empty() { None } else { Some(&extra) },
                )
            );
            (
                jql,
                format!("项目未完成任务（{project}）"),
                format!("project={project}"),
            )
        }
        SearchMode::Preset => {
            let preset = {
                let value = as_string(args, "preset");
                if value.is_empty() {
                    "hsrr".to_string()
                } else {
                    value
                }
            };
            if !preset.eq_ignore_ascii_case("hsrr")
                && !matches!(preset.as_str(), "呼市燃热" | "呼市" | "燃热")
            {
                return Err(ToolFailure::validation(
                    "未知预设，当前可用: hsrr（呼市燃热）",
                ));
            }
            let assignee = as_string(args, "assignee");
            let projects: Vec<String> = HSRR_PROJECTS.iter().map(|p| p.to_string()).collect();
            let jql = format!(
                "{} ORDER BY updated DESC",
                unfinished_jql(
                    None,
                    &projects,
                    if assignee.is_empty() {
                        None
                    } else {
                        Some(&assignee)
                    },
                    None,
                )
            );
            (
                jql,
                "呼市燃热 未完成任务".to_string(),
                "preset=hsrr".to_string(),
            )
        }
    };

    // 只有原始 JQL 搜索允许自定义 fields，其余模式固定用默认字段集。
    let fields = match mode {
        SearchMode::Raw => sanitize_fields(&as_string(args, "fields"))?,
        _ => DEFAULT_FIELDS.join(","),
    };
    let value = get_json(runtime, &search_path(&jql, max_results, start_at, &fields))?;
    let issues: Vec<Value> = value
        .get("issues")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(summarize_issue).collect())
        .unwrap_or_default();
    let total = value.get("total").and_then(Value::as_i64).unwrap_or(0);

    let mut lines = vec![
        title,
        format!("JQL: {jql}"),
        format!(
            "合计 {total} 条，本次返回 {} 条（startAt={start_at}, maxResults={max_results}）",
            issues.len()
        ),
        String::new(),
    ];
    if issues.is_empty() {
        lines.push("（无匹配任务）".into());
    }
    for issue in &issues {
        lines.push(format_issue_line(issue));
    }
    if (start_at as usize) + issues.len() < total.max(0) as usize {
        lines.push(String::new());
        lines.push(format!(
            "还有更多结果，下一页传 startAt={}",
            start_at as usize + issues.len()
        ));
    }

    let detail = if detail_extra.is_empty() {
        format!("total={total} returned={}", issues.len())
    } else {
        format!("{detail_extra} total={total} returned={}", issues.len())
    };
    Ok(ToolOutcome {
        text: lines.join("\n"),
        count: Some(issues.len()),
        detail,
    })
}

fn format_issue_line(issue: &Value) -> String {
    let key = issue.get("key").and_then(Value::as_str).unwrap_or("-");
    let summary = issue.get("summary").and_then(Value::as_str).unwrap_or("");
    let status = issue.get("status").and_then(Value::as_str).unwrap_or("-");
    let priority = issue.get("priority").and_then(Value::as_str).unwrap_or("-");
    let assignee = issue
        .get("assignee")
        .and_then(Value::as_str)
        .unwrap_or("未指派");
    let issue_type = issue
        .get("issuetype")
        .and_then(Value::as_str)
        .unwrap_or("-");
    format!("- {key} | {status} | {priority} | {assignee} | {issue_type}\n  {summary}")
}

fn summarize_issue(issue: &Value) -> Value {
    let fields = issue.get("fields").unwrap_or(&Value::Null);
    json!({
        "key": issue.get("key").and_then(Value::as_str),
        "summary": limited(fields.get("summary")),
        "status": fields.get("status").and_then(|v| v.get("name")).and_then(Value::as_str),
        "assignee": fields
            .get("assignee")
            .and_then(|v| v.get("displayName").or_else(|| v.get("name")))
            .and_then(Value::as_str),
        "reporter": fields
            .get("reporter")
            .and_then(|v| v.get("displayName").or_else(|| v.get("name")))
            .and_then(Value::as_str),
        "priority": fields.get("priority").and_then(|v| v.get("name")).and_then(Value::as_str),
        "issuetype": fields.get("issuetype").and_then(|v| v.get("name")).and_then(Value::as_str),
        "created": fields.get("created").and_then(Value::as_str),
        "updated": fields.get("updated").and_then(Value::as_str),
    })
}

fn limited(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(|text| {
        if text.len() > 512 {
            let mut end = 512;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}…", &text[..end])
        } else {
            text.to_string()
        }
    })
}

fn search_path(jql: &str, max_results: u64, start_at: u64, fields: &str) -> String {
    let mut path = format!(
        "/rest/api/2/search?jql={}&maxResults={}&fields={}",
        encode_component(jql),
        max_results,
        encode_component(fields)
    );
    if start_at > 0 {
        path.push_str(&format!("&startAt={start_at}"));
    }
    path
}

/// 校验模型传入的 `fields`：只接受逗号分隔的 JIRA 字段名。
/// 空值回落到默认字段集；出现非法字符直接拒绝，不回显原值。
fn sanitize_fields(raw: &str) -> Result<String, ToolFailure> {
    let parts: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return Ok(DEFAULT_FIELDS.join(","));
    }
    if parts.len() > 64 {
        return Err(ToolFailure::validation("fields 最多 64 个字段"));
    }
    let valid = parts.iter().all(|part| {
        part.len() <= 64
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    });
    if !valid {
        return Err(ToolFailure::validation(
            "fields 只能包含字母、数字、下划线、点和连字符，以逗号分隔",
        ));
    }
    Ok(parts.join(","))
}

fn unfinished_jql(
    project: Option<&str>,
    projects: &[String],
    assignee: Option<&str>,
    extra: Option<&str>,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(project) = project {
        parts.push(format!("project = {}", quote_if_needed(project)));
    } else if !projects.is_empty() {
        let list = projects
            .iter()
            .map(|p| quote_if_needed(p))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("project in ({list})"));
    }
    if let Some(assignee) = assignee {
        if assignee == "currentUser()" {
            parts.push("assignee = currentUser()".into());
        } else {
            parts.push(format!("assignee = {}", quote_if_needed(assignee)));
        }
    }
    parts.push(format!("status not in ({})", DONE_STATUSES.join(", ")));
    if let Some(extra) = extra {
        parts.push(format!("({extra})"));
    }
    parts.join(" AND ")
}

fn quote_if_needed(value: &str) -> String {
    let text = value.trim();
    if text.is_empty() {
        return text.to_string();
    }
    let simple = text.chars().enumerate().all(|(index, c)| {
        if index == 0 {
            c.is_ascii_alphabetic()
        } else {
            c.is_ascii_alphanumeric() || c == '_'
        }
    });
    if simple || text.contains('"') {
        return text.to_string();
    }
    format!("\"{text}\"")
}

fn valid_issue_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key.split('-').count() == 2
        && key
            .split('-')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric()))
}

fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let safe = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
        if safe {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

fn get_json(runtime: &EndpointRuntime, path: &str) -> Result<Value, ToolFailure> {
    if !path.starts_with('/') {
        return Err(ToolFailure::validation("内部路径必须以 / 开头"));
    }
    let url = format!("{}{}", runtime.base_url, path);
    let credentials = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", runtime.username, runtime.secret.as_str()).as_bytes());
    let response = runtime
        .agent
        .get(&url)
        .set("Authorization", &format!("Basic {credentials}"))
        .set("Accept", "application/json")
        .call();
    let (status, body, truncated) = match response {
        Ok(response) => {
            let raw = read_capped(response);
            (raw.status, raw.body, raw.truncated)
        }
        Err(ureq::Error::Status(status, response)) => {
            let raw = read_capped(response);
            (status, raw.body, raw.truncated)
        }
        Err(ureq::Error::Transport(error)) => {
            return Err(ToolFailure {
                message: format!("JIRA 网络请求失败: {error}"),
                status: None,
                reason: "network",
                detail: format!("path={}", safe_path(path)),
            })
        }
    };
    if !(200..300).contains(&status) {
        let message = extract_error_message(&body);
        let suffix = if truncated {
            "（响应超限被截断）"
        } else {
            ""
        };
        return Err(ToolFailure {
            message: format!("JIRA HTTP {status}: {message}{suffix}"),
            status: Some(status),
            reason: "remote_http",
            detail: format!(
                "path={} status={status} truncated={truncated}",
                safe_path(path)
            ),
        });
    }
    let mut value: Value = serde_json::from_slice(&body).map_err(|_| {
        if truncated {
            ToolFailure::request("JIRA 响应超过大小上限被截断，无法解析", Some(status))
        } else {
            ToolFailure::request("JIRA 响应不是有效 JSON", Some(status))
        }
    })?;
    trim_json(&mut value, 2048);
    Ok(value)
}

fn safe_path(path: &str) -> String {
    path.split('?').next().unwrap_or(path).to_string()
}

fn extract_error_message(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return "请求失败".into();
    };
    if let Some(messages) = value.get("errorMessages").and_then(Value::as_array) {
        let joined = messages
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("; ");
        if !joined.is_empty() {
            return joined;
        }
    }
    if let Some(errors) = value.get("errors").and_then(Value::as_object) {
        let joined = errors
            .iter()
            .map(|(key, value)| format!("{key}: {}", value.as_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("; ");
        if !joined.is_empty() {
            return joined;
        }
    }
    value
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("请求失败")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn all_ten_tools_are_read_only_and_closed() {
        let definitions = tool_definitions();
        assert_eq!(definitions.len(), 10);
        for definition in &definitions {
            assert_eq!(definition["readOnly"], true);
            assert_eq!(definition["risk"], "low");
            assert_eq!(definition["inputSchema"]["additionalProperties"], false);
            assert!(definition["name"]
                .as_str()
                .unwrap()
                .starts_with("zoomkey_jira_"));
        }
    }

    #[test]
    fn unfinished_jql_matches_plugin_semantics() {
        assert_eq!(
            unfinished_jql(Some("HSRR"), &[], None, None),
            "project = HSRR AND status not in (Done, Closed)"
        );
        assert_eq!(
            unfinished_jql(None, &[], Some("currentUser()"), None),
            "assignee = currentUser() AND status not in (Done, Closed)"
        );
        assert_eq!(
            unfinished_jql(Some("HSRR"), &[], Some("zhang san"), Some("issuetype = 项目缺陷")),
            "project = HSRR AND assignee = \"zhang san\" AND status not in (Done, Closed) AND (issuetype = 项目缺陷)"
        );
        let projects = vec!["HSRR".to_string(), "HSRRERP".to_string()];
        assert_eq!(
            unfinished_jql(None, &projects, None, None),
            "project in (HSRR, HSRRERP) AND status not in (Done, Closed)"
        );
    }

    #[test]
    fn quote_if_needed_only_quotes_when_required() {
        assert_eq!(quote_if_needed("HSRR"), "HSRR");
        assert_eq!(quote_if_needed("呼市燃热"), "\"呼市燃热\"");
        assert_eq!(quote_if_needed("a b"), "\"a b\"");
    }

    #[test]
    fn search_path_encodes_jql_and_skips_zero_start() {
        let defaults = DEFAULT_FIELDS.join(",");
        let path = search_path(
            "project = HSRR AND status not in (Done, Closed)",
            50,
            0,
            &defaults,
        );
        assert!(path.starts_with("/rest/api/2/search?jql=project%20%3D%20HSRR"));
        assert!(path.contains("maxResults=50"));
        assert!(!path.contains("startAt"));
        let paged = search_path("project = HSRR", 10, 20, &defaults);
        assert!(paged.contains("startAt=20"));
    }

    #[test]
    fn custom_fields_are_validated_and_defaulted() {
        // 空值回落默认字段集
        assert_eq!(sanitize_fields("").unwrap(), DEFAULT_FIELDS.join(","));
        assert_eq!(sanitize_fields("   ").unwrap(), DEFAULT_FIELDS.join(","));
        // 正常自定义字段会被裁剪并保留顺序
        assert_eq!(
            sanitize_fields(" key , summary ,customfield_10001").unwrap(),
            "key,summary,customfield_10001"
        );
        // 非法字符被拒绝，且不回显原值
        let failure = sanitize_fields("key; DROP TABLE").unwrap_err();
        assert!(!failure.message.contains("DROP"));
        assert!(sanitize_fields("key,sum mary").is_err());
        // 数量上限
        let many = (0..65)
            .map(|i| format!("f{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(sanitize_fields(&many).is_err());
    }

    #[test]
    fn field_map_static_covers_every_section() {
        for section in [
            "overview",
            "status",
            "issuetype",
            "fields",
            "presets",
            "playbooks",
            "crm-bridge",
        ] {
            let lines = field_map_static(section);
            assert!(
                lines.iter().any(|line| !line.trim().is_empty()),
                "section {section} 应有内容"
            );
        }
        // 未知 section 回落到 overview
        assert_eq!(field_map_static("nonsense"), field_map_static("overview"));
    }

    #[test]
    fn field_map_static_mentions_known_facts() {
        let overview = field_map_static("overview").join("\n");
        assert!(overview.contains("status not in (Done, Closed)"));
        for key in HSRR_PROJECTS {
            assert!(overview.contains(key), "overview 应包含 {key}");
        }
        let status = field_map_static("status").join("\n");
        assert!(status.contains("Done"));
        assert!(status.contains("[完成]"));
    }

    #[test]
    fn status_map_marks_finished_states_as_closed() {
        // 内置状态表里 Done / Closed / 已关闭 三项标为完成态。
        // 注意：JQL 的未完成过滤只用 status not in (Done, Closed)，与源插件一致，
        // 所以「已关闭」在查询侧仍会被算进来——这是插件既有语义，不擅自改动。
        for (name, _, open) in STATUS_MAP {
            let expected = !matches!(name, "Done" | "Closed" | "已关闭");
            assert_eq!(open, expected, "状态 {name} 的未完成标记不符");
        }
    }

    #[test]
    fn issue_key_validation_rejects_traversal() {
        assert!(valid_issue_key("HSRR-123"));
        assert!(!valid_issue_key("../etc/passwd"));
        assert!(!valid_issue_key("HSRR"));
        assert!(!valid_issue_key("HSRR-12-3"));
        assert!(!valid_issue_key("HSRR-"));
        assert!(!valid_issue_key(""));
    }

    #[test]
    fn summarize_issue_keeps_only_safe_fields() {
        let issue = json!({
            "key": "HSRR-1",
            "fields": {
                "summary": "标题",
                "status": {"name": "进行中"},
                "assignee": {"displayName": "张三"},
                "priority": {"name": "高"},
                "issuetype": {"name": "任务"},
                "created": "2026-01-01T00:00:00.000+0800",
                "updated": "2026-01-02T00:00:00.000+0800",
                "customfield_10001": "should not leak"
            }
        });
        let summary = summarize_issue(&issue);
        assert_eq!(summary["key"], "HSRR-1");
        assert_eq!(summary["status"], "进行中");
        assert_eq!(summary["assignee"], "张三");
        assert!(summary.get("customfield_10001").is_none());
    }

    #[test]
    fn error_message_extraction_handles_jira_shapes() {
        assert_eq!(
            extract_error_message(br#"{"errorMessages":["Issue does not exist"]}"#),
            "Issue does not exist"
        );
        assert_eq!(
            extract_error_message(br#"{"errors":{"jql":"bad"}}"#),
            "jql: bad"
        );
        assert_eq!(extract_error_message(b"not json"), "请求失败");
    }
}
