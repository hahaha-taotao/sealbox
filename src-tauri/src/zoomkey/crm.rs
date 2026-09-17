//! ZoomKey CRM（Vtiger Webservice）只读客户端。
//!
//! 对应 `plugins/zoomkey-crm/tools/*.js` 的 10 个只读工具（`configure` 不移植）。
//!
//! 鉴权链：`getchallenge` → `md5(token + AccessKey)` → `login` → `sessionName`，
//! 会话在进程内缓存约 4 分钟（与插件一致），过期或被判失效时重登一次。

use super::{
    as_bool, as_string, as_u64, read_capped, to_pretty, trim_json, EndpointRuntime, ToolFailure,
    ToolOutcome,
};
use crate::session::Session;
use md5::{Digest, Md5};
use serde_json::{json, Map, Value};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const SESSION_TTL: Duration = Duration::from_secs(4 * 60);
const MAX_SQL_LEN: usize = 2000;

#[derive(Clone)]
struct CrmSession {
    session_name: String,
    username: String,
    base_url: String,
    expires_at: Instant,
}

fn cache() -> &'static Mutex<Option<CrmSession>> {
    static CACHE: OnceLock<Mutex<Option<CrmSession>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

pub fn clear_cache() {
    if let Ok(mut guard) = cache().lock() {
        *guard = None;
    }
}

pub fn tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "zoomkey_crm_nav",
            "CRM 导航首页：返回连通摘要与最近项目列表，避免多轮试探。",
            schema(
                &[
                    ("recentProjects", json!({"type":"boolean","default":true})),
                    ("limit", json!({"type":"integer","minimum":1,"maximum":20,"default":8})),
                ],
                &[],
            ),
        ),
        tool(
            "zoomkey_crm_connection_status",
            "检查 CRM 连通性。ping=true 时会真正走一次 getchallenge + login 验证账号与 AccessKey。",
            schema(&[("ping", json!({"type":"boolean","default":false}))], &[]),
        ),
        tool(
            "zoomkey_crm_describe_module",
            "查看 CRM 模块列表，或某个模块的字段结构。不传 elementType 时返回全部模块名。",
            schema(&[("elementType", string_schema(1, 64))], &[]),
        ),
        tool(
            "zoomkey_crm_field_map",
            "CRM 项目字段与关联导航（先结构后查询）。默认返回 ID 前缀/关联主线/核心字段/查询剧本；live=true 时在线 describe 指定模块。",
            schema(
                &[
                    ("module", string_schema(1, 64)),
                    ("live", json!({"type":"boolean","default":false})),
                ],
                &[],
            ),
        ),
        tool(
            "zoomkey_crm_find_account",
            "查找 CRM 客户 Accounts，可按客户 ID 或客户名称精确匹配。",
            schema(
                &[
                    ("id", string_schema(1, 64)),
                    ("name", string_schema(1, 200)),
                    ("limit", json!({"type":"integer","minimum":1,"maximum":100,"default":20})),
                ],
                &[],
            ),
        ),
        tool(
            "zoomkey_crm_find_project",
            "查找 CRM 项目，可按项目编号 project_no、项目名称或项目 ID 查询。",
            schema(
                &[
                    ("projectNo", string_schema(1, 64)),
                    ("name", string_schema(1, 200)),
                    ("id", string_schema(1, 64)),
                    ("limit", json!({"type":"integer","minimum":1,"maximum":100,"default":20})),
                ],
                &[],
            ),
        ),
        tool(
            "zoomkey_crm_list_service_contracts",
            "查询服务合同 ServiceContracts，可按客户 ID 或项目 ID 过滤，可选只看付费合同。",
            schema(
                &[
                    ("accountId", string_schema(1, 64)),
                    ("projectId", string_schema(1, 64)),
                    ("paidOnly", json!({"type":"boolean","default":false})),
                    ("limit", json!({"type":"integer","minimum":1,"maximum":100,"default":50})),
                ],
                &[],
            ),
        ),
        tool(
            "zoomkey_crm_project_members",
            "查询项目成员 Members，需要项目 ID（如 30x489839）。",
            schema(
                &[
                    ("projectId", string_schema(1, 64)),
                    ("limit", json!({"type":"integer","minimum":1,"maximum":100,"default":100})),
                ],
                &["projectId"],
            ),
        ),
        tool(
            "zoomkey_crm_query",
            "执行 Vtiger 只读查询（仅允许 select 语句，分号结尾）。中文 picklist 条件可能查不到，可先宽查再本地过滤。",
            schema(&[("sql", string_schema(1, MAX_SQL_LEN as u64))], &["sql"]),
        ),
        tool(
            "zoomkey_crm_retrieve",
            "按记录 ID 读取单条 CRM 记录，例如 30x489839 / 11x53。",
            schema(&[("id", string_schema(1, 64))], &["id"]),
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
        "zoomkey_crm_nav"
        | "zoomkey_crm_connection_status"
        | "zoomkey_crm_describe_module"
        | "zoomkey_crm_field_map"
        | "zoomkey_crm_find_account"
        | "zoomkey_crm_find_project"
        | "zoomkey_crm_list_service_contracts"
        | "zoomkey_crm_project_members"
        | "zoomkey_crm_query"
        | "zoomkey_crm_retrieve" => {}
        _ => return Err(ToolFailure::validation(format!("未知 CRM 工具 {name}"))),
    }
    let runtime = super::build_runtime(session, "crm")?;
    match name {
        "zoomkey_crm_nav" => nav(&runtime, args),
        "zoomkey_crm_connection_status" => connection_status(&runtime, args),
        "zoomkey_crm_describe_module" => describe_module(&runtime, args),
        "zoomkey_crm_field_map" => field_map(&runtime, args),
        "zoomkey_crm_find_account" => find_account(&runtime, args),
        "zoomkey_crm_find_project" => find_project(&runtime, args),
        "zoomkey_crm_list_service_contracts" => list_service_contracts(&runtime, args),
        "zoomkey_crm_project_members" => project_members(&runtime, args),
        "zoomkey_crm_query" => run_query(&runtime, args),
        "zoomkey_crm_retrieve" => retrieve(&runtime, args),
        _ => Err(ToolFailure::validation("未知 CRM 工具")),
    }
}

fn nav(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let limit = as_u64(args, "limit", 8, 1, 20);
    // 与插件一致：recentProjects 默认 true，显式传 false 时只做链路预检，不返回项目列表。
    let want_recent = match args.get("recentProjects") {
        Some(Value::Bool(value)) => *value,
        _ => true,
    };
    let rows = if want_recent {
        let records = run_query_inner(runtime, &format!("select * from Project limit {limit};"))?;
        project_rows(&records)
    } else {
        run_query_inner(runtime, "select * from Project limit 1;")?;
        Vec::new()
    };

    let mut lines = vec![
        "CRM 概况".to_string(),
        format!("地址: {}", runtime.origin),
        format!("账号: {}", runtime.username),
        if want_recent {
            format!("最近项目: {} 条", rows.len())
        } else {
            "最近项目: 未拉取（recentProjects=false）".to_string()
        },
        String::new(),
    ];
    for row in &rows {
        lines.push(format!(
            "- {} {} {}",
            row["project_no"].as_str().unwrap_or("-"),
            row["projectname"].as_str().unwrap_or(""),
            row["projectstatus"].as_str().unwrap_or("")
        ));
    }
    lines.push(String::new());
    lines.push("下一步可选：".into());
    lines.push("- zoomkey_crm_find_project  按编号/名称查项目".into());
    lines.push("- zoomkey_crm_find_account  查客户".into());
    lines.push("- zoomkey_crm_query  自定义只读查询".into());

    Ok(ToolOutcome {
        text: lines.join("\n"),
        count: Some(rows.len()),
        detail: format!("projects={}", rows.len()),
    })
}

fn connection_status(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let challenge = call_operation(
        runtime,
        "GET",
        &[
            ("operation", "getchallenge".into()),
            ("username", runtime.username.clone()),
        ],
        None,
    )?;
    let has_token = challenge
        .get("token")
        .and_then(Value::as_str)
        .map(|t| !t.is_empty())
        .unwrap_or(false);
    if !has_token {
        return Err(ToolFailure::request("getchallenge 未返回 token", Some(200)));
    }
    let mut lines = vec![
        "CRM 连通正常".to_string(),
        format!("地址: {}", runtime.origin),
        format!("账号: {}", runtime.username),
        "challenge 已下发".into(),
    ];
    let mut detail = format!("origin={} challenge=ok", runtime.origin);
    if as_bool(args, "ping") {
        let session_name = ensure_session(runtime, true)?;
        if session_name.is_empty() {
            return Err(ToolFailure::request("登录未返回 sessionName", Some(200)));
        }
        lines.push("账号与 AccessKey 校验通过".into());
        detail.push_str(" login=ok");
    }
    Ok(ToolOutcome {
        text: lines.join("\n"),
        count: None,
        detail,
    })
}

fn describe_module(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let element_type = as_string(args, "elementType");
    if element_type.is_empty() {
        let result = with_session(runtime, |session_name| {
            call_operation(
                runtime,
                "GET",
                &[
                    ("operation", "listtypes".into()),
                    ("sessionName", session_name.to_string()),
                ],
                None,
            )
        })?;
        let list = result
            .get("types")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut lines = vec![format!("CRM 模块 共 {} 个", list.len()), String::new()];
        lines.extend(list.iter().take(120).map(|name| format!("- {name}")));
        return Ok(ToolOutcome {
            text: lines.join("\n"),
            count: Some(list.len()),
            detail: format!("types={}", list.len()),
        });
    }
    let fields = describe_fields(runtime, &element_type)?;
    let mut lines = vec![
        format!("模块 {element_type} 字段 共 {} 个", fields.len()),
        String::new(),
    ];
    for field in fields.iter().take(120) {
        lines.push(format!(
            "- {}: {} ({})",
            field["name"].as_str().unwrap_or("-"),
            field["label"].as_str().unwrap_or(""),
            field["type"].as_str().unwrap_or("")
        ));
    }
    Ok(ToolOutcome {
        text: lines.join("\n"),
        count: Some(fields.len()),
        detail: format!("elementType={element_type} fields={}", fields.len()),
    })
}

/// CRM 模块 ID 前缀。
const ID_PREFIX: [(&str, &str); 11] = [
    ("Accounts", "11x"),
    ("Contacts", "12x"),
    ("Potentials", "13x"),
    ("SalesOrder", "6x"),
    ("ServiceContracts", "24x"),
    ("Project", "30x"),
    ("HelpDesk", "17x"),
    ("Members", "118x"),
    ("Hour", "122x"),
    ("Documents", "15x"),
    ("Users", "19x"),
];

/// 模块核心字段：(模块, [(字段, 说明)])。
const CORE_MODULE_FIELDS: [(&str, &[(&str, &str)]); 7] = [
    (
        "Project",
        &[
            ("id", "记录ID 30x"),
            ("project_no", "项目编号 PROJ*"),
            ("projectname", "项目名称"),
            ("projectstatus", "状态"),
            ("startdate", "开始日期"),
            ("linktoaccountscontacts", "签约客户 → Accounts/Contacts"),
            ("cf_nrl_accounts271_id", "实际使用方 → Accounts"),
            ("cf_nrl_contacts778_id", "客户负责人 → Contacts"),
            ("assigned_user_id", "指派给"),
            ("cf_1486", "合同额"),
            ("cf_2932", "总回款"),
            ("cf_1634", "总工时"),
            ("cf_6806", "项目性质"),
            ("cf_1695", "项目分级"),
        ],
    ),
    (
        "Accounts",
        &[
            ("id", "客户ID 11x"),
            ("accountname", "客户名称"),
            ("account_no", "客户编号"),
            ("phone", "电话"),
            ("cf_nrl_staff528_id", "售后负责人"),
            ("cf_nrl_staff126_id", "销售负责人"),
            ("cf_711", "热用户（万）"),
            ("cf_729", "供热面积（万平米）"),
        ],
    ),
    (
        "Members",
        &[
            ("id", "成员ID 118x"),
            ("name", "成员名称"),
            ("cf_project_id", "项目 → Project"),
            ("cf_5646", "项目角色"),
            ("cf_7620", "参与状态"),
            ("cf_5659", "总工时"),
            ("cf_5655", "参与起始"),
            ("cf_5662", "参与退出"),
        ],
    ),
    (
        "ServiceContracts",
        &[
            ("id", "合同ID 24x"),
            ("subject", "主题"),
            ("contract_status", "状态"),
            ("cf_project_id", "项目 → Project"),
            ("cf_nrl_accounts356_id", "签约客户 → Accounts"),
            ("sc_related_to", "实际使用方"),
            ("cf_10088", "服务性质"),
            ("cf_7338", "服务费应收"),
            ("cf_777", "服务费已收"),
        ],
    ),
    (
        "SalesOrder",
        &[
            ("id", "订单ID 6x"),
            ("salesorder_no", "销售订单编号"),
            ("subject", "主题"),
            ("account_id", "客户"),
            ("cf_project_id", "项目"),
            ("cf_4645", "合同编号"),
            ("hdnGrandTotal", "总计"),
        ],
    ),
    (
        "HelpDesk",
        &[
            ("ticket_no", "编号"),
            ("ticket_title", "标题"),
            ("ticketstatus", "状态"),
            ("parent_id", "关联客户"),
            ("cf_project_id", "关联项目"),
            ("cf_servicecontracts_id", "服务合同"),
            ("cf_jiratask_id", "JIRA任务(CRM内)"),
        ],
    ),
    (
        "Hour",
        &[
            ("cf_project_id", "项目"),
            ("cf_members_id", "项目成员"),
            ("cf_6057", "工时(小时)"),
            ("cf_6059", "出差人天"),
            ("cf_7543", "数据日期"),
        ],
    ),
];

/// 内置查询剧本。
const CRM_PLAYBOOKS: [(&str, &[&str]); 3] = [
    (
        "项目概况",
        &[
            "zoomkey_crm_find_project { projectNo }",
            "zoomkey_crm_retrieve { id: 30x… }",
            "zoomkey_crm_project_members { projectId }",
            "zoomkey_crm_list_service_contracts { projectId 或 accountId }",
        ],
    ),
    (
        "客户全景",
        &[
            "zoomkey_crm_find_account { name 或 id }",
            "query Project where linktoaccountscontacts='11x…'",
            "zoomkey_crm_list_service_contracts { accountId }",
        ],
    ),
    (
        "成员与工时",
        &[
            "zoomkey_crm_project_members { projectId }",
            "query Hour where cf_project_id='30x…' limit 50;",
        ],
    ),
];

fn prefix_of(module: &str) -> &'static str {
    ID_PREFIX
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(module))
        .map(|(_, prefix)| *prefix)
        .unwrap_or("?")
}

fn field_map(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let module = as_string(args, "module");
    // live=true 才联网 describe；默认返回内置结构图，离线也能先看清关系。
    if as_bool(args, "live") {
        let target = if module.is_empty() {
            "Project".to_string()
        } else {
            module.clone()
        };
        let fields = describe_fields(runtime, &target)?;
        let mut payload = Value::Array(fields.clone());
        trim_json(&mut payload, 256);
        return Ok(ToolOutcome {
            text: format!(
                "CRM 在线字段 · {target}（{} 个）\n\n{}",
                fields.len(),
                to_pretty(&payload)
            ),
            count: Some(fields.len()),
            detail: format!("module={target} fields={} mode=live", fields.len()),
        });
    }

    let lines = field_map_static(&module);
    Ok(ToolOutcome {
        text: lines.join("\n"),
        count: None,
        detail: format!(
            "module={} mode=static",
            if module.is_empty() {
                "ALL"
            } else {
                module.as_str()
            }
        ),
    })
}

/// 内置结构图正文（纯静态，不联网）。抽成独立函数便于单测。
fn field_map_static(module: &str) -> Vec<String> {
    let mut lines = vec![
        "CRM 项目字段与关联导航（内置）".to_string(),
        String::new(),
        "ID 前缀:".to_string(),
    ];
    for (name, prefix) in ID_PREFIX {
        lines.push(format!("- {prefix} {name}"));
    }
    lines.push(String::new());
    lines.push("关联主线:".into());
    lines.push("Accounts(11x) ←签约— Project(30x) —实际使用→ Accounts".into());
    lines.push("Project → Members(118x) → Hour(122x)".into());
    lines.push("Project → SalesOrder(6x) / ServiceContracts(24x) / HelpDesk(17x)".into());
    lines.push("Potentials(13x) → Accounts；可转化到项目/订单".into());
    lines.push(String::new());
    lines.push("查询剧本:".into());
    for (name, steps) in CRM_PLAYBOOKS {
        lines.push(format!("【{name}】"));
        for step in steps {
            lines.push(format!("  · {step}"));
        }
    }

    if !module.is_empty() {
        lines.push(String::new());
        lines.push(format!("模块核心字段 · {module} ({})", prefix_of(module)));
        match CORE_MODULE_FIELDS
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(module))
        {
            Some((_, rows)) => {
                for (field, note) in *rows {
                    lines.push(format!("- {field}: {note}"));
                }
            }
            None => lines.push("（无内置核心字段表，请 live=true 在线 describe）".into()),
        }
        lines.push(String::new());
        lines.push("需要全量字段时: field_map module=... live=true".into());
    } else {
        lines.push(String::new());
        lines.push("模块核心字段摘要:".into());
        for (name, rows) in CORE_MODULE_FIELDS {
            lines.push(String::new());
            lines.push(format!("## {name} ({})", prefix_of(name)));
            for (field, note) in rows {
                lines.push(format!("- {field}: {note}"));
            }
        }
        lines.push(String::new());
        lines.push("指定模块: field_map module=Project".into());
        lines.push("在线全量: field_map module=Project live=true".into());
    }

    lines
}

fn find_account(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let limit = as_u64(args, "limit", 20, 1, 100);
    let id = as_string(args, "id");
    let name = as_string(args, "name");
    let sql = if !id.is_empty() {
        format!(
            "select * from Accounts where id = '{}' limit {limit};",
            escape_sql(&id)
        )
    } else if !name.is_empty() {
        format!(
            "select * from Accounts where accountname = '{}' limit {limit};",
            escape_sql(&name)
        )
    } else {
        return Err(ToolFailure::validation("请提供 id 或 name"));
    };
    let records = run_query_inner(runtime, &sql)?;
    let rows = project_records(
        &records,
        &[
            "accountname",
            "phone",
            "email1",
            "bill_city",
            "assigned_user_id",
        ],
    );
    Ok(ToolOutcome {
        text: format_records("CRM 客户", &rows),
        count: Some(rows.len()),
        detail: format!("sql_len={} returned={}", sql.len(), rows.len()),
    })
}

fn find_project(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let limit = as_u64(args, "limit", 20, 1, 100);
    let id = as_string(args, "id");
    let project_no = as_string(args, "projectNo");
    let name = as_string(args, "name");
    let sql = if !id.is_empty() {
        format!(
            "select * from Project where id = '{}' limit {limit};",
            escape_sql(&id)
        )
    } else if !project_no.is_empty() {
        format!(
            "select * from Project where project_no = '{}' limit {limit};",
            escape_sql(&project_no)
        )
    } else if !name.is_empty() {
        format!(
            "select * from Project where projectname = '{}' limit {limit};",
            escape_sql(&name)
        )
    } else {
        return Err(ToolFailure::validation("请提供 projectNo / name / id 之一"));
    };
    let records = run_query_inner(runtime, &sql)?;
    let rows = project_rows(&records);
    Ok(ToolOutcome {
        text: format_records("CRM 项目", &rows),
        count: Some(rows.len()),
        detail: format!("returned={}", rows.len()),
    })
}

fn list_service_contracts(
    runtime: &EndpointRuntime,
    args: &Value,
) -> Result<ToolOutcome, ToolFailure> {
    let limit = as_u64(args, "limit", 50, 1, 100);
    let account_id = as_string(args, "accountId");
    let project_id = as_string(args, "projectId");
    let mut conditions = Vec::new();
    if !account_id.is_empty() {
        conditions.push(format!(
            "cf_nrl_accounts356_id = '{}'",
            escape_sql(&account_id)
        ));
    }
    if !project_id.is_empty() {
        conditions.push(format!("cf_project_id = '{}'", escape_sql(&project_id)));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" where {}", conditions.join(" and "))
    };
    let sql = format!("select * from ServiceContracts{where_clause} limit {limit};");
    let records = run_query_inner(runtime, &sql)?;
    let paid_only = as_bool(args, "paidOnly");
    let rows: Vec<Value> = project_records(
        &records,
        &[
            "subject",
            "contract_no",
            "contract_status",
            "start_date",
            "due_date",
            "cf_10088",
            "cf_7338",
            "cf_777",
        ],
    )
    .into_iter()
    .filter(|row| !paid_only || row.get("cf_10088").and_then(Value::as_str) == Some("付费"))
    .collect();
    Ok(ToolOutcome {
        text: format_records("服务合同", &rows),
        count: Some(rows.len()),
        detail: format!("returned={} paidOnly={paid_only}", rows.len()),
    })
}

fn project_members(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let project_id = as_string(args, "projectId");
    if project_id.is_empty() {
        return Err(ToolFailure::validation("projectId 不能为空"));
    }
    let limit = as_u64(args, "limit", 100, 1, 100);
    let sql = format!(
        "select * from Members where cf_project_id = '{}' limit {limit};",
        escape_sql(&project_id)
    );
    let records = run_query_inner(runtime, &sql)?;
    let rows = project_records(
        &records,
        &[
            "name", "cf_5646", "cf_5655", "cf_5662", "cf_7620", "cf_5659",
        ],
    );
    Ok(ToolOutcome {
        text: format_records(&format!("项目成员 {project_id}"), &rows),
        count: Some(rows.len()),
        detail: format!("projectId={project_id} returned={}", rows.len()),
    })
}

fn run_query(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let sql = as_string(args, "sql");
    if sql.is_empty() {
        return Err(ToolFailure::validation("sql 不能为空"));
    }
    let records = run_query_inner(runtime, &sql)?;
    let rows: Vec<Value> = records.iter().take(200).cloned().collect();
    Ok(ToolOutcome {
        text: format_records("CRM 查询结果", &rows),
        count: Some(records.len()),
        detail: format!("returned={}", records.len()),
    })
}

fn retrieve(runtime: &EndpointRuntime, args: &Value) -> Result<ToolOutcome, ToolFailure> {
    let id = as_string(args, "id");
    if id.is_empty() {
        return Err(ToolFailure::validation("id 不能为空"));
    }
    if !valid_record_id(&id) {
        return Err(ToolFailure::validation("id 格式不合法"));
    }
    let result = with_session(runtime, |session_name| {
        call_operation(
            runtime,
            "GET",
            &[
                ("operation", "retrieve".into()),
                ("sessionName", session_name.to_string()),
                ("id", id.clone()),
            ],
            None,
        )
    })?;
    let mut payload = result.clone();
    trim_json(&mut payload, 512);
    Ok(ToolOutcome {
        text: format!("CRM 记录 {id}\n\n{}", to_pretty(&payload)),
        count: None,
        detail: format!("id={id}"),
    })
}

/// 执行一次需要会话的调用：会话失效时清缓存、重登，并在同一次调用内重试一次。
/// 对齐插件 `withSession`，避免会话过期（TTL 约 4 分钟）时让模型白跑一轮。
fn with_session<T>(
    runtime: &EndpointRuntime,
    mut action: impl FnMut(&str) -> Result<T, ToolFailure>,
) -> Result<T, ToolFailure> {
    let session_name = ensure_session(runtime, false)?;
    match action(&session_name) {
        Ok(value) => Ok(value),
        Err(error) => {
            if !is_session_error(&error) {
                return Err(error);
            }
            clear_cache();
            let fresh = ensure_session(runtime, true)?;
            action(&fresh)
        }
    }
}

/// Vtiger 会话失效的判定。
fn is_session_error(error: &ToolFailure) -> bool {
    let text = format!("{} {}", error.message, error.detail).to_ascii_lowercase();
    text.contains("session")
}

fn run_query_inner(runtime: &EndpointRuntime, sql: &str) -> Result<Vec<Value>, ToolFailure> {
    let normalized = normalize_sql(sql)?;
    with_session(runtime, |session_name| {
        raw_query(runtime, session_name, &normalized)
    })
}

fn raw_query(
    runtime: &EndpointRuntime,
    session_name: &str,
    sql: &str,
) -> Result<Vec<Value>, ToolFailure> {
    let result = call_operation(
        runtime,
        "GET",
        &[
            ("operation", "query".into()),
            ("sessionName", session_name.to_string()),
            ("query", sql.to_string()),
        ],
        None,
    )?;
    Ok(match result {
        Value::Array(items) => items,
        Value::Null => Vec::new(),
        other => vec![other],
    })
}

fn describe_fields(
    runtime: &EndpointRuntime,
    element_type: &str,
) -> Result<Vec<Value>, ToolFailure> {
    let result = with_session(runtime, |session_name| {
        call_operation(
            runtime,
            "GET",
            &[
                ("operation", "describe".into()),
                ("sessionName", session_name.to_string()),
                ("elementType", element_type.to_string()),
            ],
            None,
        )
    })?;
    let fields = result
        .get("fields")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(fields
        .iter()
        .take(400)
        .map(|field| {
            let type_name = field
                .get("type")
                .and_then(|t| t.get("name").and_then(Value::as_str).or_else(|| t.as_str()))
                .unwrap_or("");
            json!({
                "name": field.get("name").and_then(Value::as_str),
                "label": field.get("label").and_then(Value::as_str),
                "type": type_name,
                "mandatory": field.get("mandatory").and_then(Value::as_bool),
            })
        })
        .collect())
}

fn ensure_session(runtime: &EndpointRuntime, force: bool) -> Result<String, ToolFailure> {
    let now = Instant::now();
    if !force {
        if let Ok(guard) = cache().lock() {
            if let Some(session) = guard.as_ref() {
                if session.username == runtime.username
                    && session.base_url == runtime.base_url
                    && session.expires_at > now + Duration::from_secs(30)
                {
                    return Ok(session.session_name.clone());
                }
            }
        }
    }

    let challenge = call_operation(
        runtime,
        "GET",
        &[
            ("operation", "getchallenge".into()),
            ("username", runtime.username.clone()),
        ],
        None,
    )?;
    let token = challenge
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| ToolFailure::request("getchallenge 未返回 token", Some(200)))?;

    let mut hasher = Md5::new();
    hasher.update(token.as_bytes());
    hasher.update(runtime.secret.as_bytes());
    let access_key_hash = hex::encode(hasher.finalize());

    let login = call_operation(
        runtime,
        "POST",
        &[],
        Some(vec![
            ("operation", "login".to_string()),
            ("username", runtime.username.clone()),
            ("accessKey", access_key_hash),
        ]),
    )?;
    let session_name = login
        .get("sessionName")
        .and_then(Value::as_str)
        .ok_or_else(|| ToolFailure::request("登录未返回 sessionName", Some(200)))?
        .to_string();

    if let Ok(mut guard) = cache().lock() {
        *guard = Some(CrmSession {
            session_name: session_name.clone(),
            username: runtime.username.clone(),
            base_url: runtime.base_url.clone(),
            expires_at: now + SESSION_TTL,
        });
    }
    Ok(session_name)
}

fn call_operation(
    runtime: &EndpointRuntime,
    method: &str,
    query: &[(&str, String)],
    form: Option<Vec<(&str, String)>>,
) -> Result<Value, ToolFailure> {
    let mut url = runtime.base_url.clone();
    if !query.is_empty() {
        let pairs: Vec<String> = query
            .iter()
            .map(|(key, value)| format!("{}={}", encode_component(key), encode_component(value)))
            .collect();
        url.push('?');
        url.push_str(&pairs.join("&"));
    }

    let mut request = if method == "POST" {
        runtime.agent.post(&url)
    } else {
        runtime.agent.get(&url)
    };
    request = request.set("Accept", "application/json");

    let body = form.map(|pairs| {
        pairs
            .iter()
            .map(|(key, value)| format!("{}={}", encode_component(key), encode_component(value)))
            .collect::<Vec<_>>()
            .join("&")
    });

    let response = match &body {
        Some(body) => request
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(body),
        None => request.call(),
    };

    let (status, bytes, truncated) = match response {
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
                message: format!("CRM 网络请求失败: {error}"),
                status: None,
                reason: "network",
                detail: String::new(),
            })
        }
    };

    let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        if truncated {
            ToolFailure::request(
                format!("CRM 响应超过大小上限被截断，无法解析（HTTP {status}）"),
                Some(status),
            )
        } else {
            ToolFailure::request(non_json_message(status, &bytes, &runtime.base_url), Some(status))
        }
    })?;
    if value.get("success").and_then(Value::as_bool) == Some(false) {
        let message = value
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("CRM API 返回失败");
        let code = value
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("");
        // 会话失效时清缓存，下一次调用会重登。
        if code.contains("SESSION") || message.to_ascii_lowercase().contains("session") {
            clear_cache();
        }
        return Err(ToolFailure {
            message: format!("CRM {code}: {message}"),
            status: Some(status),
            reason: "remote_api",
            detail: format!("code={code}"),
        });
    }
    Ok(value.get("result").cloned().unwrap_or(Value::Null))
}

fn project_rows(records: &[Value]) -> Vec<Value> {
    project_records(
        records,
        &[
            "project_no",
            "projectname",
            "projectstatus",
            "linktoaccountscontacts",
            "startdate",
            "targetenddate",
        ],
    )
}

fn project_records(records: &[Value], fields: &[&str]) -> Vec<Value> {
    records
        .iter()
        .take(200)
        .map(|record| {
            let mut out = Map::new();
            if let Some(id) = record.get("id").and_then(Value::as_str) {
                out.insert("id".into(), Value::String(id.to_string()));
            }
            for field in fields {
                if let Some(value) = record.get(*field) {
                    if value.is_null() {
                        continue;
                    }
                    if let Some(text) = value.as_str() {
                        if text.is_empty() {
                            continue;
                        }
                        let capped = if text.len() > 300 {
                            let mut end = 300;
                            while end > 0 && !text.is_char_boundary(end) {
                                end -= 1;
                            }
                            format!("{}…", &text[..end])
                        } else {
                            text.to_string()
                        };
                        out.insert((*field).to_string(), Value::String(capped));
                    } else {
                        out.insert((*field).to_string(), value.clone());
                    }
                }
            }
            Value::Object(out)
        })
        .collect()
}

fn format_records(title: &str, rows: &[Value]) -> String {
    let mut lines = vec![
        title.to_string(),
        format!("共 {} 条", rows.len()),
        String::new(),
    ];
    if rows.is_empty() {
        lines.push("（无数据）".into());
        return lines.join("\n");
    }
    for row in rows.iter().take(50) {
        let id = row.get("id").and_then(Value::as_str).unwrap_or("-");
        let mut headline = id.to_string();
        for key in ["project_no", "projectname", "accountname", "subject"] {
            if let Some(value) = row.get(key).and_then(Value::as_str) {
                headline.push(' ');
                headline.push_str(value);
            }
        }
        lines.push(format!("- {headline}"));
        let parts: Vec<String> = row
            .as_object()
            .map(|map| {
                map.iter()
                    .filter(|(key, _)| {
                        !matches!(
                            key.as_str(),
                            "id" | "project_no" | "projectname" | "accountname" | "subject"
                        )
                    })
                    .filter_map(|(key, value)| {
                        value
                            .as_str()
                            .map(|text| format!("{key}={text}"))
                            .or_else(|| Some(format!("{key}={value}")))
                    })
                    .take(6)
                    .collect()
            })
            .unwrap_or_default();
        if !parts.is_empty() {
            lines.push(format!("  {}", parts.join(" | ")));
        }
    }
    if rows.len() > 50 {
        lines.push(String::new());
        lines.push(format!("…仅显示前 50 条（共 {} 条）", rows.len()));
    }
    lines.join("\n")
}

fn escape_sql(value: &str) -> String {
    value.replace('\'', "''")
}

/// 只放行单条 select。Vtiger 的 query operation 本身只支持 SELECT，
/// 这里再收一道，避免模型把写操作或语句拼接塞进来。
fn normalize_sql(raw: &str) -> Result<String, ToolFailure> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ToolFailure::validation("sql 不能为空"));
    }
    if trimmed.len() > MAX_SQL_LEN {
        return Err(ToolFailure::validation("sql 过长"));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(ToolFailure::validation("sql 含控制字符"));
    }
    let without_trailing = trimmed.trim_end_matches(';').trim_end();
    if without_trailing.contains(';') {
        return Err(ToolFailure::validation("只允许单条语句"));
    }
    let lower = without_trailing.to_ascii_lowercase();
    if !lower.starts_with("select") {
        return Err(ToolFailure::validation("只允许 select 查询"));
    }
    for forbidden in [
        "insert ",
        "update ",
        "delete ",
        "drop ",
        "truncate ",
        "alter ",
        "create ",
        "replace ",
        "grant ",
        "attach ",
        "pragma ",
    ] {
        if lower.contains(forbidden) {
            return Err(ToolFailure::validation("只允许只读查询"));
        }
    }
    Ok(format!("{without_trailing};"))
}

fn valid_record_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == 'x' || c == 'X')
        && id.contains('x')
}

fn non_json_message(status: u16, body: &[u8], base_url: &str) -> String {
    let looks_like_html = body_looks_like_html(body);
    let preview = body_preview(body);
    if looks_like_html {
        format!(
            "CRM 返回了登录页 HTML 而不是 Webservice JSON（HTTP {status}）。请把地址改成以 /webservice.php 结尾（当前: {base_url}）"
        )
    } else if preview.is_empty() {
        format!("CRM 返回了非 JSON 响应（HTTP {status}）")
    } else {
        format!("CRM 返回了非 JSON 响应（HTTP {status}）: {preview}")
    }
}

fn body_looks_like_html(body: &[u8]) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.windows(b"<!doctype html".len()).any(|w| w == b"<!doctype html")
        || lower.windows(b"<html".len()).any(|w| w == b"<html")
}

fn body_preview(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let collapsed: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if collapsed.is_empty() {
        return String::new();
    }
    let mut end = collapsed.len().min(120);
    while end > 0 && !collapsed.is_char_boundary(end) {
        end -= 1;
    }
    if collapsed.len() > end {
        format!("{}…", &collapsed[..end])
    } else {
        collapsed
    }
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
                .starts_with("zoomkey_crm_"));
        }
    }

    #[test]
    fn session_errors_are_detected_for_relogin() {
        let expired = ToolFailure {
            message: "CRM INVALID_SESSION: Session is not valid".into(),
            status: Some(200),
            reason: "remote_api",
            detail: "code=INVALID_SESSION".into(),
        };
        assert!(is_session_error(&expired));
        // 非会话类错误不应触发重登
        assert!(!is_session_error(&ToolFailure::validation("sql 不能为空")));
        assert!(!is_session_error(&ToolFailure::request(
            "CRM HTTP 500",
            Some(500)
        )));
    }

    #[test]
    fn prefix_of_resolves_known_modules_case_insensitively() {
        assert_eq!(prefix_of("Project"), "30x");
        assert_eq!(prefix_of("project"), "30x");
        assert_eq!(prefix_of("Members"), "118x");
        assert_eq!(prefix_of("不存在"), "?");
    }

    #[test]
    fn every_core_module_has_an_id_prefix() {
        for (name, rows) in CORE_MODULE_FIELDS {
            assert_ne!(prefix_of(name), "?", "模块 {name} 缺少 ID 前缀");
            assert!(!rows.is_empty(), "模块 {name} 核心字段表不应为空");
        }
    }

    #[test]
    fn field_map_static_expands_only_the_requested_module() {
        let all = field_map_static("").join("\n");
        assert!(all.contains("ID 前缀"));
        assert!(all.contains("## Project"));
        // 指定模块时只展开该模块
        let one = field_map_static("Accounts").join("\n");
        assert!(one.contains("模块核心字段 · Accounts"));
        assert!(!one.contains("## Project"));
        // 未知模块给出 live 提示
        let unknown = field_map_static("Nope").join("\n");
        assert!(unknown.contains("无内置核心字段表"));
    }

    #[test]
    fn normalize_sql_only_allows_a_single_select() {
        assert_eq!(
            normalize_sql("select * from Project").unwrap(),
            "select * from Project;"
        );
        assert_eq!(
            normalize_sql("  SELECT id FROM Project;  ").unwrap(),
            "SELECT id FROM Project;"
        );
        assert!(normalize_sql("").is_err());
        assert!(normalize_sql("delete from Project").is_err());
        assert!(normalize_sql("select * from Project; drop table X").is_err());
        assert!(normalize_sql("select * from Project where a = 'x'").is_ok());
        assert!(normalize_sql("update Project set x=1").is_err());
    }

    #[test]
    fn sql_escaping_doubles_single_quotes() {
        assert_eq!(escape_sql("O'Brien"), "O''Brien");
        assert_eq!(escape_sql("plain"), "plain");
    }

    #[test]
    fn record_id_validation_requires_vtiger_shape() {
        assert!(valid_record_id("30x489839"));
        assert!(valid_record_id("11x53"));
        assert!(!valid_record_id("489839"));
        assert!(!valid_record_id("30x489839; drop"));
        assert!(!valid_record_id(""));
    }

    #[test]
    fn project_records_project_and_cap_fields() {
        let records = vec![json!({
            "id": "30x1",
            "project_no": "PROJ3096",
            "projectname": "桦南协联",
            "internal_secret": "should not leak",
            "projectstatus": "进行中"
        })];
        let rows = project_rows(&records);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["project_no"], "PROJ3096");
        assert!(rows[0].get("internal_secret").is_none());
    }

    #[test]
    fn format_records_handles_empty_and_non_empty() {
        assert!(format_records("标题", &[]).contains("无数据"));
        let rows = vec![json!({"id": "30x1", "project_no": "PROJ1", "projectname": "甲"})];
        let text = format_records("CRM 项目", &rows);
        assert!(text.contains("共 1 条"));
        assert!(text.contains("PROJ1"));
    }

    #[test]
    fn vtyper_url_encoding_is_rfc3986() {
        assert_eq!(
            encode_component("select * from Project"),
            "select%20%2A%20from%20Project"
        );
        assert_eq!(encode_component("30x489839"), "30x489839");
    }

    #[test]
    fn html_login_page_is_explained_instead_of_generic_non_json() {
        let html = b"<!DOCTYPE html><html><head><title>ZoomKey CRM</title></head></html>";
        let message = non_json_message(200, html, "https://crm.zoomkey.com.cn");
        assert!(message.contains("登录页 HTML"), "{message}");
        assert!(message.contains("/webservice.php"), "{message}");
        assert!(message.contains("https://crm.zoomkey.com.cn"), "{message}");
    }

    #[test]
    fn non_json_plain_text_keeps_a_short_preview() {
        let message = non_json_message(200, b"Invalid request", "https://crm.zoomkey.com.cn/webservice.php");
        assert!(message.contains("Invalid request"), "{message}");
        assert!(!message.contains("登录页 HTML"), "{message}");
    }
}
