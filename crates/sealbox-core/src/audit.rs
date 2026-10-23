use crate::vault::AuditEvent;
use serde::{Deserialize, Serialize};

pub const ACTIONS: &[(&str, &str)] = &[
    ("unlock", "解锁密码库"),
    ("change_master", "修改主密码"),
    ("create", "新建条目"),
    ("update", "更新条目"),
    ("delete", "移入回收站"),
    ("restore", "恢复条目"),
    ("empty_trash", "清空回收站"),
    ("copy", "复制信息"),
    ("reveal", "查看秘密"),
    ("copy_certificate", "复制公开证书"),
    ("create_folder", "新建文件夹"),
    ("rename_folder", "重命名文件夹"),
    ("delete_folder", "删除文件夹"),
    ("merge_folders", "合并文件夹"),
    ("rename_tag", "重命名标签"),
    ("delete_tag", "删除标签"),
    ("merge_tags", "合并标签"),
    ("export", "导出备份"),
    ("import", "导入备份"),
    ("import_csv", "导入 CSV"),
    ("sync", "同步密码库"),
    ("sync_apply", "应用同步数据"),
    ("sync_config", "修改同步配置"),
    ("browser_fill", "浏览器自动填充"),
    ("mcp_start", "启动 MCP 服务"),
    ("mcp_stop", "停止 MCP 服务"),
    ("mcp_rotate", "轮换 MCP 令牌"),
    ("fill_rotate", "轮换浏览器令牌"),
    ("copy_mcp_token", "复制 MCP 令牌"),
    ("copy_fill_token", "复制浏览器令牌"),
    ("copy_mcp_snippet", "复制 MCP 配置"),
    ("fill_pair_open", "开放浏览器配对"),
    ("mcp_zoomkey_policy", "修改 ZoomKey 策略"),
    ("mcp_zoomkey_test", "测试 ZoomKey 连通性"),
    ("mcp_github", "GitHub 调用"),
    ("mcp_github_denied", "GitHub 调用未成功"),
    ("mcp_zoomkey", "ZoomKey 调用"),
    ("mcp_zoomkey_denied", "ZoomKey 调用未成功"),
];

const TOOLS: &[(&str, &str)] = &[
    ("github_get_authenticated_user", "查询 GitHub 账号"),
    ("github_list_repositories", "列出仓库"),
    ("github_get_repository", "查询仓库"),
    ("github_list_issues", "列出 Issue"),
    ("github_list_pull_requests", "列出 PR"),
    ("github_create_issue", "创建 Issue"),
    ("github_create_issue_comment", "追加评论"),
    ("github_create_pull_request", "创建 PR"),
    ("github_create_release", "创建版本"),
    ("github_list_releases", "列出版本"),
    ("github_get_release", "查询版本"),
    ("github_git_stage", "提交 Git 改动"),
    ("github_list_credentials", "列出 GitHub 凭据"),
    ("github_user_info", "查询 GitHub 账号"),
    ("github_repo_list", "列出仓库"),
    ("github_repo_get", "查询仓库"),
    ("github_issues_list", "列出 Issue"),
    ("github_issues_get", "查询 Issue"),
    ("github_issue_create", "创建 Issue"),
    ("github_issue_comment", "追加评论"),
    ("github_issue_close", "关闭 Issue"),
    ("github_pulls_list", "列出 PR"),
    ("github_get_pull_request", "查询 PR"),
    ("github_pr_create", "创建 PR"),
    ("github_pr_merge", "合并 PR"),
    ("github_release_list", "列出版本"),
    ("github_release_get", "查询版本"),
    ("github_release_create", "创建版本"),
    ("github_release_publish", "发布版本"),
    ("github_release_generate_notes", "生成版本说明"),
    ("github_git", "Git 操作"),
    ("github_issue", "Issue 操作"),
    ("github_pr", "PR 操作"),
    ("github_release", "版本操作"),
    ("github_git_status", "查看 Git 状态"),
    ("github_git_diff", "查看 Git 差异"),
    ("github_git_log", "查看 Git 历史"),
    ("github_git_branches", "查看 Git 分支"),
    ("github_git_fetch", "获取 Git 远端"),
    ("github_git_pull", "拉取 Git 更新"),
    ("github_git_commit", "提交 Git 改动"),
    ("github_git_push", "推送 Git 改动"),
    ("github_git_clone", "克隆仓库"),
    ("zoomkey_jira_nav", "JIRA 导航"),
    ("zoomkey_jira_connection_status", "检查 JIRA 连通性"),
    ("zoomkey_jira_field_map", "查询 JIRA 字段导航"),
    ("zoomkey_jira_list_projects", "列出 JIRA 项目"),
    ("zoomkey_jira_project_statuses", "查询 JIRA 状态"),
    ("zoomkey_jira_search_issues", "搜索 JIRA 任务"),
    ("zoomkey_jira_get_issue", "查询 JIRA 任务"),
    ("zoomkey_jira_my_open_issues", "查询我的未完成任务"),
    ("zoomkey_jira_project_unfinished", "查询项目未完成任务"),
    ("zoomkey_jira_preset_unfinished", "查询呼市燃热未完成任务"),
    ("zoomkey_crm_nav", "CRM 导航"),
    ("zoomkey_crm_connection_status", "检查 CRM 连通性"),
    ("zoomkey_crm_field_map", "查询 CRM 字段导航"),
    ("zoomkey_crm_describe_module", "查询 CRM 模块"),
    ("zoomkey_crm_find_account", "查询 CRM 客户"),
    ("zoomkey_crm_find_project", "查询 CRM 项目"),
    ("zoomkey_crm_list_service_contracts", "查询服务合同"),
    ("zoomkey_crm_project_members", "查询项目成员"),
    ("zoomkey_crm_query", "查询 CRM 数据"),
    ("zoomkey_crm_retrieve", "读取 CRM 记录"),
];

pub const RESULTS: &[(&str, &str)] = &[
    ("recorded", "已记录"),
    ("success", "成功"),
    ("failure", "失败"),
    ("denied", "未获准"),
    ("network", "网络失败"),
    ("remote_http", "远端 HTTP 失败"),
    ("remote_api", "远端接口失败"),
    ("validation", "校验未通过"),
    ("disabled", "功能未启用"),
];

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AuditQuery {
    pub keyword: String,
    pub actions: Vec<String>,
    pub result: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditDisplay {
    #[serde(flatten)]
    pub raw: AuditEvent,
    pub operation: String,
    pub result: String,
    pub result_label: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
pub struct AuditPage {
    pub items: Vec<AuditDisplay>,
    pub total: i64,
    pub actions: Vec<(&'static str, &'static str)>,
    pub results: Vec<(&'static str, &'static str)>,
}

fn label<'a>(dictionary: &[(&str, &'a str)], key: &str) -> Option<&'a str> {
    dictionary
        .iter()
        .find(|(id, _)| *id == key)
        .map(|(_, text)| *text)
}

fn structured<'a>(detail: &'a str, keys: &[&str]) -> Option<Vec<&'a str>> {
    let mut rest = detail.strip_prefix(&format!("{}=", keys[0]))?;
    let mut values = Vec::new();
    for key in &keys[1..] {
        let marker = format!(" {key}=");
        let (value, tail) = rest.split_once(&marker)?;
        // Historical key=value logs have no escaping. Ambiguous boundaries stay raw.
        if tail.contains(&marker) {
            return None;
        }
        values.push(value);
        rest = tail;
    }
    values.push(rest);
    Some(values)
}

fn summary(detail: &str, fields: &[(&str, &str)]) -> Option<String> {
    let keys: Vec<&str> = fields.iter().map(|(key, _)| *key).collect();
    let values = structured(detail, &keys)?;
    let mut text = Vec::new();
    for ((key, name), value) in fields.iter().zip(values) {
        let value = if *key == "overwrite" {
            match value {
                "true" => "是",
                "false" => "否",
                _ => return None,
            }
        } else {
            value.parse::<u64>().ok()?;
            value
        };
        text.push(format!("{name}：{value}"));
    }
    Some(text.join("；"))
}

fn named_count(detail: &str, key: &str, name: &str) -> Option<String> {
    let (names, count) = detail.rsplit_once(&format!(" {key}="))?;
    count.parse::<u64>().ok()?;
    Some(format!("名称记录：{names}；{name}：{count}"))
}

pub fn format_event(raw: AuditEvent) -> AuditDisplay {
    let operation = label(ACTIONS, &raw.action)
        .unwrap_or("其他操作")
        .to_string();
    let mut result = "recorded";
    let mut description = String::new();
    if matches!(
        raw.action.as_str(),
        "mcp_github" | "mcp_github_denied" | "mcp_zoomkey" | "mcp_zoomkey_denied"
    ) {
        let github = raw.action.starts_with("mcp_github");
        let keys: &[&str] = if github {
            &[
                "operation",
                "decision",
                "reason",
                "repo",
                "path",
                "ref",
                "status",
                "count",
                "credential",
            ]
        } else {
            &[
                "operation",
                "decision",
                "reason",
                "endpoint",
                "detail",
                "status",
                "count",
                "credential",
            ]
        };
        if let Some(v) = structured(&raw.detail, keys) {
            let expected = if raw.action.ends_with("_denied") {
                "deny"
            } else {
                "allow"
            };
            if v[1] == expected {
                result = match (v[1], v[2]) {
                    ("allow", "ok") => "success",
                    ("deny", "denied") => "denied",
                    ("deny", "network") => "network",
                    ("deny", "remote_http" | "github_http") => "remote_http",
                    ("deny", "remote_api") => "remote_api",
                    ("deny", "validation") => "validation",
                    ("deny", "disabled") => "disabled",
                    ("deny", _) => "failure",
                    _ => "recorded",
                };
            }
            description = format!("操作：{}", label(TOOLS, v[0]).unwrap_or(v[0]));
            let fields: &[&str] = if github {
                &["仓库", "路径", "引用", "HTTP 状态", "结果数量", "凭据指纹"]
            } else {
                &["服务", "详情", "HTTP 状态", "结果数量", "凭据指纹"]
            };
            for (name, value) in fields.iter().zip(&v[3..]) {
                if !value.is_empty() && *value != "-" {
                    description.push_str(&format!("；{name}：{value}"));
                }
            }
        }
    } else {
        let d = raw.detail.as_str();
        if d == "ok"
            && matches!(
                raw.action.as_str(),
                "unlock"
                    | "change_master"
                    | "restore"
                    | "reveal"
                    | "export"
                    | "browser_fill"
                    | "mcp_stop"
                    | "mcp_rotate"
                    | "fill_rotate"
            )
        {
            result = "success";
            description = match raw.action.as_str() {
                "unlock" => "已解锁密码库",
                "browser_fill" => "已向浏览器填充登录信息",
                _ => "操作成功",
            }
            .into();
        } else if raw.action == "unlock" && d == "fail" {
            result = "failure";
            description = "解锁失败".into();
        } else if raw.action == "copy" {
            description = match d {
                "account" => "已复制账号",
                "totp" => "已复制动态验证码",
                "secret" => "已复制密码或密钥",
                _ => "已复制信息（字段见原始记录）",
            }
            .into();
        } else if matches!(raw.action.as_str(), "create" | "update") {
            if let Some((kind, title)) = d.split_once(' ') {
                if let Some(kind) = label(
                    &[
                        ("website", "网站账号"),
                        ("api_token", "API 令牌"),
                        ("ssh", "SSH 密钥"),
                        ("mailbox", "邮箱"),
                        ("mail_auth", "邮箱授权码"),
                        ("server", "服务器"),
                        ("database", "数据库"),
                        ("client_cert", "客户端证书"),
                    ],
                    kind,
                ) {
                    description = format!("类型：{kind}；标题：{title}");
                }
            }
        } else if raw.action == "mcp_zoomkey_test" {
            if matches!(
                d,
                "endpoint=jira decision=allow" | "endpoint=crm decision=allow"
            ) {
                result = "success";
                description = format!(
                    "连通性检查成功；服务：{}",
                    d.strip_prefix("endpoint=")
                        .unwrap()
                        .split_once(' ')
                        .unwrap()
                        .0
                );
            } else if let Some(v) = structured(d, &["endpoint", "decision", "reason", "status"]) {
                if v[1] == "deny" {
                    result = match v[2] {
                        "network" => "network",
                        "remote_http" => "remote_http",
                        "remote_api" => "remote_api",
                        "validation" => "validation",
                        "denied" => "denied",
                        "disabled" => "disabled",
                        _ => "failure",
                    };
                }
                description = format!("服务：{}；HTTP 状态：{}", v[0], v[3]);
            }
        } else {
            description = match (raw.action.as_str(), d) {
                ("delete", "trash") => "已移入回收站".into(),
                ("copy_certificate", "public_pem") => "已复制公开证书".into(),
                ("copy_mcp_token" | "copy_fill_token" | "copy_mcp_snippet", "clipboard") => {
                    "已复制到剪贴板".into()
                }
                ("sync_config", "saved") => "已保存同步配置".into(),
                ("sync_config", "cleared") => "已清除同步配置".into(),
                ("mcp_zoomkey_policy", "on" | "enabled") => "已启用 ZoomKey".into(),
                ("mcp_zoomkey_policy", "off" | "disabled") => "已停用 ZoomKey".into(),
                ("create_folder", _) => format!("文件夹：{d}"),
                ("rename_folder" | "rename_tag", _) => format!("名称变更记录：{d}"),
                ("delete_folder" | "merge_folders", _) => {
                    named_count(d, "moved", "移出条目数").unwrap_or_default()
                }
                ("delete_tag" | "merge_tags", _) => {
                    named_count(d, "links", "关联条目数").unwrap_or_default()
                }
                ("empty_trash", _) => summary(d, &[("purged", "彻底删除数")]).unwrap_or_default(),
                ("import", _) => summary(
                    d,
                    &[
                        ("imported", "导入数"),
                        ("skipped", "跳过数"),
                        ("overwrite", "覆盖已有条目"),
                    ],
                )
                .unwrap_or_default(),
                ("sync_apply", _) => summary(d, &[("entries", "应用条目数")]).unwrap_or_default(),
                ("sync", _) => summary(
                    d,
                    &[
                        ("pulled", "拉取数"),
                        ("pushed", "推送数"),
                        ("unchanged", "未变更数"),
                        ("removed", "移除数"),
                        ("conflicts", "冲突数"),
                    ],
                )
                .unwrap_or_default(),
                ("import_csv", _) => structured(
                    d,
                    &["format", "inserted", "updated", "skipped", "overwrite"],
                )
                .and_then(|v| {
                    summary(
                        &format!(
                            "inserted={} updated={} skipped={} overwrite={}",
                            v[1], v[2], v[3], v[4]
                        ),
                        &[
                            ("inserted", "新增数"),
                            ("updated", "更新数"),
                            ("skipped", "跳过数"),
                            ("overwrite", "覆盖已有条目"),
                        ],
                    )
                    .map(|s| format!("格式：{}；{s}", v[0]))
                })
                .unwrap_or_default(),
                ("mcp_start", _) => d
                    .strip_prefix("port=")
                    .filter(|s| s.parse::<u16>().is_ok())
                    .map(|s| format!("服务端口：{s}"))
                    .unwrap_or_default(),
                ("fill_pair_open", _) => d
                    .strip_prefix("secs=")
                    .filter(|s| s.parse::<u64>().is_ok())
                    .map(|s| format!("配对有效期：{s} 秒"))
                    .unwrap_or_default(),
                _ => String::new(),
            };
        }
    }
    if description.is_empty() {
        description = "已记录操作，详情请查看原始记录".into();
    }
    AuditDisplay {
        raw,
        operation,
        result: result.into(),
        result_label: label(RESULTS, result).unwrap().into(),
        description,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(action: &str, detail: &str) -> AuditDisplay {
        format_event(AuditEvent {
            id: "1".into(),
            at: "".into(),
            action: action.into(),
            detail: detail.into(),
            entry_id: None,
        })
    }
    #[test]
    fn conservative_results_and_free_text() {
        assert_eq!(event("unknown", "ok").result, "recorded");
        assert_eq!(
            event("create_folder", "reason=network ok").result,
            "recorded"
        );
        assert_eq!(event("unlock", "fail").description, "解锁失败");
        assert_eq!(event("copy", "secret").result, "recorded");
        assert!(event("update", "website title -> name key=value")
            .description
            .ends_with("title -> name key=value"));
        for (reason, expected) in [
            ("denied", "denied"),
            ("network", "network"),
            ("error", "failure"),
            ("validation", "validation"),
            ("remote_http", "remote_http"),
            ("remote_api", "remote_api"),
            ("disabled", "disabled"),
        ] {
            let d = format!("operation=github_git decision=deny reason={reason} repo=a/b path=C:/has spaces ref=main status=- count=- credential=");
            let e = event("mcp_github_denied", &d);
            assert_eq!(e.result, expected);
            assert!(e.description.contains("Git 操作"));
            assert!(e.description.contains("C:/has spaces"));
            assert!(!e.description.contains("用户拒绝"));
        }
        assert_eq!(
            event(
                "mcp_github_denied",
                "operation=bad decision=allow reason=ok"
            )
            .result,
            "recorded"
        );
        assert_eq!(event("mcp_github_denied", "operation=github_repo_get decision=deny reason=github_http repo=a/b path=- ref=- status=403 count=- credential=").result, "remote_http");
        assert_eq!(
            event("mcp_zoomkey_test", "endpoint=crm decision=allow").description,
            "连通性检查成功；服务：crm"
        );
        assert_eq!(
            event(
                "sync",
                "pulled=1 pushed=2 unchanged=3 removed=4 conflicts=5"
            )
            .description,
            "拉取数：1；推送数：2；未变更数：3；移除数：4；冲突数：5"
        );
        assert_eq!(
            event("import", "imported=2 skipped=1 overwrite=false").description,
            "导入数：2；跳过数：1；覆盖已有条目：否"
        );
        assert_eq!(
            event("merge_tags", "a links=not a count -> b links=2").description,
            "名称记录：a links=not a count -> b；关联条目数：2"
        );
        assert_eq!(
            event("empty_trash", "purged=not-a-number").description,
            "已记录操作，详情请查看原始记录"
        );
    }
}
