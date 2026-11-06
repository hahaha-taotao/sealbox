//! Credential-scoped adapters. Platform operation names are data in a profile,
//! never a second MCP tool surface. Generic recipes use the `http` adapter.
use crate::confirm::{ConfirmField, ConfirmPayload};
use crate::session::Session;
use crate::vault::SecretPayload;
use sealbox_core::profile::{
    validate_operation_params, validate_profile, CredentialProfile, ProfileAuth, ProfileOperation,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// A saved profile wins, including an intentionally empty operation menu.
pub fn effective_profile(
    session: &Session,
    credential_id: &str,
) -> Result<Option<CredentialProfile>, String> {
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    if let Some(profile) = vault.credential_profile(dek, credential_id).map_err(|e| e.to_string())? {
        validate_profile(&profile)?;
        return Ok(Some(profile));
    }
    builtin_profile(session, credential_id)
}

/// Ignores a saved profile so the UI can preview/reset the built-in recipe.
/// Legacy ZoomKey settings are consulted only when migrating their selected ID.
pub fn builtin_profile(
    session: &Session,
    credential_id: &str,
) -> Result<Option<CredentialProfile>, String> {
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    let payload = vault.get_active_secret(dek, credential_id).map_err(|e| e.to_string())?;
    let SecretPayload::ApiToken { service, .. } = payload else { return Ok(None); };
    let service = service.trim().to_ascii_lowercase();
    let profile = match service.as_str() {
        "github" => github_profile(),
        crate::zoomkey::JIRA_SERVICE | crate::zoomkey::CRM_SERVICE => {
            let policy = crate::zoomkey::load_policy(vault, dek);
            let endpoint = if service == crate::zoomkey::JIRA_SERVICE { &policy.jira } else { &policy.crm };
            if endpoint.credential_id != credential_id || endpoint.client_cert_id.is_empty()
                || endpoint.ca_bundle_path.is_empty() {
                return Ok(None);
            }
            let (origin, path) = split_endpoint(&endpoint.base_url)?;
            if (service == crate::zoomkey::JIRA_SERVICE && path != "/" && !path.is_empty())
                || (service == crate::zoomkey::CRM_SERVICE && path != "/webservice.php") {
                return Err("内置 ZoomKey profile 只支持站点根地址及固定 /webservice.php".into());
            }
            zoomkey_profile(
                &service, &origin, &endpoint.client_cert_id, &endpoint.ca_bundle_path,
            )
        }
        _ => return Ok(None),
    };
    validate_profile(&profile)?;
    Ok(Some(profile))
}

fn split_endpoint(url: &str) -> Result<(String, String), String> {
    // URL syntax and the eventual DNS/IP policy are independently validated.
    crate::http_guard::parse_http_url(url, true)?;
    let authority = url.strip_prefix("https://").ok_or("ZoomKey 只允许 HTTPS")?;
    if authority.contains(['?', '#']) { return Err("ZoomKey 地址不能包含查询或片段".into()); }
    let (authority, path) = authority.split_once('/').unwrap_or((authority, ""));
    Ok((format!("https://{authority}"), if path.is_empty() { "/".into() } else { format!("/{path}") }))
}

fn auth(kind: &str) -> ProfileAuth {
    ProfileAuth {
        kind: kind.into(), header_name: None, prefix: None,
        client_cert_id: None, ca_bundle_path: None,
    }
}

fn github_profile() -> CredentialProfile {
    CredentialProfile {
        version: 1, adapter: "github".into(), service: "github".into(),
        origin: "https://api.github.com".into(), auth: auth("bearer"),
        allowed_methods: strings(&["GET", "POST", "PATCH", "PUT"]),
        allowed_path_prefixes: strings(&["/user", "/repos"]),
        operations: github_operations(),
    }
}

fn strings(values: &[&str]) -> Vec<String> { values.iter().map(|value| (*value).into()).collect() }

fn github_operations() -> Vec<ProfileOperation> {
    let mut operations = Vec::new();
    for definition in crate::github_mcp::api_tool_definitions() {
        let Some(internal_name) = definition["name"].as_str() else { continue; };
        let Some(name) = internal_name.strip_prefix("github_") else { continue; };
        if name == "list_credentials" { continue; } // vault_list is the only discovery API.
        let mut params = definition["inputSchema"].clone();
        if let Some(properties) = params.get_mut("properties").and_then(Value::as_object_mut) {
            properties.remove("credential");
            properties.remove("credential_id");
        }
        params["additionalProperties"] = Value::Bool(false);
        let (method, path, query, body): (&str, &str, &[&str], &[&str]) = match name {
            "user_info" => ("GET", "/user", &[], &[]),
            "repo_list" => ("GET", "/user/repos", &["type", "visibility", "affiliation", "sort", "direction", "page", "per_page"], &[]),
            "repo_get" => ("GET", "/repos/{repo}", &[], &[]),
            "issues_list" => ("GET", "/repos/{repo}/issues", &["state", "labels", "assignee", "creator", "since", "sort", "direction", "page", "per_page"], &[]),
            "issues_get" => ("GET", "/repos/{repo}/issues/{number}", &[], &[]),
            "issue_close" => ("PATCH", "/repos/{repo}/issues/{number}", &[], &[]),
            "pulls_list" => ("GET", "/repos/{repo}/pulls", &["state", "page", "per_page"], &[]),
            "get_pull_request" => ("GET", "/repos/{repo}/pulls/{number}", &[], &[]),
            "release_list" => ("GET", "/repos/{repo}/releases", &["page", "per_page"], &[]),
            "release_get" => ("GET", "/repos/{repo}/releases/{id}", &[], &[]),
            "issue_create" => ("POST", "/repos/{repo}/issues", &[], &["title", "body", "labels"]),
            "issue_comment" => ("POST", "/repos/{repo}/issues/{number}/comments", &[], &["body"]),
            "pr_create" => ("POST", "/repos/{repo}/pulls", &[], &["title", "head", "base", "body", "draft"]),
            "pr_merge" => ("PUT", "/repos/{repo}/pulls/{number}/merge", &[], &["merge_method"]),
            "release_generate_notes" => ("POST", "/repos/{repo}/releases/generate-notes", &[], &["tag_name", "previous_tag_name", "target_commitish"]),
            "release_publish" => ("PATCH", "/repos/{repo}/releases/{id}", &[], &["name", "body", "prerelease"]),
            "release_create" => ("POST", "/repos/{repo}/releases", &[], &["tag_name", "target_commitish", "name", "body", "draft", "prerelease", "generate_release_notes", "make_latest"]),
            _ => continue,
        };
        let read_only = method == "GET";
        let mut operation = ProfileOperation {
            name: name.into(),
            description: definition["description"].as_str().unwrap_or("").into(),
            method: method.into(), path_template: path.into(), params,
            query_params: strings(query), body_params: strings(body),
            fixed_query: BTreeMap::new(), fixed_body: BTreeMap::new(),
            risk: if read_only || name == "release_generate_notes" { "low" } else { "high" }.into(),
            read_only,
        };
        operation.description.push_str(" 仅向 api.github.com 发送请求；沿用裁剪后的 DTO、响应限额与脱敏。repo 为 owner/repo（owner 仅为兼容拆分填写）；凭据由 http_call 的 credential_id 固定选择。");
        match name {
            "repo_list" => operation.description.push_str(" name_contains 仅在本地过滤 full_name，不作为远程查询参数。"),
            "issue_create" => operation.description.push_str(" labels 是逗号分隔字符串，适配器转换为标签数组。"),
            "issue_close" => {
                operation.fixed_body.insert("state".into(), json!("closed"));
                operation.description.push_str(" 先 GET 同一路径确认不是 PR，再经本机确认 PATCH state=closed；两次请求都受 profile 方法/路径约束。");
            }
            "release_publish" => { operation.fixed_body.insert("draft".into(), json!(false)); }
            "release_generate_notes" => operation.description.push_str(" 此 POST 不创建资源；profile 仍按非只读方法要求本机确认。"),
            "release_get" => {
                operation.params["properties"].as_object_mut().unwrap().remove("tag_name");
                operation.params["required"] = json!(["repo", "id"]);
                operation.description = "按 release id 读取版本元数据（含草稿，不含 body/资产二进制）；按标签请用 release_get_by_tag。仅访问 api.github.com，沿用 DTO 裁剪及脱敏。".into();
            }
            _ => {}
        }
        operations.push(operation);
    }
    if let Some(by_id) = operations.iter().find(|operation| operation.name == "release_get").cloned() {
        let mut by_tag = by_id;
        by_tag.name = "release_get_by_tag".into();
        by_tag.description = "按 tag_name 读取已发布版本元数据（不含正文与资产），GET /repos/{repo}/releases/tags/{tag_name}；草稿请使用 release_list / release_get。".into();
        by_tag.path_template = "/repos/{repo}/releases/tags/{tag_name}".into();
        by_tag.params["properties"].as_object_mut().unwrap().remove("id");
        by_tag.params["properties"]["tag_name"] = json!({"type":"string","minLength":1,"maxLength":200});
        by_tag.params["required"] = json!(["repo", "tag_name"]);
        operations.push(by_tag);
    }
    operations
}

fn zoomkey_profile(service: &str, origin: &str, cert: &str, ca: &str) -> CredentialProfile {
    let jira = service == crate::zoomkey::JIRA_SERVICE;
    let mut auth = auth(if jira { "basic" } else { "mtls" });
    auth.client_cert_id = Some(cert.into());
    auth.ca_bundle_path = Some(ca.into());
    CredentialProfile {
        version: 1, adapter: if jira { "zoomkey_jira" } else { "zoomkey_crm" }.into(),
        service: service.into(), origin: origin.into(), auth,
        allowed_methods: if jira { strings(&["GET"]) } else { strings(&["GET", "POST"]) },
        allowed_path_prefixes: if jira { strings(&["/rest/api/2"]) } else { strings(&["/webservice.php"]) },
        operations: zoomkey_operations(jira),
    }
}

fn zoomkey_operations(jira: bool) -> Vec<ProfileOperation> {
    let definitions = if jira { crate::zoomkey::jira::tool_definitions() } else { crate::zoomkey::crm::tool_definitions() };
    definitions.into_iter().filter_map(|definition| {
        let prefix = if jira { "zoomkey_jira_" } else { "zoomkey_crm_" };
        let name = definition["name"].as_str()?.strip_prefix(prefix)?;
        let (path, query): (&str, &[&str]) = if jira {
            match name {
                "nav" => ("/rest/api/2/serverInfo", &["maxResults"]),
                "connection_status" => ("/rest/api/2/serverInfo", &[]),
                "list_projects" => ("/rest/api/2/project", &[]),
                "project_statuses" => ("/rest/api/2/project/{project}/statuses", &[]),
                "field_map" => ("/rest/api/2/field", &[]),
                "get_issue" => ("/rest/api/2/issue/{issueKey}", &["fields"]),
                "search_issues" => ("/rest/api/2/search", &["jql", "maxResults", "startAt", "fields"]),
                "my_open_issues" | "project_unfinished" | "preset_unfinished" => ("/rest/api/2/search", &["maxResults", "startAt"]),
                _ => return None,
            }
        } else { ("/webservice.php", &[]) };
        let mut operation = ProfileOperation {
            name: name.into(), description: definition["description"].as_str().unwrap_or("").into(),
            method: "GET".into(), path_template: path.into(), params: definition["inputSchema"].clone(),
            query_params: strings(query), body_params: Vec::new(),
            fixed_query: BTreeMap::new(), fixed_body: BTreeMap::new(),
            risk: "low".into(), read_only: true,
        };
        operation.params["additionalProperties"] = json!(false);
        if jira {
            operation.description.push_str(" 使用所选凭据的 Basic 认证和 profile 指定的客户端证书/CA；所有实际请求均受 profile 方法/路径前缀约束。");
            match name {
                "nav" => operation.description.push_str(" 组合读取 serverInfo、myself、search（我的任务及可选 hsrr 统计），均为 GET；includeHsrr 仅控制额外统计。"),
                "connection_status" => operation.description.push_str(" ping=true 时额外 GET /rest/api/2/myself。"),
                "list_projects" => operation.description.push_str(" query 在本地过滤项目 key/名称。"),
                "field_map" => operation.description.push_str(" section 本地选择静态地图；live=true 时 GET /rest/api/2/field。"),
                "my_open_issues" | "project_unfinished" | "preset_unfinished" => operation.description.push_str(" assignee/project/extraJql/preset 在固定适配器内生成 jql，fields 使用裁剪的默认字段；不开放任意路径或请求体。"),
                _ => {}
            }
        } else {
            let remote_operation = match name {
                "connection_status" => "getchallenge",
                "describe_module" => "describe",
                "field_map" => "describe",
                "retrieve" => "retrieve",
                _ => "query",
            };
            operation.fixed_query.insert("operation".into(), remote_operation.into());
            operation.description.push_str(" 仅访问 profile origin 下固定 /webservice.php；mTLS 使用所选证书/CA，所选凭据账号与 AccessKey 仅在封装的 getchallenge → POST login 中使用；业务接口只读。登录 POST 也受 allowed_methods 约束。不会返回 challenge、sessionName 或 AccessKey。");
            match name {
                "nav" => operation.description.push_str(" 内部生成 Project SELECT；recentProjects/limit 仅控制只读查询结果。"),
                "describe_module" => operation.description.push_str(" 无 elementType 时使用 operation=listtypes，否则 describe。"),
                "field_map" => operation.description.push_str(" 默认只返回静态字段地图；live=true 才 describe 指定 module。"),
                "query" => operation.description.push_str(" sql 经只读 SELECT 校验后转换为 query 参数，拒绝其他语句。"),
                "retrieve" => operation.description.push_str(" id 作为固定 retrieve 的记录 ID 参数。"),
                _ => operation.description.push_str(" 具名过滤参数在适配器中转为经过转义的固定模块 SELECT，再裁剪 DTO；不接受任意 body/path。"),
            }
        }
        Some(operation)
    }).collect()
}

enum BuiltinExecution {
    Github {
        call: crate::github_mcp::PreparedGithubCall,
        methods: Vec<String>, paths: Vec<String>,
    },
    Zoomkey {
        runtime: crate::zoomkey::EndpointRuntime,
        jira: bool, name: String, params: Value,
    },
}

/// The MCP handler prepares under the Session mutex, releases it to ask the user,
/// rechecks lock/revocation/profile revision, then executes after approval.
/// No Vault/Session reference survives preparation.
pub struct PreparedBuiltinCall {
    pub confirmation: Option<ConfirmPayload>,
    inner: BuiltinExecution,
}

impl PreparedBuiltinCall {
    /// Safe standalone wrapper: never silently skips required desktop approval.
    pub fn execute(self) -> Result<String, String> {
        let allowed = self.confirmation.as_ref().map(crate::confirm::ask_payload).unwrap_or(true);
        self.execute_after_confirmation(allowed)
    }

    /// `allowed=true` is an explicit caller attestation that this exact payload
    /// was approved and caller/session/profile revocation checks ran afterwards.
    /// Only the owned prepared call is executed; no user input can replace it.
    pub fn execute_after_confirmation(self, allowed: bool) -> Result<String, String> {
        self.execute_with_status_after_confirmation(allowed).map(|(_, text)| text)
    }

    /// Same approval contract, retaining the real HTTP status for the audit log.
    pub fn execute_with_status_after_confirmation(self, allowed: bool) -> Result<(u16, String), String> {
        if !allowed { return Err("用户拒绝了这次 HTTP 操作".into()); }
        match self.inner {
            BuiltinExecution::Github { call, methods, paths } => {
                crate::github_api::with_profile_limits(&methods, &paths, || {
                    // Legacy direct calls still ask independently. The prepared
                    // profile path has already been approved at its outer gate.
                    crate::confirm::with_auto(Some(true), || call.execute())
                })
            }
            BuiltinExecution::Zoomkey { runtime, jira, name, params } => {
                let result = if jira {
                    crate::zoomkey::jira::call_with_runtime(&runtime, &name, &params)
                } else {
                    crate::zoomkey::crm::call_with_runtime(&runtime, &name, &params)
                };
                result.map(|outcome| (200, crate::redact::redact_text(&outcome.text, &[runtime.secret.as_str()])))
                    .map_err(|error| crate::redact::redact_text(&error.message, &[runtime.secret.as_str()]))
            }
        }
    }
}

pub fn prepare_builtin(
    session: &Session,
    credential_id: &str,
    profile: &CredentialProfile,
    op: &str,
    params: Value,
) -> Option<Result<PreparedBuiltinCall, String>> {
    if profile.adapter == "http" { return None; }
    Some(prepare_builtin_inner(session, credential_id, profile, op, params))
}

fn prepare_builtin_inner(
    session: &Session,
    credential_id: &str,
    profile: &CredentialProfile,
    op: &str,
    mut params: Value,
) -> Result<PreparedBuiltinCall, String> {
    validate_profile(profile)?;
    let selected = profile.operations.iter().find(|operation| operation.name == op)
        .ok_or("所选 profile 未登记该操作；请先调用 vault_describe")?;
    let jira = profile.adapter == "zoomkey_jira";
    let baseline = match profile.adapter.as_str() {
        "github" => github_operations(),
        "zoomkey_jira" | "zoomkey_crm" => zoomkey_operations(jira),
        _ => return Err("未知内置 adapter；自定义操作请使用 http adapter".into()),
    };
    let baseline = baseline.iter().find(|operation| operation.name == op)
        .ok_or("内置 adapter 不支持该操作；自定义操作请使用 http adapter")?;
    // A native adapter cannot silently ignore edited routes/fixed envelopes.
    // Retain the protocol binding; user schemas and global limits may tighten it.
    if selected.method != baseline.method || selected.path_template != baseline.path_template
        || selected.query_params != baseline.query_params || selected.body_params != baseline.body_params
        || selected.fixed_query != baseline.fixed_query || selected.fixed_body != baseline.fixed_body
        || (selected.read_only && !baseline.read_only)
        || risk_level(&selected.risk) < risk_level(&baseline.risk) {
        return Err("内置操作的方法、路径、参数路由及最低风险不可更改；自定义请求请使用 http adapter".into());
    }
    apply_defaults(&selected.params, &mut params);
    validate_operation_params(selected, &params)?;
    validate_operation_params(baseline, &params)?;
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    if !crate::zoomkey::mcp_enabled(vault, dek) {
        return Err("MCP 未启用。请先在 Sealbox 的 MCP 页面打开。".into());
    }
    let payload = vault.get_active_secret(dek, credential_id).map_err(|e| e.to_string())?;
    let SecretPayload::ApiToken { service, token, .. } = payload else {
        return Err("内置 profile 必须绑定 API Token 凭据".into());
    };
    let service = service.trim();
    let expected_service = match profile.adapter.as_str() {
        "github" => "github", "zoomkey_jira" => crate::zoomkey::JIRA_SERVICE,
        "zoomkey_crm" => crate::zoomkey::CRM_SERVICE, _ => unreachable!(),
    };
    if !service.eq_ignore_ascii_case(expected_service) || !profile.service.eq_ignore_ascii_case(expected_service) {
        return Err("所选凭据服务与内置 adapter/profile 不匹配".into());
    }
    let auth_kind = if profile.adapter == "github" { "bearer" } else if jira { "basic" } else { "mtls" };
    if profile.auth.kind != auth_kind {
        return Err("内置 profile 的认证类型与固定协议不匹配".into());
    }
    if profile.adapter == "github" &&
        (profile.auth.client_cert_id.is_some() || profile.auth.ca_bundle_path.is_some()) {
        return Err("内置 GitHub adapter 不使用客户端证书；自定义通道请使用 http adapter".into());
    }
    let confirmation = if !selected.read_only {
        let title = vault.list_entries(&crate::vault::ListFilter::default()).map_err(|e| e.to_string())?
            .into_iter().find(|entry| entry.id == credential_id).ok_or("所选凭据不存在")?.title;
        let summary = serde_json::to_string_pretty(&params).map_err(|e| e.to_string())?;
        let summary = crate::redact::redact_text(&summary, &[token.as_str()]);
        Some(ConfirmPayload {
            title: "允许凭据 HTTP 操作？".into(),
            prompt: format!("{}（风险：{}）", selected.description, selected.risk),
            fields: vec![
                ConfirmField { label: "凭据".into(), value: title },
                ConfirmField { label: "固定目标".into(), value: profile.origin.clone() },
                ConfirmField { label: "操作".into(), value: format!("{} {} {}", selected.name, selected.method, selected.path_template) },
                ConfirmField { label: "参数".into(), value: summary },
            ],
        })
    } else { None };
    let inner = if profile.adapter == "github" {
        let name = if op == "release_get_by_tag" { "github_release_get".to_string() } else { format!("github_{op}") };
        BuiltinExecution::Github {
            call: crate::github_mcp::prepare_profile_call(session, credential_id, &name, params)?,
            methods: profile.allowed_methods.clone(), paths: profile.allowed_path_prefixes.clone(),
        }
    } else {
        let runtime = crate::zoomkey::build_profile_runtime(session, credential_id, profile)
            .map_err(|error| error.message)?;
        BuiltinExecution::Zoomkey {
            runtime, jira, name: format!("zoomkey_{}_{op}", if jira { "jira" } else { "crm" }), params,
        }
    };
    Ok(PreparedBuiltinCall { confirmation, inner })
}

fn risk_level(risk: &str) -> u8 { match risk { "high" => 2, "medium" => 1, _ => 0 } }

fn apply_defaults(schema: &Value, value: &mut Value) {
    if let (Some(properties), Some(object)) = (schema.get("properties").and_then(Value::as_object), value.as_object_mut()) {
        for (name, child) in properties {
            if !object.contains_key(name) {
                if let Some(default) = child.get("default") { object.insert(name.clone(), default.clone()); }
            }
            if let Some(value) = object.get_mut(name) { apply_defaults(child, value); }
        }
    }
}

/// `None` means only the generic HTTP adapter should handle this recipe.
/// Unknown/restricted built-in operations are always an explicit error.
pub fn call_builtin(
    session: &mut Session,
    credential_id: &str,
    profile: &CredentialProfile,
    op: &str,
    params: Value,
) -> Option<Result<String, String>> {
    prepare_builtin(session, credential_id, profile, op, params).map(|prepared| {
        let result = prepared.and_then(PreparedBuiltinCall::execute);
        if result.is_ok() { session.touch(); }
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{EntryKind, UpsertEntry, Vault};

    fn add_token(vault: &Vault, dek: &[u8; 32], service: &str, title: &str, token: &str) -> String {
        vault.upsert_entry(dek, UpsertEntry {
            id: None, kind: EntryKind::ApiToken, title: title.into(),
            account: Some("octocat".into()), url: None, folder_id: None,
            tags: Vec::new(), pinned: false, expires_at: None, notes: None,
            secret: SecretPayload::ApiToken {
                service: service.into(), account: Some("octocat".into()), token: token.into(),
            },
        }).unwrap().id
    }

    fn github_session() -> (Session, String) {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let id = add_token(&vault, &dek, "github", "selected", "ghp_selected_secret");
        add_token(&vault, &dek, "github", "other", "ghp_other_secret");
        crate::zoomkey::save_policy(&vault, &dek, &crate::zoomkey::ZoomkeyMcpPolicy {
            enabled: true, ..Default::default()
        }).unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        (session, id)
    }

    #[test]
    fn all_builtin_profiles_are_valid_and_closed() {
        let profiles = [
            github_profile(),
            zoomkey_profile(crate::zoomkey::JIRA_SERVICE, "https://jira.zoomkey.com.cn", "cert-id", "/local/ca.pem"),
            zoomkey_profile(crate::zoomkey::CRM_SERVICE, "https://crm.zoomkey.com.cn", "cert-id", "/local/ca.pem"),
        ];
        assert_eq!(profiles[0].operations.len(), crate::github_mcp::api_tool_definitions().len());
        assert_eq!(profiles[1].operations.len(), 10);
        assert_eq!(profiles[2].operations.len(), 10);
        for profile in profiles {
            validate_profile(&profile).unwrap_or_else(|error| panic!("{}: {error}", profile.adapter));
            for operation in profile.operations {
                assert!(!operation.name.starts_with("github_"));
                assert!(!operation.name.starts_with("zoomkey_"));
                assert_eq!(operation.params["additionalProperties"], false);
                let properties = operation.params["properties"].as_object().unwrap();
                assert!(!properties.contains_key("credential"));
                assert!(!properties.contains_key("credential_id"));
                assert!(!operation.description.is_empty());
            }
        }
    }

    #[test]
    fn builtin_coverage_contains_every_remote_github_implementation() {
        let operations = github_operations();
        for definition in crate::github_mcp::api_tool_definitions() {
            let name = definition["name"].as_str().unwrap();
            if name != "github_list_credentials" {
                assert!(operations.iter().any(|op| op.name == name.strip_prefix("github_").unwrap()), "{name}");
            }
        }
        let by_id = operations.iter().find(|op| op.name == "release_get").unwrap();
        assert_eq!(by_id.params["required"], json!(["repo", "id"]));
        let by_tag = operations.iter().find(|op| op.name == "release_get_by_tag").unwrap();
        assert_eq!(by_tag.params["required"], json!(["repo", "tag_name"]));
    }

    #[test]
    fn selected_credential_is_exact_and_dto_is_still_redacted() {
        let (session, id) = github_session();
        let probe = crate::github_api::TransportProbe::install(|call| {
            assert_eq!(call.authorization, "Bearer ghp_selected_secret");
            assert_eq!(call.url, "https://api.github.com/user");
            Ok(crate::github_api::HttpReply { status: 200, body: serde_json::to_vec(&json!({
                "id": 1, "login": "octocat", "name": "ghp_selected_secret",
                "token": "ghp_selected_secret", "unregistered": "not exposed",
            })).unwrap() })
        });
        let prepared = prepare_builtin(&session, &id, &github_profile(), "user_info", json!({})).unwrap().unwrap();
        assert!(prepared.confirmation.is_none());
        let (status, text) = prepared.execute_with_status_after_confirmation(true).unwrap();
        assert_eq!(status, 200);
        assert!(text.contains("octocat"));
        assert!(!text.contains("ghp_selected_secret"));
        assert!(!text.contains("unregistered"));
        assert_eq!(probe.calls().len(), 1);
        for key in ["credential", "credential_id", "credential_name"] {
            assert!(prepare_builtin(&session, &id, &github_profile(), "user_info", json!({(key): "other"})).unwrap().is_err());
        }
        assert_eq!(probe.calls().len(), 1);
    }

    #[test]
    fn removed_or_unknown_builtin_operations_never_fall_back_to_http() {
        let (session, id) = github_session();
        let mut profile = github_profile();
        profile.operations.retain(|operation| operation.name != "user_info");
        assert!(prepare_builtin(&session, &id, &profile, "user_info", json!({})).unwrap().is_err());
        profile.operations[0].name = "arbitrary_dispatch".into();
        assert!(prepare_builtin(&session, &id, &profile, "arbitrary_dispatch", json!({})).unwrap().is_err());
        profile.adapter = "http".into();
        assert!(prepare_builtin(&session, &id, &profile, "arbitrary_dispatch", json!({})).is_none());
    }

    #[test]
    fn edited_builtin_schema_is_enforced_but_cannot_relax_baseline() {
        let (session, id) = github_session();
        let mut profile = github_profile();
        let operation = profile.operations.iter_mut().find(|operation| operation.name == "repo_list").unwrap();
        operation.params["properties"]["per_page"]["maximum"] = json!(2);
        operation.params["properties"]["per_page"]["default"] = json!(2);
        assert!(prepare_builtin(&session, &id, &profile, "repo_list", json!({"per_page":3})).unwrap().is_err());
        let operation = profile.operations.iter_mut().find(|operation| operation.name == "repo_list").unwrap();
        operation.params["properties"]["per_page"]["maximum"] = json!(1000);
        assert!(prepare_builtin(&session, &id, &profile, "repo_list", json!({"per_page":500})).unwrap().is_err());
        let operation = profile.operations.iter_mut().find(|operation| operation.name == "repo_list").unwrap();
        operation.path_template = "/user/other".into();
        assert!(prepare_builtin(&session, &id, &profile, "repo_list", json!({})).unwrap().is_err());
    }

    #[test]
    fn real_prerequisite_requests_obey_profile_methods_before_network() {
        let (session, id) = github_session();
        let mut profile = github_profile();
        profile.operations.retain(|operation| operation.name == "issue_close");
        profile.allowed_methods = strings(&["PATCH"]);
        let probe = crate::github_api::TransportProbe::install(|_| panic!("GET is forbidden"));
        let prepared = prepare_builtin(&session, &id, &profile, "issue_close", json!({"repo":"o/r","number":1})).unwrap().unwrap();
        assert!(prepared.confirmation.is_some());
        let error = prepared.execute_after_confirmation(true).unwrap_err();
        assert!(error.contains("方法"), "{error}");
        assert!(probe.calls().is_empty());
    }

    #[test]
    fn prepared_write_denial_never_sends_and_status_survives_success() {
        let (session, id) = github_session();
        let profile = github_profile();
        let probe = crate::github_api::TransportProbe::install(|call| {
            assert_eq!(call.method, "POST");
            assert_eq!(call.url, "https://api.github.com/repos/o/r/issues");
            Ok(crate::github_api::HttpReply { status: 201, body: br#"{"number":1,"title":"test","state":"open"}"#.to_vec() })
        });
        let prepare = || prepare_builtin(&session, &id, &profile, "issue_create", json!({"repo":"o/r","title":"test"})).unwrap().unwrap();
        assert!(prepare().execute_after_confirmation(false).is_err());
        assert!(probe.calls().is_empty());
        let (status, _) = prepare().execute_with_status_after_confirmation(true).unwrap();
        assert_eq!(status, 201);
        assert_eq!(probe.calls().len(), 1);
    }

    #[test]
    fn unconfigured_services_do_not_gain_a_default_proxy() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let unrelated = add_token(&vault, &dek, "other", "other", "unrelated");
        let jira = add_token(&vault, &dek, crate::zoomkey::JIRA_SERVICE, "jira", "jira-secret");
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        assert!(builtin_profile(&session, &unrelated).unwrap().is_none());
        assert!(builtin_profile(&session, &jira).unwrap().is_none());
    }
}
