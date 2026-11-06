//! Secret-free MCP discovery. A profile is a recipe, never a transport override.
use crate::session::Session;
use crate::vault::{EntryKind, ListFilter, SecretPayload};
use serde_json::{json, Value};
use zeroize::{Zeroize, Zeroizing};

pub const TOOL_NAMES: &[&str] = &["vault_list", "vault_describe", "http_call", "git", "mail", "vault_revoke"];

pub fn tool_definitions() -> Vec<Value> {
    vec![
        definition("vault_list", "列出凭据 ID、标题、类型、服务、固定 origin 与已登记操作名，不含秘密、备注、Token。先调用此工具，再 vault_describe 查看该凭据说明书。", json!({
            "type":"object", "properties": {
                "query":{"type":"string","maxLength":100,"description":"可选：仅搜索公开元数据"},
                "kind":{"type":"string","enum":["website","api_token","ssh","mailbox","mail_auth","server","database","client_cert"]},
                "limit":{"type":"integer","minimum":1,"maximum":100,"description":"默认 50"},
                "offset":{"type":"integer","minimum":0,"maximum":100000,"description":"默认 0"}
            }, "additionalProperties":false
        }), true, "low"),
        definition("vault_describe", "读取一条凭据的操作说明书：固定 origin、操作名、方法、路径模板、参数白名单、风险。不会注册新工具，也不返回认证材料。", json!({
            "type":"object", "properties":{"credential_id":{"type":"string","minLength":1,"maxLength":128}},
            "required":["credential_id"],"additionalProperties":false
        }), true, "low"),
        definition("http_call", "唯一远程 HTTP 入口。使用 vault_describe 声明的凭据 ID、操作名和参数；不能自行传 URL、方法、请求头或认证。写操作需 Sealbox 桌面逐次确认。", json!({
            "type":"object", "properties":{
                "credential_id":{"type":"string","minLength":1,"maxLength":128},
                "op":{"type":"string","minLength":1,"maxLength":64},
                "params":{"type":"object","properties":{},"additionalProperties":true,"description":"仅填写 vault_describe 为该操作声明的参数；服务端按该操作封闭 schema 校验"}
            }, "required":["credential_id","op","params"],"additionalProperties":false
        }), false, "high"),
        definition("vault_revoke", "吊销当前 MCP 调用会话尚未使用的授权，并使该会话与待审批操作失效。不影响其他会话或浏览器填表；继续使用需重新初始化会话。", json!({
            "type":"object","properties":{},"additionalProperties":false
        }), false, "low"),
    ]
}

fn definition(name:&str, description:&str, schema:Value, read_only:bool, risk:&str)->Value {
    json!({"name":name,"description":description,"inputSchema":schema,"readOnly":read_only,"risk":risk,
        "annotations":crate::github_mcp::annotations(read_only,!read_only)})
}

pub fn validate_tool(name:&str,args:&Value)->Result<(),String> {
    let definition = tool_definitions().into_iter().find(|tool| tool["name"] == name)
        .ok_or_else(|| "未知凭据工具".to_string())?;
    crate::github_mcp::validate_tool_arguments(&definition["inputSchema"],args)
}

/// Authorization is checked when calling, never by changing tools/list.
pub fn require_enabled(session:&Session)->Result<(),String> {
    let vault=session.vault().map_err(|e|e.to_string())?;
    let dek=session.dek().map_err(|e|e.to_string())?;
    if !crate::zoomkey::mcp_enabled(vault,dek) {
        return Err("MCP 未启用。请先在 Sealbox 的 MCP 页面打开。".into());
    }
    Ok(())
}

pub fn list(session:&Session,args:&Value)->Result<String,String> {
    validate_tool("vault_list",args)?;
    let vault=session.vault().map_err(|e|e.to_string())?;
    let dek=session.dek().map_err(|e|e.to_string())?;
    let kind=args.get("kind").and_then(Value::as_str).map(EntryKind::parse).transpose().map_err(|e|e.to_string())?;
    let query=args.get("query").and_then(Value::as_str).unwrap_or("").to_lowercase();
    let limit=args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
    let offset=args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
    let entries=vault.list_entries(&ListFilter {kind,sort:crate::vault::SortBy::Title,..Default::default()}).map_err(|e|e.to_string())?;
    let mut all=Vec::new();
    for entry in entries {
        let mut payload=vault.get_active_secret(dek,&entry.id).map_err(|_|"凭据不可用".to_string())?;
        let secrets=Zeroizing::new(crate::redact::secrets_from_payload(&payload));
        let service=match &payload {
            SecretPayload::ApiToken{service,..}=>service.clone(),
            SecretPayload::MailAuth{provider,..}=>provider.clone(),
            SecretPayload::Server{protocol,..}=>protocol.clone(),
            SecretPayload::Database{engine,..}=>engine.clone(),
            _=>entry.kind.as_str().to_string(),
        };
        payload.zeroize();
        let profile=crate::http_profiles::effective_profile(session,&entry.id)?;
        let service=profile.as_ref().map(|p|p.service.as_str()).unwrap_or(&service);
        let origin=profile.as_ref().map(|p|p.origin.as_str());
        if !query.is_empty() && !format!("{} {} {} {}",entry.title,entry.kind.as_str(),service,origin.unwrap_or("")).to_lowercase().contains(&query) {continue;}
        let row=json!({"id":entry.id,"title":entry.title,"kind":entry.kind,"service":service,
            "origin":origin,"operations":profile.as_ref().map(|p|p.operations.iter().map(|op|op.name.clone()).collect::<Vec<_>>()).unwrap_or_default()});
        all.push(redact_value(row,&secrets));
    }
    let count=all.len();
    let credentials=all.into_iter().skip(offset).take(limit).collect::<Vec<_>>();
    serde_json::to_string(&json!({"credentials":credentials,"count":count,"offset":offset,"has_more":offset+limit<count})).map_err(|_|"无法编码元数据".into())
}

pub fn describe(session:&Session,args:&Value)->Result<String,String> {
    validate_tool("vault_describe",args)?;
    let id=args["credential_id"].as_str().ok_or("缺少凭据 ID")?;
    let vault=session.vault().map_err(|e|e.to_string())?;
    let dek=session.dek().map_err(|e|e.to_string())?;
    let mut payload=vault.get_active_secret(dek,id).map_err(|_|"凭据不存在或已在回收站".to_string())?;
    let secrets=Zeroizing::new(crate::redact::secrets_from_payload(&payload));
    payload.zeroize();
    let profile=crate::http_profiles::effective_profile(session,id)?;
    let value=if let Some(p)=profile {
        let ops=p.operations.iter().map(|op| json!({"name":op.name,"description":op.description,
            "method":op.method,"path_template":op.path_template,"params":op.params,
            "query_params":op.query_params,"body_params":op.body_params,"risk":op.risk,
            "read_only":op.read_only,"confirmation_required":!op.read_only || !matches!(op.method.as_str(),"GET"|"HEAD"|"OPTIONS")})).collect::<Vec<_>>();
        json!({"credential_id":id,"service":p.service,"origin":p.origin,"auth":p.auth.kind,
            "allowed_methods":p.allowed_methods,"allowed_path_prefixes":p.allowed_path_prefixes,"operations":ops})
    } else {
        json!({"credential_id":id,"origin":null,"operations":[],"message":"该凭据没有 HTTP profile。请在 Sealbox 凭据详情中登记操作；不能请求任意 URL。"})
    };
    serde_json::to_string(&redact_value(value,&secrets)).map_err(|_|"无法编码说明书".into())
}

pub fn redact_value(value:Value,secrets:&[String])->Value {
    fn scrub(value:Value,secrets:&[String])->Value {
        match value {
            Value::String(mut text)=>{
                // redact_text deliberately ignores short secrets for ordinary logs; tool results must not.
                for secret in secrets.iter().filter(|secret|!secret.is_empty()) {text=text.replace(secret,"[REDACTED]");}
                Value::String(crate::redact::redact_text(&text,&[]))
            },
            Value::Array(items)=>Value::Array(items.into_iter().map(|v|scrub(v,secrets)).collect()),
            Value::Object(map)=>Value::Object(map.into_iter().map(|(k,v)|(k,scrub(v,secrets))).collect()),
            other=>other
        }
    }
    scrub(value,secrets)
}
