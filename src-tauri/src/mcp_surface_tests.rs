use super::*;
use crate::vault::{EntryKind, SecretPayload, UpsertEntry, Vault};

fn session_with_token(enabled: bool, service: &str) -> (Mutex<Session>, String) {
    let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
    vault.set_secret_setting(&dek, "zoomkey_mcp_policy", &format!(r#"{{"enabled":{enabled}}}"#)).unwrap();
    let entry = vault.upsert_entry(&dek, UpsertEntry {
        id: None, kind: EntryKind::ApiToken, title: "work credential".into(), account: Some("octocat".into()),
        url: None, folder_id: None, tags: vec![], pinned: false, expires_at: None,
        notes: Some("PRIVATE NOTE MUST NOT LEAK".into()),
        secret: SecretPayload::ApiToken {service: service.into(), account: Some("octocat".into()), token: "secret-token-123456789".into()},
    }).unwrap();
    let mut session=Session::default(); session.set_unlocked(vault,dek);
    (Mutex::new(session),entry.id)
}
fn rpc(session:&Mutex<Session>,mcp:&McpState,caller:&str,name:&str,args:Value)->Value {
    handle_rpc(session,mcp,JsonRpcReq{jsonrpc:"2.0".into(),id:Some(json!(1)),method:"tools/call".into(),params:json!({"name":name,"arguments":args})},caller).unwrap()["result"].clone()
}
fn operation(session:&Mutex<Session>,id:&str,path:&str,method:&str)->String {
    crate::http_profiles::effective_profile(&lock_session(session),id).unwrap().unwrap().operations.iter()
        .find(|op|op.path_template==path && op.method==method).unwrap_or_else(||panic!("missing {method} {path}" )).name.clone()
}

#[test]
fn catalog_is_exactly_six_tools_and_does_not_follow_lock_switch_or_credentials() {
    let locked=Mutex::new(Session::default());
    let (disabled,_)=session_with_token(false,"github");
    let (enabled,id)=session_with_token(true,"github");
    let expected=tools_list(&locked);
    assert_eq!(expected,tools_list(&disabled)); assert_eq!(expected,tools_list(&enabled));
    let mut names=expected["tools"].as_array().unwrap().iter().map(|tool|tool["name"].as_str().unwrap()).collect::<Vec<_>>();
    names.sort_unstable(); let mut want=crate::credential_mcp::TOOL_NAMES.to_vec(); want.sort_unstable();
    assert_eq!(names,want);
    assert_eq!(names.len(),6);
    assert!(crate::http_profiles::effective_profile(&lock_session(&enabled),&id).unwrap().is_some());
    for tool in expected["tools"].as_array().unwrap() {assert_eq!(tool["inputSchema"]["additionalProperties"],false);}
}

#[test]
fn discovery_omits_secrets_notes_and_internal_transport_configuration() {
    let (session,id)=session_with_token(true,"github");
    let mcp=McpState::default(); let caller=mcp.open_caller().unwrap();
    let result=rpc(&session,&mcp,&caller,"vault_list",json!({}));
    assert_eq!(result["isError"],false,"{result}");
    let rows=result["structuredContent"]["credentials"].as_array().unwrap(); assert_eq!(rows.len(),1);
    assert_eq!(rows[0]["id"],id); assert_eq!(rows[0]["origin"],"https://api.github.com");
    assert!(!rows[0]["operations"].as_array().unwrap().is_empty());
    let described=rpc(&session,&mcp,&caller,"vault_describe",json!({"credential_id":id}));
    assert_eq!(described["isError"],false,"{described}");
    for value in [result,described] {
        let raw=value.to_string();
        for forbidden in ["secret-token-123456789","PRIVATE NOTE MUST NOT LEAK","ca_bundle_path","client_cert_id","secret_blob"] {assert!(!raw.contains(forbidden),"leaked {forbidden}");}
    }
}

#[test]
fn unprofiled_credentials_have_no_http_operations() {
    let (session,id)=session_with_token(true,"new-platform");
    let mcp=McpState::default();let caller=mcp.open_caller().unwrap();
    let described=rpc(&session,&mcp,&caller,"vault_describe",json!({"credential_id":id}));
    assert_eq!(described["structuredContent"]["operations"],json!([]));
    let call=rpc(&session,&mcp,&caller,"http_call",json!({"credential_id":id,"op":"get","params":{}}));
    assert_eq!(call["isError"],true); assert!(call.to_string().contains("profile"));
}

#[test]
fn only_fixed_names_are_callable_no_platform_backdoors() {
    let (session,_)=session_with_token(true,"github");let mcp=McpState::default();let caller=mcp.open_caller().unwrap();
    for name in ["github_user_info","github_git","github_issue","zoomkey_jira_nav","mail_accounts","http_request","copy_secret"] {
        let result=rpc(&session,&mcp,&caller,name,json!({})); assert_eq!(result["isError"],true,"{name}: {result}");
        assert!(result.to_string().contains("未知 MCP 工具"));
    }
}

#[test]
fn calls_require_unlocked_enabled_and_valid_caller() {
    let (disabled,id)=session_with_token(false,"github");let locked=Mutex::new(Session::default());
    let mcp=McpState::default();let caller=mcp.open_caller().unwrap();
    for (session,expected) in [(&disabled,"未启用"),(&locked,"锁定")] {
        for (name,args) in [("vault_list",json!({})),("vault_describe",json!({"credential_id":id})),("http_call",json!({"credential_id":id,"op":"user_info","params":{}})),("git",json!({"action":"status","path":"/tmp"})),("mail",json!({"action":"accounts"}))] {
            let result=rpc(session,&mcp,&caller,name,args);assert_eq!(result["isError"],true);assert!(result.to_string().contains(expected),"{result}");
        }
    }
    let result=rpc(&disabled,&mcp,"unissued","vault_revoke",json!({}));assert_eq!(result["isError"],true);
}

#[test]
fn revocation_is_caller_scoped_invalidates_pending_grants_and_survives_locked_vault() {
    let session=Mutex::new(Session::default());let mcp=McpState::default();
    let alice=mcp.open_caller().unwrap();let bob=mcp.open_caller().unwrap();let pending=mcp.caller_permit(&alice).unwrap();
    let result=rpc(&session,&mcp,&alice,"vault_revoke",json!({}));assert_eq!(result["isError"],false);
    assert_eq!(result["structuredContent"]["scope"],"current_caller");
    assert!(!pending.alive());assert!(mcp.caller_permit(&alice).is_err());assert!(mcp.caller_permit(&bob).is_ok());
    assert_eq!(rpc(&session,&mcp,&alice,"vault_list",json!({}))["isError"],true);
    mcp.invalidate_callers();assert!(mcp.caller_permit(&bob).is_err());
}

#[test]
fn unknown_actions_return_the_legal_action_list() {
    let (session,_)=session_with_token(true,"github");let mcp=McpState::default();let caller=mcp.open_caller().unwrap();
    for (tool,actions) in [("git",vec!["status","diff","log","branches","fetch","pull","commit","push","clone"]),("mail",vec!["accounts","list","read","save"])] {
        let result=rpc(&session,&mcp,&caller,tool,json!({"action":"not-a-real-action","path":"/tmp"}));
        assert_eq!(result["isError"],true);let raw=result.to_string();for action in actions {assert!(raw.contains(action),"missing {action}: {raw}");}
    }
}

#[test]
fn github_profile_rpc_keeps_dto_redaction_and_confirmation() {
    let (session,id)=session_with_token(true,"github");let mcp=McpState::default();let caller=mcp.open_caller().unwrap();
    let op=operation(&session,&id,"/user","GET");
    let probe=crate::github_api::TransportProbe::install(|call| {
        assert_eq!(call.method,"GET");
        Ok(crate::github_api::HttpReply{status:200,body:br#"{"login":"octocat","token":"DO NOT RETURN","name":"secret-token-123456789"}"#.to_vec()})
    });
    let result=rpc(&session,&mcp,&caller,"http_call",json!({"credential_id":id,"op":op,"params":{}}));
    assert_eq!(result["isError"],false,"{result}"); assert_eq!(result["structuredContent"]["login"],"octocat");
    assert!(!result.to_string().contains("DO NOT RETURN")); assert!(!result.to_string().contains("secret-token-123456789"));
    assert_eq!(probe.calls()[0].url,"https://api.github.com/user");
    let profile=crate::http_profiles::effective_profile(&lock_session(&session),&id).unwrap().unwrap();
    let create=profile.operations.iter().find(|op|op.name.contains("issue") && op.method=="POST" && op.params["properties"].get("title").is_some()).unwrap();
    let denied=crate::confirm::with_auto(Some(false),||rpc(&session,&mcp,&caller,"http_call",json!({"credential_id":id,"op":create.name,"params":{"repo":"o/r","title":"bug"}})));
    assert_eq!(denied["isError"],true,"{denied}");assert!(denied.to_string().contains("拒绝"));assert_eq!(probe.calls().len(),1);
}

#[test]
fn http_wrapper_rejects_transport_overrides_and_undeclared_parameters() {
    let (session,id)=session_with_token(true,"github");let mcp=McpState::default();let caller=mcp.open_caller().unwrap();let op=operation(&session,&id,"/user","GET");
    let probe=crate::github_api::TransportProbe::install(|_|panic!("invalid params must not reach HTTP"));
    for args in [json!({"credential_id":id,"op":op,"params":{},"url":"https://evil.example"}),json!({"credential_id":id,"op":op,"params":{"headers":{"Authorization":"x"}}}),json!({"credential_id":id,"op":op,"params":{"credential_id":"another"}})] {
        assert_eq!(rpc(&session,&mcp,&caller,"http_call",args)["isError"],true);
    }
    assert!(probe.calls().is_empty());
}

#[test]
fn generation_or_revoke_changes_invalidate_confirmation_permits() {
    let (session,_)=session_with_token(true,"github");let mcp=McpState::default();let caller=mcp.open_caller().unwrap();let permit=mcp.caller_permit(&caller).unwrap();
    let generation=lock_session(&session).generation();
    assert!(require_call_authorized(&lock_session(&session),&permit,generation).is_ok());
    mcp.revoke_caller(&caller).unwrap();assert!(require_call_authorized(&lock_session(&session),&permit,generation).is_err());
    let other=mcp.open_caller().unwrap();let permit=mcp.caller_permit(&other).unwrap();lock_session(&session).lock();
    assert!(require_call_authorized(&lock_session(&session),&permit,generation).is_err());
}

#[test]
fn host_must_be_loopback_with_port() {
    for host in ["127.0.0.1:17891","localhost:17891","[::1]:17891"] {assert!(host_allowed(&[("host".into(),host.into())],17891));}
    for host in ["example.com:17891","127.0.0.1:9","localhost.evil:17891"] {assert!(!host_allowed(&[("host".into(),host.into())],17891));}
    assert!(!host_allowed(&[],17891));
}
#[test]
fn advertised_schemas_keep_the_dsh_subset_but_server_bounds_remain() {
    fn walk(value:&Value){match value {Value::Object(map)=>{for banned in ["minimum","maximum","minLength","maxLength","pattern"] {assert!(!map.contains_key(banned));}for child in map.values(){walk(child)}},Value::Array(items)=>for item in items{walk(item)},_=>{}}}
    let list=tools_list(&Mutex::new(Session::default()));for tool in list["tools"].as_array().unwrap(){walk(&tool["inputSchema"]);}
    assert!(crate::credential_mcp::validate_tool("vault_list",&json!({"limit":1000})).is_err());
    let http=list["tools"].as_array().unwrap().iter().find(|tool|tool["name"]=="http_call").unwrap();
    assert_eq!(http["inputSchema"]["properties"]["params"]["additionalProperties"],true);
}
#[test]
fn pairing_code_is_one_shot_and_windowed(){let mcp=McpState::default();let status=mcp.open_pairing();assert!(status.active);assert_eq!(status.expires_in_secs,60);let code=status.code.unwrap();assert!(mcp.pairing_status().active);mcp.consume_pairing(&code).unwrap();assert!(mcp.consume_pairing(&code).is_err());assert!(!mcp.pairing_status().active);}
#[test]
fn json_tool_results_include_structured_content(){let result=tool_call_result(r#"{"ok":true}"#,false);assert_eq!(result["structuredContent"]["ok"],true);assert!(tool_call_result("not json",false).get("structuredContent").is_none());}
#[test]
fn listen_config_accepts_only_private_ipv4(){
    assert_eq!(normalize_listen_config("loopback", "").unwrap(), ("loopback".into(), "".into()));
    assert_eq!(normalize_listen_config("lan", "ignored").unwrap(), ("lan".into(), "".into()));
    assert_eq!(normalize_listen_config("address", "192.168.1.20").unwrap(), ("address".into(), "192.168.1.20".into()));
    for address in ["127.0.0.1", "0.0.0.0", "169.254.1.1", "8.8.8.8", "::1"] {
        assert!(normalize_listen_config("address", address).is_err(), "{address} must be rejected");
    }
}

#[test]
fn lan_host_and_peer_policy_is_exact_and_loopback_fill_only(){
    let policy=ListenPolicy{mode:LISTEN_MODE_LAN.into(),address:"192.168.1.20".into()};
    let remote="192.168.1.20:17891";
    assert!(host_allowed_with_policy(&[("host".into(),remote.into())],17891,&policy,"192.168.1.9".parse().unwrap()));
    assert!(!host_allowed_with_policy(&[("host".into(),"localhost:17891".into())],17891,&policy,"192.168.1.9".parse().unwrap()));
    assert!(!host_allowed_with_policy(&[("host".into(),remote.into()),("host".into(),"evil:17891".into())],17891,&policy,"192.168.1.9".parse().unwrap()));
    assert!(peer_allowed("192.168.1.9".parse().unwrap(),&policy));
    assert!(!peer_allowed("8.8.8.8".parse().unwrap(),&policy));
}

#[test]
fn start_while_locked_does_not_mint_tokens(){let mcp=McpState::default();let port=start(&mcp,Arc::new(Mutex::new(Session::default()))).unwrap();assert_ne!(port,0);assert!(recover_lock(&mcp.token).is_empty());assert!(recover_lock(&mcp.fill_token).is_empty());stop(&mcp);}

#[test]
fn expired_session_ticket_is_rejected_before_any_tool_runs() {
    let (session,_)=session_with_token(true,"github");let mcp=McpState::default();
    let caller=mcp.open_caller().unwrap();
    // Fresh ticket works, then the absolute deadline is forced into the past.
    assert!(mcp.caller_permit(&caller).is_ok());
    { let ticket=recover_lock(&mcp.callers).get(&caller).cloned().unwrap(); *recover_lock(&ticket.idle_deadline)=Instant::now()-Duration::from_secs(1); }
    assert!(mcp.caller_permit(&caller).is_err());
    assert_eq!(rpc(&session,&mcp,&caller,"vault_list",json!({}))["isError"],true);
}

#[test]
fn session_without_a_tool_grant_is_denied() {
    let (session,_)=session_with_token(true,"github");let mcp=McpState::default();
    let caller=mcp.open_caller().unwrap();
    assert_eq!(rpc(&session,&mcp,&caller,"vault_list",json!({}))["isError"],false);
    // Revoke the ticket: every tool must refuse, not just the ones with scopes.
    mcp.revoke_caller(&caller).unwrap();
    for tool in crate::credential_mcp::TOOL_NAMES {
        assert_eq!(rpc(&session,&mcp,&caller,tool,json!({}))["isError"],true,"{tool} must be denied");
    }
}
