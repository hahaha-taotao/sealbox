//! Compile a credential profile into one immutable, public-only HTTPS request.
//!
//! `prepare` runs under the Session lock. The caller then releases that lock,
//! asks `confirmation`, rechecks session/policy/credential/profile revisions,
//! and calls `execute`. Execution never consults mutable params or the vault.
//! Decision/result auditing belongs to the caller; errors and confirmation
//! fields here never contain request params, query strings or bodies.

use crate::confirm::{ConfirmField, ConfirmPayload};
use crate::http_guard::{assert_public_target, parse_http_url, PublicResolver, Target};
use crate::session::Session;
use crate::vault::SecretPayload;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use sealbox_core::profile::{validate_operation_params, validate_profile, CredentialProfile, ProfileAuth, ProfileOperation};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_URL_BYTES: usize = 16 * 1024;
const MAX_CA_BYTES: usize = 512 * 1024;
const REDACTED: &str = "[REDACTED]";
const NETWORK_ERROR: &str = "Profile HTTPS 请求失败（网络、DNS 或 TLS 错误）";

/// Not Clone/Debug/Serialize: this owns copied authentication. Only the
/// confirmation is public; method, URL, body and auth cannot be rewritten.
pub struct PreparedHttp {
    pub confirmation: Option<ConfirmPayload>,
    request: FixedRequest,
}

struct FixedRequest {
    method: String,
    url: Zeroizing<String>,
    body: Option<Zeroizing<Vec<u8>>>,
    auth_header: Option<AuthHeader>,
    tls: Option<Arc<ClientConfig>>,
    secrets: Secrets,
}

struct AuthHeader {
    name: String,
    value: Zeroizing<String>,
}

struct RawResponse {
    status: u16,
    body: Zeroizing<Vec<u8>>,
    truncated: bool,
}

pub fn prepare(
    session: &Session,
    credential_id: &str,
    profile: &CredentialProfile,
    op: &ProfileOperation,
    params: &Value,
) -> Result<PreparedHttp, String> {
    validate_profile(profile).map_err(|_| "Profile 配置未通过安全校验".to_string())?;
    if !profile.operations.iter().any(|registered| same_operation(registered, op)) {
        return Err("操作不属于该 Profile，或操作定义已改变".into());
    }
    // Actual server-side validation, including closed nested objects, arrays,
    // numeric/length/enum bounds, not trust in the client's tool schema.
    validate_operation_params(op, params)
        .map_err(|_| "Profile 参数未通过闭合 schema 校验".to_string())?;
    let object = params.as_object().ok_or("Profile 参数必须是对象")?;
    if object.keys().any(|name| transport_override_name(name)) {
        return Err("参数不能覆盖请求目标、方法、请求头或认证配置".into());
    }
    let (origin, target) = pin_origin(profile)?;
    let method = op.method.as_str();
    if !matches!(method, "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE")
        || !profile.allowed_methods.iter().any(|allowed| allowed == method)
    {
        return Err("Profile 不允许该 HTTP 方法".into());
    }
    let mut used = BTreeSet::new();
    let path = compile_path(profile, &op.path_template, object, &mut used)?;
    if !profile.allowed_path_prefixes.iter().any(|prefix| path_prefix_allows(prefix, &path)) {
        return Err("请求路径超出 Profile 允许范围".into());
    }
    let mut url = Zeroizing::new(origin.clone());
    url.push_str(&path);
    compile_query(&mut url, op, object, &mut used)?;
    let body = compile_body(op, object, &mut used)?;
    if object.keys().any(|name| !used.contains(name.as_str())) {
        return Err("Profile 参数未绑定到固定请求".into());
    }
    if url.len() > MAX_URL_BYTES { return Err("Profile 请求 URL 超过安全大小限制".into()); }
    let compiled_target = parse_http_url(&url, true).map_err(|_| "编译后的请求目标无效".to_string())?;
    if compiled_target != target || !url.starts_with(&format!("{origin}/")) {
        return Err("请求目标与 Profile HTTPS origin 不一致".into());
    }
    let vault = session.vault().map_err(|_| "金库未解锁".to_string())?;
    let dek = session.dek().map_err(|_| "金库未解锁".to_string())?;
    // SecretPayload is Zeroize, not ZeroizeOnDrop. Wrap the complete payload
    // so unused fields are erased on *every* return path as well.
    let payload = Zeroizing::new(vault.get_active_secret(dek, credential_id)
        .map_err(|_| "所选凭据不存在、已删除或无法读取".to_string())?);
    if let SecretPayload::ApiToken { service, .. } = &*payload {
        if service.trim().eq_ignore_ascii_case("github") && !is_github_api(&target) {
            return Err("GitHub 凭据只能发送到 api.github.com 的 HTTPS API".into());
        }
    }
    let mut secrets = Secrets::default();
    secrets.add_payload(&payload);
    secrets.add_sensitive_json(params, 0);
    for (name, value) in &op.fixed_query {
        if sensitive_key(name) { secrets.add(value); }
    }
    for (name, value) in &op.fixed_body {
        if sensitive_key(name) { secrets.add_json_strings(value, 0); }
    }
    let (auth_header, tls) = compile_auth(session, credential_id, &profile.auth, &payload, &mut secrets)?;
    secrets.finish();
    let confirmation = if !op.read_only || mutating_method(method) {
        Some(ConfirmPayload {
            title: "确认 Profile HTTPS 请求".into(),
            prompt: "此操作可能修改远端数据。确认后仅发送已经编译的固定请求。".into(),
            fields: vec![
                ConfirmField { label: "操作".into(), value: secrets.sanitize(&op.name) },
                ConfirmField { label: "方法".into(), value: method.to_string() },
                ConfirmField { label: "目标 origin".into(), value: secrets.sanitize(&origin) },
                ConfirmField { label: "风险".into(), value: secrets.sanitize(&op.risk) },
            ],
        })
    } else { None };
    Ok(PreparedHttp {
        confirmation,
        request: FixedRequest { method: method.to_string(), url, body, auth_header, tls, secrets },
    })
}

impl PreparedHttp {
    /// Caller must have approved confirmation and rechecked authorization.
    /// Consumes the fixed request: no redirects and no second execution.
    pub fn execute(self) -> Result<String, String> {
        let response = self.request.exchange()?;
        if !(200..300).contains(&response.status) {
            // No remote status text, Location, body or ureq error reaches the
            // error/audit paths, since each can echo authentication.
            return Err(format!("Profile HTTP {}（响应正文已隐藏，不跟随重定向）", response.status));
        }
        safe_response(response, &self.request.secrets)
    }
}

fn same_operation(a: &ProfileOperation, b: &ProfileOperation) -> bool {
    a.name == b.name && a.description == b.description && a.method == b.method
        && a.path_template == b.path_template && a.params == b.params
        && a.query_params == b.query_params && a.body_params == b.body_params
        && a.fixed_query == b.fixed_query && a.fixed_body == b.fixed_body
        && a.risk == b.risk && a.read_only == b.read_only
}

fn mutating_method(method: &str) -> bool { !matches!(method, "GET" | "HEAD" | "OPTIONS") }

fn transport_override_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase().replace('-', "_");
    matches!(name.as_str(), "host" | "hostname" | "port" | "scheme" | "url" | "uri" | "origin"
        | "base_url" | "endpoint" | "method" | "headers" | "header" | "auth" | "authorization"
        | "authentication" | "credential_id" | "client_cert_id" | "ca_bundle_path" | "proxy"
        | "redirect" | "redirects")
}

fn is_github_api(target: &Target) -> bool {
    target.scheme == "https" && target.host.eq_ignore_ascii_case("api.github.com") && target.port == 443
}

fn pin_origin(profile: &CredentialProfile) -> Result<(String, Target), String> {
    let origin = profile.origin.strip_suffix('/').unwrap_or(&profile.origin);
    let authority = origin.strip_prefix("https://").ok_or("Profile origin 必须是 HTTPS")?;
    if authority.is_empty() || authority.len() > 512 || !authority.is_ascii()
        || authority.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || authority.contains(['/', '\\', '@', '?', '#', '%', '{', '}'])
    { return Err("Profile origin 必须是无路径、无用户信息的固定 HTTPS origin".into()); }
    let target = parse_http_url(origin, true).map_err(|_| "Profile origin 无效".to_string())?;
    let host = target.host.as_str();
    if host.parse::<IpAddr>().is_err() {
        // Canonical DNS syntax prevents alternate IPv4/authority parsing.
        // PublicResolver rechecks the resolved addresses when connecting.
        let labels: Vec<_> = host.split('.').collect();
        if host.len() > 253 || labels.len() < 2
            || labels.iter().any(|label| label.is_empty() || label.len() > 63
                || label.starts_with('-') || label.ends_with('-')
                || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            || !labels.last().unwrap_or(&"").bytes().any(|b| b.is_ascii_alphabetic())
        { return Err("Profile origin 的主机格式不合法".into()); }
    }
    assert_public_target(&target).map_err(|_| "通用 Profile 只允许公网 HTTPS 目标".to_string())?;
    if (profile.adapter == "github" || profile.service.eq_ignore_ascii_case("github")) && !is_github_api(&target) {
        return Err("GitHub Profile 只能使用 api.github.com 的 HTTPS API".into());
    }
    Ok((origin.to_string(), target))
}

fn literal_segment_safe(segment: &str) -> bool {
    !matches!(segment.split(';').next(), Some("." | "..")) && segment.bytes().all(|b| b.is_ascii_alphanumeric()
        || matches!(b, b'-' | b'_' | b'.' | b'~' | b'!' | b'$' | b'&' | b'\''
            | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'@'))
}

fn identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn compile_path<'a>(profile: &CredentialProfile, template: &str, params: &'a Map<String, Value>, used: &mut BTreeSet<&'a str>) -> Result<Zeroizing<String>, String> {
    if !template.starts_with('/') || template.contains("//") {
        return Err("Profile 路径模板必须是固定的绝对路径".into());
    }
    let mut result = Zeroizing::new(String::new());
    for (index, segment) in template.split('/').enumerate() {
        if index == 0 { continue; }
        result.push('/');
        if let Some(name) = segment.strip_prefix('{').and_then(|part| part.strip_suffix('}')) {
            if !identifier(name) || transport_override_name(name) { return Err("Profile 路径占位符不合法".into()); }
            let (key, value) = params.get_key_value(name).ok_or("缺少路径参数")?;
            used.insert(key.as_str());
            let text = match value {
                Value::String(text) => Zeroizing::new(text.clone()),
                Value::Number(number) => Zeroizing::new(number.to_string()),
                _ => return Err("路径参数必须是字符串或数字".into()),
            };
            safe_path_value(&text)?;
            if name == "repo" && (profile.adapter == "github" || profile.service.eq_ignore_ascii_case("github")) {
                // Only explicit GitHub repo gets two strict owner/repo
                // segments. Never accept a repository URL or arbitrary path.
                let parts: Vec<_> = text.split('/').collect();
                if parts.len() != 2 || parts.iter().any(|part| part.is_empty() || part.len() > 100
                    || !part.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
                { return Err("repo 路径参数必须是严格的 owner/repo".into()); }
                result.push_str(parts[0]); result.push('/'); result.push_str(parts[1]);
            } else { append_encoded(&mut result, &text, false); }
        } else if literal_segment_safe(segment) && !segment.contains(['{', '}']) {
            result.push_str(segment);
        } else { return Err("Profile 路径模板包含不安全字符或遍历".into()); }
    }
    if result.len() > MAX_URL_BYTES { return Err("Profile 路径过长".into()); }
    Ok(result)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte { b'0'..=b'9' => Some(byte - b'0'), b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10), _ => None }
}

fn safe_path_value(text: &str) -> Result<(), String> {
    if text.is_empty() || text.len() > MAX_URL_BYTES { return Err("路径参数为空或过长".into()); }
    let mut decoded = Zeroizing::new(text.as_bytes().to_vec());
    // Reject traversal even when a backend percent-decodes more than once.
    // Actual substitution always encodes '%' as %25 and '/' as %2F.
    for round in 0..=16 {
        if decoded.iter().any(|b| b.is_ascii_control() || *b == b'\\')
            || decoded.starts_with(b"//") || decoded.windows(3).any(|part| part == b"://")
            || decoded.split(|b| *b == b'/').any(|part| {
                let part = part.split(|b| *b == b';').next().unwrap_or_default();
                part == b"." || part == b".."
            })
        { return Err("路径参数不能包含 URL、控制字符或路径遍历".into()); }
        let mut next = Zeroizing::new(Vec::with_capacity(decoded.len()));
        let mut at = 0; let mut changed = false;
        while at < decoded.len() {
            if decoded[at] == b'%' && at + 2 < decoded.len() {
                if let (Some(hi), Some(lo)) = (hex_digit(decoded[at + 1]), hex_digit(decoded[at + 2])) {
                    next.push((hi << 4) | lo); at += 3; changed = true; continue;
                }
            }
            next.push(decoded[at]); at += 1;
        }
        if !changed { return Ok(()); }
        if round == 16 { return Err("路径参数的嵌套编码过深".into()); }
        decoded = next;
    }
    Err("路径参数不合法".into())
}

fn path_prefix_allows(prefix: &str, path: &str) -> bool {
    if !prefix.starts_with('/') || prefix.contains("//")
        || prefix.split('/').any(|segment| !literal_segment_safe(segment)) { return false; }
    let prefix = prefix.trim_end_matches('/');
    prefix.is_empty() || path == prefix || path.strip_prefix(prefix).map(|tail| tail.starts_with('/')).unwrap_or(false)
}

fn append_encoded(out: &mut String, text: &str, lower: bool) {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let hex = if lower { LOWER } else { UPPER };
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') { out.push(byte as char); }
        else { out.push('%'); out.push(hex[(byte >> 4) as usize] as char); out.push(hex[(byte & 15) as usize] as char); }
    }
}

fn append_query_pair(url: &mut String, first: &mut bool, key: &str, value: &str) {
    url.push(if *first { '?' } else { '&' }); *first = false;
    append_encoded(url, key, false); url.push('='); append_encoded(url, value, false);
}

fn compile_query<'a>(url: &mut String, op: &ProfileOperation, params: &'a Map<String, Value>, used: &mut BTreeSet<&'a str>) -> Result<(), String> {
    let mut first = true; let mut seen = BTreeSet::new();
    for (key, value) in &op.fixed_query { append_query_pair(url, &mut first, key, value); }
    for name in &op.query_params {
        if !seen.insert(name) || op.fixed_query.contains_key(name) || transport_override_name(name) {
            return Err("Profile 查询参数存在覆盖或重复".into());
        }
        let Some((key, value)) = params.get_key_value(name) else { continue; };
        used.insert(key.as_str());
        match value {
            Value::String(text) => append_query_pair(url, &mut first, name, text),
            Value::Number(_) | Value::Bool(_) => {
                let text = Zeroizing::new(value.to_string()); append_query_pair(url, &mut first, name, &text);
            }
            Value::Array(items) => for item in items {
                if let Some(text) = item.as_str() { append_query_pair(url, &mut first, name, text); }
                else if item.is_number() || item.is_boolean() {
                    let text = Zeroizing::new(item.to_string()); append_query_pair(url, &mut first, name, &text);
                } else { return Err("查询数组只能包含简单值".into()); }
            },
            _ => return Err("查询参数必须是简单值或简单值数组".into()),
        }
        if url.len() > MAX_URL_BYTES { return Err("Profile 查询参数过长".into()); }
    }
    Ok(())
}

fn compile_body<'a>(op: &ProfileOperation, params: &'a Map<String, Value>, used: &mut BTreeSet<&'a str>) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    // Serialize borrowed JSON: cloning Values leaves unzeroized secret copies.
    let mut fields: BTreeMap<&str, &Value> = op.fixed_body.iter().map(|(key, value)| (key.as_str(), value)).collect();
    let mut seen = BTreeSet::new();
    for name in &op.body_params {
        if !seen.insert(name) || fields.contains_key(name.as_str()) || transport_override_name(name) {
            return Err("Profile 正文参数存在覆盖或重复".into());
        }
        if let Some((key, value)) = params.get_key_value(name) { used.insert(key.as_str()); fields.insert(key, value); }
    }
    if fields.is_empty() { return Ok(None); }
    if matches!(op.method.as_str(), "GET" | "HEAD") { return Err("GET 和 HEAD 不能携带 Profile JSON 正文".into()); }
    let body = Zeroizing::new(serde_json::to_vec(&fields).map_err(|_| "无法编码 Profile JSON 请求体".to_string())?);
    if body.len() > MAX_REQUEST_BYTES { return Err("Profile 请求体超过安全大小限制".into()); }
    Ok(Some(body))
}

fn header_name_safe(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 || !name.as_bytes()[0].is_ascii_alphabetic()
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) { return false; }
    let lower = name.to_ascii_lowercase().replace('_', "-");
    !matches!(lower.as_str(), "host" | "cookie" | "cookie2" | "set-cookie" | "connection" | "keep-alive"
        | "te" | "trailer" | "transfer-encoding" | "upgrade" | "expect" | "forwarded" | "via"
        | "origin" | "referer" | "user-agent" | "accept-encoding" | "range" | "destination"
        | "location" | "x-real-ip" | "x-client-ip" | "true-client-ip" | "cf-connecting-ip"
        | "client-ip" | "front-end-https" | "x-host" | "x-http-method" | "x-http-method-override" | "x-method-override"
        | "x-original-url" | "x-rewrite-url" | "x-url-scheme")
        && !["proxy-", "sec-", "content-", "x-forwarded", "x-original-", "x-rewrite-", "access-control-"]
            .iter().any(|prefix| lower.starts_with(prefix))
}

fn header_value_safe(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_RESPONSE_BYTES && value.bytes().all(|b| (b' '..=b'~').contains(&b))
}

fn basic_parts(payload: &SecretPayload) -> Option<(&str, &str)> {
    match payload {
        SecretPayload::ApiToken { account: Some(account), token, .. } => Some((account, token)),
        SecretPayload::Website { username: Some(username), password, .. } => Some((username, password)),
        SecretPayload::Server { username, password, .. } | SecretPayload::Database { username, password, .. } => Some((username, password)),
        SecretPayload::Mailbox { email, password, .. } => Some((email, password)),
        SecretPayload::MailAuth { email, auth_code, .. } => Some((email, auth_code)),
        _ => None,
    }
}

macro_rules! tls_builder {
    () => {
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| "无法初始化安全 TLS 配置".to_string())?
    };
}

fn compile_auth(session: &Session, credential_id: &str, auth: &ProfileAuth, payload: &SecretPayload, secrets: &mut Secrets) -> Result<(Option<AuthHeader>, Option<Arc<ClientConfig>>), String> {
    if auth.kind == "mtls" {
        return Ok((None, Some(referenced_client_tls(session, credential_id, auth, payload, secrets)?)));
    }
    let (name, value) = match auth.kind.as_str() {
        "bearer" | "header" => {
            let SecretPayload::ApiToken { token, .. } = payload else { return Err("Bearer 和自定义请求头认证必须使用 API Token 凭据".into()); };
            let name = if auth.kind == "bearer" { "Authorization" } else { auth.header_name.as_deref().ok_or("缺少认证请求头名称")? };
            if !header_name_safe(name) || !header_value_safe(token) { return Err("认证请求头名称或密钥格式不安全".into()); }
            let prefix = auth.prefix.as_deref().unwrap_or(if auth.kind == "bearer" { "Bearer " } else { "" });
            if prefix.len() > 256 || !prefix.bytes().all(|b| (b' '..=b'~').contains(&b)) { return Err("认证请求头前缀格式不安全".into()); }
            let mut value = Zeroizing::new(String::with_capacity(prefix.len() + token.len())); value.push_str(prefix); value.push_str(token);
            if !header_value_safe(&value) { return Err("认证请求头超过安全大小限制".into()); }
            (name.to_string(), value)
        }
        "basic" => {
            let (account, password) = basic_parts(payload).ok_or("Basic 认证需要带账号的密码或 API Token 凭据")?;
            if account.trim().is_empty() || account.contains(':') || account.chars().any(char::is_control)
                || password.is_empty() || account.len().saturating_add(password.len()) > MAX_RESPONSE_BYTES / 2
            { return Err("Basic 认证账号或密钥格式不安全".into()); }
            let mut pair = Zeroizing::new(String::with_capacity(account.len() + password.len() + 1)); pair.push_str(account); pair.push(':'); pair.push_str(password);
            secrets.add(&pair);
            let mut value = Zeroizing::new(String::from("Basic ")); STANDARD.encode_string(pair.as_bytes(), &mut value);
            ("Authorization".to_string(), value)
        }
        _ => return Err("不支持的 Profile 认证类型".into()),
    };
    secrets.add(&value);
    let tls = if auth.client_cert_id.is_some() {
        Some(referenced_client_tls(session, credential_id, auth, payload, secrets)?)
    } else {
        match read_ca(auth.ca_bundle_path.as_deref())? {
            Some(ca) => Some(Arc::new(tls_builder!().with_root_certificates(ca_roots(&ca)?).with_no_client_auth())),
            None => None,
        }
    };
    Ok((Some(AuthHeader { name, value }), tls))
}

fn referenced_client_tls(
    session: &Session,
    credential_id: &str,
    auth: &ProfileAuth,
    payload: &SecretPayload,
    secrets: &mut Secrets,
) -> Result<Arc<ClientConfig>, String> {
    let cert_id = auth.client_cert_id.as_deref().unwrap_or(credential_id);
    if cert_id == credential_id { return client_tls(auth, payload); }
    let cert = Zeroizing::new(session.vault().map_err(|_| "金库未解锁".to_string())?
        .get_active_secret(session.dek().map_err(|_| "金库未解锁".to_string())?, cert_id)
        .map_err(|_| "客户端证书不存在、已删除或无法读取".to_string())?);
    secrets.add_payload(&cert);
    client_tls(auth, &cert)
}

fn read_ca(path: Option<&str>) -> Result<Option<Zeroizing<String>>, String> {
    match path {
        None => Ok(None),
        Some(path) if path.trim().is_empty() => Err("CA bundle 路径不能为空".into()),
        Some(path) => crate::certificate::read_text_file(path, "CA bundle", MAX_CA_BYTES)
            .map(|pem| Some(Zeroizing::new(pem))).map_err(|_| "无法读取受限大小的 PEM CA bundle".into()),
    }
}

fn public_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty(); roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()); roots
}

fn ca_roots(ca: &str) -> Result<RootCertStore, String> {
    let mut roots = public_roots(); let mut count = 0;
    for certificate in rustls_pemfile::certs(&mut Cursor::new(ca.as_bytes())) {
        roots.add(certificate.map_err(|_| "CA bundle PEM 无效".to_string())?).map_err(|_| "CA bundle 含无效的根证书".to_string())?;
        count += 1;
    }
    if count == 0 { return Err("CA bundle 中没有可信根证书".into()); }
    Ok(roots)
}

fn client_tls(auth: &ProfileAuth, payload: &SecretPayload) -> Result<Arc<ClientConfig>, String> {
    let SecretPayload::ClientCert { cert_pem, key_pem, passphrase } = payload else { return Err("mTLS 认证需要金库中的客户端证书条目".into()); };
    if passphrase.as_deref().map(|value| !value.is_empty()).unwrap_or(false) || key_pem.contains("ENCRYPTED PRIVATE KEY") {
        return Err("mTLS 暂不支持带口令的客户端私钥".into());
    }
    if cert_pem.len() > crate::certificate::MAX_CERT_PEM_BYTES || key_pem.len() > crate::certificate::MAX_KEY_PEM_BYTES {
        return Err("mTLS 客户端证书或私钥超过安全大小限制".into());
    }
    if let Some(ca) = read_ca(auth.ca_bundle_path.as_deref())? {
        // Reuse the safe existing PEM/key-matching parser, NOT the global
        // cache: keys must not outlive the prepared request in a global cache.
        return crate::zoomkey::tls::build_client_config(&ca, cert_pem, key_pem)
            .map_err(|_| "mTLS CA、客户端证书或私钥无效或不匹配".into());
    }
    let certificates: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut Cursor::new(cert_pem.as_bytes()))
        .collect::<Result<_, _>>().map_err(|_| "mTLS 客户端证书 PEM 无效".to_string())?;
    if certificates.is_empty() { return Err("mTLS 客户端证书为空".into()); }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut Cursor::new(key_pem.as_bytes()))
        .map_err(|_| "mTLS 客户端私钥 PEM 无效".to_string())?.ok_or("mTLS 客户端私钥为空")?;
    tls_builder!().with_root_certificates(public_roots()).with_client_auth_cert(certificates, key)
        .map(Arc::new).map_err(|_| "mTLS 客户端证书与私钥不匹配".into())
}

impl FixedRequest {
    fn exchange(&self) -> Result<RawResponse, String> {
        #[cfg(test)]
        if let Some(result) = probe_exchange(self) { return result.map_err(|_| NETWORK_ERROR.to_string()); }
        let mut builder = ureq::builder().https_only(true).redirects(0).try_proxy_from_env(false)
            .timeout(Duration::from_secs(15)).timeout_connect(Duration::from_secs(8))
            .resolver(PublicResolver).max_idle_connections(0).user_agent(concat!("Sealbox/", env!("CARGO_PKG_VERSION")));
        if let Some(tls) = &self.tls { builder = builder.tls_config(tls.clone()); }
        let agent = builder.build();
        let mut request = agent.request(&self.method, &self.url).set("Accept", "application/json");
        if let Some(auth) = &self.auth_header { request = request.set(&auth.name, &auth.value); }
        let response = if let Some(body) = &self.body { request.set("Content-Type", "application/json").send_bytes(body) } else { request.call() };
        let response = match response {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(_) => return Err(NETWORK_ERROR.into()),
        };
        let status = response.status(); let (body, truncated) = read_capped(response.into_reader())?;
        Ok(RawResponse { status, body, truncated })
    }
}

fn read_capped(reader: impl Read) -> Result<(Zeroizing<Vec<u8>>, bool), String> {
    let mut body = Zeroizing::new(Vec::new());
    // 64 KiB plus one sentinel, even for chunked responses. Never trust a
    // Content-Length or return an unredacted partial JSON document.
    reader.take((MAX_RESPONSE_BYTES + 1) as u64).read_to_end(&mut body).map_err(|_| "无法完整读取 Profile HTTPS 响应".to_string())?;
    let truncated = body.len() > MAX_RESPONSE_BYTES;
    if truncated { body[MAX_RESPONSE_BYTES..].zeroize(); body.truncate(MAX_RESPONSE_BYTES); }
    Ok((body, truncated))
}

#[derive(Default)]
struct Secrets { values: Zeroizing<Vec<String>> }

impl Secrets {
    fn add(&mut self, secret: &str) {
        if secret.is_empty() { return; }
        if secret.len() > MAX_RESPONSE_BYTES {
            // Whole oversized PEM cannot fit in a response, but its base64
            // lines might be echoed without the BEGIN/END markers.
            for line in secret.lines().filter(|line| !line.starts_with("-----") && (16..=MAX_RESPONSE_BYTES).contains(&line.len())).take(256) { self.add(line); }
            return;
        }
        self.values.push(secret.to_string());
        self.values.push(STANDARD.encode(secret)); self.values.push(STANDARD_NO_PAD.encode(secret));
        self.values.push(URL_SAFE.encode(secret)); self.values.push(URL_SAFE_NO_PAD.encode(secret));
        for lower in [false, true] {
            let mut encoded = Zeroizing::new(String::new()); append_encoded(&mut encoded, secret, lower); self.values.push(std::mem::take(&mut *encoded));
        }
        if let Ok(encoded) = serde_json::to_string(secret) {
            let encoded = Zeroizing::new(encoded); self.values.push(encoded[1..encoded.len() - 1].to_string());
        }
    }

    fn add_payload(&mut self, payload: &SecretPayload) {
        match payload {
            SecretPayload::ApiToken { account, token, .. } => { self.add(token); if let Some(account) = account { self.add(account); } }
            SecretPayload::Website { username, password, totp_secret, .. } => {
                self.add(password); if let Some(name) = username { self.add(name); } if let Some(secret) = totp_secret { self.add(secret); }
            }
            SecretPayload::Server { username, password, .. } | SecretPayload::Database { username, password, .. } => { self.add(username); self.add(password); }
            SecretPayload::Mailbox { email, password, .. } => { self.add(email); self.add(password); }
            SecretPayload::MailAuth { email, auth_code, .. } => { self.add(email); self.add(auth_code); }
            SecretPayload::ClientCert { cert_pem, key_pem, passphrase } => {
                self.add(cert_pem); self.add(key_pem); if let Some(passphrase) = passphrase { self.add(passphrase); }
                for line in key_pem.lines().filter(|line| !line.starts_with("-----") && line.len() >= 16).take(256) { self.add(line); }
            }
            SecretPayload::Ssh { private_key, passphrase, .. } => { self.add(private_key); if let Some(passphrase) = passphrase { self.add(passphrase); } }
        }
    }

    fn add_json_strings(&mut self, value: &Value, depth: usize) {
        if depth > 16 { return; }
        match value {
            Value::String(text) => self.add(text),
            Value::Array(values) => for value in values { self.add_json_strings(value, depth + 1); },
            Value::Object(values) => for value in values.values() { self.add_json_strings(value, depth + 1); },
            Value::Number(_) | Value::Bool(_) => self.add(&value.to_string()), Value::Null => {}
        }
    }

    fn add_sensitive_json(&mut self, value: &Value, depth: usize) {
        if depth > 16 { return; }
        match value {
            Value::Object(values) => for (key, value) in values {
                if sensitive_key(key) { self.add_json_strings(value, depth + 1); } else { self.add_sensitive_json(value, depth + 1); }
            },
            Value::Array(values) => for value in values { self.add_sensitive_json(value, depth + 1); }, _ => {}
        }
    }

    fn finish(&mut self) {
        self.values.sort_unstable_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        // dedup() drops unzeroized duplicate String allocations.
        let mut index = 1;
        while index < self.values.len() {
            if self.values[index] == self.values[index - 1] { self.values[index].zeroize(); self.values.remove(index); }
            else { index += 1; }
        }
    }

    fn sanitize(&self, text: &str) -> String {
        if sensitive_assignment().is_match(text) { return REDACTED.into(); }
        let mut result = Zeroizing::new(text.to_string());
        // Include even short credentials; wipe intermediate auth encodings.
        for secret in self.values.iter() {
            if result.contains(secret.as_str()) { let next = result.replace(secret.as_str(), REDACTED); result.zeroize(); *result = next; }
        }
        let next = authorization_echo().replace_all(&result, REDACTED).into_owned(); result.zeroize(); *result = next;
        crate::redact::redact_text(&result, &[])
    }
}

fn sensitive_key(key: &str) -> bool {
    let compact: String = key.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_lowercase()).collect();
    compact == "auth" || compact.ends_with("auth") || compact == "authheader" || compact == "bearer"
        || compact == "key" || compact == "pwd" || compact == "session" || compact == "jwt"
        || ["token", "password", "passwd", "passphrase", "secret", "authorization", "authentication", "authcode", "authkey", "privatekey", "keypem", "certpem", "apikey", "accesskey", "credential", "cookie", "sessionid", "clientcert", "certificate"]
            .iter().any(|word| compact.contains(word))
}

fn sensitive_assignment() -> &'static regex::Regex {
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    PATTERN.get_or_init(|| regex::Regex::new(r#"(?i)(?:[a-z0-9_.-]*(?:token|password|passwd|secret|authorization|authentication|private[_ -]?key|api[_ -]?key|credential|cookie|session[_ -]?id)[a-z0-9_.-]*|\bauth)["']?\s*[:=]"#).expect("constant redaction pattern"))
}

fn authorization_echo() -> &'static regex::Regex {
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    PATTERN.get_or_init(|| regex::Regex::new(r"(?i)\b(?:Basic|Bearer)\s+[A-Za-z0-9._~+/=-]+").expect("constant authorization pattern"))
}

fn wipe_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => for item in items { wipe_json(item); },
        Value::Object(map) => for (mut key, mut value) in std::mem::take(map) { key.zeroize(); wipe_json(&mut value); }, _ => {}
    }
}

fn sanitize_json(value: &mut Value, secrets: &Secrets, depth: usize) {
    if depth > 64 { wipe_json(value); *value = Value::String(REDACTED.into()); return; }
    match value {
        Value::String(text) => { let original = Zeroizing::new(std::mem::take(text)); *text = secrets.sanitize(&original); }
        Value::Array(items) => for item in items { sanitize_json(item, secrets, depth + 1); },
        Value::Object(map) => for (key, mut item) in std::mem::take(map) {
            let key = Zeroizing::new(key);
            if sensitive_key(&key) { wipe_json(&mut item); item = Value::String(REDACTED.into()); }
            else { sanitize_json(&mut item, secrets, depth + 1); }
            map.insert(secrets.sanitize(&key), item);
        },
        Value::Number(_) | Value::Bool(_) => {
            let original = Zeroizing::new(value.to_string()); if secrets.sanitize(&original) != *original { *value = Value::String(REDACTED.into()); }
        }
        Value::Null => {}
    }
}

fn safe_response(response: RawResponse, secrets: &Secrets) -> Result<String, String> {
    let mut truncated = response.truncated;
    let mut body = if truncated {
        Value::String("[响应超过 64 KiB，正文已隐藏]".into())
    } else if response.body.is_empty() { Value::Null }
    else if let Ok(mut value) = serde_json::from_slice::<Value>(&response.body) { sanitize_json(&mut value, secrets, 0); value }
    else {
        let text = Zeroizing::new(String::from_utf8_lossy(&response.body).into_owned());
        if text.trim_start().starts_with(['{', '[']) || sensitive_assignment().is_match(&text) {
            Value::String("[无法安全解析或含敏感字段的响应正文已隐藏]".into())
        } else { Value::String(secrets.sanitize(&text)) }
    };
    let encoded = serde_json::to_vec(&body).map_err(|_| "无法编码脱敏响应".to_string())?;
    if encoded.len() > MAX_RESPONSE_BYTES {
        wipe_json(&mut body); body = Value::String("[脱敏响应超过 64 KiB，正文已隐藏]".into()); truncated = true;
    }
    serde_json::to_string(&json!({"status": response.status, "truncated": truncated, "body": body})).map_err(|_| "无法编码脱敏响应".into())
}

#[cfg(test)]
thread_local! {
    static PROBE: std::cell::RefCell<Option<Box<ProbeFn>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
type ProbeFn = dyn FnMut(&FixedRequest) -> Result<(u16, Vec<u8>), String>;
#[cfg(test)]
fn probe_exchange(request: &FixedRequest) -> Option<Result<RawResponse, String>> {
    PROBE.with(|slot| {
        let mut slot = slot.borrow_mut(); let reply = slot.as_mut()?;
        Some(reply(request).and_then(|(status, bytes)| {
            let bytes = Zeroizing::new(bytes); let (body, truncated) = read_capped(Cursor::new(&*bytes))?;
            Ok(RawResponse { status, body, truncated })
        }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{UpsertEntry, Vault};

    fn profile(method: &str, read_only: bool) -> CredentialProfile {
        serde_json::from_value(json!({
            "version":1, "adapter":"http", "service":"test-service", "origin":"https://api.example.com",
            "auth":{"kind":"bearer"}, "allowed_methods":[method], "allowed_path_prefixes":["/v1/items"],
            "operations":[{"name":"item", "description":"test operation", "method":method, "path_template":"/v1/items/{id}",
                "params":{"type":"object","additionalProperties":false,"properties":{"id":{"type":"string","minLength":1,"maxLength":200}},"required":["id"]},
                "query_params":[],"body_params":[],"fixed_query":{},"fixed_body":{},"risk":"low","read_only":read_only}]
        })).unwrap()
    }
    fn session_with(payload: SecretPayload) -> (Session, String) {
        let (vault, dek) = Vault::create_in_memory("profile-http-test-password").unwrap();
        let id = vault.upsert_entry(&dek, UpsertEntry {
            id:None, kind:payload.kind(), title:"profile credential".into(), account:None, url:None, folder_id:None,
            tags:vec![], pinned:false, expires_at:None, notes:None, secret:payload,
        }).unwrap().id;
        let mut session = Session::default(); session.set_unlocked(vault, dek); (session, id)
    }
    fn token_session() -> (Session, String) {
        session_with(SecretPayload::ApiToken { service:"test-service".into(), account:Some("test-account".into()), token:"test-secret-value".into() })
    }
    fn with_probe<T>(handler: impl FnMut(&FixedRequest) -> Result<(u16, Vec<u8>), String> + 'static, run: impl FnOnce() -> T) -> T {
        struct Guard;
        impl Drop for Guard { fn drop(&mut self) { PROBE.with(|slot| { slot.borrow_mut().take(); }); } }
        PROBE.with(|slot| { assert!(slot.borrow().is_none()); *slot.borrow_mut() = Some(Box::new(handler)); });
        let _guard = Guard; run()
    }

    #[test]
    fn compiled_request_is_one_segment_and_immutable() {
        let (mut session, id) = token_session(); let mut profile = profile("GET", true);
        let prepared = prepare(&session, &id, &profile, &profile.operations[0], &json!({"id":"hello/world ?#&=é%"})).unwrap();
        assert!(prepared.confirmation.is_none());
        // Caller owns the authorization recheck; changing inputs does not
        // rewrite the request or cause execute to consult the now-locked vault.
        profile.origin = "https://other.example.com".into(); session.lock();
        with_probe(|request| {
            assert_eq!(&*request.url,"https://api.example.com/v1/items/hello%2Fworld%20%3F%23%26%3D%C3%A9%25");
            assert_eq!(request.method,"GET"); assert!(request.body.is_none());
            assert_eq!(&*request.auth_header.as_ref().unwrap().value,"Bearer test-secret-value");
            Ok((200,br#"{"ok":true}"#.to_vec()))
        }, || { assert!(prepared.execute().unwrap().contains("\"ok\":true")); });
    }

    #[test]
    fn mutation_and_read_only_false_always_require_confirmation() {
        let (session, id) = token_session();
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            assert!(mutating_method(method));
            let invalid = profile(method, true);
            assert!(prepare(&session, &id, &invalid, &invalid.operations[0], &json!({"id":"x"})).is_err());
        }
        for (method, read_only) in [("POST",false),("PUT",false),("PATCH",false),("DELETE",false),("GET",false)] {
            let profile = profile(method,read_only);
            let prepared = prepare(&session,&id,&profile,&profile.operations[0],&json!({"id":"request-value-must-not-be-shown"})).unwrap();
            let payload = serde_json::to_string(&prepared.confirmation.unwrap()).unwrap();
            assert!(!payload.contains("request-value-must-not-be-shown")); assert!(!payload.contains("test-secret-value"));
        }
    }

    #[test]
    fn unknown_overrides_and_unregistered_operations_are_rejected() {
        let (session,id) = token_session(); let profile = profile("GET",true);
        for params in [json!({"id":"x","host":"elsewhere.example.com"}),json!({"id":"x","method":"DELETE"}),json!({"id":"x","headers":{"Authorization":"evil"}})] {
            assert!(prepare(&session,&id,&profile,&profile.operations[0],&params).is_err());
        }
        let mut altered = profile.operations[0].clone(); altered.path_template = "/v1/items/other".into();
        assert!(prepare(&session,&id,&profile,&altered,&json!({"id":"x"})).is_err());
    }

    #[test]
    fn traversal_and_prefix_lookalikes_are_rejected() {
        for value in [".","..","../other","x/../other","x\\..\\other","%2e%2e",".%252e","%252e%252e%252fother","https://evil.example.com","//evil.example.com","%00"] {
            assert!(safe_path_value(value).is_err(),"{value}");
        }
        assert!(safe_path_value("safe.file name/child").is_ok());
        assert!(!path_prefix_allows("/v1/items","/v1/items-evil/x"));
        assert!(path_prefix_allows("/v1/items","/v1/items/x"));
    }

    #[test]
    fn https_public_origin_and_github_api_are_pinned() {
        for origin in ["http://api.example.com","https://api.example.com/path","https://user:pass@api.example.com","https://127.0.0.1","https://169.254.169.254","https://[::1]","https://localhost","https://name.internal","https://0x7f.0.0.1","https://api.example.com\\@evil.example.com"] {
            let mut profile = profile("GET",true); profile.origin = origin.into(); assert!(pin_origin(&profile).is_err(),"{origin}");
        }
        let mut profile = profile("GET",true); profile.adapter = "github".into();
        for origin in ["https://github.com","https://uploads.github.com","https://api.github.com.evil.example.com","https://api.github.com:8443"] {
            profile.origin=origin.into(); assert!(pin_origin(&profile).is_err());
        }
        profile.origin="https://api.github.com".into(); assert!(pin_origin(&profile).is_ok());
        assert!(crate::http_guard::resolve_public("127.0.0.1:443").is_err());
    }

    #[test]
    fn basic_auth_and_custom_headers_cannot_control_transport() {
        for name in ["Host","Cookie","Content-Length","Transfer-Encoding","X-Forwarded-Host","Proxy-Authorization","X-HTTP-Method-Override","X-Rewrite-URL","X-Test\r\nHost"] { assert!(!header_name_safe(name),"{name}"); }
        assert!(header_name_safe("X-API-Key")); assert!(header_name_safe("Authorization"));
        assert!(!header_value_safe("secret\r\nHost: evil"));
        let (session,id) = session_with(SecretPayload::Server { host:"api.example.com".into(),port:None,protocol:"https".into(),username:"basic-user".into(),password:"basic-password".into() });
        let mut profile=profile("GET",true); profile.auth.kind="basic".into();
        let prepared=prepare(&session,&id,&profile,&profile.operations[0],&json!({"id":"item"})).unwrap();
        with_probe(|request| {
            assert_eq!(&*request.auth_header.as_ref().unwrap().value,&format!("Basic {}",STANDARD.encode("basic-user:basic-password")));
            Ok((200,json!({"echo":STANDARD.encode("basic-user:basic-password"),"other":"basic-password"}).to_string().into_bytes()))
        },|| { let reply=prepared.execute().unwrap(); assert!(!reply.contains("basic-password")); assert!(!reply.contains(&STANDARD.encode("basic-user:basic-password"))); });
    }

    #[test]
    fn recursive_redaction_covers_new_secrets_and_auth_echoes() {
        let mut secrets=Secrets::default(); secrets.add("abc"); secrets.add("Basic dTpw"); secrets.finish();
        let body=json!({"nested":[{"access_token":"newly-issued-value","password":"new-password","auth":{"data":"new-auth"},"private_key":"new-key"}],"echo":"abc Basic dTpw","encoded":STANDARD.encode("abc"),"safe":"kept","embedded":"password: never-return-this"});
        let reply=safe_response(RawResponse { status:200,body:Zeroizing::new(body.to_string().into_bytes()),truncated:false },&secrets).unwrap();
        for secret in ["newly-issued-value","new-password","new-auth","new-key","abc","dTpw","never-return-this"] { assert!(!reply.contains(secret),"{reply}"); }
        assert!(reply.contains("kept")); assert!(reply.contains(REDACTED));
    }

    #[test]
    fn cap_uses_one_sentinel_and_never_returns_partial_secret_fields() {
        let mut bytes=br#"{"token":"new-secret-to-hide","padding":""#.to_vec(); bytes.resize(MAX_RESPONSE_BYTES+200,b'x');
        let (body,truncated)=read_capped(Cursor::new(bytes)).unwrap(); assert_eq!(body.len(),MAX_RESPONSE_BYTES); assert!(truncated);
        let reply=safe_response(RawResponse {status:200,body,truncated},&Secrets::default()).unwrap();
        assert!(reply.contains("\"truncated\":true")); assert!(!reply.contains("new-secret-to-hide"));
        assert!(!read_capped(Cursor::new(vec![b'x';MAX_RESPONSE_BYTES])).unwrap().1);
    }

    #[test]
    fn remote_errors_never_return_body_or_transport_messages() {
        let (session,id)=token_session(); let profile=profile("GET",true);
        let prepared=prepare(&session,&id,&profile,&profile.operations[0],&json!({"id":"x"})).unwrap();
        with_probe(|_| Ok((302,b"secret response test-secret-value".to_vec())),|| {
            let error=prepared.execute().unwrap_err(); assert!(error.contains("302")); assert!(!error.contains("test-secret-value"));
        });
        let prepared=prepare(&session,&id,&profile,&profile.operations[0],&json!({"id":"x"})).unwrap();
        with_probe(|_| Err("transport echoed test-secret-value and raw body".into()),|| {assert_eq!(prepared.execute().unwrap_err(),NETWORK_ERROR);});
    }

    #[test]
    fn query_body_and_fixed_values_are_compiled_before_execution() {
        let (session,id)=token_session(); let mut profile=profile("POST",false); let op=&mut profile.operations[0];
        op.params["properties"]["search"]=json!({"type":"string"});
        op.params["properties"]["count"]=json!({"type":"integer","minimum":1,"maximum":3});
        op.query_params.push("search".into()); op.fixed_query.insert("scope".into(),"fixed".into());
        op.body_params.push("count".into()); op.fixed_body.insert("mode".into(),json!("fixed"));
        let prepared=prepare(&session,&id,&profile,&profile.operations[0],&json!({"id":"x","search":"a&scope=evil","count":2})).unwrap();
        with_probe(|request| {
            assert!(request.url.contains("scope=fixed&search=a%26scope%3Devil"));
            assert_eq!(serde_json::from_slice::<Value>(request.body.as_ref().unwrap()).unwrap(),json!({"count":2,"mode":"fixed"}));
            Ok((204,vec![]))
        },|| {assert!(prepared.execute().unwrap().contains("\"status\":204"));});
        assert!(prepare(&session,&id,&profile,&profile.operations[0],&json!({"id":"x","count":4})).is_err());
    }

    #[test]
    fn actual_arguments_enforce_nested_closed_schema_and_bounds() {
        let (session, id) = token_session();
        let mut profile = profile("POST", false);
        let op = &mut profile.operations[0];
        op.params["properties"]["input"] = json!({
            "type":"object", "additionalProperties":false,
            "properties": {
                "text":{"type":"string","minLength":2,"maxLength":4},
                "mode":{"type":"string","enum":["a","b"]},
                "count":{"type":"integer","minimum":-2,"maximum":2},
                "ratio":{"type":"number","minimum":0.1,"maximum":0.9},
                "enabled":{"type":"boolean"},
                "tags":{"type":"array","minItems":1,"maxItems":2,"items":{"type":"string","enum":["x","y"]}}
            },
            "required":["text","mode","count","ratio","enabled","tags"]
        });
        op.params["required"] = json!(["id","input"]);
        op.body_params.push("input".into());
        let valid = json!({"id":"x","input":{"text":"good","mode":"a","count":-1,"ratio":0.5,"enabled":true,"tags":["x"]}});
        assert!(prepare(&session,&id,&profile,&profile.operations[0],&valid).is_ok());
        for (key, invalid) in [
            ("text",json!("x")), ("text",json!("too-long")), ("text",json!(2)),
            ("mode",json!("other")), ("count",json!(2.5)), ("count",json!(3)),
            ("ratio",json!(0.0)), ("enabled",json!("true")), ("tags",json!([])),
            ("tags",json!(["x","y","x"])), ("tags",json!(["bad"])),
        ] {
            let mut params = valid.clone(); params["input"][key] = invalid;
            assert!(prepare(&session,&id,&profile,&profile.operations[0],&params).is_err());
        }
        let mut params = valid.clone(); params["input"]["unknown"] = json!("must-reject");
        assert!(prepare(&session,&id,&profile,&profile.operations[0],&params).is_err());
        assert!(prepare(&session,&id,&profile,&profile.operations[0],&json!({"id":"x"})).is_err());
        // Even a declared parameter cannot grant transport control.
        profile.operations[0].params["properties"]["method"] = json!({"type":"string"});
        profile.operations[0].query_params.push("method".into());
        let mut params = valid; params["method"] = json!("DELETE");
        assert!(prepare(&session,&id,&profile,&profile.operations[0],&params).is_err());
    }

    #[test]
    fn custom_header_prefix_and_echo_are_secret() {
        let (session, id) = token_session();
        let mut profile = profile("GET", true);
        profile.auth.kind = "header".into();
        profile.auth.header_name = Some("X-API-Key".into());
        profile.auth.prefix = Some("Custom ".into());
        let prepared = prepare(&session,&id,&profile,&profile.operations[0],&json!({"id":"x"})).unwrap();
        with_probe(|request| {
            let header = request.auth_header.as_ref().unwrap();
            assert_eq!(header.name,"X-API-Key");
            assert_eq!(&*header.value,"Custom test-secret-value");
            Ok((200,json!({"echo":"Custom test-secret-value","encoded":STANDARD.encode("Custom test-secret-value"),"nested":{"auth_code":"new-auth-code"}}).to_string().into_bytes()))
        },|| {
            let reply = prepared.execute().unwrap();
            assert!(!reply.contains("test-secret-value"));
            assert!(!reply.contains(&STANDARD.encode("Custom test-secret-value")));
            assert!(!reply.contains("new-auth-code"));
        });
    }

    #[test]
    fn mtls_requires_vault_certificate_and_pem_errors_are_static() {
        let (session,id)=token_session(); let mut profile=profile("GET",true);
        profile.auth.kind="mtls".into(); profile.auth.client_cert_id=Some("missing-certificate".into());
        assert!(prepare(&session,&id,&profile,&profile.operations[0],&json!({"id":"x"})).is_err());
        let payload=SecretPayload::ClientCert {cert_pem:"raw-certificate-secret".into(),key_pem:"raw-private-key-secret".into(),passphrase:None};
        let error=client_tls(&profile.auth,&payload).unwrap_err();
        assert!(!error.contains("raw-certificate-secret")); assert!(!error.contains("raw-private-key-secret"));
    }
}

/* End of module. */
