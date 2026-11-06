//! Credential-scoped MCP profile metadata.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv6Addr;

const MAX_PROFILE_BYTES: usize = 256 * 1024;
const MAX_PARAMS_BYTES: usize = 128 * 1024;
const MAX_DEPTH: usize = 6;
const MAX_NODES: usize = 256;
const MAX_PROPERTIES: usize = 64;
const DEFAULT_MAX_LENGTH: u64 = 8192;
const MAX_LENGTH: u64 = 65_536;
const MAX_ITEMS: u64 = 100;
const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
fn version_one() -> u32 { 1 }
fn http_adapter() -> String { "http".into() }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CredentialProfile {
    #[serde(default = "version_one")]
    pub version: u32,
    #[serde(default = "http_adapter")]
    pub adapter: String,
    pub service: String,
    pub origin: String,
    pub auth: ProfileAuth,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allowed_path_prefixes: Vec<String>,
    #[serde(default)]
    pub operations: Vec<ProfileOperation>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileAuth {
    pub kind: String,
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub client_cert_id: Option<String>,
    #[serde(default)]
    pub ca_bundle_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProfileOperation {
    pub name: String,
    pub description: String,
    pub method: String,
    pub path_template: String,
    pub params: Value,
    #[serde(default)]
    pub query_params: Vec<String>,
    #[serde(default)]
    pub body_params: Vec<String>,
    #[serde(default)]
    pub fixed_query: BTreeMap<String, String>,
    #[serde(default)]
    pub fixed_body: BTreeMap<String, Value>,
    pub risk: String,
    pub read_only: bool,
}
/// Validate metadata; errors never echo caller-supplied values.
pub fn validate_profile(profile: &CredentialProfile) -> Result<(), String> {
    if serde_json::to_vec(profile).map_err(|_| "profile encoding failed")?.len() > MAX_PROFILE_BYTES { return Err("profile is too large".into()); }
    if profile.version != 1 { return Err("unsupported profile version".into()); }
    if !matches!(profile.adapter.as_str(), "http" | "github" | "zoomkey_jira" | "zoomkey_crm") { return Err("unsupported profile adapter".into()); }
    text(&profile.service, 128, false)?;
    validate_origin(&profile.origin)?;
    if (profile.adapter == "github" || profile.service.eq_ignore_ascii_case("github")) && profile.origin != "https://api.github.com" { return Err("GitHub profiles require exactly https://api.github.com".into()); }
    validate_auth(&profile.auth)?;
    if profile.allowed_methods.is_empty() || profile.allowed_methods.len() > METHODS.len() { return Err("profile requires a bounded method allowlist".into()); }
    let mut methods = BTreeSet::new();
    for method in &profile.allowed_methods {
        if !METHODS.contains(&method.as_str()) || !methods.insert(method.as_str()) { return Err("invalid or duplicate allowed HTTP method".into()); }
    }
    if profile.allowed_path_prefixes.is_empty() || profile.allowed_path_prefixes.len() > 64 { return Err("profile requires a bounded path-prefix allowlist".into()); }
    let mut prefixes = BTreeSet::new();
    for prefix in &profile.allowed_path_prefixes {
        validate_path(prefix, false)?;
        if !prefixes.insert(prefix.as_str()) { return Err("duplicate allowed path prefix".into()); }
    }
    if profile.operations.len() > 128 { return Err("too many profile operations".into()); }
    let mut names = BTreeSet::new();
    for op in &profile.operations {
        if !identifier(&op.name, true) || !names.insert(op.name.as_str()) { return Err("invalid or duplicate operation name".into()); }
        text(&op.description, 4096, true)?;
        if !methods.contains(op.method.as_str()) { return Err("operation method is not allowed".into()); }
        if !matches!(op.risk.as_str(), "low" | "medium" | "high") { return Err("invalid operation risk".into()); }
        if op.read_only && !matches!(op.method.as_str(), "GET" | "HEAD" | "OPTIONS") { return Err("mutating HTTP methods cannot be read-only".into()); }
        let placeholders = validate_path(&op.path_template, true)?;
        if !prefixes.iter().any(|prefix| path_within(&op.path_template, prefix)) { return Err("operation path is outside allowed prefixes".into()); }
        validate_schema(&op.params)?;
        if op.params.get("type").and_then(Value::as_str) != Some("object") { return Err("params schema must describe a closed object".into()); }
        let properties = op.params.get("properties").and_then(Value::as_object);
        let required: BTreeSet<&str> = op.params.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
        let mut routed = BTreeSet::new();
        for name in &placeholders {
            let property = properties.and_then(|p| p.get(name)).ok_or("undeclared path parameter")?;
            if !required.contains(name.as_str()) { return Err("path parameters must be required".into()); }
            if !matches!(property.get("type").and_then(Value::as_str), Some("string" | "integer")) { return Err("path parameters must be strings or integers".into()); }
            routed.insert(name.as_str());
        }
        if [op.query_params.len(), op.body_params.len(), op.fixed_query.len(), op.fixed_body.len()].iter().any(|n| *n > MAX_PROPERTIES) { return Err("too many operation parameter routes".into()); }
        for name in &op.query_params {
            let property = properties.and_then(|p| p.get(name)).ok_or("undeclared query parameter")?;
            if !matches!(property.get("type").and_then(Value::as_str), Some("string" | "integer" | "number" | "boolean")) { return Err("query parameters must be scalar values".into()); }
            if !routed.insert(name.as_str()) { return Err("parameter has duplicate routes".into()); }
        }
        for name in &op.body_params {
            if !properties.map(|p| p.contains_key(name)).unwrap_or(false) { return Err("undeclared body parameter".into()); }
            if !routed.insert(name.as_str()) { return Err("parameter has duplicate routes".into()); }
        }
        for (name, value) in &op.fixed_query {
            fixed_name(name)?;
            if routed.contains(name.as_str()) || op.fixed_body.contains_key(name) { return Err("fixed parameter conflicts with another route".into()); }
            text(value, DEFAULT_MAX_LENGTH as usize, true)?;
            validate_fixed_value(&Value::String(value.clone()), 0)?;
        }
        for (name, value) in &op.fixed_body {
            fixed_name(name)?;
            if routed.contains(name.as_str()) { return Err("fixed parameter conflicts with a dynamic route".into()); }
            validate_fixed_value(value, 0)?;
        }
        if matches!(op.method.as_str(), "GET" | "HEAD") && (!op.body_params.is_empty() || !op.fixed_body.is_empty()) { return Err("GET and HEAD operations cannot carry request bodies".into()); }
    }
    Ok(())
}

/// Validate arguments with finite defaults; no coercion or default insertion.
pub fn validate_operation_params(op: &ProfileOperation, params: &Value) -> Result<(), String> {
    validate_schema(&op.params)?;
    if op.params.get("type").and_then(Value::as_str) != Some("object") { return Err("params schema must describe a closed object".into()); }
    if serde_json::to_vec(params).map_err(|_| "parameter encoding failed")?.len() > MAX_PARAMS_BYTES { return Err("operation parameters are too large".into()); }
    validate_instance(&op.params, params, 0)
}

fn text(value: &str, max: usize, empty: bool) -> Result<(), String> {
    if value.len() > max || (!empty && value.trim().is_empty()) || value.chars().any(char::is_control) { return Err("invalid profile text or text length".into()); }
    Ok(())
}
fn identifier(value: &str, operation: bool) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 64 && matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_')) && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || (operation && (b == b'-' || b == b'.')))
}
fn validate_origin(origin: &str) -> Result<(), String> {
    let authority = origin.strip_prefix("https://").ok_or("profile origin must use HTTPS")?;
    if authority.is_empty() || authority.len() > 261 || !authority.is_ascii() || authority.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || matches!(b, b'/' | b'\\' | b'@' | b'?' | b'#' | b'%')) { return Err("profile origin must be an exact bare HTTPS origin".into()); }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or("invalid origin host")?;
        host.parse::<Ipv6Addr>().map_err(|_| "invalid origin IPv6 host")?;
        (host, if after.is_empty() { None } else { Some(after.strip_prefix(':').ok_or("invalid origin port")?) })
    } else {
        let (host, port) = match authority.split_once(':') { Some((h, p)) => (h, Some(p)), None => (authority, None) };
        if host.is_empty() || host.len() > 253 || host.ends_with('.') || host.split('.').any(|label| label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')) { return Err("invalid origin host".into()); }
        (host, port)
    };
    let port = match port { Some(raw) => { let n = raw.parse::<u16>().map_err(|_| "invalid origin port")?; if n == 0 || n.to_string() != raw { return Err("invalid origin port".into()); } n }, None => 443 };
    crate::http_guard::assert_public_target(&crate::http_guard::Target { scheme: "https".into(), host: host.into(), port })
}
fn validate_auth(auth: &ProfileAuth) -> Result<(), String> {
    if !matches!(auth.kind.as_str(), "bearer" | "basic" | "header" | "mtls") { return Err("unsupported profile authentication".into()); }
    if auth.kind == "header" && auth.header_name.is_none() { return Err("header authentication needs a header name".into()); }
    if let Some(name) = &auth.header_name {
        if name.is_empty() || name.len() > 128 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)) { return Err("invalid authentication header name".into()); }
        let lower = name.to_ascii_lowercase();
        if matches!(lower.as_str(), "host" | "cookie" | "set-cookie" | "connection" | "keep-alive" | "te" | "trailer" | "upgrade" | "transfer-encoding" | "content-length" | "expect" | "origin" | "referer" | "forwarded" | "via" | "accept-encoding") || lower.starts_with("proxy-") || lower.starts_with("sec-") || lower.starts_with("x-forwarded-") || lower.starts_with("content-") || lower.starts_with("x-http-method") || lower.starts_with("access-control-") { return Err("unsafe authentication header name".into()); }
        if matches!(auth.kind.as_str(), "basic" | "bearer") && lower != "authorization" { return Err("basic and bearer authentication use Authorization".into()); }
    }
    if let Some(prefix) = &auth.prefix {
        if prefix.len() > 64 || prefix.bytes().any(|b| !(0x20..=0x7e).contains(&b)) { return Err("invalid authentication prefix".into()); }
        if (auth.kind == "basic" && prefix != "Basic ") || (auth.kind == "bearer" && prefix != "Bearer ") { return Err("invalid standard authentication prefix".into()); }
    }
    if auth.kind == "mtls" && (auth.header_name.is_some() || auth.prefix.is_some()) { return Err("mTLS does not use an HTTP authentication header".into()); }
    for value in [&auth.client_cert_id, &auth.ca_bundle_path].into_iter().flatten() { text(value, 2048, false)?; }
    Ok(())
}
fn validate_path(path: &str, template: bool) -> Result<BTreeSet<String>, String> {
    if !path.starts_with('/') || path.len() > 2048 || !path.is_ascii() || path.contains("//") || path.bytes().any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || matches!(b, b'%' | b'\\' | b'?' | b'#')) { return Err("unsafe profile path".into()); }
    let mut params = BTreeSet::new();
    for segment in path.split('/') {
        if segment == "." || segment == ".." { return Err("path traversal is not allowed".into()); }
        if segment.contains(['{', '}']) {
            let name = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')).ok_or("invalid path parameter")?;
            if !template || !identifier(name, false) { return Err("invalid path parameter".into()); }
            params.insert(name.into());
        } else if !segment.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&b)) { return Err("unsafe profile path character".into()); }
    }
    Ok(params)
}
fn path_within(path: &str, prefix: &str) -> bool { prefix == "/" || path == prefix || path.strip_prefix(prefix).map(|rest| prefix.ends_with('/') || rest.starts_with('/')).unwrap_or(false) }
fn credential_key(name: &str) -> bool {
    let normalized: String = name.chars().filter(|c| c.is_ascii_alphanumeric()).flat_map(char::to_lowercase).collect();
    matches!(normalized.as_str(), "password" | "passwd" | "passphrase" | "token" | "accesstoken" | "refreshtoken" | "apikey" | "apisecret" | "authorization" | "proxyauthorization" | "cookie" | "setcookie" | "secret" | "clientsecret" | "privatekey" | "keypem" | "certpem" | "totpsecret" | "authcode")
}
fn fixed_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) || credential_key(name) { return Err("fixed parameters cannot contain credential material".into()); }
    Ok(())
}
fn validate_fixed_value(value: &Value, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH { return Err("fixed body is too deeply nested".into()); }
    match value {
        Value::String(text) => {
            if text.len() > MAX_LENGTH as usize { return Err("fixed body string is too long".into()); }
            if text.contains("-----BEGIN ") || text.starts_with("Bearer ") || text.starts_with("Basic ") { return Err("fixed parameters cannot contain credential material".into()); }
        }
        Value::Array(items) => { if items.len() > MAX_ITEMS as usize { return Err("fixed body array is too long".into()); } for item in items { validate_fixed_value(item, depth + 1)?; } }
        Value::Object(items) => { if items.len() > MAX_PROPERTIES { return Err("too many fixed body properties".into()); } for (name, value) in items { fixed_name(name)?; validate_fixed_value(value, depth + 1)?; } }
        _ => {}
    }
    Ok(())
}
fn validate_schema(schema: &Value) -> Result<(), String> { let mut nodes = 0; schema_node(schema, 0, &mut nodes) }
fn schema_node(schema: &Value, depth: usize, nodes: &mut usize) -> Result<(), String> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES { return Err("params schema is too complex".into()); }
    let object = schema.as_object().ok_or("params schema nodes must be objects")?;
    let kind = object.get("type").and_then(Value::as_str).ok_or("params schema requires a single type")?;
    let extra: &[&str] = match kind {
        "object" => &["properties", "required", "additionalProperties"], "string" => &["minLength", "maxLength"],
        "number" | "integer" => &["minimum", "maximum"], "boolean" => &[], "array" => &["items", "minItems", "maxItems"],
        _ => return Err("unsupported params schema type".into()),
    };
    if object.keys().any(|key| !["type", "title", "description", "default", "enum"].contains(&key.as_str()) && !extra.contains(&key.as_str())) { return Err("unsupported params schema keyword".into()); }
    for key in ["title", "description"] { if let Some(value) = object.get(key) { text(value.as_str().ok_or("schema annotation must be a string")?, 4096, true)?; } }
    match kind {
        "object" => {
            if object.get("additionalProperties") != Some(&Value::Bool(false)) { return Err("params schema objects must be closed".into()); }
            let props = object.get("properties").map(|p| p.as_object().ok_or("schema properties must be an object")).transpose()?;
            if props.map(Map::len).unwrap_or(0) > MAX_PROPERTIES { return Err("too many schema properties".into()); }
            if let Some(props) = props {
                for (name, child) in props {
                    if !identifier(name, false) { return Err("invalid schema property name".into()); }
                    schema_node(child, depth + 1, nodes)?;
                    if credential_key(name) && (child.get("default").is_some() || child.get("enum").is_some()) { return Err("schema cannot embed credential defaults or enums".into()); }
                }
            }
            if let Some(required) = object.get("required") {
                let required = required.as_array().ok_or("schema required must be an array")?;
                let mut seen = BTreeSet::new();
                if required.len() > MAX_PROPERTIES { return Err("too many required properties".into()); }
                for name in required {
                    let name = name.as_str().ok_or("required property names must be strings")?;
                    if !seen.insert(name) || !props.map(|p| p.contains_key(name)).unwrap_or(false) { return Err("required property is undeclared or duplicated".into()); }
                }
            }
        }
        "string" => { if bound(object, "minLength", 0, MAX_LENGTH)? > bound(object, "maxLength", DEFAULT_MAX_LENGTH, MAX_LENGTH)? { return Err("invalid schema string bounds".into()); } }
        "array" => {
            if bound(object, "minItems", 0, MAX_ITEMS)? > bound(object, "maxItems", MAX_ITEMS, MAX_ITEMS)? { return Err("invalid schema array bounds".into()); }
            schema_node(object.get("items").ok_or("array schema requires items")?, depth + 1, nodes)?;
        }
        "number" | "integer" => {
            for key in ["minimum", "maximum"] {
                if let Some(value) = object.get(key) {
                    let number = value.as_f64().filter(|n| n.is_finite() && n.abs() <= 9_007_199_254_740_991.0).ok_or("schema numeric bounds must be within the exact JSON integer range")?;
                    if kind == "integer" && number.fract() != 0.0 { return Err("integer schema bounds must be integral".into()); }
                }
            }
            if let (Some(min), Some(max)) = (object.get("minimum").and_then(Value::as_f64), object.get("maximum").and_then(Value::as_f64)) { if min > max { return Err("invalid schema numeric bounds".into()); } }
        }
        _ => {}
    }
    if let Some(choices) = object.get("enum") {
        let choices = choices.as_array().ok_or("schema enum must be an array")?;
        if choices.is_empty() || choices.len() > 64 || matches!(kind, "object" | "array") { return Err("schema enum must be a bounded scalar list".into()); }
        for (index, value) in choices.iter().enumerate() { if choices[..index].contains(value) { return Err("duplicate schema enum value".into()); } validate_instance(schema, value, depth)?; }
    }
    if let Some(value) = object.get("default") { validate_instance(schema, value, depth)?; validate_fixed_value(value, depth)?; }
    Ok(())
}
fn bound(object: &Map<String, Value>, key: &str, default: u64, limit: u64) -> Result<u64, String> {
    let value = object.get(key).map(|v| v.as_u64().ok_or("schema bound must be a nonnegative integer")).transpose()?.unwrap_or(default);
    if value > limit { return Err("schema bound exceeds the safety limit".into()); }
    Ok(value)
}
fn validate_instance(schema: &Value, value: &Value, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH { return Err("operation parameters are too deeply nested".into()); }
    let object = schema.as_object().ok_or("invalid params schema")?;
    let kind = object.get("type").and_then(Value::as_str).ok_or("invalid params schema type")?;
    if let Some(choices) = object.get("enum").and_then(Value::as_array) { if !choices.contains(value) { return Err("parameter is outside its enum".into()); } }
    match kind {
        "object" => {
            let values = value.as_object().ok_or("parameter must be an object")?;
            if values.len() > MAX_PROPERTIES { return Err("too many parameter properties".into()); }
            let props = object.get("properties").and_then(Value::as_object);
            if let Some(required) = object.get("required").and_then(Value::as_array) { for name in required { if !values.contains_key(name.as_str().ok_or("invalid required property")?) { return Err("required parameter is missing".into()); } } }
            for (name, value) in values { validate_instance(props.and_then(|p| p.get(name)).ok_or("undeclared operation parameter")?, value, depth + 1)?; }
        }
        "string" => {
            let text = value.as_str().ok_or("parameter must be a string")?;
            let length = text.chars().count() as u64;
            if length < bound(object, "minLength", 0, MAX_LENGTH)? || length > bound(object, "maxLength", DEFAULT_MAX_LENGTH, MAX_LENGTH)? || text.contains('\0') { return Err("parameter string is outside its bounds".into()); }
        }
        "array" => {
            let items = value.as_array().ok_or("parameter must be an array")?;
            if (items.len() as u64) < bound(object, "minItems", 0, MAX_ITEMS)? || (items.len() as u64) > bound(object, "maxItems", MAX_ITEMS, MAX_ITEMS)? { return Err("parameter array is outside its bounds".into()); }
            for item in items { validate_instance(object.get("items").ok_or("invalid array schema")?, item, depth + 1)?; }
        }
        "integer" | "number" => {
            if kind == "integer" && !value.is_i64() && !value.is_u64() { return Err("parameter must be an integer".into()); }
            let number = value.as_f64().filter(|n| n.is_finite() && n.abs() <= 9_007_199_254_740_991.0).ok_or("numeric parameter exceeds the exact JSON integer range")?;
            if object.get("minimum").and_then(Value::as_f64).map(|min| number < min).unwrap_or(false) || object.get("maximum").and_then(Value::as_f64).map(|max| number > max).unwrap_or(false) { return Err("numeric parameter is outside its bounds".into()); }
        }
        "boolean" => if !value.is_boolean() { return Err("parameter must be a boolean".into()); },
        _ => return Err("unsupported params schema type".into()),
    }
    Ok(())
}
/// Check the profile against the actual credential before exposing it as metadata.
pub(crate) fn validate_for_secret(profile: &CredentialProfile, secret: &crate::vault::SecretPayload) -> Result<(), String> {
    use crate::vault::SecretPayload;
    validate_profile(profile)?;
    match profile.auth.kind.as_str() {
        "bearer" | "header" => if !matches!(secret, SecretPayload::ApiToken { .. }) { return Err("authentication requires an API token credential".into()); },
        "basic" => {
            let account = match secret {
                SecretPayload::ApiToken { account, .. } => account.as_deref(),
                SecretPayload::Website { username, .. } => username.as_deref(),
                SecretPayload::Server { username, .. } | SecretPayload::Database { username, .. } => Some(username.as_str()),
                SecretPayload::Mailbox { email, .. } | SecretPayload::MailAuth { email, .. } => Some(email.as_str()),
                _ => None,
            }.ok_or("basic authentication requires an account credential")?;
            if account.trim().is_empty() || account.contains(':') || account.chars().any(char::is_control) { return Err("invalid basic authentication account".into()); }
        }
        "mtls" => if profile.auth.client_cert_id.is_none() && !matches!(secret, SecretPayload::ClientCert { .. }) { return Err("mTLS requires a client certificate credential or reference".into()); },
        _ => return Err("unsupported profile authentication".into()),
    }
    if let SecretPayload::ApiToken { service, .. } = secret {
        if service.trim().eq_ignore_ascii_case("github") && profile.origin != "https://api.github.com" { return Err("GitHub credentials require exactly https://api.github.com".into()); }
    }
    reject_embedded_secret(profile, secret)
}

pub(crate) fn reject_embedded_secret(profile: &CredentialProfile, secret: &crate::vault::SecretPayload) -> Result<(), String> {
    use crate::vault::SecretPayload;
    use base64::Engine;
    let mut values: Vec<&str> = Vec::new();
    let mut basic: Option<(&str, &str)> = None;
    match secret {
        SecretPayload::Website { username, password, totp_secret, .. } => { values.push(password); values.extend(totp_secret.as_deref()); basic = username.as_deref().map(|a| (a, password.as_str())); }
        SecretPayload::ApiToken { account, token, .. } => { values.push(token); basic = account.as_deref().map(|a| (a, token.as_str())); }
        SecretPayload::Ssh { private_key, passphrase, .. } => { values.push(private_key); values.extend(passphrase.as_deref()); }
        SecretPayload::Mailbox { email, password, .. } => { values.push(password); basic = Some((email, password)); }
        SecretPayload::MailAuth { email, auth_code, .. } => { values.push(auth_code); basic = Some((email, auth_code)); }
        SecretPayload::Server { username, password, .. } | SecretPayload::Database { username, password, .. } => { values.push(password); basic = Some((username, password)); }
        SecretPayload::ClientCert { key_pem, passphrase, .. } => { values.push(key_pem); values.extend(passphrase.as_deref()); }
    }
    let encoded = basic.map(|(account, password)| zeroize::Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(format!("{account}:{password}"))));
    if let Some(encoded) = &encoded { values.push(encoded.as_str()); }
    fn contains(value: &Value, needles: &[&str]) -> bool {
        match value {
            Value::String(text) => needles.iter().any(|s| !s.is_empty() && (text == s || (s.len() >= 4 && text.contains(s)))),
            Value::Array(items) => items.iter().any(|v| contains(v, needles)),
            Value::Object(items) => items.iter().any(|(key, v)| needles.iter().any(|s| !s.is_empty() && (key == s || (s.len() >= 4 && key.contains(s)))) || contains(v, needles)),
            _ => false,
        }
    }
    if contains(&serde_json::to_value(profile).map_err(|_| "profile encoding failed")?, &values) { return Err("profile cannot contain plaintext credential material".into()); }
    Ok(())
}

pub(crate) fn open_profile_blob(dek: &[u8; 32], blob: &[u8], secret: &crate::vault::SecretPayload) -> Result<CredentialProfile, crate::vault::VaultError> {
    use crate::crypto::{decrypt, Encrypted};
    use crate::vault::VaultError;
    if blob.len() > MAX_PROFILE_BYTES + 28 { return Err(VaultError::InvalidProfile("profile is too large".into())); }
    let plain = zeroize::Zeroizing::new(decrypt(dek, &Encrypted::from_bytes(blob)?)?);
    let profile: CredentialProfile = serde_json::from_slice(&plain).map_err(|_| VaultError::InvalidProfile("invalid stored profile".into()))?;
    validate_for_secret(&profile, secret).map_err(VaultError::InvalidProfile)?;
    Ok(profile)
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn example() -> CredentialProfile {
        serde_json::from_value(json!({"service":"Custom service","origin":"https://api.example.com","auth":{"kind":"bearer"},
            "allowed_methods":["GET"],"allowed_path_prefixes":["/v1"],
            "operations":[{"name":"item_get","description":"Read one item","method":"GET","path_template":"/v1/items/{id}",
            "params":{"type":"object","properties":{"id":{"type":"string","minLength":1,"maxLength":64},"limit":{"type":"integer","minimum":1,"maximum":100,"default":10}},"required":["id"],"additionalProperties":false},
            "query_params":["limit"],"risk":"low","read_only":true}]})).unwrap()
    }

    #[test]
    fn defaults_roundtrip_and_unknown_secret_fields() {
        let p = example(); assert_eq!(p.version, 1); assert_eq!(p.adapter, "http"); assert_eq!(p.auth.header_name, None);
        assert!(p.operations[0].fixed_query.is_empty()); assert!(p.operations[0].body_params.is_empty()); validate_profile(&p).unwrap();
        assert_eq!(serde_json::from_slice::<CredentialProfile>(&serde_json::to_vec(&p).unwrap()).unwrap(), p);
        let p: CredentialProfile = serde_json::from_value(json!({"service":"custom","origin":"https://api.example.com","auth":{"kind":"mtls"}})).unwrap();
        assert!(p.operations.is_empty()); assert!(p.allowed_methods.is_empty()); assert!(p.allowed_path_prefixes.is_empty());
        for key in ["token", "password", "secret", "private_key"] {
            let mut v = serde_json::to_value(example()).unwrap(); v["auth"][key] = json!("not-allowed"); assert!(serde_json::from_value::<CredentialProfile>(v).is_err());
        }
    }

    #[test]
    fn origins_are_exact_https_and_github_is_pinned() {
        for origin in ["http://api.example.com","https://api.example.com/","https://api.example.com/path","https://u:p@api.example.com","https://api.example.com?q=1","https://api.example.com#x","https://api.example.com\\x","https://api.example.com%2f","https://api.example.com:0","https://api.example.com:","https://api.example.com:bad","https://api.example.com.","https://api.example.com\n","https://127.0.0.1","https://localhost"] {
            let mut p = example(); p.origin = origin.into(); assert!(validate_profile(&p).is_err());
        }
        let mut p = example(); p.adapter = "github".into(); assert!(validate_profile(&p).is_err()); p.origin = "https://api.github.com".into(); validate_profile(&p).unwrap();
        for origin in ["https://github.com","https://api.github.com:443","https://api.github.com.attacker.test"] { p.origin = origin.into(); assert!(validate_profile(&p).is_err()); }
    }

    #[test]
    fn paths_methods_and_undeclared_templates_fail_closed() {
        for path in ["//evil.test/x","/v1//x","/v1/./x","/v1/../x","/v1/%2e%2e/x","/v1/x\\y","/v1/x?q=1","/v1/x#frag","/v1/\nx","/v1/{missing}","/v1/{id}.json","/v1/{id","/v10/items/{id}"] {
            let mut p = example(); p.operations[0].path_template = path.into(); assert!(validate_profile(&p).is_err());
        }
        let mut p = example(); p.operations[0].method = "DELETE".into(); assert!(validate_profile(&p).is_err()); p.allowed_methods.push("DELETE".into()); assert!(validate_profile(&p).is_err()); p.operations[0].read_only = false; validate_profile(&p).unwrap();
        p.allowed_methods.push("TRACE".into()); assert!(validate_profile(&p).is_err());
        let mut p = example(); p.operations[0].params["required"] = json!([]); assert!(validate_profile(&p).is_err());
        let mut p = example(); p.operations[0].query_params.push("id".into()); assert!(validate_profile(&p).is_err());
        let mut p = example(); p.operations.push(p.operations[0].clone()); assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn unsafe_auth_headers_prefixes_and_fixed_secrets_are_rejected() {
        for name in ["Host","Cookie","Proxy-Authorization","Content-Length","Transfer-Encoding","Connection","Sec-Fetch-Site","X-Forwarded-Host","X-HTTP-Method-Override","Authorization\r\nHost","bad header"] {
            let mut p = example(); p.auth.header_name = Some(name.into()); assert!(validate_profile(&p).is_err());
        }
        let mut p = example(); p.auth.prefix = Some("Bearer \r\nHost: evil.test".into()); assert!(validate_profile(&p).is_err());
        let mut p = example(); p.auth.kind = "header".into(); p.auth.header_name = Some("X-Api-Key".into()); p.auth.prefix = Some("Token ".into()); validate_profile(&p).unwrap();
        p.auth.client_cert_id = Some("client-certificate".into()); p.auth.ca_bundle_path = Some("ca.pem".into()); validate_profile(&p).unwrap();
        let mut p = example(); p.operations[0].fixed_query.insert("api_key".into(), "secret".into()); assert!(validate_profile(&p).is_err());
        let mut p = example(); p.allowed_methods.push("POST".into()); p.operations[0].method = "POST".into(); p.operations[0].read_only = false;
        p.operations[0].fixed_body.insert("config".into(), json!({"nested":{"password":"secret"}})); assert!(validate_profile(&p).is_err());
    }

    #[test]
    fn only_bounded_closed_schemas_are_accepted() {
        for s in [json!({"type":"object"}),json!({"type":"object","additionalProperties":true}),json!({"type":"object","additionalProperties":false,"$ref":"https://example.com/s"}),json!({"type":"object","properties":{"id":{"type":"string","pattern":".*"}},"additionalProperties":false}),json!({"type":"object","properties":{"id":{"type":"string","maxLength":65537}},"additionalProperties":false}),json!({"type":"object","properties":{"id":{"type":"array","items":{"type":"string"},"maxItems":101}},"additionalProperties":false}),json!({"type":"object","properties":{},"required":["nope"],"additionalProperties":false}),json!({"type":"object","properties":{"id":{"type":"string","enum":[1]}},"additionalProperties":false})] { assert!(validate_schema(&s).is_err()); }
        let mut s = json!({"type":"string"}); for _ in 0..8 { s = json!({"type":"array","items":s}); } assert!(validate_schema(&s).is_err());
        let mut s = example().operations.remove(0).params; s["properties"]["limit"]["maximum"] = json!(9007199254740992u64); assert!(validate_schema(&s).is_err());
    }

    #[test]
    fn arguments_enforce_types_bounds_enums_required_and_nested_closure() {
        let mut op = example().operations.remove(0);
        op.params = json!({"type":"object","properties":{"title":{"type":"string","minLength":1,"maxLength":3,"enum":["你好","yes"]},"count":{"type":"integer","minimum":1,"maximum":3},"ratio":{"type":"number","minimum":0,"maximum":1},"active":{"type":"boolean"},"items":{"type":"array","maxItems":2,"items":{"type":"object","properties":{"name":{"type":"string"}},"additionalProperties":false}}},"required":["title","count"],"additionalProperties":false});
        validate_operation_params(&op, &json!({"title":"你好","count":2,"ratio":0.5,"active":true,"items":[{"name":"item"}]})).unwrap();
        for p in [json!({"title":"yes"}),json!({"title":"bad","count":2}),json!({"title":"yes","count":1.5}),json!({"title":"yes","count":4}),json!({"title":"yes","count":2,"ratio":2}),json!({"title":"yes","count":2,"active":"true"}),json!({"title":"yes","count":2,"extra":1}),json!({"title":"yes","count":2,"items":[{"unknown":true}]}),json!({"title":"yes","count":2,"items":[{},{},{}]}),json!({"title":"yes","count":9007199254740993u64})] { assert!(validate_operation_params(&op, &p).is_err()); }
        op.params = json!({"type":"object","properties":{"text":{"type":"string"}},"additionalProperties":false});
        assert!(validate_operation_params(&op, &json!({"text":"x".repeat(8193)})).is_err()); op.params["properties"]["text"]["maxLength"] = json!(65536);
        validate_operation_params(&op, &json!({"text":"x".repeat(65536)})).unwrap();
    }
}
