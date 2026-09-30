use crate::confirm::{self, ConfirmField, ConfirmPayload};
use crate::http_guard::{assert_public_target, parse_http_url, sha256_hex, PublicResolver};
use crate::redact::redact_text;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const API: &str = "https://api.github.com";
const UPLOADS: &str = "https://uploads.github.com";
const MAX_JSON: usize = 512 * 1024;
const MAX_REQUEST: usize = 128 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

pub enum Body {
    Json(Value),
    Octet {
        content_type: String,
        bytes: Vec<u8>,
    },
}

pub struct Call {
    pub method: Method,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<Body>,
    pub ok: &'static [u16],
    pub allow_missing_confirm: bool,
}

pub struct Confirm {
    pub title: String,
    pub prompt: String,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct Saved {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
}

pub struct HttpReply {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Clone)]
pub struct Captured {
    pub method: String,
    pub url: String,
    pub authorization: String,
    pub body: Vec<u8>,
}

pub struct Github {
    token: String,
    #[allow(dead_code)]
    label: String,
}

type ReplyFn = dyn FnMut(&Captured) -> Result<HttpReply, String> + Send;

thread_local! {
    static PROBE: RefCell<Option<ProbeSlot>> = const { RefCell::new(None) };
    static PROBE_GEN: Cell<u64> = const { Cell::new(0) };
}

struct ProbeSlot {
    generation: u64,
    reply: Box<ReplyFn>,
    calls: Vec<Captured>,
}

/// Records outbound GitHub calls and supplies canned replies. Tests install one
/// on the current thread so `exchange` never opens a socket.
pub struct TransportProbe {
    generation: u64,
}

impl TransportProbe {
    pub fn install<F>(reply: F) -> Self
    where
        F: FnMut(&Captured) -> Result<HttpReply, String> + Send + 'static,
    {
        let generation = PROBE_GEN.with(|gen| {
            let next = gen.get().wrapping_add(1);
            gen.set(next);
            next
        });
        PROBE.with(|slot| {
            *slot.borrow_mut() = Some(ProbeSlot {
                generation,
                reply: Box::new(reply),
                calls: Vec::new(),
            });
        });
        Self { generation }
    }

    pub fn calls(&self) -> Vec<Captured> {
        PROBE.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|probe| probe.calls.clone())
                .unwrap_or_default()
        })
    }
}

impl Drop for TransportProbe {
    fn drop(&mut self) {
        PROBE.with(|slot| {
            let current = slot.borrow().as_ref().map(|probe| probe.generation);
            if current == Some(self.generation) {
                *slot.borrow_mut() = None;
            }
        });
    }
}

impl Github {
    pub fn open(token: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            label: label.into(),
        }
    }

    #[cfg(test)]
    pub fn open_for_test(token: impl Into<String>, label: impl Into<String>) -> Self {
        Self::open(token, label)
    }

    pub fn get(
        &self,
        path: &str,
        query: Vec<(String, String)>,
    ) -> Result<(u16, Value), String> {
        self.send(
            &Call {
                method: Method::Get,
                path: path.to_string(),
                query,
                body: None,
                ok: &[200],
                allow_missing_confirm: true,
            },
            None,
        )
    }

    pub fn send(&self, call: &Call, confirm: Option<&Confirm>) -> Result<(u16, Value), String> {
        let url = pinned_url(API, "api.github.com", &call.path, &call.query)?;
        self.exchange_json(call, confirm, &url)
    }

    pub fn upload(
        &self,
        file: &Path,
        path: &str,
        content_type: &str,
        ok: &'static [u16],
        confirm: Option<&Confirm>,
    ) -> Result<(u16, Value), String> {
        if !file.is_absolute() {
            return Err("上传文件必须是绝对路径".into());
        }
        let meta = std::fs::metadata(file).map_err(|e| format!("无法读取上传文件: {e}"))?;
        if !meta.is_file() {
            return Err("上传目标必须是普通文件".into());
        }
        let bytes = std::fs::read(file).map_err(|e| format!("无法读取上传文件: {e}"))?;
        self.upload_bytes(path, content_type, bytes, ok, confirm)
    }

    pub fn upload_bytes(
        &self,
        path: &str,
        content_type: &str,
        bytes: Vec<u8>,
        ok: &'static [u16],
        confirm: Option<&Confirm>,
    ) -> Result<(u16, Value), String> {
        let url = pinned_url(UPLOADS, "uploads.github.com", path, &[])?;
        let call = Call {
            method: Method::Post,
            path: path.to_string(),
            query: Vec::new(),
            body: Some(Body::Octet {
                content_type: content_type.to_string(),
                bytes,
            }),
            ok,
            allow_missing_confirm: false,
        };
        self.exchange_json(&call, confirm, &url)
    }

    pub fn download(
        &self,
        path: &str,
        query: Vec<(String, String)>,
        dest: &Path,
        cap: u64,
        confirm: Option<&Confirm>,
    ) -> Result<Saved, String> {
        if dest.exists() {
            return Err("目标文件已存在".into());
        }
        let url = pinned_url(API, "api.github.com", path, &query)?;
        let call = Call {
            method: Method::Get,
            path: path.to_string(),
            query,
            body: None,
            ok: &[200],
            allow_missing_confirm: true,
        };
        self.require_confirm(&call, confirm)?;
        let temp = dest.with_extension("part");
        let saved = match stream_download(&self.token, &url, &temp, cap) {
            Ok(saved) => saved,
            Err(error) => {
                let _ = std::fs::remove_file(&temp);
                return Err(error);
            }
        };
        if let Err(error) = std::fs::rename(&temp, dest) {
            let _ = std::fs::remove_file(&temp);
            return Err(format!("无法保存下载文件: {error}"));
        }
        Ok(Saved {
            path: dest.to_path_buf(),
            bytes: saved.bytes,
            sha256: saved.sha256,
        })
    }

    fn exchange_json(
        &self,
        call: &Call,
        confirm: Option<&Confirm>,
        url: &str,
    ) -> Result<(u16, Value), String> {
        self.require_confirm(call, confirm)?;
        let encoded = encode_body(&call.body)?;
        let reply = exchange(&self.token, call.method, url, encoded.as_ref())?;
        if !call.ok.contains(&reply.status) {
            return Err(http_error(reply.status, &reply.body, &self.token));
        }
        parse_ok_json(reply.status, &reply.body, &self.token)
    }

    fn require_confirm(&self, call: &Call, confirm: Option<&Confirm>) -> Result<(), String> {
        if call.method != Method::Get && !call.allow_missing_confirm && confirm.is_none() {
            return Err("缺少确认".into());
        }
        if let Some(confirm) = confirm {
            let allowed = confirm::ask_payload(&ConfirmPayload {
                title: confirm.title.clone(),
                prompt: confirm.prompt.clone(),
                fields: confirm
                    .fields
                    .iter()
                    .map(|(label, value)| ConfirmField {
                        label: label.clone(),
                        value: value.clone(),
                    })
                    .collect(),
            });
            if !allowed {
                return Err("用户拒绝了这次 GitHub 写操作".into());
            }
        }
        Ok(())
    }
}

struct EncodedBody {
    content_type: String,
    bytes: Vec<u8>,
}

fn encode_body(body: &Option<Body>) -> Result<Option<EncodedBody>, String> {
    let Some(body) = body else {
        return Ok(None);
    };
    let encoded = match body {
        Body::Json(value) => {
            let bytes = serde_json::to_vec(value).map_err(|e| format!("无法编码 JSON: {e}"))?;
            if bytes.len() > MAX_REQUEST {
                return Err(format!("请求体超过 {MAX_REQUEST} 字节"));
            }
            EncodedBody {
                content_type: "application/json".into(),
                bytes,
            }
        }
        Body::Octet {
            content_type,
            bytes,
        } => EncodedBody {
            content_type: content_type.clone(),
            bytes: bytes.clone(),
        },
    };
    Ok(Some(encoded))
}

fn pinned_url(
    origin: &str,
    host: &str,
    path: &str,
    query: &[(String, String)],
) -> Result<String, String> {
    validate_path(path)?;
    let mut url = format!("{origin}{path}");
    if !query.is_empty() && !path.contains('?') {
        url.push('?');
        url.push_str(&encode_query(query));
    } else if !query.is_empty() {
        url.push('&');
        url.push_str(&encode_query(query));
    }
    let target = parse_http_url(&url, true)?;
    assert_public_target(&target)?;
    if target.scheme != "https" || target.host != host || target.port != 443 {
        return Err("GitHub 地址不合法".into());
    }
    Ok(url)
}

fn validate_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') || path.contains("://") || path.contains("..") || path.contains('\\') || path.contains('@')
    {
        return Err("GitHub 路径不合法".into());
    }
    Ok(())
}

fn encode_query(query: &[(String, String)]) -> String {
    query
        .iter()
        .map(|(key, value)| format!("{}={}", encode_component(key), encode_component(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode_component(raw: &str) -> String {
    let mut out = String::new();
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn exchange(
    token: &str,
    method: Method,
    url: &str,
    body: Option<&EncodedBody>,
) -> Result<HttpReply, String> {
    if let Some(reply) = probe_exchange(token, method, url, body) {
        return reply;
    }
    let agent = ureq::builder()
        .redirects(0)
        .timeout(Duration::from_secs(15))
        .timeout_connect(Duration::from_secs(8))
        .resolver(PublicResolver)
        .user_agent(concat!("Sealbox/", env!("CARGO_PKG_VERSION")))
        .build();
    let mut request = agent
        .request(method_name(method), url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28");
    let response = if let Some(body) = body {
        request = request.set("Content-Type", &body.content_type);
        request.send_bytes(&body.bytes)
    } else {
        request.call()
    };
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(error) => return Err(redact_text(&format!("GitHub 请求失败: {error}"), &[token])),
    };
    let status = response.status();
    let bytes = read_limited(response, MAX_JSON);
    Ok(HttpReply {
        status,
        body: bytes,
    })
}

fn probe_exchange(
    token: &str,
    method: Method,
    url: &str,
    body: Option<&EncodedBody>,
) -> Option<Result<HttpReply, String>> {
    PROBE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let probe = slot.as_mut()?;
        let captured = Captured {
            method: method_name(method).to_string(),
            url: url.to_string(),
            authorization: format!("Bearer {token}"),
            body: body.map(|item| item.bytes.clone()).unwrap_or_default(),
        };
        let reply = (probe.reply)(&captured);
        if reply.is_ok() {
            probe.calls.push(captured);
        }
        Some(reply)
    })
}

fn method_name(method: Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Patch => "PATCH",
        Method::Delete => "DELETE",
    }
}

fn read_limited(response: ureq::Response, max: usize) -> Vec<u8> {
    let mut reader = response.into_reader().take(max as u64);
    let mut body = Vec::new();
    let _ = reader.read_to_end(&mut body);
    body
}

fn parse_ok_json(status: u16, body: &[u8], token: &str) -> Result<(u16, Value), String> {
    if status == 204 || body.is_empty() {
        return Ok((status, Value::Null));
    }
    let text = String::from_utf8_lossy(body);
    let redacted = if token.is_empty() {
        text.into_owned()
    } else {
        text.replace(token, "***")
    };
    match serde_json::from_str::<Value>(&redacted) {
        Ok(value) => Ok((status, value)),
        Err(_) => Err("GitHub 返回了无效 JSON".into()),
    }
}

fn http_error(status: u16, body: &[u8], token: &str) -> String {
    let message = extract_message(body);
    let message = truncate_utf8(&message, 240);
    redact_text(&format!("GitHub HTTP {status}: {message}"), &[token])
}

fn extract_message(body: &[u8]) -> String {
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        if let Some(message) = value.get("message").and_then(Value::as_str) {
            return message.to_string();
        }
    }
    String::from_utf8_lossy(body).into_owned()
}

fn truncate_utf8(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

struct Streamed {
    bytes: u64,
    sha256: String,
}

fn stream_download(token: &str, url: &str, temp: &Path, cap: u64) -> Result<Streamed, String> {
    if let Some(reply) = probe_exchange(token, Method::Get, url, None) {
        let reply = reply?;
        if reply.status != 200 {
            return Err(http_error(reply.status, &reply.body, token));
        }
        if reply.body.len() as u64 > cap {
            return Err(format!("下载超过 {cap} 字节上限"));
        }
        let digest = sha256_hex(&reply.body);
        let saved = write_capped(temp, &reply.body, cap)?;
        return Ok(Streamed {
            bytes: saved.bytes,
            sha256: digest,
        });
    }
    let agent = ureq::builder()
        .redirects(0)
        .timeout(Duration::from_secs(15))
        .timeout_connect(Duration::from_secs(8))
        .resolver(PublicResolver)
        .user_agent(concat!("Sealbox/", env!("CARGO_PKG_VERSION")))
        .build();
    let response = agent
        .request("GET", url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .call();
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(error) => return Err(redact_text(&format!("GitHub 请求失败: {error}"), &[token])),
    };
    if response.status() != 200 {
        let status = response.status();
        let body = read_limited(response, MAX_JSON);
        return Err(http_error(status, &body, token));
    }
    if let Some(parent) = temp.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("无法创建下载目录: {e}"))?;
        }
    }
    let mut file = std::fs::File::create(temp).map_err(|e| format!("无法写入下载文件: {e}"))?;
    let mut reader = response.into_reader();
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut buffer)
            .map_err(|e| format!("无法读取下载: {e}"))?;
        if n == 0 {
            break;
        }
        let next = written.saturating_add(n as u64);
        if next > cap {
            return Err(format!("下载超过 {cap} 字节上限"));
        }
        file.write_all(&buffer[..n])
            .map_err(|e| format!("无法写入下载文件: {e}"))?;
        hasher.update(&buffer[..n]);
        written = next;
    }
    file.flush()
        .map_err(|e| format!("无法写入下载文件: {e}"))?;
    Ok(Streamed {
        bytes: written,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn write_capped(temp: &Path, body: &[u8], cap: u64) -> Result<Streamed, String> {
    if body.len() as u64 > cap {
        return Err(format!("下载超过 {cap} 字节上限"));
    }
    if let Some(parent) = temp.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("无法创建下载目录: {e}"))?;
        }
    }
    let mut file = std::fs::File::create(temp).map_err(|e| format!("无法写入下载文件: {e}"))?;
    let mut written = 0u64;
    let mut hasher = Sha256::new();
    for chunk in body.chunks(8192) {
        let next = written.saturating_add(chunk.len() as u64);
        if next > cap {
            return Err(format!("下载超过 {cap} 字节上限"));
        }
        file.write_all(chunk)
            .map_err(|e| format!("无法写入下载文件: {e}"))?;
        hasher.update(chunk);
        written = next;
    }
    file.flush()
        .map_err(|e| format!("无法写入下载文件: {e}"))?;
    Ok(Streamed {
        bytes: written,
        sha256: hex::encode(hasher.finalize()),
    })
}

#[cfg(test)]
fn sample_post() -> Call {
    Call {
        method: Method::Post,
        path: "/repos/a/b/issues".into(),
        query: Vec::new(),
        body: Some(Body::Json(serde_json::json!({"title": "hi"}))),
        ok: &[201],
        allow_missing_confirm: false,
    }
}

#[cfg(test)]
fn sample_confirm() -> Confirm {
    Confirm {
        title: "GitHub".into(),
        prompt: "确认写入".into(),
        fields: vec![("仓库".into(), "a/b".into())],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> &'static str {
        "ghp_testtoken"
    }

    #[test]
    fn get_does_not_confirm_and_returns_json() {
        confirm::with_auto(Some(false), || {
            let probe = TransportProbe::install(|_captured| {
                Ok(HttpReply {
                    status: 200,
                    body: br#"{"login":"octo","token":"ghp_testtoken"}"#.to_vec(),
                })
            });
            let github = Github::open_for_test(token(), "work");
            let (status, value) = github.get("/user", Vec::new()).unwrap();
            assert_eq!(status, 200);
            assert_eq!(value["login"], "octo");
            let rendered = value.to_string();
            assert!(!rendered.contains(token()));
            let calls = probe.calls();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].method, "GET");
            assert_eq!(calls[0].url, "https://api.github.com/user");
            assert!(calls[0].authorization.ends_with(token()));
        });
    }

    #[test]
    fn write_without_confirm_makes_no_request() {
        let probe = TransportProbe::install(|_captured| unreachable!("transport must not run"));
        let github = Github::open_for_test(token(), "work");
        let error = github.send(&sample_post(), None).unwrap_err();
        assert!(error.contains("缺少确认"), "{error}");
        assert!(probe.calls().is_empty());
    }

    #[test]
    fn denied_confirm_makes_no_request() {
        confirm::with_auto(Some(false), || {
            let probe = TransportProbe::install(|_captured| unreachable!("transport must not run"));
            let github = Github::open_for_test(token(), "work");
            let confirm = sample_confirm();
            let error = github.send(&sample_post(), Some(&confirm)).unwrap_err();
            assert!(error.contains("用户拒绝"), "{error}");
            assert!(probe.calls().is_empty());
        });
    }

    #[test]
    fn send_cannot_select_uploads_host() {
        confirm::with_auto(Some(true), || {
            let probe = TransportProbe::install(|captured| {
                assert!(captured.url.starts_with("https://api.github.com/"));
                Ok(HttpReply {
                    status: 201,
                    body: b"{}".to_vec(),
                })
            });
            let github = Github::open_for_test(token(), "work");
            let confirm = sample_confirm();
            let (status, _) = github.send(&sample_post(), Some(&confirm)).unwrap();
            assert_eq!(status, 201);
            assert_eq!(probe.calls().len(), 1);

            let probe = TransportProbe::install(|_captured| unreachable!("transport must not run"));
            let mut evil = sample_post();
            evil.path = "/uploads.github.com/repos/a/b".into();
            // A path may mention the uploads host as text, but send still pins api.github.com.
            // A scheme or an absolute URL must be rejected with no transport call.
            evil.path = "https://uploads.github.com/repos/a/b".into();
            let error = github.send(&evil, Some(&confirm)).unwrap_err();
            assert!(error.contains("不合法"), "{error}");
            assert!(probe.calls().is_empty());
        });
    }

    #[test]
    fn upload_targets_uploads_host() {
        confirm::with_auto(Some(true), || {
            let probe = TransportProbe::install(|captured| {
                assert!(captured.url.starts_with("https://uploads.github.com/"));
                assert_eq!(captured.body, b"hi");
                Ok(HttpReply {
                    status: 201,
                    body: b"{}".to_vec(),
                })
            });
            let github = Github::open_for_test(token(), "work");
            let confirm = sample_confirm();
            let (status, _) = github
                .upload_bytes(
                    "/repos/a/b/releases/1/assets?name=a",
                    "application/octet-stream",
                    b"hi".to_vec(),
                    &[201],
                    Some(&confirm),
                )
                .unwrap();
            assert_eq!(status, 201);
            assert_eq!(probe.calls().len(), 1);
        });
    }

    #[test]
    fn absolute_url_never_reaches_transport() {
        let probe = TransportProbe::install(|_captured| unreachable!("transport must not run"));
        let github = Github::open_for_test(token(), "work");
        let error = github
            .get("https://evil.example/user", Vec::new())
            .unwrap_err();
        assert!(error.contains("不合法"), "{error}");
        assert!(probe.calls().is_empty());
    }

    #[test]
    fn error_body_redacts_token() {
        let probe = TransportProbe::install(|_captured| {
            Ok(HttpReply {
                status: 404,
                body: br#"{"message":"nope ghp_testtoken"}"#.to_vec(),
            })
        });
        let github = Github::open_for_test(token(), "work");
        let error = github.get("/user", Vec::new()).unwrap_err();
        assert!(!error.contains(token()), "{error}");
        assert!(error.contains("GitHub HTTP 404"), "{error}");
        assert_eq!(probe.calls().len(), 1);
    }

    #[test]
    fn download_refuses_existing_and_cleans_overflow() {
        let dir = std::env::temp_dir().join(format!(
            "sealbox-gh-dl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let existing = dir.join("logs.zip");
        std::fs::write(&existing, b"already").unwrap();
        let probe = TransportProbe::install(|_captured| unreachable!("transport must not run"));
        let github = Github::open_for_test(token(), "work");
        let error = github
            .download("/repos/a/b/actions/runs/1/logs", Vec::new(), &existing, 100, None)
            .unwrap_err();
        assert!(error.contains("已存在"), "{error}");
        assert!(probe.calls().is_empty());
        assert!(existing.is_file());

        let dest = dir.join("fresh.zip");
        let probe = TransportProbe::install(|_captured| {
            Ok(HttpReply {
                status: 200,
                body: b"0123456789".to_vec(),
            })
        });
        let error = github
            .download("/repos/a/b/actions/runs/1/logs", Vec::new(), &dest, 4, None)
            .unwrap_err();
        assert!(error.contains("超过"), "{error}");
        assert!(!dest.exists());
        assert!(!dest.with_extension("part").exists());
        assert_eq!(probe.calls().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_204_is_null_and_oversized_json_skips_transport() {
        let probe = TransportProbe::install(|_captured| {
            Ok(HttpReply {
                status: 204,
                body: Vec::new(),
            })
        });
        let github = Github::open_for_test(token(), "work");
        let call = Call {
            method: Method::Get,
            path: "/repos/a/b/subscription".into(),
            query: Vec::new(),
            body: None,
            ok: &[204],
            allow_missing_confirm: true,
        };
        let (status, value) = github.send(&call, None).unwrap();
        assert_eq!(status, 204);
        assert!(value.is_null());
        assert_eq!(probe.calls().len(), 1);

        let probe = TransportProbe::install(|_captured| unreachable!("transport must not run"));
        let huge = "x".repeat(MAX_REQUEST + 1);
        let call = Call {
            method: Method::Post,
            path: "/repos/a/b/issues".into(),
            query: Vec::new(),
            body: Some(Body::Json(Value::String(huge))),
            ok: &[201],
            allow_missing_confirm: false,
        };
        let confirm = sample_confirm();
        let error = confirm::with_auto(Some(true), || github.send(&call, Some(&confirm)).unwrap_err());
        assert!(error.contains("超过") || error.contains(&MAX_REQUEST.to_string()), "{error}");
        assert!(probe.calls().is_empty());
    }
}
