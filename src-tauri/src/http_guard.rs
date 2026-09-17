use crate::vault::SecretPayload;
use sha2::{Digest, Sha256};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Target {
    fn origin_key(&self) -> (String, String, u16) {
        (self.scheme.clone(), normalize_host(&self.host), self.port)
    }
}

pub fn parse_http_url(url: &str, require_scheme: bool) -> Result<Target, String> {
    let u = url.trim();
    if u.is_empty() {
        return Err("url 不能为空".into());
    }
    let (scheme, rest) = if let Some(r) = u.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = u.strip_prefix("http://") {
        ("http", r)
    } else if u.contains("://") || require_scheme {
        return Err("url 必须以 http:// 或 https:// 开头".into());
    } else {
        ("https", u)
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("").trim();
    if authority.is_empty() {
        return Err("url 缺少主机".into());
    }
    if authority.contains('@') {
        return Err("url 不能包含用户名或密码".into());
    }
    let default_port = if scheme == "http" { 80 } else { 443 };
    let (host, port) = parse_authority(authority, default_port)?;
    if host.is_empty() {
        return Err("url 缺少主机".into());
    }
    Ok(Target {
        scheme: scheme.to_string(),
        host,
        port,
    })
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(|| "无效 IPv6 地址".to_string())?;
        let host = rest[..end].to_string();
        let after = &rest[end + 1..];
        let port = if after.is_empty() {
            default_port
        } else {
            let p = after
                .strip_prefix(':')
                .ok_or_else(|| "无效端口".to_string())?;
            parse_port(p)?
        };
        Ok((host, port))
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            Ok((h.to_string(), parse_port(p)?))
        } else {
            Ok((authority.to_string(), default_port))
        }
    } else {
        Ok((authority.to_string(), default_port))
    }
}

fn parse_port(p: &str) -> Result<u16, String> {
    p.parse::<u16>()
        .map_err(|_| "无效端口".to_string())
        .and_then(|n| {
            if n == 0 {
                Err("无效端口".into())
            } else {
                Ok(n)
            }
        })
}

fn normalize_host(host: &str) -> String {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    h.strip_prefix("www.").unwrap_or(&h).to_string()
}

pub fn ip_is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_blocked(v4),
        IpAddr::V6(v6) => ipv6_is_blocked(v6),
    }
}

fn ipv4_is_blocked(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_documentation()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || o == [100, 100, 100, 200]
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
}

fn ipv6_is_blocked(v6: Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4() {
        return ipv4_is_blocked(v4);
    }
    let s = v6.segments();
    if s[0] == 0x2002 {
        let embedded = Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8);
        return ipv4_is_blocked(embedded);
    }
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || v6.is_unique_local()
        || v6.is_unicast_link_local()
        || (s[0] == 0x2001 && s[1] == 0)
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x64 && s[1] == 0xff9b)
        || s == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
}

fn host_is_blocked_name(host: &str) -> bool {
    let h = normalize_host(host);
    if h.is_empty() {
        return true;
    }
    if h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") {
        return true;
    }
    if h == "metadata"
        || h == "metadata.google.internal"
        || h.ends_with(".metadata.google.internal")
        || h.ends_with(".internal")
        || h == "host.docker.internal"
        || h.ends_with(".docker.internal")
    {
        return true;
    }
    if h.parse::<IpAddr>().is_err() && !h.contains('.') {
        return true;
    }
    false
}

fn host_as_ip(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    let labels: Vec<&str> = host.split('.').collect();
    if !labels.is_empty()
        && labels.len() <= 4
        && labels
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        return host.parse::<Ipv4Addr>().ok().map(IpAddr::V4);
    }
    None
}

pub fn assert_public_target(target: &Target) -> Result<(), String> {
    let host = target.host.trim().trim_end_matches('.');
    if host.is_empty() {
        return Err("拒绝访问内网或本机地址".into());
    }
    if host.chars().all(|c| c.is_ascii_digit()) {
        return Err("拒绝访问内网或本机地址".into());
    }
    if host_is_blocked_name(host) {
        return Err("拒绝访问内网或本机地址".into());
    }
    if let Some(ip) = host_as_ip(host) {
        if ip_is_blocked(ip) {
            return Err("拒绝访问内网或本机地址".into());
        }
        return Ok(());
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 4
        && labels
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        return Err("拒绝访问内网或本机地址".into());
    }
    Ok(())
}

pub fn bind_origins(
    payload: &SecretPayload,
    entry_url: Option<&str>,
) -> Result<Vec<Target>, String> {
    match payload {
        SecretPayload::Website { url, .. } => {
            let raw = url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .or_else(|| entry_url.map(str::trim).filter(|s| !s.is_empty()));
            let Some(raw) = raw else {
                return Err("网站凭据没有绑定网址，无法代发 HTTP".into());
            };
            Ok(vec![parse_http_url(raw, false)?])
        }
        SecretPayload::ApiToken { service, .. } => {
            let out = service_origins(service);
            if !out.is_empty() {
                return Ok(out);
            }
            if let Some(raw) = entry_url.map(str::trim).filter(|s| !s.is_empty()) {
                return Ok(vec![parse_http_url(raw, false)?]);
            }
            Err("自定义 Token 需要在条目中填写允许的网址，才能代发 HTTP".into())
        }
        SecretPayload::Ssh { .. } => {
            Err("SSH 凭据不能用于 http_request，请选 API Token 或网站账号".into())
        }
        SecretPayload::MailAuth { .. } => {
            Err("邮箱授权码不能用于 http_request，请选 API Token 或网站账号".into())
        }
        SecretPayload::Mailbox { .. }
        | SecretPayload::Server { .. }
        | SecretPayload::Database { .. }
        | SecretPayload::ClientCert { .. } => {
            Err("该类型凭据不能用于 http_request，请选 API Token 或网站账号".into())
        }
    }
}

fn service_origins(service: &str) -> Vec<Target> {
    let s = service.trim();
    if s.is_empty() {
        return Vec::new();
    }
    if s.contains("://") || s.contains('.') {
        if let Ok(t) = parse_http_url(s, false) {
            return vec![t];
        }
    }
    let hosts: &[&str] = match s.to_ascii_lowercase().as_str() {
        "github" => &["api.github.com", "github.com"],
        "gitee" => &["gitee.com"],
        "gitlab" => &["gitlab.com"],
        "custom" => &[],
        _ => &[],
    };
    hosts
        .iter()
        .filter_map(|h| parse_http_url(&format!("https://{h}"), true).ok())
        .collect()
}

pub fn credential_allows_url(
    payload: &SecretPayload,
    entry_url: Option<&str>,
    url: &str,
) -> Result<(), String> {
    let target = parse_http_url(url, true)?;
    let allowed = bind_origins(payload, entry_url)?;
    if allowed
        .iter()
        .any(|o| o.origin_key() == target.origin_key())
    {
        Ok(())
    } else {
        Err("目标网址与凭据绑定的 origin 不一致，已拒绝注入 Authorization".into())
    }
}

pub fn sha256_hex(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

pub fn summarize_response(status: u16, body: &[u8]) -> String {
    format!(
        "HTTP {status}\nbytes: {}\nsha256: {}\n完整响应只在 Sealbox 窗口的 MCP 页查看，不会返回给模型。",
        body.len(),
        sha256_hex(body)
    )
}

pub struct PublicResolver;

impl ureq::Resolver for PublicResolver {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        resolve_public(netloc)
    }
}

pub fn resolve_public(netloc: &str) -> io::Result<Vec<SocketAddr>> {
    let host = netloc_host(netloc)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid netloc"))?;
    if host_is_blocked_name(host) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "blocked address",
        ));
    }
    if let Some(ip) = host_as_ip(host) {
        if ip_is_blocked(ip) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "blocked address",
            ));
        }
    }
    let addrs: Vec<SocketAddr> = netloc.to_socket_addrs()?.collect();
    let public: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| !ip_is_blocked(a.ip()))
        .collect();
    if public.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "blocked address",
        ));
    }
    Ok(public)
}

fn netloc_host(netloc: &str) -> Option<&str> {
    if let Some(rest) = netloc.strip_prefix('[') {
        let end = rest.find(']')?;
        return Some(&rest[..end]);
    }
    netloc.rsplit_once(':').map(|(h, _)| h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_token(service: &str) -> SecretPayload {
        SecretPayload::ApiToken {
            service: service.into(),
            account: None,
            token: "ghp_abcdefghijklmnopqrstuvwxyz012345".into(),
        }
    }

    fn website(url: &str) -> SecretPayload {
        SecretPayload::Website {
            url: Some(url.into()),
            username: Some("alice".into()),
            password: "s3cret".into(),
            totp_secret: None,
        }
    }

    #[test]
    fn request_url_requires_scheme() {
        assert!(parse_http_url("github.com/foo", true).is_err());
        assert_eq!(
            parse_http_url("https://API.GitHub.com/user", true).unwrap(),
            Target {
                scheme: "https".into(),
                host: "API.GitHub.com".into(),
                port: 443,
            }
        );
    }

    #[test]
    fn rejects_userinfo_in_url() {
        assert!(parse_http_url("https://user:pass@github.com/", true).is_err());
    }

    #[test]
    fn blocks_loopback_link_local_private_and_metadata() {
        for url in [
            "http://127.0.0.1/fill/pair",
            "http://127.0.0.1:17891/fill/pair",
            "http://localhost:17891/fill/pair",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]:17891/fill/pair",
            "http://[::ffff:169.254.169.254]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://172.16.0.5/",
            "http://100.64.0.1/",
            "http://100.100.100.200/",
            "http://[fd00:ec2::254]/",
            "http://[2001:db8::1]/",
            "http://[2002:a9fe:a9fe::]/",
            "http://[64:ff9b::a9fe:a9fe]/",
            "http://metadata.google.internal/",
            "http://2130706433/",
            "http://127.1/",
        ] {
            let parsed = parse_http_url(url, true);
            if let Ok(t) = parsed {
                assert!(assert_public_target(&t).is_err(), "expected block {url}");
            } else {
                assert!(parsed.is_err(), "expected parse/block {url}");
            }
        }
    }

    #[test]
    fn allows_public_hostname() {
        let t = parse_http_url("https://api.github.com/user", true).unwrap();
        assert_public_target(&t).unwrap();
    }

    #[test]
    fn github_token_only_allows_github_origins() {
        let p = api_token("github");
        credential_allows_url(&p, None, "https://api.github.com/user").unwrap();
        credential_allows_url(&p, None, "https://github.com/login").unwrap();
        assert!(credential_allows_url(&p, None, "https://evil.example/steal").is_err());
        assert!(credential_allows_url(&p, None, "http://api.github.com/user").is_err());
        assert!(credential_allows_url(&p, None, "https://api.github.com:8443/user").is_err());
    }

    #[test]
    fn custom_token_requires_bound_url() {
        let p = api_token("custom");
        assert!(credential_allows_url(&p, None, "https://api.example.com/v1").is_err());
        credential_allows_url(
            &p,
            Some("https://api.example.com"),
            "https://api.example.com/v1",
        )
        .unwrap();
        assert!(credential_allows_url(
            &p,
            Some("https://api.example.com"),
            "https://other.example/v1"
        )
        .is_err());
    }

    #[test]
    fn github_token_ignores_custom_bound_url() {
        let p = api_token("github");
        assert!(credential_allows_url(
            &p,
            Some("https://evil.example"),
            "https://evil.example/steal"
        )
        .is_err());
        credential_allows_url(
            &p,
            Some("https://evil.example"),
            "https://api.github.com/user",
        )
        .unwrap();
    }

    #[test]
    fn website_matches_origin_not_path() {
        let p = website("https://www.example.com/login");
        credential_allows_url(&p, None, "https://example.com/account").unwrap();
        assert!(credential_allows_url(&p, None, "https://other.example.com/login").is_err());
    }

    #[test]
    fn ssh_and_mailbox_cannot_http() {
        let ssh = SecretPayload::Ssh {
            key_type: "ed25519".into(),
            private_key: "k".into(),
            passphrase: None,
            public_fingerprint: None,
        };
        assert!(bind_origins(&ssh, None).is_err());
    }

    #[test]
    fn summary_omits_body() {
        let secret = b"password-from-the-forty-first-vault-entry";
        let text = summarize_response(200, secret);
        assert!(text.contains("HTTP 200"));
        assert!(text.contains("bytes: 41"));
        assert!(text.contains("sha256:"));
        assert!(!text.contains("password-from-the-forty-first"));
        assert!(!text.contains("fill_"));
        assert!(text.contains("不会返回给模型"));
        assert_eq!(text.matches('\n').count(), 3);
    }

    #[test]
    fn resolver_blocks_loopback_literal() {
        assert!(resolve_public("127.0.0.1:17891").is_err());
        assert!(resolve_public("169.254.169.254:80").is_err());
        assert!(resolve_public("8.8.8.8:53").is_ok());
    }
}
