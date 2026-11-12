//! Mail account resolution: which IMAP host an account talks to.
//!
//! Two vault entry kinds become mail accounts. `mail_auth` stores a provider id that must be
//! one of the built-in presets; `mailbox` stores the user's own IMAP host. Neither path lets a
//! caller supply an arbitrary host, which keeps the original promise — the desktop UI, the MCP
//! tool and a synced vault cannot point this module at an attacker-chosen server.

use std::io::Read as _;
use std::time::Duration;

/// One built-in provider preset. `imap` is the server the reader connects to.
pub struct ProviderPreset {
    pub id: &'static str,
    pub label: &'static str,
    /// Domains that make `auto_detect` pick this preset.
    pub domains: &'static [&'static str],
    pub imap: (&'static str, u16),
}

pub const PROVIDERS: &[ProviderPreset] = &[
    ProviderPreset { id: "qq", label: "QQ 邮箱", domains: &["qq.com", "foxmail.com"], imap: ("imap.qq.com", 993) },
    ProviderPreset { id: "163", label: "网易 163", domains: &["163.com"], imap: ("imap.163.com", 993) },
    ProviderPreset { id: "126", label: "网易 126", domains: &["126.com"], imap: ("imap.126.com", 993) },
    ProviderPreset { id: "yeah", label: "网易 yeah.net", domains: &["yeah.net"], imap: ("imap.yeah.net", 993) },
    ProviderPreset { id: "gmail", label: "Gmail", domains: &["gmail.com", "googlemail.com"], imap: ("imap.gmail.com", 993) },
    ProviderPreset { id: "outlook", label: "Outlook", domains: &["outlook.com", "hotmail.com", "live.com", "live.cn", "msn.com"], imap: ("outlook.office365.com", 993) },
    ProviderPreset { id: "yahoo", label: "Yahoo", domains: &["yahoo.com", "yahoo.co.jp", "ymail.com"], imap: ("imap.mail.yahoo.com", 993) },
    ProviderPreset { id: "icloud", label: "iCloud", domains: &["icloud.com", "me.com", "mac.com"], imap: ("imap.mail.me.com", 993) },
    ProviderPreset { id: "sina", label: "新浪邮箱", domains: &["sina.com", "sina.cn"], imap: ("imap.sina.com", 993) },
    ProviderPreset { id: "sohu", label: "搜狐邮箱", domains: &["sohu.com"], imap: ("imap.sohu.com", 993) },
    ProviderPreset { id: "aliyun", label: "阿里邮箱", domains: &["aliyun.com", "aliyun.com.cn"], imap: ("imap.aliyun.com", 993) },
    ProviderPreset { id: "139", label: "中国移动 139", domains: &["139.com"], imap: ("imap.139.com", 993) },
    ProviderPreset { id: "ftqq", label: "腾讯企业邮", domains: &["exmail.qq.com"], imap: ("imap.exmail.qq.com", 993) },
    ProviderPreset { id: "yandex", label: "Yandex", domains: &["yandex.com", "yandex.ru"], imap: ("imap.yandex.com", 993) },
    ProviderPreset { id: "mailru", label: "Mail.ru", domains: &["mail.ru", "bk.ru", "inbox.ru", "list.ru"], imap: ("imap.mail.ru", 993) },
    ProviderPreset { id: "zoho", label: "Zoho", domains: &["zoho.com", "zohomail.com"], imap: ("imap.zoho.com", 993) },
    ProviderPreset { id: "aol", label: "AOL", domains: &["aol.com"], imap: ("imap.aol.com", 993) },
    ProviderPreset { id: "fastmail", label: "Fastmail", domains: &["fastmail.com", "fastmail.fm"], imap: ("imap.fastmail.com", 993) },
];

pub fn preset(provider: &str) -> Option<&'static ProviderPreset> {
    PROVIDERS.iter().find(|entry| entry.id == provider)
}

/// The IMAP server for a `mail_auth` provider. `None` means the provider is not built in.
pub fn endpoint(provider: &str) -> Option<(&'static str, u16)> {
    preset(provider).map(|entry| entry.imap)
}

/// True when the string is a plausible host name: ASCII letters, digits, dots and hyphens only.
/// This rejects URLs, `user@host` pairs, ports, IPv6 literals and anything with whitespace, so a
/// stored `imap_host` cannot smuggle a different endpoint into `connect_tls`.
pub fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    if trimmed.is_empty() || trimmed.starts_with('.') || trimmed.starts_with('-') {
        return false;
    }
    trimmed
        .split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn domain_of(email: &str) -> Option<String> {
    let (_, domain) = email.rsplit_once('@')?;
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if valid_host(&domain) {
        Some(domain)
    } else {
        None
    }
}

/// A resolved IMAP endpoint plus how it was found, so the UI can tell the user to double-check
/// a guess and can stay quiet about a preset hit.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredServer {
    pub host: String,
    pub port: u16,
    /// `preset`, `autoconfig` or `guess`.
    pub source: &'static str,
}

fn guess_from_domain(domain: &str) -> Option<DiscoveredServer> {
    Some(DiscoveredServer { host: format!("imap.{domain}"), port: 993, source: "guess" })
}

/// Extracts the IMAP host and port from a Thunderbird `autoconfig` XML document.
///
/// The parser is deliberately tiny: it looks for `<incomingServer type="imap">`, takes the
/// first `<hostname>` and `<port>` that follow it, and ignores everything else. A document
/// with no IMAP server, or with a host that fails [`valid_host`], yields `None`.
pub fn parse_autoconfig(xml: &str) -> Option<(String, u16)> {
    // All offsets stay inside `lower`; the matching text is sliced out of `xml` with the same
    // offsets, which is only sound because `to_ascii_lowercase` preserves byte lengths. Anything
    // that would make an offset land mid-character returns `None` instead of panicking.
    let lower = xml.to_ascii_lowercase();
    let mut search = 0usize;
    // Prefer an explicit imap server; fall back to an untyped one, which autoconfig uses for
    // providers that only offer IMAP.
    let mut section = None;
    while let Some(at) = lower.get(search..)?.find("<incomingserver") {
        let start = search + at;
        let close = lower.get(start..)?.find('>')?;
        let open_tag = lower.get(start..start + close + 1)?;
        let section_end = lower
            .get(start..)?
            .find("</incomingserver>")
            .map(|end| start + end)
            .unwrap_or(lower.len());
        let body = xml.get(start + close + 1..section_end)?;
        if open_tag.contains("type=\"imap\"") || open_tag.contains("type='imap'") {
            section = Some(body);
            break;
        }
        if !open_tag.contains("type=") && section.is_none() {
            section = Some(body);
        }
        search = section_end.max(start + close + 1);
        if search >= lower.len() {
            break;
        }
    }
    let body = section?;
    let host = element_text(body, "hostname")?;
    if !valid_host(&host) {
        return None;
    }
    let port = element_text(body, "port")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(993);
    Some((host, port))
}

fn element_text(body: &str, name: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = lower.find(&open)? + open.len();
    let rest = lower.get(start..)?;
    let end = rest.find(&close)?;
    let value = body.get(start..start + end)?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Looks up the provider's public autoconfig document. Any failure — offline, timeout, 404,
/// malformed XML — is `None`; detection then falls through to the heuristic guess.
pub fn fetch_autoconfig(domain: &str, timeout: Duration) -> Option<DiscoveredServer> {
    if !valid_host(domain) {
        return None;
    }
    let url = format!("https://autoconfig.thunderbird.net/v1.1/{domain}");
    let response = ureq::builder()
        .timeout(timeout)
        .build()
        .get(&url)
        .call()
        .ok()?;
    if response.status() != 200 {
        return None;
    }
    // The document is a few KB; cap the read so a hostile reply cannot balloon memory.
    let mut body = String::new();
    response.into_reader().take(64 * 1024).read_to_string(&mut body).ok()?;
    let (host, port) = parse_autoconfig(&body)?;
    Some(DiscoveredServer { host, port, source: "autoconfig" })
}

/// Three-level detection: built-in preset, then the public autoconfig lookup, then a guess.
/// The guess always succeeds for a syntactically valid address, so the form can be prefilled
/// even when everything else is unavailable.
pub fn auto_detect(email: &str) -> Option<DiscoveredServer> {
    let domain = domain_of(email)?;
    if let Some(preset) = PROVIDERS.iter().find(|entry| entry.domains.iter().any(|known| *known == domain)) {
        return Some(DiscoveredServer {
            host: preset.imap.0.to_string(),
            port: preset.imap.1,
            source: "preset",
        });
    }
    if let Some(found) = fetch_autoconfig(&domain, Duration::from_secs(5)) {
        return Some(found);
    }
    guess_from_domain(&domain)
}

/// Resolves the IMAP server for an `mail_auth` entry. `provider` must be a preset id.
pub fn server_for_provider(provider: &str) -> Option<(String, u16)> {
    endpoint(provider).map(|(host, port)| (host.to_string(), port))
}

/// Resolves the IMAP server for a `mailbox` entry: an explicit host wins, otherwise the stored
/// address is detected like a fresh form entry.
pub fn server_for_mailbox(email: &str, imap_host: Option<&str>, imap_port: Option<u16>) -> Option<(String, u16)> {
    if let Some(host) = imap_host.map(str::trim).filter(|host| !host.is_empty()) {
        if !valid_host(host) {
            return None;
        }
        return Some((host.to_string(), imap_port.filter(|port| *port > 0).unwrap_or(993)));
    }
    let domain = domain_of(email)?;
    if let Some(preset) = PROVIDERS.iter().find(|entry| entry.domains.iter().any(|known| *known == domain)) {
        return Some((preset.imap.0.to_string(), preset.imap.1));
    }
    guess_from_domain(&domain).map(|found| (found.host, found.port))
}

/// The provider label shown next to an account, for both entry kinds.
pub fn provider_label(provider: &str) -> &'static str {
    preset(provider).map(|entry| entry.label).unwrap_or("其他邮箱")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_preset_has_a_loadable_endpoint() {
        assert_eq!(PROVIDERS.len(), 18);
        for entry in PROVIDERS {
            assert_eq!(endpoint(entry.id), Some(entry.imap), "{}", entry.id);
            assert!(valid_host(entry.imap.0), "{}", entry.imap.0);
            assert!(!entry.domains.is_empty());
            assert_eq!(provider_label(entry.id), entry.label);
        }
        assert_eq!(endpoint("custom"), None);
        assert_eq!(endpoint(""), None);
    }

    #[test]
    fn host_validation_rejects_anything_that_is_not_a_bare_hostname() {
        // A bare IPv4 literal is a legitimate IMAP host for a self-hosted server.
        for good in ["imap.qq.com", "mail.example.co.uk", "a-b.example.com", "localhost", "198.51.100.7"] {
            assert!(valid_host(good), "{good}");
        }
        for bad in [
            "",
            "imap.qq.com:993",
            "https://imap.qq.com",
            "user@imap.qq.com",
            "imap qq com",
            "imap.qq.com/path",
            "-bad.example.com",
            "bad-.example.com",
            "a..b",
            "[::1]",
        ] {
            assert!(!valid_host(bad), "{bad}");
        }
    }

    #[test]
    fn autodetect_prefers_the_built_in_preset() {
        assert_eq!(
            auto_detect("me@qq.com"),
            Some(DiscoveredServer { host: "imap.qq.com".into(), port: 993, source: "preset" })
        );
        assert_eq!(auto_detect("me@foxmail.com").unwrap().host, "imap.qq.com");
        assert_eq!(auto_detect("me@163.com").unwrap().host, "imap.163.com");
        assert_eq!(auto_detect("me@hotmail.com").unwrap().host, "outlook.office365.com");
        assert_eq!(auto_detect("me@gmail.com").unwrap().host, "imap.gmail.com");
        assert_eq!(auto_detect("not-an-email"), None);
        assert_eq!(auto_detect(""), None);
    }

    #[test]
    fn autoconfig_document_yields_the_imap_server() {
        let xml = r#"<?xml version="1.0"?>
        <clientConfig version="1.1">
          <emailProvider id="example.com">
            <incomingServer type="pop3"><hostname>pop.example.com</hostname><port>995</port></incomingServer>
            <incomingServer type="imap">
              <hostname>imap.example.com</hostname>
              <port>993</port>
              <socketType>SSL</socketType>
            </incomingServer>
            <outgoingServer type="smtp"><hostname>smtp.example.com</hostname><port>465</port></outgoingServer>
          </emailProvider>
        </clientConfig>"#;
        assert_eq!(parse_autoconfig(xml), Some(("imap.example.com".into(), 993)));
    }

    #[test]
    fn autoconfig_without_imap_and_with_a_bad_host_yields_nothing() {
        let pop_only = r#"<clientConfig><emailProvider>
            <incomingServer type="pop3"><hostname>pop.example.com</hostname><port>995</port></incomingServer>
        </emailProvider></clientConfig>"#;
        assert_eq!(parse_autoconfig(pop_only), None);
        let bad_host = r#"<clientConfig><emailProvider>
            <incomingServer type="imap"><hostname>imap.example.com:993</hostname></incomingServer>
        </emailProvider></clientConfig>"#;
        assert_eq!(parse_autoconfig(bad_host), None);
        assert_eq!(parse_autoconfig("not xml at all"), None);
    }

    #[test]
    fn autoconfig_keeps_a_custom_port() {
        let xml = r#"<clientConfig><emailProvider>
            <incomingServer type="imap"><hostname>mail.internal.example</hostname><port>1993</port></incomingServer>
        </emailProvider></clientConfig>"#;
        assert_eq!(parse_autoconfig(xml), Some(("mail.internal.example".into(), 1993)));
    }

    #[test]
    fn mailbox_entries_use_their_stored_host_or_a_detected_one() {
        assert_eq!(
            server_for_mailbox("me@corp.example", Some("mail.corp.example"), Some(1993)),
            Some(("mail.corp.example".into(), 1993))
        );
        // No stored port falls back to the implicit-TLS port.
        assert_eq!(
            server_for_mailbox("me@corp.example", Some("mail.corp.example"), None),
            Some(("mail.corp.example".into(), 993))
        );
        // An explicit but invalid host is rejected rather than repaired.
        assert_eq!(server_for_mailbox("me@corp.example", Some("https://evil.example"), Some(993)), None);
        // A blank host falls back to detection from the address.
        assert_eq!(
            server_for_mailbox("me@qq.com", Some("  "), None),
            Some(("imap.qq.com".into(), 993))
        );
        assert_eq!(
            server_for_mailbox("me@corp.example", None, None),
            Some(("imap.corp.example".into(), 993))
        );
    }

    #[test]
    fn provider_lookup_is_strict() {
        assert_eq!(server_for_provider("qq"), Some(("imap.qq.com".into(), 993)));
        assert_eq!(server_for_provider("custom"), None);
        assert_eq!(server_for_provider("IMAP.QQ.COM"), None);
        assert_eq!(provider_label("custom"), "其他邮箱");
    }

    #[test]
    fn non_ascii_and_malformed_autoconfig_never_panics() {
        // A CJK comment before the element exercises byte offsets in a multi-byte document.
        let xml = "<!-- 公共配置 --><clientConfig><emailProvider>\
                   <incomingServer type=\"imap\"><hostname>imap.example.com</hostname></incomingServer>\
                   </emailProvider></clientConfig>";
        assert_eq!(parse_autoconfig(xml), Some(("imap.example.com".into(), 993)));
        for malformed in ["", "<", "<incomingserver", "<incomingserver>", "已发送 <incomingserver"] {
            assert_eq!(parse_autoconfig(malformed), None, "{malformed}");
        }
        assert_eq!(element_text("<hostname>中文主机</hostname>", "hostname").as_deref(), Some("中文主机"));
    }
}
