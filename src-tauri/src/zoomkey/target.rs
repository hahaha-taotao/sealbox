//! ZoomKey 内网目标的守卫。
//!
//! 与 `http_guard::assert_public_target` 不同，ZoomKey 的两个站点位于 RFC1918 内网
//! （实测 `jira.zoomkey.com.cn` → 172.16.1.40，`crm.zoomkey.com.cn` → 172.16.1.147），
//! 现有的公网守卫会把它们全部拦掉。这里刻意开一个口子，但收得很紧：
//!
//! 1. 只有 ZoomKey MCP 总开关打开后才会走到这里；
//! 2. 主机名必须精确命中 `allowed_hosts` 白名单（不做后缀匹配，不做通配）；
//! 3. 解析出来的**每一个**地址都要通过 `ip_allowed`——回环、链路本地、
//!    云元数据（169.254.169.254 / 100.100.100.200）永远拒绝，私网地址才放行；
//! 4. 校验完成后地址被**钉住**，请求时用 `PinnedResolver` 直接返回这份地址，
//!    不再重新解析，堵掉校验与使用之间的 DNS 重绑定。

use crate::http_guard::parse_http_url;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

#[derive(Clone, Debug)]
pub struct PinnedTarget {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub addresses: Vec<SocketAddr>,
}

impl PinnedTarget {
    pub fn origin(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port)
    }

    pub fn resolver(&self) -> PinnedResolver {
        PinnedResolver {
            addresses: self.addresses.clone(),
        }
    }
}

/// 解析并校验 base url，返回钉住地址的目标。
pub fn pin(base_url: &str, allowed_hosts: &[String]) -> Result<PinnedTarget, String> {
    let target = parse_http_url(base_url, true)?;
    if target.scheme != "https" {
        return Err("ZoomKey 只允许 https".into());
    }
    let host = target.host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Err("地址缺少主机".into());
    }
    if !allowed_hosts
        .iter()
        .any(|allowed| allowed.trim().eq_ignore_ascii_case(&host))
    {
        return Err(format!("主机 {host} 不在允许列表内，已拒绝"));
    }
    let netloc = format!("{}:{}", target.host, target.port);
    let resolved = netloc
        .to_socket_addrs()
        .map_err(|e| format!("域名 {host} 解析失败: {e}"))?;
    let mut addresses = Vec::new();
    for addr in resolved {
        if !ip_allowed(addr.ip()) {
            return Err(format!("{host} 解析到 {}，该地址不被允许", addr.ip()));
        }
        addresses.push(addr);
    }
    if addresses.is_empty() {
        return Err(format!("域名 {host} 没有解析到任何地址"));
    }
    Ok(PinnedTarget {
        scheme: target.scheme,
        host,
        port: target.port,
        addresses,
    })
}

/// 私网可放行，但回环 / 链路本地 / 元数据 / 保留段永远拒绝。
pub fn ip_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 0
                || o[0] >= 240
                || o == [100, 100, 100, 200]
                || (o[0] == 198 && matches!(o[1], 18 | 19)))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4() {
                return ip_allowed(IpAddr::V4(v4));
            }
            let s = v6.segments();
            if s[0] == 0x2002 {
                let embedded = std::net::Ipv4Addr::new(
                    (s[1] >> 8) as u8,
                    s[1] as u8,
                    (s[2] >> 8) as u8,
                    s[2] as u8,
                );
                return ip_allowed(IpAddr::V4(embedded));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local())
        }
    }
}

/// 只返回已校验并钉住的地址，ureq 不会再走系统解析。
pub struct PinnedResolver {
    addresses: Vec<SocketAddr>,
}

impl ureq::Resolver for PinnedResolver {
    fn resolve(&self, _netloc: &str) -> io::Result<Vec<SocketAddr>> {
        if self.addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "no pinned address",
            ));
        }
        Ok(self.addresses.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts() -> Vec<String> {
        vec![
            "jira.zoomkey.com.cn".to_string(),
            "crm.zoomkey.com.cn".to_string(),
        ]
    }

    #[test]
    fn rejects_host_outside_allowlist() {
        let err = pin("https://evil.example.com", &hosts()).unwrap_err();
        assert!(err.contains("不在允许列表"), "{err}");
    }

    #[test]
    fn rejects_plain_http() {
        let err = pin("http://jira.zoomkey.com.cn", &hosts()).unwrap_err();
        assert!(err.contains("https"), "{err}");
    }

    #[test]
    fn metadata_and_loopback_are_never_allowed() {
        for raw in [
            "169.254.169.254",
            "100.100.100.200",
            "127.0.0.1",
            "::1",
            "fe80::1",
            "0.0.0.0",
            "224.0.0.1",
        ] {
            let ip: IpAddr = raw.parse().unwrap();
            assert!(!ip_allowed(ip), "{raw} should be blocked");
        }
        for raw in ["172.16.1.40", "10.1.2.3", "192.168.1.10", "8.8.8.8"] {
            let ip: IpAddr = raw.parse().unwrap();
            assert!(ip_allowed(ip), "{raw} should be allowed");
        }
    }

    #[test]
    fn resolver_only_returns_pinned_addresses() {
        let pinned = PinnedTarget {
            scheme: "https".into(),
            host: "jira.zoomkey.com.cn".into(),
            port: 443,
            addresses: vec!["172.16.1.40:443".parse().unwrap()],
        };
        let resolver = pinned.resolver();
        let out = ureq::Resolver::resolve(&resolver, "jira.zoomkey.com.cn:443").unwrap();
        assert_eq!(out, vec!["172.16.1.40:443".parse::<SocketAddr>().unwrap()]);
    }
}
