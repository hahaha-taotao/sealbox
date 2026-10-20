/// Scheme, host without a leading www, explicit or default port, and username.
pub type WebsiteIdentityKey = (String, String, u16, String);

pub fn host_of(url: &str) -> Option<String> {
    origin_of(url).map(|(_scheme, host, _port)| host)
}

pub fn website_identity_key(url: &str, username: &str) -> Option<WebsiteIdentityKey> {
    let (scheme, host, port) = origin_of(url)?;
    Some((scheme, host, port, username.trim().to_string()))
}

/// Scheme, host without a leading www, and the explicit or default port.
pub fn origin_of(url: &str) -> Option<(String, String, u16)> {
    let u = url.trim();
    if u.is_empty() {
        return None;
    }
    let (scheme, rest) = if let Some(r) = u.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = u.strip_prefix("http://") {
        ("http", r)
    } else if u.contains("://") {
        return None;
    } else {
        ("https", u)
    };
    let hostport = rest.split(['/', '?', '#']).next()?.trim();
    let hostport = hostport.split('@').next_back()?.trim();
    if hostport.is_empty() {
        return None;
    }
    let default_port = if scheme == "http" { 80 } else { 443 };
    let (host, port) = if let Some((h, p)) = hostport.rsplit_once(':') {
        if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            (h, p.parse().ok()?)
        } else {
            (hostport, default_port)
        }
    } else {
        (hostport, default_port)
    };
    let host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let host = host.trim_start_matches("www.");
    if host.is_empty() || host == "localhost" || !host.contains('.') {
        None
    } else {
        Some((scheme.to_string(), host.to_string(), port))
    }
}
