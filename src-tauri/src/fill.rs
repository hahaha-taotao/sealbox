use crate::lock::lock_session;
use crate::session::Session;
use crate::vault::{EntryKind, ListFilter, SecretPayload, SortBy, UpsertEntry};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FillMatch {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub score: i32,
    pub has_totp: bool,
}

#[derive(Serialize)]
pub struct FillSecret {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
    pub totp_period_remaining: Option<u8>,
}

pub fn host_of(url: &str) -> Option<String> {
    origin_of(url).map(|(_scheme, host, _port)| host)
}

/// Scheme, host without leading www, and explicit or default port.
fn origin_of(url: &str) -> Option<(String, String, u16)> {
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

fn path_of(url: &str) -> String {
    let u = url.trim();
    let rest = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
        .unwrap_or(u);
    let path = if let Some(i) = rest.find('/') {
        rest[i..].split(['?', '#']).next().unwrap_or("/")
    } else {
        "/"
    };
    let mut p = path.to_ascii_lowercase();
    if p.is_empty() {
        p = "/".into();
    }
    if p != "/" && p.ends_with('/') {
        p.pop();
    }
    p
}

fn score_url(page_url: &str, stored_url: &str) -> i32 {
    let Some(page) = origin_of(page_url) else {
        return 0;
    };
    let Some(stored) = origin_of(stored_url) else {
        return 0;
    };
    if page != stored {
        return 0;
    }
    let page_path = path_of(page_url);
    let stored_path = path_of(stored_url);
    if page_path == stored_path {
        100
    } else if stored_path != "/"
        && (page_path.starts_with(&format!("{stored_path}/"))
            || stored_path.starts_with(&format!("{page_path}/")))
    {
        90
    } else {
        70
    }
}

pub fn match_websites(session: &Mutex<Session>, page_url: &str) -> Result<Vec<FillMatch>, String> {
    let mut s = lock_session(session);
    s.maybe_idle_lock();
    if !s.is_unlocked() {
        return Err("locked".into());
    }
    let dek = *s.dek().map_err(|e| e.to_string())?;
    let vault = s.vault().map_err(|e| e.to_string())?;
    let list = vault
        .list_entries(&ListFilter {
            query: None,
            kind: Some(EntryKind::Website),
            kinds: vec![EntryKind::Website],
            folder_id: None,
            uncategorized: false,
            tag: None,
            trash: false,
            sort: SortBy::UseCount,
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for e in list {
        let Some(stored) = e.url.as_deref().filter(|u| !u.trim().is_empty()) else {
            continue;
        };
        let score = score_url(page_url, stored);
        if score > 0 {
            let notes = vault.get_notes(&dek, &e.id).ok().flatten();
            out.push(FillMatch {
                id: e.id,
                title: e.title,
                username: e.account.unwrap_or_default(),
                url: e.url,
                notes,
                score,
                has_totp: e.has_totp,
            });
        }
    }
    out.sort_by(|a, b| b.score.cmp(&a.score));
    Ok(out)
}

pub fn reveal_for_fill(
    session: &Mutex<Session>,
    id: &str,
    page_url: &str,
) -> Result<FillSecret, String> {
    if page_url.trim().is_empty() {
        return Err("url required".into());
    }
    let mut s = lock_session(session);
    s.maybe_idle_lock();
    if !s.is_unlocked() {
        return Err("locked".into());
    }
    let dek = *s.dek().map_err(|e| e.to_string())?;
    let vault = s.vault().map_err(|e| e.to_string())?;
    let dto = vault
        .list_entries(&ListFilter {
            query: None,
            kind: Some(EntryKind::Website),
            kinds: vec![EntryKind::Website],
            folder_id: None,
            uncategorized: false,
            tag: None,
            trash: false,
            sort: SortBy::UseCount,
        })
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|e| e.id == id)
        .ok_or_else(|| "entry does not match page".to_string())?;
    let stored = dto.url.as_deref().unwrap_or("");
    if score_url(page_url, stored) <= 0 {
        return Err("entry does not match page".into());
    }
    let payload = vault.get_secret(&dek, id).map_err(|e| e.to_string())?;
    let SecretPayload::Website {
        username,
        password,
        totp_secret,
        ..
    } = payload
    else {
        return Err("not a website entry".into());
    };
    let (totp, totp_period_remaining) = match totp_secret.as_deref() {
        Some(secret) if !secret.is_empty() => {
            let code = crate::totp::totp_now(secret).map_err(|e| e.to_string())?;
            let remaining = 30 - (chrono::Utc::now().timestamp().rem_euclid(30) as u8);
            (Some(code), Some(remaining.max(1)))
        }
        _ => (None, None),
    };
    let _ = vault.bump_use(id);
    let _ = vault.audit("browser_fill", Some(id), "ok");
    s.touch();
    Ok(FillSecret {
        id: id.to_string(),
        title: dto.title,
        username: username.unwrap_or_default(),
        password,
        totp,
        totp_period_remaining,
    })
}

pub fn save_from_browser(
    session: &Mutex<Session>,
    title: &str,
    url: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    save_from_browser_with_notes(session, title, url, username, password, None)
}

pub fn save_from_browser_with_notes(
    session: &Mutex<Session>,
    title: &str,
    url: &str,
    username: &str,
    password: &str,
    notes: Option<&str>,
) -> Result<String, String> {
    let mut s = lock_session(session);
    s.maybe_idle_lock();
    if !s.is_unlocked() {
        return Err("locked".into());
    }
    let dek = *s.dek().map_err(|e| e.to_string())?;
    let vault = s.vault().map_err(|e| e.to_string())?;
    let existing = vault
        .list_entries(&ListFilter {
            query: None,
            kind: Some(EntryKind::Website),
            kinds: vec![EntryKind::Website],
            folder_id: None,
            uncategorized: false,
            tag: None,
            trash: false,
            sort: SortBy::UseCount,
        })
        .map_err(|e| e.to_string())?;
    if origin_of(url).is_none() {
        return Err("invalid page url".into());
    }
    let mut reuse_id = None;
    let mut totp_secret = None;
    let mut folder_id = None;
    let mut tags = vec!["browser".into()];
    let mut pinned = false;
    let mut expires_at = None;
    let mut existing_notes = None;
    for e in existing {
        let Some(stored) = e.url.as_deref() else {
            continue;
        };
        if score_url(url, stored) > 0 && e.account.as_deref() == Some(username) {
            reuse_id = Some(e.id.clone());
            folder_id = e.folder_id;
            tags = e.tags;
            pinned = e.pinned;
            expires_at = e.expires_at;
            existing_notes = vault.get_notes(&dek, &e.id).ok().flatten();
            if let Ok(SecretPayload::Website { totp_secret: t, .. }) = vault.get_secret(&dek, &e.id)
            {
                totp_secret = t;
            }
            break;
        }
    }
    let notes = match notes.map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => Some(n.to_string()),
        None => existing_notes,
    };
    let dto = vault
        .upsert_entry(
            &dek,
            UpsertEntry {
                id: reuse_id,
                kind: EntryKind::Website,
                title: if title.trim().is_empty() {
                    host_of(url).unwrap_or_else(|| "website".into())
                } else {
                    title.to_string()
                },
                account: Some(username.to_string()),
                url: Some(url.to_string()),
                folder_id,
                tags,
                pinned,
                expires_at,
                notes,
                secret: SecretPayload::Website {
                    url: Some(url.to_string()),
                    username: Some(username.to_string()),
                    password: password.to_string(),
                    totp_secret,
                },
            },
        )
        .map_err(|e| e.to_string())?;
    s.touch();
    Ok(dto.id)
}

#[derive(Clone, Debug, Serialize)]
pub struct FillClassify {
    pub action: String,
    pub id: Option<String>,
}

fn peek_website_password(session: &Mutex<Session>, id: &str) -> Result<String, String> {
    let s = lock_session(session);
    if !s.is_unlocked() {
        return Err("locked".into());
    }
    let dek = *s.dek().map_err(|e| e.to_string())?;
    let vault = s.vault().map_err(|e| e.to_string())?;
    match vault.get_secret(&dek, id).map_err(|e| e.to_string())? {
        SecretPayload::Website { password, .. } => Ok(password),
        _ => Err("not a website entry".into()),
    }
}

pub fn classify_save(
    session: &Mutex<Session>,
    url: &str,
    username: &str,
    password: &str,
) -> Result<FillClassify, String> {
    if password.trim().is_empty() {
        return Ok(FillClassify {
            action: "none".into(),
            id: None,
        });
    }
    let matches = match_websites(session, url)?;
    let Some(hit) = matches.into_iter().find(|m| m.username == username) else {
        return Ok(FillClassify {
            action: "save".into(),
            id: None,
        });
    };
    let stored = peek_website_password(session, &hit.id)?;
    if stored == password {
        Ok(FillClassify {
            action: "unchanged".into(),
            id: Some(hit.id),
        })
    } else {
        Ok(FillClassify {
            action: "update".into(),
            id: Some(hit.id),
        })
    }
}

pub fn handle_fill_http(
    session: &Mutex<Session>,
    path: &str,
    body: &[u8],
) -> Result<Value, (u16, String)> {
    let v: Value = serde_json::from_slice(body).unwrap_or(json!({}));
    match path {
        "/fill/status" => {
            let unlocked = lock_session(session).is_unlocked();
            Ok(json!({ "ok": true, "unlocked": unlocked }))
        }
        "/fill/match" => {
            let url = v.get("url").and_then(|x| x.as_str()).unwrap_or("");
            match match_websites(session, url) {
                Ok(list) => Ok(json!({ "ok": true, "matches": list })),
                Err(e) if e == "locked" => Err((403, "vault locked".into())),
                Err(e) => Err((400, e)),
            }
        }
        "/fill/secret" => {
            let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let url = v.get("url").and_then(|x| x.as_str()).unwrap_or("");
            if url.trim().is_empty() {
                return Err((400, "url required".into()));
            }
            match reveal_for_fill(session, id, url) {
                Ok(sec) => Ok(json!({ "ok": true, "entry": sec })),
                Err(e) if e == "locked" => Err((403, "vault locked".into())),
                Err(e) if e == "entry does not match page" => Err((403, e)),
                Err(e) => Err((400, e)),
            }
        }
        "/fill/classify" => {
            let url = v.get("url").and_then(|x| x.as_str()).unwrap_or("");
            let username = v.get("username").and_then(|x| x.as_str()).unwrap_or("");
            let password = v.get("password").and_then(|x| x.as_str()).unwrap_or("");
            match classify_save(session, url, username, password) {
                Ok(c) => Ok(json!({
                    "ok": true,
                    "action": c.action,
                    "id": c.id.unwrap_or_default(),
                })),
                Err(e) if e == "locked" => Err((403, "vault locked".into())),
                Err(e) => Err((400, e)),
            }
        }
        "/fill/save" => {
            let title = v.get("title").and_then(|x| x.as_str()).unwrap_or("");
            let url = v.get("url").and_then(|x| x.as_str()).unwrap_or("");
            let username = v.get("username").and_then(|x| x.as_str()).unwrap_or("");
            let password = v.get("password").and_then(|x| x.as_str()).unwrap_or("");
            let notes = v.get("notes").and_then(|x| x.as_str());
            if url.is_empty() || password.is_empty() {
                return Err((400, "url and password required".into()));
            }
            match save_from_browser_with_notes(session, title, url, username, password, notes) {
                Ok(id) => Ok(json!({ "ok": true, "id": id })),
                Err(e) if e == "locked" => Err((403, "vault locked".into())),
                Err(e) => Err((400, e)),
            }
        }
        _ => Err((404, "not found".into())),
    }
}

pub fn new_fill_token() -> String {
    format!("fill_{}", Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;
    use std::time::Duration;

    fn unlocked_github() -> Mutex<Session> {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .upsert_entry(
                &dek,
                UpsertEntry {
                    id: None,
                    kind: EntryKind::Website,
                    title: "GitHub".into(),
                    account: Some("octocat".into()),
                    url: Some("https://github.com".into()),
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::Website {
                        url: Some("https://github.com".into()),
                        username: Some("octocat".into()),
                        password: "gh-pass".into(),
                        totp_secret: None,
                    },
                },
            )
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        Mutex::new(session)
    }

    fn unlocked_github_totp() -> Mutex<Session> {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .upsert_entry(
                &dek,
                UpsertEntry {
                    id: None,
                    kind: EntryKind::Website,
                    title: "GitHub".into(),
                    account: Some("octocat".into()),
                    url: Some("https://github.com".into()),
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::Website {
                        url: Some("https://github.com".into()),
                        username: Some("octocat".into()),
                        password: "gh-pass".into(),
                        totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
                    },
                },
            )
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        Mutex::new(session)
    }

    #[test]
    fn match_and_secret_include_totp_code_not_secret() {
        let mutex = unlocked_github_totp();
        let hits = match_websites(&mutex, "https://github.com/login").unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].has_totp);
        let body = format!(
            r#"{{"id":"{}","url":"https://github.com/login"}}"#,
            hits[0].id
        );
        let json = handle_fill_http(&mutex, "/fill/secret", body.as_bytes()).unwrap();
        let entry = &json["entry"];
        assert_eq!(entry["password"], "gh-pass");
        let code = entry["totp"].as_str().unwrap();
        assert_eq!(code.len(), 6);
        assert!(entry["totp_secret"].is_null() || entry.get("totp_secret").is_none());
        let remaining = entry["totp_period_remaining"].as_u64().unwrap();
        assert!((1..=30).contains(&remaining));
        let dumped = json.to_string();
        assert!(!dumped.contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn secret_without_totp_returns_null_code() {
        let mutex = unlocked_github();
        let hits = match_websites(&mutex, "https://github.com/login").unwrap();
        assert!(!hits[0].has_totp);
        let sec = reveal_for_fill(&mutex, &hits[0].id, "https://github.com/login").unwrap();
        assert!(sec.totp.is_none());
    }

    #[test]
    fn match_does_not_refresh_idle_timer() {
        let mutex = unlocked_github();
        {
            let mut s = mutex.lock().unwrap();
            s.idle_secs = 2;
            s.age_last_active(Duration::from_secs(1));
        }
        let hits = match_websites(&mutex, "https://github.com/login").unwrap();
        assert_eq!(hits.len(), 1);
        let mut s = mutex.lock().unwrap();
        s.age_last_active(Duration::from_millis(1500));
        assert!(
            s.maybe_idle_lock(),
            "browser match probes must not keep the vault unlocked"
        );
        assert!(!s.is_unlocked());
    }

    #[test]
    fn reveal_for_fill_refreshes_idle_timer() {
        let mutex = unlocked_github();
        let hits = match_websites(&mutex, "https://github.com/login").unwrap();
        {
            let mut s = mutex.lock().unwrap();
            s.idle_secs = 2;
            s.age_last_active(Duration::from_secs(1));
        }
        let sec = reveal_for_fill(&mutex, &hits[0].id, "https://github.com/login").unwrap();
        assert_eq!(sec.password, "gh-pass");
        let mut s = mutex.lock().unwrap();
        s.age_last_active(Duration::from_millis(1500));
        assert!(!s.maybe_idle_lock());
        assert!(s.is_unlocked());
    }

    #[test]
    fn match_locks_when_already_idle() {
        let mutex = unlocked_github();
        {
            let mut s = mutex.lock().unwrap();
            s.idle_secs = 1;
            s.age_last_active(Duration::from_secs(2));
        }
        assert_eq!(
            match_websites(&mutex, "https://github.com/login").unwrap_err(),
            "locked"
        );
    }

    #[test]
    fn fill_http_rejects_match_secret_and_save_after_lock() {
        let mutex = unlocked_github();
        let hits = match_websites(&mutex, "https://github.com/login").unwrap();
        assert_eq!(hits.len(), 1);
        {
            let mut s = mutex.lock().unwrap();
            s.lock();
        }
        let status = handle_fill_http(&mutex, "/fill/status", b"{}").unwrap();
        assert_eq!(status["unlocked"], false);
        assert_eq!(
            handle_fill_http(
                &mutex,
                "/fill/match",
                br#"{"url":"https://github.com/login"}"#
            )
            .unwrap_err()
            .0,
            403
        );
        let secret = handle_fill_http(
            &mutex,
            "/fill/secret",
            format!(
                r#"{{"id":"{}","url":"https://github.com/login"}}"#,
                hits[0].id
            )
            .as_bytes(),
        );
        assert_eq!(secret.unwrap_err().0, 403);
        assert_eq!(
            handle_fill_http(
                &mutex,
                "/fill/save",
                br#"{"title":"x","url":"https://new.example","username":"a","password":"b"}"#
            )
            .unwrap_err()
            .0,
            403
        );
        assert_eq!(
            handle_fill_http(
                &mutex,
                "/fill/classify",
                br#"{"url":"https://github.com/login","username":"octocat","password":"gh-pass"}"#
            )
            .unwrap_err()
            .0,
            403
        );
    }

    #[test]
    fn classify_does_not_refresh_idle_timer() {
        let mutex = unlocked_github();
        {
            let mut s = mutex.lock().unwrap();
            s.idle_secs = 2;
            s.age_last_active(Duration::from_secs(1));
        }
        let classified =
            classify_save(&mutex, "https://github.com/login", "octocat", "gh-pass").unwrap();
        assert_eq!(classified.action, "unchanged");
        let mut s = mutex.lock().unwrap();
        s.age_last_active(Duration::from_millis(1500));
        assert!(
            s.maybe_idle_lock(),
            "password-update probes must not keep the vault unlocked"
        );
        assert!(!s.is_unlocked());
    }

    #[test]
    fn host_and_score() {
        assert_eq!(
            host_of("https://www.github.com/login").as_deref(),
            Some("github.com")
        );
        assert!(score_url("https://github.com/login", "https://www.github.com") >= 70);
        assert_eq!(
            score_url("https://login.taobao.com/", "https://www.taobao.com"),
            0
        );
        assert_eq!(
            score_url(
                "https://csm.hhughg.com:8280/",
                "https://iam.hhughg.com:8381"
            ),
            0
        );
        assert!(
            score_url(
                "https://csm.hhughg.com:8280/",
                "https://csm.hhughg.com:8280"
            ) >= 70
        );
        assert_eq!(
            score_url(
                "https://csm.hhughg.com:8280/",
                "https://csm.hhughg.com:8281"
            ),
            0
        );
        assert_eq!(score_url("https://example.com", "https://other.net"), 0);
        assert!(
            score_url(
                "https://heat.example.com/billing/login",
                "https://heat.example.com/iam"
            ) > 0
        );
        assert!(
            score_url(
                "https://heat.example.com/iam/login",
                "https://heat.example.com/iam"
            ) >= 90
        );
        assert!(
            score_url(
                "https://csm.hhughg.com:8280/#",
                "https://csm.hhughg.com:8280/sof_login.jsp"
            ) > 0
        );
        assert_eq!(
            score_url(
                "https://csm.hhughg.com:8280/",
                "http://csm.hhughg.com:8280/"
            ),
            0
        );
        let login_score = score_url(
            "https://csm.hhughg.com:8280/sof_login.jsp",
            "https://csm.hhughg.com:8280/sof_login.jsp",
        );
        let root_score = score_url(
            "https://csm.hhughg.com:8280/#",
            "https://csm.hhughg.com:8280/sof_login.jsp",
        );
        assert!(login_score > root_score);
        assert_eq!(host_of("iam"), None);
        assert_eq!(score_url("https://foo.iam.com/x", "iam"), 0);
    }

    #[test]
    fn match_and_save() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .upsert_entry(
                &dek,
                UpsertEntry {
                    id: None,
                    kind: EntryKind::Website,
                    title: "GitHub".into(),
                    account: Some("octocat".into()),
                    url: Some("https://github.com".into()),
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::Website {
                        url: Some("https://github.com".into()),
                        username: Some("octocat".into()),
                        password: "gh-pass".into(),
                        totp_secret: None,
                    },
                },
            )
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let mutex = Mutex::new(session);
        let hits = match_websites(&mutex, "https://github.com/login").unwrap();
        assert_eq!(hits.len(), 1);
        let sub = match_websites(&mutex, "https://login.github.com/").unwrap();
        assert!(sub.is_empty());
        let other = match_websites(&mutex, "https://csm.hhughg.com:8280/").unwrap();
        assert!(other.is_empty());
        assert_eq!(hits[0].username, "octocat");
        let sec = reveal_for_fill(&mutex, &hits[0].id, "https://github.com/login").unwrap();
        assert_eq!(sec.password, "gh-pass");
        assert!(reveal_for_fill(&mutex, &hits[0].id, "").is_err());
        assert!(reveal_for_fill(&mutex, &hits[0].id, "https://evil.example/login").is_err());
        let mismatch = handle_fill_http(
            &mutex,
            "/fill/secret",
            format!(
                r#"{{"id":"{}","url":"https://evil.example/login"}}"#,
                hits[0].id
            )
            .as_bytes(),
        );
        assert_eq!(mismatch.unwrap_err().0, 403);
        let login_id = save_from_browser(
            &mutex,
            "客服",
            "https://csm.hhughg.com:8280/sof_login.jsp",
            "18698459937",
            "login-pass",
        )
        .unwrap();
        let hash_hits = match_websites(&mutex, "https://csm.hhughg.com:8280/#").unwrap();
        assert!(hash_hits.iter().any(|m| m.id == login_id));
        let updated = save_from_browser(
            &mutex,
            "客服",
            "https://csm.hhughg.com:8280/#",
            "18698459937",
            "new-login-pass",
        )
        .unwrap();
        assert_eq!(updated, login_id);
        assert_eq!(
            reveal_for_fill(&mutex, &login_id, "https://csm.hhughg.com:8280/#")
                .unwrap()
                .password,
            "new-login-pass"
        );
        let other_host = save_from_browser(
            &mutex,
            "IAM",
            "https://iam.hhughg.com:8381/login",
            "18698459937",
            "iam-pass",
        )
        .unwrap();
        assert_ne!(other_host, login_id);
        assert!(reveal_for_fill(&mutex, &other_host, "https://csm.hhughg.com:8280/#").is_err());
        assert!(save_from_browser(&mutex, "x", "not-a-url", "a", "b").is_err());
        let id = save_from_browser(&mutex, "New", "https://new.example", "a", "b").unwrap();
        assert!(!id.is_empty());
        let denied = handle_fill_http(&mutex, "/fill/secret", br#"{"id":"anything"}"#);
        assert!(denied.is_err());
    }

    #[test]
    fn classify_save_detects_password_update_without_returning_secret() {
        let mutex = unlocked_github();
        let hits = match_websites(&mutex, "https://github.com/login").unwrap();
        let changed = handle_fill_http(
            &mutex,
            "/fill/classify",
            br#"{"url":"https://github.com/login","username":"octocat","password":"new-pass"}"#,
        )
        .unwrap();
        assert_eq!(changed["ok"], true);
        assert_eq!(changed["action"], "update");
        assert_eq!(changed["id"], hits[0].id);
        assert!(changed.get("password").is_none());
        assert!(changed.get("entry").is_none());

        let same = handle_fill_http(
            &mutex,
            "/fill/classify",
            br#"{"url":"https://github.com/login","username":"octocat","password":"gh-pass"}"#,
        )
        .unwrap();
        assert_eq!(same["action"], "unchanged");
        assert_eq!(same["id"], hits[0].id);
        {
            let s = mutex.lock().unwrap();
            let listed = s
                .vault()
                .unwrap()
                .list_entries(&ListFilter {
                    query: None,
                    kind: Some(EntryKind::Website),
                    kinds: vec![EntryKind::Website],
                    folder_id: None,
                    uncategorized: false,
                    tag: None,
                    trash: false,
                    sort: SortBy::UseCount,
                })
                .unwrap();
            assert_eq!(listed[0].use_count, 0, "classify must not count as a fill");
        }

        let fresh = handle_fill_http(
            &mutex,
            "/fill/classify",
            br#"{"url":"https://github.com/login","username":"hubot","password":"robot"}"#,
        )
        .unwrap();
        assert_eq!(fresh["action"], "save");
        assert!(fresh
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty());
    }

    #[test]
    fn match_includes_notes_and_save_keeps_or_sets_notes() {
        let mutex = unlocked_github();
        let hits = match_websites(&mutex, "https://github.com/login").unwrap();
        {
            let s = mutex.lock().unwrap();
            let dek = *s.dek().unwrap();
            let vault = s.vault().unwrap();
            let secret = vault.get_secret(&dek, &hits[0].id).unwrap();
            vault
                .upsert_entry(
                    &dek,
                    UpsertEntry {
                        id: Some(hits[0].id.clone()),
                        kind: EntryKind::Website,
                        title: "GitHub".into(),
                        account: Some("octocat".into()),
                        url: Some("https://github.com".into()),
                        folder_id: None,
                        tags: vec![],
                        pinned: false,
                        expires_at: None,
                        notes: Some("工作号，别给外人用".into()),
                        secret,
                    },
                )
                .unwrap();
        }
        let listed = match_websites(&mutex, "https://github.com/login").unwrap();
        assert_eq!(listed[0].notes.as_deref(), Some("工作号，别给外人用"));
        let http = handle_fill_http(
            &mutex,
            "/fill/match",
            br#"{"url":"https://github.com/login"}"#,
        )
        .unwrap();
        assert_eq!(http["matches"][0]["notes"], "工作号，别给外人用");

        let updated = save_from_browser(
            &mutex,
            "GitHub",
            "https://github.com/login",
            "octocat",
            "new-pass",
        )
        .unwrap();
        assert_eq!(updated, hits[0].id);
        {
            let s = mutex.lock().unwrap();
            let dek = *s.dek().unwrap();
            let notes = s.vault().unwrap().get_notes(&dek, &hits[0].id).unwrap();
            assert_eq!(notes.as_deref(), Some("工作号，别给外人用"));
        }

        let id = save_from_browser_with_notes(
            &mutex,
            "New",
            "https://new.example",
            "alice",
            "pw",
            Some("浏览器登记"),
        )
        .unwrap();
        {
            let s = mutex.lock().unwrap();
            let dek = *s.dek().unwrap();
            let notes = s.vault().unwrap().get_notes(&dek, &id).unwrap();
            assert_eq!(notes.as_deref(), Some("浏览器登记"));
        }
    }
}
