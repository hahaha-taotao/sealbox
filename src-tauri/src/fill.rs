use crate::session::Session;
use crate::vault::{EntryKind, ListFilter, SecretPayload, SortBy, UpsertEntry};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct FillMatch {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    pub score: i32,
}

#[derive(Serialize)]
pub struct FillSecret {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
}

pub fn host_of(url: &str) -> Option<String> {
    origin_of(url).map(|(host, _port)| host)
}

/// Host without leading www, plus explicit or default port.
fn origin_of(url: &str) -> Option<(String, u16)> {
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
    let host = host.trim().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    let host = host.trim_start_matches("www.");
    if host.is_empty() || host == "localhost" || !host.contains('.') {
        None
    } else {
        Some((host.to_string(), port))
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

fn path_matches(page_path: &str, stored_path: &str) -> bool {
    if stored_path == "/" {
        return true;
    }
    page_path == stored_path || page_path.starts_with(&format!("{stored_path}/"))
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
    if !path_matches(&page_path, &stored_path) {
        return 0;
    }
    if stored_path == "/" {
        70
    } else {
        100
    }
}

pub fn match_websites(session: &Mutex<Session>, page_url: &str) -> Result<Vec<FillMatch>, String> {
    let mut s = session.lock().map_err(|e| e.to_string())?;
    s.maybe_idle_lock();
    if !s.is_unlocked() {
        return Err("locked".into());
    }
    s.touch();
    let vault = s.vault().map_err(|e| e.to_string())?;
    let list = vault
        .list_entries(&ListFilter {
            query: None,
            kind: Some(EntryKind::Website),
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
            out.push(FillMatch {
                id: e.id,
                title: e.title,
                username: e.account.unwrap_or_default(),
                url: e.url,
                score,
            });
        }
    }
    out.sort_by(|a, b| b.score.cmp(&a.score));
    Ok(out)
}

pub fn reveal_for_fill(session: &Mutex<Session>, id: &str) -> Result<FillSecret, String> {
    let mut s = session.lock().map_err(|e| e.to_string())?;
    s.maybe_idle_lock();
    if !s.is_unlocked() {
        return Err("locked".into());
    }
    let dek = *s.dek().map_err(|e| e.to_string())?;
    let payload = {
        let vault = s.vault().map_err(|e| e.to_string())?;
        vault.get_secret(&dek, id).map_err(|e| e.to_string())?
    };
    let SecretPayload::Website {
        username, password, ..
    } = payload
    else {
        return Err("not a website entry".into());
    };
    let vault = s.vault().map_err(|e| e.to_string())?;
    let dto = vault
        .list_entries(&ListFilter {
            query: None,
            kind: None,
            folder_id: None,
            uncategorized: false,
            tag: None,
            trash: false,
            sort: SortBy::UseCount,
        })
        .ok()
        .and_then(|list| list.into_iter().find(|e| e.id == id));
    let _ = vault.bump_use(id);
    let _ = vault.audit("browser_fill", Some(id), "ok");
    Ok(FillSecret {
        id: id.to_string(),
        title: dto.as_ref().map(|d| d.title.clone()).unwrap_or_default(),
        username: username.unwrap_or_default(),
        password,
    })
}

pub fn save_from_browser(
    session: &Mutex<Session>,
    title: &str,
    url: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let mut s = session.lock().map_err(|e| e.to_string())?;
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
            folder_id: None,
            uncategorized: false,
            tag: None,
            trash: false,
            sort: SortBy::UseCount,
        })
        .map_err(|e| e.to_string())?;
    let origin = origin_of(url);
    let mut reuse_id = None;
    let mut totp_secret = None;
    let mut folder_id = None;
    let mut tags = vec!["browser".into()];
    let mut pinned = false;
    let mut expires_at = None;
    for e in existing {
        let Some(stored) = e.url.as_deref() else {
            continue;
        };
        if origin.is_some() && origin == origin_of(stored) && e.account.as_deref() == Some(username)
        {
            reuse_id = Some(e.id.clone());
            folder_id = e.folder_id;
            tags = e.tags;
            pinned = e.pinned;
            expires_at = e.expires_at;
            if let Ok(SecretPayload::Website { totp_secret: t, .. }) = vault.get_secret(&dek, &e.id)
            {
                totp_secret = t;
            }
            break;
        }
    }
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
                notes: None,
                secret: SecretPayload::Website {
                    url: Some(url.to_string()),
                    username: Some(username.to_string()),
                    password: password.to_string(),
                    totp_secret,
                },
            },
        )
        .map_err(|e| e.to_string())?;
    Ok(dto.id)
}

pub fn handle_fill_http(session: &Mutex<Session>, path: &str, body: &[u8]) -> Result<Value, (u16, String)> {
    let v: Value = serde_json::from_slice(body).unwrap_or(json!({}));
    match path {
        "/fill/status" => {
            let unlocked = session.lock().map(|s| s.is_unlocked()).unwrap_or(false);
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
            match reveal_for_fill(session, id) {
                Ok(sec) => Ok(json!({ "ok": true, "entry": sec })),
                Err(e) if e == "locked" => Err((403, "vault locked".into())),
                Err(e) => Err((400, e)),
            }
        }
        "/fill/save" => {
            let title = v.get("title").and_then(|x| x.as_str()).unwrap_or("");
            let url = v.get("url").and_then(|x| x.as_str()).unwrap_or("");
            let username = v.get("username").and_then(|x| x.as_str()).unwrap_or("");
            let password = v.get("password").and_then(|x| x.as_str()).unwrap_or("");
            if url.is_empty() || password.is_empty() {
                return Err((400, "url and password required".into()));
            }
            match save_from_browser(session, title, url, username, password) {
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

pub fn write_bridge_file(dir: &std::path::Path, port: u16, fill_token: &str) {
    let path = dir.join("fill.json");
    let body = serde_json::json!({ "port": port, "fillToken": fill_token });
    let _ = std::fs::write(path, body.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;

    #[test]
    fn host_and_score() {
        assert_eq!(host_of("https://www.github.com/login").as_deref(), Some("github.com"));
        assert!(score_url("https://github.com/login", "https://www.github.com") >= 70);
        assert_eq!(score_url("https://login.taobao.com/", "https://www.taobao.com"), 0);
        assert_eq!(
            score_url("https://csm.hhughg.com:8280/", "https://iam.hhughg.com:8381"),
            0
        );
        assert!(
            score_url("https://csm.hhughg.com:8280/", "https://csm.hhughg.com:8280") >= 70
        );
        assert_eq!(
            score_url("https://csm.hhughg.com:8280/", "https://csm.hhughg.com:8281"),
            0
        );
        assert_eq!(score_url("https://example.com", "https://other.net"), 0);
        assert_eq!(
            score_url(
                "https://heat.example.com/billing/login",
                "https://heat.example.com/iam"
            ),
            0
        );
        assert!(
            score_url(
                "https://heat.example.com/iam/login",
                "https://heat.example.com/iam"
            ) >= 90
        );
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
        let sec = reveal_for_fill(&mutex, &hits[0].id).unwrap();
        assert_eq!(sec.password, "gh-pass");
        let id = save_from_browser(&mutex, "New", "https://new.example", "a", "b").unwrap();
        assert!(!id.is_empty());
    }
}
