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
    let u = url.trim();
    let rest = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
        .unwrap_or(u);
    let host = rest.split(['/', '?', '#']).next()?.trim();
    let host = host.split('@').next_back()?.trim();
    let host = host.split(':').next()?.trim().to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn registrable(host: &str) -> String {
    let h = host.trim_start_matches("www.");
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        h.to_string()
    }
}

fn score_host(page_host: &str, stored: &str) -> i32 {
    if page_host.is_empty() || stored.is_empty() {
        return 0;
    }
    let a = page_host.trim_start_matches("www.");
    let b = stored.trim_start_matches("www.");
    if a == b {
        100
    } else if registrable(a) == registrable(b) {
        90
    } else if a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}")) {
        80
    } else if a.contains(b) || b.contains(a) {
        40
    } else {
        0
    }
}

pub fn match_websites(session: &Mutex<Session>, page_url: &str) -> Result<Vec<FillMatch>, String> {
    let mut s = session.lock().map_err(|e| e.to_string())?;
    s.maybe_idle_lock();
    if !s.is_unlocked() {
        return Err("locked".into());
    }
    s.touch();
    let host = host_of(page_url).unwrap_or_default();
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
        let stored_host = e.url.as_deref().and_then(host_of).unwrap_or_default();
        let mut score = score_host(&host, &stored_host);
        let title_l = e.title.to_ascii_lowercase();
        let acc_l = e.account.clone().unwrap_or_default().to_ascii_lowercase();
        if score == 0 {
            let page_reg = registrable(&host);
            if title_l.contains(&host) || title_l.contains(&page_reg) || acc_l.contains(&host) {
                score = 30;
            }
        }
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
    let dto = vault
        .upsert_entry(
            &dek,
            UpsertEntry {
                id: None,
                kind: EntryKind::Website,
                title: if title.trim().is_empty() {
                    host_of(url).unwrap_or_else(|| "website".into())
                } else {
                    title.to_string()
                },
                account: Some(username.to_string()),
                url: Some(url.to_string()),
                folder_id: None,
                tags: vec!["browser".into()],
                pinned: false,
                expires_at: None,
                notes: None,
                secret: SecretPayload::Website {
                    url: Some(url.to_string()),
                    username: Some(username.to_string()),
                    password: password.to_string(),
                    totp_secret: None,
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
        assert_eq!(host_of("https://www.github.com/login").as_deref(), Some("www.github.com"));
        assert!(score_host("github.com", "www.github.com") >= 80);
        assert!(score_host("login.taobao.com", "www.taobao.com") >= 80);
        assert_eq!(score_host("example.com", "other.net"), 0);
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
        assert_eq!(sub.len(), 1);
        assert_eq!(hits[0].username, "octocat");
        let sec = reveal_for_fill(&mutex, &hits[0].id).unwrap();
        assert_eq!(sec.password, "gh-pass");
        let id = save_from_browser(&mutex, "New", "https://new.example", "a", "b").unwrap();
        assert!(!id.is_empty());
    }
}
