//! Local cache for the mail reader.
//!
//! Two rules keep this store honest:
//!
//! 1. It is a **cache**, never a source of truth. Every row can be thrown away and rebuilt from
//!    the server, which is why nothing here is part of the backup bundle or the sync payload.
//! 2. It never stores secrets the vault does not already hold. Rows are keyed by the vault entry
//!    id, hold only what the server returned to an already-authenticated session, and live in the
//!    encrypted vault database like every other table.
//!
//! Bodies are cached on demand: listing a folder stores metadata only, and the full body is
//! written back when the user opens a message. That keeps background polling from pulling every
//! mailbox down the wire.

use rusqlite::{params, Connection, OptionalExtension};

use crate::db::DbError;
use crate::mail::{MailBody, MailMessage};

/// `unread` counts only these roles. Sent/drafts/trash are excluded on purpose: servers commonly
/// omit `\Seen` on them, which would leave a badge that can never be cleared.
const BADGE_ROLES: [&str; 2] = ["inbox", "archive"];

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedMessage {
    pub uid: u32,
    pub from: String,
    pub subject: String,
    pub date: String,
    pub has_attachment: bool,
    pub seen: bool,
    pub flagged: bool,
    /// The first line or two of the body, so a list row can show a preview without a fetch.
    pub preview: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedFolder {
    pub account_id: String,
    pub name: String,
    pub role: String,
    pub unread: u32,
    /// The server's UIDVALIDITY, kept so a rebuilt folder is detected instead of misaligned.
    pub uid_validity: Option<u32>,
}

/// Collapses whitespace and truncates a body into a list preview.
pub fn make_preview(body: &str, limit: usize) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    for word in body.split_whitespace() {
        // The separator only exists once something has been written already.
        let separator = usize::from(!out.is_empty());
        let needed = word.chars().count();
        if used + needed + separator > limit {
            // CJK text has no spaces, so a single "word" can be the whole preview. Take as many
            // characters as still fit rather than returning nothing.
            let room = limit.saturating_sub(used + separator);
            if room == 0 {
                break;
            }
            if separator == 1 {
                out.push(' ');
            }
            out.extend(word.chars().take(room));
            return out;
        }
        if separator == 1 {
            out.push(' ');
        }
        out.push_str(word);
        used += needed + separator;
    }
    out
}

fn to_cached(message: &MailMessage, preview: &str) -> CachedMessage {
    CachedMessage {
        uid: message.uid,
        from: message.from.clone(),
        subject: message.subject.clone(),
        date: message.date.clone(),
        has_attachment: message.has_attachment,
        seen: message.seen,
        flagged: message.flagged,
        preview: preview.to_string(),
    }
}

/// Adds the mail cache tables. Called from [`crate::db::migrate`].
pub fn ensure_schema(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS mail_folders (
          account_id TEXT NOT NULL,
          name TEXT NOT NULL,
          role TEXT NOT NULL,
          uid_validity INTEGER,
          unread INTEGER NOT NULL DEFAULT 0,
          last_sync TEXT,
          PRIMARY KEY (account_id, name)
        );
        CREATE TABLE IF NOT EXISTS mail_messages (
          account_id TEXT NOT NULL,
          folder TEXT NOT NULL,
          uid INTEGER NOT NULL,
          subject TEXT NOT NULL DEFAULT '',
          from_addr TEXT NOT NULL DEFAULT '',
          date TEXT NOT NULL DEFAULT '',
          seen INTEGER NOT NULL DEFAULT 0,
          flagged INTEGER NOT NULL DEFAULT 0,
          has_attachment INTEGER NOT NULL DEFAULT 0,
          preview TEXT NOT NULL DEFAULT '',
          body_text TEXT,
          body_html TEXT,
          truncated INTEGER NOT NULL DEFAULT 0,
          body_fetched_at TEXT,
          PRIMARY KEY (account_id, folder, uid)
        );
        CREATE INDEX IF NOT EXISTS mail_messages_recent
          ON mail_messages (account_id, folder, uid DESC);
        "#,
    )?;
    Ok(())
}

/// Stores the folder list for an account, preserving each folder's cached unread count and its
/// UIDVALIDITY so a later sync can tell a rebuilt folder from an extended one.
pub fn save_folders(conn: &Connection, account_id: &str, folders: &[(String, String, Option<u32>)]) -> Result<(), DbError> {
    for (name, role, uid_validity) in folders {
        conn.execute(
            "INSERT INTO mail_folders (account_id, name, role, uid_validity, unread)
             VALUES (?1,?2,?3,?4,0)
             ON CONFLICT(account_id, name) DO UPDATE SET
               role=excluded.role,
               uid_validity=excluded.uid_validity,
               unread=CASE WHEN mail_folders.uid_validity IS excluded.uid_validity
                           THEN mail_folders.unread ELSE 0 END",
            params![account_id, name, role, uid_validity],
        )?;
    }
    Ok(())
}

pub fn folders(conn: &Connection, account_id: &str) -> Result<Vec<CachedFolder>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT account_id, name, role, unread, uid_validity FROM mail_folders
         WHERE account_id=?1 ORDER BY name",
    )?;
    let rows = stmt
        .query_map(params![account_id], |row| {
            Ok(CachedFolder {
                account_id: row.get(0)?,
                name: row.get(1)?,
                role: row.get(2)?,
                unread: row.get::<_, i64>(3)? as u32,
                uid_validity: row.get::<_, Option<i64>>(4)?.map(|value| value as u32),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Drops every cached message of a folder. Used when UIDVALIDITY changes, because the UIDs in
/// the cache would otherwise point at unrelated messages.
pub fn clear_folder(conn: &Connection, account_id: &str, folder: &str) -> Result<(), DbError> {
    conn.execute(
        "DELETE FROM mail_messages WHERE account_id=?1 AND folder=?2",
        params![account_id, folder],
    )?;
    Ok(())
}

/// Drops every cached message of an account, for when the credential entry disappears.
pub fn clear_account(conn: &Connection, account_id: &str) -> Result<(), DbError> {
    conn.execute("DELETE FROM mail_messages WHERE account_id=?1", params![account_id])?;
    conn.execute("DELETE FROM mail_folders WHERE account_id=?1", params![account_id])?;
    Ok(())
}

/// Stores a page of message metadata. Bodies already cached are kept, so re-listing a folder
/// does not throw away a body the user has already opened.
pub fn upsert_messages(
    conn: &Connection,
    account_id: &str,
    folder: &str,
    messages: &[MailMessage],
    previews: &[String],
) -> Result<(), DbError> {
    for (index, message) in messages.iter().enumerate() {
        let preview = previews.get(index).map(String::as_str).unwrap_or("");
        let cached = to_cached(message, preview);
        conn.execute(
            "INSERT INTO mail_messages
               (account_id, folder, uid, subject, from_addr, date, seen, flagged, has_attachment, preview)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(account_id, folder, uid) DO UPDATE SET
               subject=excluded.subject,
               from_addr=excluded.from_addr,
               date=excluded.date,
               seen=excluded.seen,
               flagged=excluded.flagged,
               has_attachment=excluded.has_attachment,
               preview=CASE WHEN excluded.preview='' THEN mail_messages.preview
                            ELSE excluded.preview END",
            params![
                account_id,
                folder,
                message.uid,
                cached.subject,
                cached.from,
                cached.date,
                cached.seen as i64,
                cached.flagged as i64,
                cached.has_attachment as i64,
                cached.preview,
            ],
        )?;
    }
    Ok(())
}

/// Stores the decoded body so reopening a message does not hit the network again.
pub fn save_body(
    conn: &Connection,
    account_id: &str,
    folder: &str,
    uid: u32,
    body: &MailBody,
    preview_limit: usize,
) -> Result<(), DbError> {
    let preview = make_preview(&body.text, preview_limit);
    conn.execute(
        "UPDATE mail_messages SET body_text=?4, body_html=?5, truncated=?6, body_fetched_at=?7,
                                  preview=CASE WHEN preview='' THEN ?8 ELSE preview END
         WHERE account_id=?1 AND folder=?2 AND uid=?3",
        params![
            account_id,
            folder,
            uid,
            body.text,
            body.html,
            body.truncated as i64,
            crate::vault::now_rfc3339_public(),
            preview,
        ],
    )?;
    Ok(())
}

/// A cached body, or `None` when the message has never been opened.
pub fn cached_body(conn: &Connection, account_id: &str, folder: &str, uid: u32) -> Result<Option<MailBody>, DbError> {
    let row: Option<(Option<String>, Option<String>, i64)> = conn
        .query_row(
            "SELECT body_text, body_html, truncated FROM mail_messages
             WHERE account_id=?1 AND folder=?2 AND uid=?3",
            params![account_id, folder, uid],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(match row {
        Some((Some(text), html, truncated)) => Some(MailBody { text, html, truncated: truncated != 0 }),
        _ => None,
    })
}

/// The newest cached messages of a folder, newest UID first.
pub fn recent_messages(
    conn: &Connection,
    account_id: &str,
    folder: &str,
    before: Option<u32>,
    limit: usize,
) -> Result<Vec<CachedMessage>, DbError> {
    let bound = before.unwrap_or(u32::MAX);
    let mut stmt = conn.prepare(
        "SELECT uid, from_addr, subject, date, has_attachment, seen, flagged, preview
         FROM mail_messages
         WHERE account_id=?1 AND folder=?2 AND uid < ?3
         ORDER BY uid DESC LIMIT ?4",
    )?;
    let rows = stmt
        .query_map(
            params![account_id, folder, bound as i64, limit as i64],
            |row| {
                Ok(CachedMessage {
                    uid: row.get::<_, i64>(0)? as u32,
                    from: row.get(1)?,
                    subject: row.get(2)?,
                    date: row.get(3)?,
                    has_attachment: row.get::<_, i64>(4)? != 0,
                    seen: row.get::<_, i64>(5)? != 0,
                    flagged: row.get::<_, i64>(6)? != 0,
                    preview: row.get(7)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Searches the messages already synced for this account, across every folder. This is what the
/// MCP `search` action reads: it never triggers a network fetch, so an AI caller cannot be used
/// to pull a mailbox down or to probe folder contents.
pub fn search_cached(
    conn: &Connection,
    account_id: &str,
    keyword: &str,
    limit: usize,
) -> Result<Vec<(String, CachedMessage)>, DbError> {
    let pattern = format!("%{}%", escape_like(keyword));
    let mut stmt = conn.prepare(
        "SELECT folder, uid, from_addr, subject, date, has_attachment, seen, flagged, preview
         FROM mail_messages
         WHERE account_id=?1 AND (subject LIKE ?2 ESCAPE '\\' OR from_addr LIKE ?2 ESCAPE '\\')
         ORDER BY uid DESC LIMIT ?3",
    )?;
    let rows = stmt
        .query_map(params![account_id, pattern, limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                CachedMessage {
                    uid: row.get::<_, i64>(1)? as u32,
                    from: row.get(2)?,
                    subject: row.get(3)?,
                    date: row.get(4)?,
                    has_attachment: row.get::<_, i64>(5)? != 0,
                    seen: row.get::<_, i64>(6)? != 0,
                    flagged: row.get::<_, i64>(7)? != 0,
                    preview: row.get(8)?,
                },
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// `%` and `_` are LIKE wildcards; a literal keyword must not turn into one.
fn escape_like(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Records the unread count for one folder.
pub fn set_unread(conn: &Connection, account_id: &str, folder: &str, unread: u32) -> Result<(), DbError> {
    conn.execute(
        "UPDATE mail_folders SET unread=?3, last_sync=?4 WHERE account_id=?1 AND name=?2",
        params![account_id, folder, unread as i64, crate::vault::now_rfc3339_public()],
    )?;
    Ok(())
}

/// The total badge number: unread across the folders a badge should count. A folder whose role is
/// unknown is skipped, so a provider-specific inbox alias cannot inflate the number.
pub fn badge_unread(conn: &Connection) -> Result<u32, DbError> {
    let mut total = 0u32;
    for role in BADGE_ROLES {
        let count: i64 = conn.query_row(
            "SELECT COALESCE(SUM(unread), 0) FROM mail_folders WHERE role=?1",
            params![role],
            |row| row.get(0),
        )?;
        total = total.saturating_add(count.max(0) as u32);
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_memory;

    fn message(uid: u32, subject: &str, from: &str, seen: bool) -> MailMessage {
        MailMessage {
            uid,
            from: from.into(),
            subject: subject.into(),
            date: "2026-11-12".into(),
            has_attachment: false,
            seen,
            flagged: false,
        }
    }

    fn seeded() -> Connection {
        let conn = open_memory().unwrap();
        save_folders(
            &conn,
            "acct",
            &[
                ("INBOX".into(), "inbox".into(), Some(7)),
                ("Sent Messages".into(), "sent".into(), Some(7)),
            ],
        )
        .unwrap();
        conn
    }

    #[test]
    fn previews_collapse_whitespace_and_stay_within_the_limit() {
        assert_eq!(make_preview("  你好  世界\n\n第二行 ", 20), "你好 世界 第二行");
        assert_eq!(make_preview("aaaa bbbb cccc", 9), "aaaa bbbb");
        assert_eq!(make_preview("", 10), "");
        // Never splits a multi-byte character.
        assert_eq!(make_preview("报销单据请查收", 3), "报销单");
    }

    #[test]
    fn messages_round_trip_newest_first_with_a_before_bound() {
        let conn = seeded();
        let page = vec![message(1, "One", "a@x.com", false), message(3, "Three", "c@x.com", true)];
        upsert_messages(&conn, "acct", "INBOX", &page, &["p1".into(), "p3".into()]).unwrap();
        let recent = recent_messages(&conn, "acct", "INBOX", None, 10).unwrap();
        assert_eq!(recent.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![3, 1]);
        assert_eq!(recent[0].preview, "p3");
        assert!(recent[0].seen);
        assert!(!recent[1].seen);
        let older = recent_messages(&conn, "acct", "INBOX", Some(3), 10).unwrap();
        assert_eq!(older.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![1]);
    }

    #[test]
    fn re_listing_keeps_an_already_cached_body() {
        let conn = seeded();
        upsert_messages(&conn, "acct", "INBOX", &[message(5, "Sub", "a@x.com", true)], &["preview".into()]).unwrap();
        let body = MailBody { text: "full text".into(), html: Some("<p>full text</p>".into()), truncated: false };
        save_body(&conn, "acct", "INBOX", 5, &body, 120).unwrap();
        // A later list refresh must not wipe the body it does not carry.
        upsert_messages(&conn, "acct", "INBOX", &[message(5, "Sub", "a@x.com", true)], &["preview".into()]).unwrap();
        assert_eq!(cached_body(&conn, "acct", "INBOX", 5).unwrap(), Some(body));
    }

    #[test]
    fn a_body_saved_before_the_row_exists_stores_nothing() {
        let conn = seeded();
        let body = MailBody { text: "text".into(), html: None, truncated: false };
        save_body(&conn, "acct", "INBOX", 99, &body, 120).unwrap();
        assert_eq!(cached_body(&conn, "acct", "INBOX", 99).unwrap(), None);
    }

    #[test]
    fn clearing_a_folder_or_an_account_drops_only_its_rows() {
        let conn = seeded();
        upsert_messages(&conn, "acct", "INBOX", &[message(1, "a", "a@x.com", false)], &[]).unwrap();
        upsert_messages(&conn, "acct", "Sent Messages", &[message(2, "b", "b@x.com", false)], &[]).unwrap();
        upsert_messages(&conn, "other", "INBOX", &[message(3, "c", "c@x.com", false)], &[]).unwrap();
        clear_folder(&conn, "acct", "INBOX").unwrap();
        assert!(recent_messages(&conn, "acct", "INBOX", None, 10).unwrap().is_empty());
        assert_eq!(recent_messages(&conn, "acct", "Sent Messages", None, 10).unwrap().len(), 1);
        assert_eq!(recent_messages(&conn, "other", "INBOX", None, 10).unwrap().len(), 1);
        clear_account(&conn, "acct").unwrap();
        assert!(recent_messages(&conn, "acct", "Sent Messages", None, 10).unwrap().is_empty());
        assert!(folders(&conn, "acct").unwrap().is_empty());
    }

    #[test]
    fn a_changed_uid_validity_resets_the_cached_unread_count() {
        let conn = seeded();
        set_unread(&conn, "acct", "INBOX", 4).unwrap();
        assert_eq!(folders(&conn, "acct").unwrap()[0].unread, 4);
        // Same UIDVALIDITY: the count survives a folder refresh.
        save_folders(&conn, "acct", &[("INBOX".into(), "inbox".into(), Some(7))]).unwrap();
        assert_eq!(folders(&conn, "acct").unwrap()[0].unread, 4);
        // Server rebuilt the folder: the old count no longer describes it.
        save_folders(&conn, "acct", &[("INBOX".into(), "inbox".into(), Some(8))]).unwrap();
        assert_eq!(folders(&conn, "acct").unwrap()[0].unread, 0);
    }

    #[test]
    fn the_badge_counts_only_inbox_and_archive() {
        let conn = seeded();
        save_folders(
            &conn,
            "acct",
            &[("Archive".into(), "archive".into(), Some(1)), ("Drafts".into(), "drafts".into(), Some(1))],
        )
        .unwrap();
        set_unread(&conn, "acct", "INBOX", 3).unwrap();
        set_unread(&conn, "acct", "Archive", 2).unwrap();
        set_unread(&conn, "acct", "Sent Messages", 50).unwrap();
        set_unread(&conn, "acct", "Drafts", 9).unwrap();
        assert_eq!(badge_unread(&conn).unwrap(), 5);
    }

    #[test]
    fn search_matches_subject_and_sender_and_escapes_wildcards() {
        let conn = seeded();
        upsert_messages(
            &conn,
            "acct",
            "INBOX",
            &[
                message(1, "10 月报销", "finance@x.com", false),
                message(2, "Invoice", "billing@x.com", false),
                message(3, "100% done", "ci@x.com", false),
            ],
            &[],
        )
        .unwrap();
        let hits = search_cached(&conn, "acct", "报销", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "INBOX");
        assert_eq!(hits[0].1.uid, 1);
        assert_eq!(search_cached(&conn, "acct", "billing", 10).unwrap().len(), 1);
        // A literal `%` must not behave as a wildcard.
        assert_eq!(search_cached(&conn, "acct", "100%", 10).unwrap().len(), 1);
        assert_eq!(search_cached(&conn, "acct", "%", 10).unwrap().len(), 1);
        assert!(search_cached(&conn, "acct", "nothing", 10).unwrap().is_empty());
    }
}
