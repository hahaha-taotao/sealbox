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

/// How a folder's unread number is derived.
///
/// **Unread is counted from `mail_messages` at read time**, not from `mail_folders.unread`.
///
/// `mail_folders.unread` is what the *server* last reported for a folder. It is a snapshot: it is
/// only written by a sync, and it counts messages this client has never cached. Counting from it
/// produces numbers the user cannot act on — a fresh account that only ever listed its inbox
/// shows 0 next to a folder full of unread mail, and a server value of 5 against 3 cached rows
/// leaves two unread the reader can never reach. Both are "a底数 that cannot be cleared".
///
/// The live count can only ever be a *lower* bound (it sees cached rows, not the whole folder),
/// and that is the failure mode worth having: too small is corrected by the next refresh, while
/// too large cannot be corrected by anything the user does. `mail_folders.unread` is therefore
/// kept only as the server's own figure for comparisons, and feeds no user-visible number.
fn folder_unread(conn: &Connection, account_id: &str, folder: &str) -> Result<u32, DbError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM mail_messages
         WHERE account_id=?1 AND folder=?2 AND seen=0 AND local_seen=0",
        params![account_id, folder],
        |row| row.get(0),
    )?;
    Ok(count.max(0) as u32)
}

/// Total live unread across one account, resolving each cached folder to its role.
fn live_unread_by_role(conn: &Connection, account_id: &str) -> Result<UnreadByRole, DbError> {
    let folders = conn
        .prepare("SELECT name, role FROM mail_folders WHERE account_id=?1")?
        .query_map(params![account_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut totals = UnreadByRole::default();
    for (name, role) in folders {
        let count = folder_unread(conn, account_id, &name)?;
        match role.as_str() {
            "inbox" => totals.inbox = totals.inbox.saturating_add(count),
            "archive" => totals.archive = totals.archive.saturating_add(count),
            "sent" => totals.sent = totals.sent.saturating_add(count),
            "drafts" => totals.drafts = totals.drafts.saturating_add(count),
            "trash" => totals.trash = totals.trash.saturating_add(count),
            _ => totals.other = totals.other.saturating_add(count),
        }
    }
    Ok(totals)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedMessage {
    pub uid: u32,
    pub from: String,
    pub subject: String,
    pub date: String,
    pub has_attachment: bool,
    /// The merged read state: `true` when the server says `\Seen` or the row was marked read
    /// locally. Unread only while both sources still say unread.
    pub seen: bool,
    pub flagged: bool,
    /// The first line or two of the body, so a list row can show a preview without a fetch.
    pub preview: String,
}

/// Which slice of a folder a local page asks for. Mirrors [`crate::mail_folder::MailFilter`] but
/// is evaluated against cached columns instead of `UID SEARCH`, so it stays valid offline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LocalFilter {
    #[default]
    All,
    Unread,
    Attached,
    Flagged,
}

impl LocalFilter {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "" | "all" => Some(Self::All),
            "unread" => Some(Self::Unread),
            "attached" => Some(Self::Attached),
            "flagged" => Some(Self::Flagged),
            _ => None,
        }
    }

    /// The `AND ...` fragment a query appends for this filter. Kept as a constant string, never
    /// built from user input, so it can be concatenated into SQL safely.
    fn clause(&self) -> &'static str {
        match self {
            Self::All => "",
            // The merged read state: unread on the server *and* not read locally.
            Self::Unread => " AND seen=0 AND local_seen=0",
            Self::Attached => " AND has_attachment<>0",
            Self::Flagged => " AND flagged<>0",
        }
    }
}

/// Read state of one folder, as the sidebar and the folder rows need it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnreadByRole {
    pub inbox: u32,
    pub archive: u32,
    pub sent: u32,
    pub drafts: u32,
    pub trash: u32,
    pub other: u32,
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

/// Longest teaser a list row carries. Kept next to [`make_preview`] so the cache writer and the
/// reader that hands a teaser to the UI cannot drift apart.
pub const PREVIEW_LIMIT: usize = 120;

/// Trims a stored teaser to what a list row may carry.
///
/// Rows written by [`save_body`] are already inside the limit, so this only matters for a row
/// restored from a backup or written by an older build. Cutting on `char` boundaries keeps a
/// multi-byte character intact — the same guarantee [`make_preview`] makes.
pub fn clamp_preview(preview: &str) -> String {
    preview.chars().take(PREVIEW_LIMIT).collect()
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

/// Adds the mail cache tables. Called from [`crate::db::migrate`], so it runs on every open of
/// every existing vault — including vaults created before a column existed here.
///
/// `CREATE TABLE IF NOT EXISTS` cannot add a column to a table that already exists, so every
/// column added after the first release is applied by [`add_column_if_missing`] instead. Nothing
/// here may fail on an old database.
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
    // Read-locally flag. Set when the reader shows a message, never sent back to the server:
    // this store is a cache, and marking seen is a write the mailbox must not receive from here.
    add_column_if_missing(conn, "mail_messages", "local_seen", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(conn, "mail_messages", "pinned_at", "TEXT")?;
    add_column_if_missing(conn, "mail_messages", "uid_validity", "INTEGER")?;
    Ok(())
}

/// `ALTER TABLE ... ADD COLUMN` that tolerates being run again. `PRAGMA table_info` is the
/// authority, so a database that already has the column is left untouched.
fn add_column_if_missing(conn: &Connection, table: &str, column: &str, decl: &str) -> Result<(), DbError> {
    // `table`/`column`/`decl` are literals from this module, never user input, so the format!
    // below cannot carry an injection.
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&sql)?;
    let names: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .collect();
    if names.iter().any(|name| name == column) {
        return Ok(());
    }
    conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"), [])?;
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
        "SELECT uid, from_addr, subject, date, has_attachment, seen, flagged, preview, local_seen
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
                    seen: merged_seen(row.get::<_, i64>(5)? != 0, row.get::<_, i64>(8)? != 0),
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
        "SELECT folder, uid, from_addr, subject, date, has_attachment, seen, flagged, preview, local_seen
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
                    seen: merged_seen(row.get::<_, i64>(6)? != 0, row.get::<_, i64>(9)? != 0),
                    flagged: row.get::<_, i64>(7)? != 0,
                    preview: row.get(8)?,
                },
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// The read state a row reports: read when either source recorded a read. `seen` is what the
/// server said, `local_seen` is "the user opened it here and we deliberately did not tell the
/// server" — so a message stays unread only while both sources still say unread.
fn merged_seen(server_seen: bool, local_seen: bool) -> bool {
    server_seen || local_seen
}

/// Everything the reader needs to open a cached message without another round trip.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BodyState {
    /// A body has been cached, so the reader can open it without the network.
    pub ready: bool,
    /// Row read state, already merged with `local_seen`.
    pub seen: bool,
}

/// A local page of one folder, newest UID first.
///
/// `before` is the UID pagination cursor — the exclusive upper bound — so the reader can scroll
/// without the server. The filter and keyword are applied to cached columns, which keeps the
/// result honest when offline: it never claims to show mail that was never synced.
pub fn list_local(
    conn: &Connection,
    account_id: &str,
    folder: &str,
    before: Option<u32>,
    limit: usize,
    filter: LocalFilter,
    keyword: &str,
) -> Result<Vec<CachedMessage>, DbError> {
    let bound = before.unwrap_or(u32::MAX);
    let keyword = keyword.trim();
    let pattern = format!("%{}%", escape_like(keyword));
    let sql = format!(
        "SELECT uid, from_addr, subject, date, has_attachment, seen, flagged, preview, local_seen
         FROM mail_messages
         WHERE account_id=?1 AND folder=?2 AND uid < ?3{}
           AND (?4='' OR subject LIKE ?5 ESCAPE '\\' OR from_addr LIKE ?5 ESCAPE '\\')
         ORDER BY uid DESC LIMIT ?6",
        filter.clause()
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(
            params![account_id, folder, bound as i64, keyword, pattern, limit as i64],
            |row| {
                Ok(CachedMessage {
                    uid: row.get::<_, i64>(0)? as u32,
                    from: row.get(1)?,
                    subject: row.get(2)?,
                    date: row.get(3)?,
                    has_attachment: row.get::<_, i64>(4)? != 0,
                    seen: merged_seen(row.get::<_, i64>(5)? != 0, row.get::<_, i64>(8)? != 0),
                    flagged: row.get::<_, i64>(6)? != 0,
                    preview: row.get(7)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// The newest cached rows of every folder at once, for a combined "all inboxes" view. `limit` is
/// applied per folder so one busy folder cannot hide the others.
pub fn cached_list_all(
    conn: &Connection,
    account_id: &str,
    limit: usize,
) -> Result<Vec<(String, CachedMessage)>, DbError> {
    let folders = conn
        .prepare("SELECT name FROM mail_folders WHERE account_id=?1 ORDER BY name")?
        .query_map(params![account_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut out: Vec<(String, CachedMessage)> = Vec::new();
    for folder in folders {
        for message in list_local(conn, account_id, &folder, None, limit, LocalFilter::All, "")? {
            out.push((folder.clone(), message));
        }
    }
    Ok(out)
}

/// Records "the user has read this" in the local cache only.
///
/// Two numbers move together: the row's `local_seen`, and the folder's cached unread count when
/// the row had counted towards it. Nothing is written to the server — no `STORE \Seen`, no
/// `EXPUNGE` — because this client is read-only by design.
pub fn set_local_seen(conn: &Connection, account_id: &str, folder: &str, uid: u32) -> Result<(), DbError> {
    let local_seen: Option<i64> = conn
        .query_row(
            "SELECT local_seen FROM mail_messages WHERE account_id=?1 AND folder=?2 AND uid=?3",
            params![account_id, folder, uid],
            |row| row.get(0),
        )
        .optional()?;
    // An unknown row, or one already marked read, is a no-op rather than an error.
    match local_seen {
        None => return Ok(()),
        Some(flag) if flag != 0 => return Ok(()),
        Some(_) => {}
    }
    conn.execute(
        "UPDATE mail_messages SET local_seen=1 WHERE account_id=?1 AND folder=?2 AND uid=?3",
        params![account_id, folder, uid],
    )?;
    // `mail_folders.unread` is deliberately left alone: unread is counted live from
    // `mail_messages` (see [`folder_unread`]), so flipping this row already moved the number by
    // exactly one and there is no counter to decrement — and therefore no counter to underflow.
    Ok(())
}

/// Marks a cached message as pinned (kept across [`sweep`]) or unpinned.
pub fn set_pinned(conn: &Connection, account_id: &str, folder: &str, uid: u32, pinned: bool) -> Result<(), DbError> {
    let value: Option<String> = if pinned {
        Some(crate::vault::now_rfc3339_public())
    } else {
        None
    };
    conn.execute(
        "UPDATE mail_messages SET pinned_at=?4 WHERE account_id=?1 AND folder=?2 AND uid=?3",
        params![account_id, folder, uid, value],
    )?;
    Ok(())
}

/// Runs a `uid`-shaped query into a set. Used by [`sweep`] to resolve its keep-sets before it
/// decides anything, so the decision lives in one readable place rather than in SQL subtleties.
fn uid_set<P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    params: P,
) -> Result<std::collections::HashSet<u32>, DbError> {
    let mut stmt = conn.prepare(sql)?;
    let uids = stmt
        .query_map(params, |row| row.get::<_, i64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(uids.into_iter().map(|uid| uid as u32).collect())
}

/// How many body-bearing rows one folder may keep. Scrollback is cheap; bodies are not, so they
/// get their own ceiling at twice the metadata window.
const fn body_keep_for(keep: usize) -> usize {
    keep.saturating_mul(2)
}

/// UIDs whose body is cached, most recently fetched first. Used by [`sweep`] and available to a
/// caller that wants to keep or show what has already been read.
pub fn recent_body_uids(
    conn: &Connection,
    account_id: &str,
    folder: &str,
    limit: usize,
) -> Result<Vec<u32>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT uid FROM mail_messages
         WHERE account_id=?1 AND folder=?2 AND body_fetched_at IS NOT NULL
         ORDER BY body_fetched_at DESC, uid DESC LIMIT ?3",
    )?;
    let uids = stmt
        .query_map(params![account_id, folder, limit as i64], |row| row.get::<_, i64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(uids.into_iter().map(|uid| uid as u32).collect())
}

/// Trims a folder's cache without throwing away the work that was expensive to produce.
///
/// Two tiers, because two kinds of row have very different replacement costs:
///
/// * **Metadata** (an envelope and a preview) is cheap: anything older than the newest `keep`
///   UIDs goes.
/// * **A cached body** costs a full `BODY.PEEK` round trip, and it is the one thing the user
///   already asked for by opening the message. Those rows are kept even when they are old, up to
///   their own ceiling of `keep * 2`, dropping the *least recently fetched* first. A sync only
///   ever rewrites the newest page, so an old row that is dropped is dropped for good — this is
///   why the order here is by `body_fetched_at` and not by UID.
///
/// `flagged` (starred) rows are always kept: the star is the user saying "not this one". Rows
/// passed in `pindowns` are pinned and marked read first, so an explicit pin can never come back
/// as a badge the user already dealt with.
///
/// 只删元数据+正文，不碰服务器: this is the only place that deletes cached mail, and it only
/// ever writes to this database.
pub fn sweep(conn: &Connection, account_id: &str, folder: &str, keep: usize, pindowns: &[u32]) -> Result<usize, DbError> {
    for uid in pindowns {
        conn.execute(
            "UPDATE mail_messages SET pinned_at=COALESCE(pinned_at, ?4), local_seen=1
             WHERE account_id=?1 AND folder=?2 AND uid=?3",
            params![account_id, folder, *uid as i64, crate::vault::now_rfc3339_public()],
        )?;
    }
    let body_keep = body_keep_for(keep);
    // The two keep-sets are resolved up front instead of being embedded as correlated
    // subqueries: a correlated `EXISTS ... ORDER BY ... LIMIT` is evaluated once per row, so its
    // LIMIT would not mean "the newest N" at all. `NOT IN` is avoided for the reason it always
    // is — one NULL makes the predicate NULL and quietly keeps every row.
    let metadata_keep = uid_set(
        conn,
        "SELECT uid FROM mail_messages
         WHERE account_id=?1 AND folder=?2
         ORDER BY uid DESC LIMIT ?3",
        params![account_id, folder, keep as i64],
    )?;
    let body_keep_set = uid_set(
        conn,
        "SELECT uid FROM mail_messages
         WHERE account_id=?1 AND folder=?2 AND body_fetched_at IS NOT NULL
         ORDER BY body_fetched_at DESC, uid DESC LIMIT ?3",
        params![account_id, folder, body_keep as i64],
    )?;
    // Starred and pinned rows are not candidates at all: they are the user's explicit keep.
    let candidates = uid_set(
        conn,
        "SELECT uid FROM mail_messages
         WHERE account_id=?1 AND folder=?2 AND pinned_at IS NULL AND flagged=0",
        params![account_id, folder],
    )?;
    let mut removed = 0usize;
    for uid in candidates {
        if !metadata_keep.contains(&uid) && !body_keep_set.contains(&uid) {
            removed += conn.execute(
                "DELETE FROM mail_messages WHERE account_id=?1 AND folder=?2 AND uid=?3",
                params![account_id, folder, uid as i64],
            )?;
            continue;
        }
        // The row stays, but a body outside the ceiling must not keep costing disk on a row that
        // would otherwise have been dropped. Clearing the body is what makes the ceiling real.
        if metadata_keep.contains(&uid) && !body_keep_set.contains(&uid) {
            conn.execute(
                "UPDATE mail_messages
                 SET body_text=NULL, body_html=NULL, truncated=0, body_fetched_at=NULL
                 WHERE account_id=?1 AND folder=?2 AND uid=?3 AND body_fetched_at IS NOT NULL",
                params![account_id, folder, uid as i64],
            )?;
        }
    }
    Ok(removed)
}

/// The newest messages of a folder whose body is not cached yet, so a background pass can fill
/// them in and make reopening the list and any message instant.
pub fn prefetch_candidates(
    conn: &Connection,
    account_id: &str,
    folder: &str,
    limit: usize,
) -> Result<Vec<u32>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT uid FROM mail_messages
         WHERE account_id=?1 AND folder=?2 AND body_text IS NULL
         ORDER BY uid DESC LIMIT ?3",
    )?;
    let uids = stmt
        .query_map(params![account_id, folder, limit as i64], |row| row.get::<_, i64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(uids.into_iter().map(|uid| uid as u32).collect())
}

/// When the cache last learned anything about a folder, as RFC 3339, or `None` when nothing has
/// been synced. The reader uses it to say how old a cached page is instead of implying it is live.
pub fn folder_fetched_at(conn: &Connection, account_id: &str, folder: &str) -> Result<Option<String>, DbError> {
    let row: Option<Option<String>> = conn
        .query_row(
            "SELECT MAX(COALESCE(body_fetched_at, '')) FROM mail_messages
             WHERE account_id=?1 AND folder=?2",
            params![account_id, folder],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(Some(value)) = row {
        if !value.is_empty() {
            return Ok(Some(value));
        }
    }
    // No body has been fetched yet, so fall back to the folder's own last sync stamp.
    let synced: Option<Option<String>> = conn
        .query_row(
            "SELECT last_sync FROM mail_folders WHERE account_id=?1 AND name=?2",
            params![account_id, folder],
            |row| row.get(0),
        )
        .optional()?;
    Ok(synced.flatten())
}

/// The merged read state of one row, for callers that already hold it open.
pub fn body_state(conn: &Connection, account_id: &str, folder: &str, uid: u32) -> Result<BodyState, DbError> {
    let row: Option<(i64, i64, Option<String>)> = conn
        .query_row(
            "SELECT seen, local_seen, body_fetched_at FROM mail_messages
             WHERE account_id=?1 AND folder=?2 AND uid=?3",
            params![account_id, folder, uid],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(match row {
        Some((server_seen, local_seen, fetched)) => BodyState {
            ready: fetched.is_some(),
            seen: merged_seen(server_seen != 0, local_seen != 0),
        },
        None => BodyState::default(),
    })
}

/// Local unread per role, so the sidebar badge and every folder row read from one place.
///
/// The numbers are the cached counters maintained by [`set_unread`] and [`set_local_seen`]; no
/// server round trip happens here.
pub fn unread_by_role(conn: &Connection) -> Result<UnreadByRole, DbError> {
    unread_by_role_for_account(conn, None)
}

/// Live unread per role, for every account or just one. See [`folder_unread`] for why the number
/// is counted from the messages table rather than read off the folder snapshot.
pub fn unread_by_role_for_account(
    conn: &Connection,
    account_id: Option<&str>,
) -> Result<UnreadByRole, DbError> {
    let accounts: Vec<String> = match account_id {
        Some(id) => vec![id.to_string()],
        None => conn
            .prepare("SELECT DISTINCT account_id FROM mail_folders")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?,
    };
    let mut totals = UnreadByRole::default();
    for account in accounts {
        let one = live_unread_by_role(conn, &account)?;
        totals.inbox = totals.inbox.saturating_add(one.inbox);
        totals.archive = totals.archive.saturating_add(one.archive);
        totals.sent = totals.sent.saturating_add(one.sent);
        totals.drafts = totals.drafts.saturating_add(one.drafts);
        totals.trash = totals.trash.saturating_add(one.trash);
        totals.other = totals.other.saturating_add(one.other);
    }
    Ok(totals)
}

/// One folder's live unread count, the number its row in the sidebar shows.
pub fn folder_unread_count(conn: &Connection, account_id: &str, folder: &str) -> Result<u32, DbError> {
    folder_unread(conn, account_id, folder)
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
    let by_role = unread_by_role_for_account(conn, None)?;
    let mut total = 0u32;
    for role in BADGE_ROLES {
        total = total.saturating_add(match role {
            "inbox" => by_role.inbox,
            _ => by_role.archive,
        });
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
            preview: String::new(),
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
        // The badge is a live count over the two badge roles, so it needs real rows in each.
        upsert_messages(&conn, "acct", "INBOX", &[message(1, "a", "a@x.com", false)], &[]).unwrap();
        upsert_messages(
            &conn,
            "acct",
            "Archive",
            &[message(2, "b", "b@x.com", false), message(3, "c", "c@x.com", false)],
            &[],
        )
        .unwrap();
        // Sent/drafts are excluded on purpose: servers commonly omit `\Seen` there, so counting
        // them would leave a badge that can never be cleared.
        upsert_messages(&conn, "acct", "Sent Messages", &[message(4, "d", "d@x.com", false)], &[]).unwrap();
        upsert_messages(&conn, "acct", "Drafts", &[message(5, "e", "e@x.com", false)], &[]).unwrap();
        set_unread(&conn, "acct", "INBOX", 3).unwrap();
        set_unread(&conn, "acct", "Archive", 2).unwrap();
        set_unread(&conn, "acct", "Sent Messages", 50).unwrap();
        set_unread(&conn, "acct", "Drafts", 9).unwrap();
        assert_eq!(badge_unread(&conn).unwrap(), 3);
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

    fn seeded_inbox(uids: &[u32]) -> Connection {
        let conn = seeded();
        let page = uids
            .iter()
            .map(|uid| message(*uid, &format!("Subject {uid}"), "a@x.com", false))
            .collect::<Vec<_>>();
        upsert_messages(&conn, "acct", "INBOX", &page, &[]).unwrap();
        save_folders(&conn, "acct", &[("Archive".into(), "archive".into(), Some(1))]).unwrap();
        conn
    }

    #[test]
    fn schema_migration_is_idempotent_on_an_existing_database() {
        // A database created before `local_seen`/`pinned_at`/`uid_validity` existed.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE mail_messages (
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
               body_text TEXT, body_html TEXT,
               truncated INTEGER NOT NULL DEFAULT 0,
               body_fetched_at TEXT,
               PRIMARY KEY (account_id, folder, uid));
             INSERT INTO mail_messages (account_id, folder, uid, subject)
               VALUES ('acct','INBOX',1,'kept');",
        )
        .unwrap();
        // Running it twice is what an upgrade does: open, migrate, open, migrate.
        ensure_schema(&conn).unwrap();
        ensure_schema(&conn).unwrap();
        // The row from the old schema survives, with the new columns at their defaults.
        let row: (String, i64) = conn
            .query_row(
                "SELECT subject, local_seen FROM mail_messages WHERE uid=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(row, ("kept".to_string(), 0));
        // And the new columns are usable.
        set_local_seen(&conn, "acct", "INBOX", 1).unwrap();
        assert_eq!(body_state(&conn, "acct", "INBOX", 1).unwrap().seen, true);
    }

    #[test]
    fn local_listing_pages_newest_first_with_a_uid_cursor() {
        let conn = seeded_inbox(&[1, 2, 3, 4, 5]);
        let page = list_local(&conn, "acct", "INBOX", None, 2, LocalFilter::All, "").unwrap();
        assert_eq!(page.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![5, 4]);
        let older = list_local(&conn, "acct", "INBOX", Some(4), 2, LocalFilter::All, "").unwrap();
        assert_eq!(older.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![3, 2]);
        // A folder with nothing cached is empty, not an error.
        assert!(list_local(&conn, "acct", "Nope", None, 10, LocalFilter::All, "").unwrap().is_empty());
    }

    #[test]
    fn local_listing_filters_on_cached_columns() {
        let conn = seeded();
        upsert_messages(
            &conn,
            "acct",
            "INBOX",
            &[
                message(1, "plain", "a@x.com", false),
                MailMessage { has_attachment: true, ..message(2, "with file", "b@x.com", false) },
                MailMessage { flagged: true, ..message(3, "starred", "c@x.com", false) },
                message(4, "already read", "d@x.com", true),
            ],
            &[],
        )
        .unwrap();
        let unread = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::Unread, "").unwrap();
        assert_eq!(unread.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![3, 2, 1]);
        let attached = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::Attached, "").unwrap();
        assert_eq!(attached.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![2]);
        let flagged = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::Flagged, "").unwrap();
        assert_eq!(flagged.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![3]);
        // A keyword matches subject or sender, and a literal `%` is not a wildcard.
        let hits = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::All, "star").unwrap();
        assert_eq!(hits.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![3]);
        let sender = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::All, "c@x").unwrap();
        assert_eq!(sender.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![3]);
        assert!(list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::All, "%").unwrap().is_empty());
        // Filter + keyword compose.
        let combined = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::Unread, "with").unwrap();
        assert_eq!(combined.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![2]);
    }

    #[test]
    fn local_seen_merges_with_the_server_flag_and_never_unreads() {
        // `seeded_inbox` saves folders after seeding, so the counter is set afterwards.
        let conn = seeded_inbox(&[1, 2]);
        set_unread(&conn, "acct", "INBOX", 2).unwrap();
        // Opening message 2 marks it read locally only.
        set_local_seen(&conn, "acct", "INBOX", 2).unwrap();
        let page = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::All, "").unwrap();
        assert!(page.iter().find(|m| m.uid == 2).unwrap().seen);
        assert!(!page.iter().find(|m| m.uid == 1).unwrap().seen);
        // Unread now means "unread on the server AND not read here".
        let unread = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::Unread, "").unwrap();
        assert_eq!(unread.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![1]);
        // The live count followed the local read. It is counted from `mail_messages`, not from
        // the `mail_folders` snapshot, so the snapshot may still hold the server's own figure.
        let inbox_unread = |conn: &Connection| folder_unread_count(conn, "acct", "INBOX").unwrap();
        assert_eq!(inbox_unread(&conn), 1);
        // Repeating it must not count twice.
        set_local_seen(&conn, "acct", "INBOX", 2).unwrap();
        assert_eq!(inbox_unread(&conn), 1);
        // An unknown row is a no-op rather than an error.
        set_local_seen(&conn, "acct", "INBOX", 99).unwrap();
        assert_eq!(inbox_unread(&conn), 1);
        // A row the server already reports read was never counted, so marking it changes nothing.
        upsert_messages(&conn, "acct", "INBOX", &[message(3, "seen", "a@x.com", true)], &[]).unwrap();
        set_local_seen(&conn, "acct", "INBOX", 3).unwrap();
        assert_eq!(inbox_unread(&conn), 1);
        // The count never goes negative however many times a read is recorded.
        set_local_seen(&conn, "acct", "INBOX", 1).unwrap();
        set_local_seen(&conn, "acct", "INBOX", 1).unwrap();
        assert_eq!(inbox_unread(&conn), 0);
    }

    #[test]
    fn a_row_the_server_flips_to_seen_stays_seen_after_a_refresh() {
        let conn = seeded_inbox(&[7]);
        upsert_messages(&conn, "acct", "INBOX", &[message(7, "Sub", "a@x.com", true)], &[]).unwrap();
        assert!(list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::All, "")
            .unwrap()[0]
            .seen);
        // A later refresh that reports unread must not rewrite a local read back to unread.
        upsert_messages(&conn, "acct", "INBOX", &[message(7, "Sub", "a@x.com", true)], &[]).unwrap();
        assert!(body_state(&conn, "acct", "INBOX", 7).unwrap().seen);
    }

    #[test]
    fn sweep_keeps_the_newest_rows_and_every_pinned_one() {
        let conn = seeded_inbox(&[1, 2, 3, 4, 5, 6]);
        set_pinned(&conn, "acct", "INBOX", 1, true).unwrap();
        // Keep the newest three (6,5,4) plus the pinned 1.
        let removed = sweep(&conn, "acct", "INBOX", 3, &[]).unwrap();
        assert_eq!(removed, 2);
        let kept = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::All, "").unwrap();
        assert_eq!(kept.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![6, 5, 4, 1]);
        // A pindown naming a row that is no longer cached is a no-op, not a resurrection.
        let removed = sweep(&conn, "acct", "INBOX", 3, &[2]).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(body_state(&conn, "acct", "INBOX", 2).unwrap(), BodyState::default());
        // Pin the row before the next sweep: it survives a tighter keep.
        set_pinned(&conn, "acct", "INBOX", 5, true).unwrap();
        sweep(&conn, "acct", "INBOX", 2, &[]).unwrap();
        let kept = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::All, "").unwrap();
        assert_eq!(kept.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![6, 5, 1]);
        // Sweeping one folder never touches another account or folder.
        upsert_messages(&conn, "other", "INBOX", &[message(1, "x", "x@x.com", false)], &[]).unwrap();
        sweep(&conn, "acct", "INBOX", 1, &[]).unwrap();
        assert_eq!(list_local(&conn, "other", "INBOX", None, 10, LocalFilter::All, "").unwrap().len(), 1);
    }

    #[test]
    fn sweep_keeps_an_old_message_whose_body_is_cached() {
        // The bug: a sync only rewrites the newest page, so dropping an old row loses its body
        // for good. Rows the user has actually opened must survive, whatever their UID.
        let conn = seeded_inbox(&[1, 2, 3, 4, 5, 6]);
        let body = MailBody { text: "expensive".into(), html: None, truncated: false };
        save_body(&conn, "acct", "INBOX", 1, &body, 120).unwrap();
        sweep(&conn, "acct", "INBOX", 2, &[]).unwrap();
        let kept: Vec<u32> = list_local(&conn, "acct", "INBOX", None, 20, LocalFilter::All, "")
            .unwrap()
            .iter()
            .map(|m| m.uid)
            .collect();
        assert_eq!(kept, vec![6, 5, 1], "the newest two plus the one with a body");
        // And the body is still readable, not just the row.
        assert_eq!(cached_body(&conn, "acct", "INBOX", 1).unwrap(), Some(body));
        assert!(body_state(&conn, "acct", "INBOX", 1).unwrap().ready);
    }

    #[test]
    fn sweep_keeps_a_starred_message_however_old() {
        let conn = seeded();
        upsert_messages(
            &conn,
            "acct",
            "INBOX",
            &[
                MailMessage { flagged: true, ..message(1, "starred", "a@x.com", false) },
                message(2, "b", "b@x.com", false),
                message(3, "c", "c@x.com", false),
            ],
            &[],
        )
        .unwrap();
        sweep(&conn, "acct", "INBOX", 1, &[]).unwrap();
        let kept: Vec<u32> = list_local(&conn, "acct", "INBOX", None, 20, LocalFilter::All, "")
            .unwrap()
            .iter()
            .map(|m| m.uid)
            .collect();
        assert_eq!(kept, vec![3, 1], "newest one plus the starred old one");
    }

    #[test]
    fn the_body_ceiling_drops_the_least_recently_fetched_first() {
        // keep=2 means at most 4 body rows survive. With six bodies cached, the two that were
        // fetched longest ago go, even though some have newer UIDs than the survivors.
        let conn = seeded_inbox(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let body = |text: &str| MailBody { text: text.into(), html: None, truncated: false };
        // Fetch order is deliberate and opposite to UID order: uid 1 was read last.
        // `save_body` stamps "now", so replace the stamps with a strict, readable sequence.
        for uid in [8u32, 7, 6, 5, 4, 3, 2, 1] {
            save_body(&conn, "acct", "INBOX", uid, &body(&format!("b{uid}")), 120).unwrap();
            conn.execute(
                "UPDATE mail_messages SET body_fetched_at=?1 WHERE account_id='acct' AND folder='INBOX' AND uid=?2",
                params![format!("2026-11-01T00:00:{:02}Z", 10 - uid), uid as i64],
            )
            .unwrap();
        }
        let removed = sweep(&conn, "acct", "INBOX", 2, &[]).unwrap();
        assert_eq!(removed, 2);
        let bodies: Vec<u32> = recent_body_uids(&conn, "acct", "INBOX", 100).unwrap();
        // Ceiling is 4, and the most recently fetched are uid 1..4.
        assert_eq!(bodies.len(), 4, "body rows are capped at keep*2");
        assert_eq!(bodies, vec![1, 2, 3, 4]);
        // The two tiers are a union, not a cap on the whole folder: uid 7 and 8 lost their body
        // but kept their row because they are the newest metadata page (`keep` = 2).
        let all: Vec<u32> = list_local(&conn, "acct", "INBOX", None, 20, LocalFilter::All, "")
            .unwrap()
            .iter()
            .map(|m| m.uid)
            .collect();
        assert_eq!(all, vec![8, 7, 4, 3, 2, 1]);
        // The dropped ones really are gone, body included.
        assert_eq!(cached_body(&conn, "acct", "INBOX", 5).unwrap(), None);
        assert_eq!(cached_body(&conn, "acct", "INBOX", 6).unwrap(), None);
        // And the ones kept only for their metadata no longer hold a body either — otherwise the
        // ceiling would be a fiction and the disk would keep growing.
        assert_eq!(cached_body(&conn, "acct", "INBOX", 7).unwrap(), None);
        assert_eq!(cached_body(&conn, "acct", "INBOX", 8).unwrap(), None);
    }

    #[test]
    fn sweep_keeps_a_cached_body_while_its_row_is_within_the_ceiling() {
        // A body makes a row expensive, so it survives a `keep` that would otherwise drop it.
        // Only the body *ceiling* can take it away, oldest fetch first (see the ceiling test).
        let conn = seeded_inbox(&[1, 2]);
        let body = MailBody { text: "kept".into(), html: None, truncated: false };
        save_body(&conn, "acct", "INBOX", 1, &body, 120).unwrap();
        assert!(body_state(&conn, "acct", "INBOX", 1).unwrap().ready);
        sweep(&conn, "acct", "INBOX", 1, &[]).unwrap();
        assert_eq!(cached_body(&conn, "acct", "INBOX", 1).unwrap(), Some(body));
    }

    #[test]
    fn prefetch_candidates_are_the_newest_rows_without_a_body() {
        let conn = seeded_inbox(&[1, 2, 3]);
        let body = MailBody { text: "cached".into(), html: None, truncated: false };
        save_body(&conn, "acct", "INBOX", 3, &body, 120).unwrap();
        assert_eq!(prefetch_candidates(&conn, "acct", "INBOX", 8).unwrap(), vec![2, 1]);
        assert_eq!(prefetch_candidates(&conn, "acct", "INBOX", 1).unwrap(), vec![2]);
        assert!(prefetch_candidates(&conn, "acct", "Archive", 8).unwrap().is_empty());
    }

    #[test]
    fn cached_list_all_returns_every_folder_newest_first_per_folder() {
        let conn = seeded_inbox(&[1, 2]);
        upsert_messages(&conn, "acct", "INBOX", &[message(9, "arch", "z@x.com", false)], &[]).unwrap();
        upsert_messages(&conn, "acct", "Archive", &[message(9, "arch", "z@x.com", false)], &[]).unwrap();
        let all = cached_list_all(&conn, "acct", 10).unwrap();
        let folders_seen: Vec<&str> = all.iter().map(|(folder, _)| folder.as_str()).collect();
        // Alpha by folder, and newest UID first inside each one.
        assert_eq!(folders_seen, vec!["Archive", "INBOX", "INBOX", "INBOX"]);
        let inbox_uids: Vec<u32> = all.iter().filter(|(f, _)| f == "INBOX").map(|(_, m)| m.uid).collect();
        assert_eq!(inbox_uids, vec![9, 2, 1]);
    }

    #[test]
    fn unread_by_role_reports_every_role_separately() {
        // Numbers are live counts over cached messages, so each folder gets real rows.
        let conn = seeded_inbox(&[1, 2, 3]);
        save_folders(&conn, "acct", &[("Drafts".into(), "drafts".into(), Some(1)), ("Trash".into(), "trash".into(), Some(1)), ("Newsletters".into(), "other".into(), Some(1))]).unwrap();
        upsert_messages(&conn, "acct", "Archive", &[message(11, "a1", "a@x.com", false), message(12, "a2", "a@x.com", false)], &[]).unwrap();
        upsert_messages(&conn, "acct", "Sent Messages", &[message(21, "s", "a@x.com", false)], &[]).unwrap();
        upsert_messages(&conn, "acct", "Drafts", &[message(31, "d", "a@x.com", false)], &[]).unwrap();
        upsert_messages(&conn, "acct", "Trash", &[message(41, "t", "a@x.com", false), message(42, "t2", "a@x.com", false)], &[]).unwrap();
        upsert_messages(&conn, "acct", "Newsletters", &[message(51, "n", "a@x.com", false)], &[]).unwrap();
        let by_role = unread_by_role(&conn).unwrap();
        assert_eq!(by_role, UnreadByRole { inbox: 3, archive: 2, sent: 1, drafts: 1, trash: 2, other: 1 });
        // Next to the badge, which stays scoped to inbox + archive.
        assert_eq!(badge_unread(&conn).unwrap(), 5);
    }

    #[test]
    fn a_folder_reports_when_its_cache_was_last_written() {
        let conn = seeded_inbox(&[1]);
        // Nothing synced yet and no body fetched: no stamp to show.
        assert_eq!(folder_fetched_at(&conn, "acct", "INBOX").unwrap(), None);
        set_unread(&conn, "acct", "INBOX", 1).unwrap();
        let synced = folder_fetched_at(&conn, "acct", "INBOX").unwrap();
        assert!(synced.is_some(), "a synced folder has a last_sync stamp");
        let body = MailBody { text: "text".into(), html: None, truncated: false };
        save_body(&conn, "acct", "INBOX", 1, &body, 120).unwrap();
        let with_body = folder_fetched_at(&conn, "acct", "INBOX").unwrap().unwrap();
        assert!(!with_body.is_empty());
        assert!(folder_fetched_at(&conn, "acct", "Archive").unwrap().is_none());
    }

    #[test]
    fn a_message_serializes_with_a_preview_and_camel_case_keys() {
        // The reader's contract: `preview` always present (empty when unknown), keys camelCase.
        let message = MailMessage { uid: 7, subject: "s".into(), ..MailMessage::default() };
        let json = serde_json::to_value(&message).unwrap();
        assert_eq!(json["preview"], "");
        assert!(json.get("hasAttachment").is_some(), "{json}");
        assert!(json.get("has_attachment").is_none(), "{json}");
        // A cached row keeps its teaser.
        let mut with_preview = MailMessage::default();
        with_preview.preview = "你好".into();
        assert_eq!(serde_json::to_value(&with_preview).unwrap()["preview"], "你好");
    }

    #[test]
    fn unread_is_counted_from_messages_without_any_sync() {
        // The bug this pins: an account whose folders were never synced still has `mail_folders`
        // rows only because something created them, and the numbers must come from the messages.
        let conn = seeded();
        save_folders(&conn, "acct", &[("Archive".into(), "archive".into(), Some(7))]).unwrap();
        upsert_messages(
            &conn,
            "acct",
            "INBOX",
            &[
                message(1, "a", "a@x.com", false),
                message(2, "b", "b@x.com", false),
                message(3, "c", "c@x.com", true),
            ],
            &[],
        )
        .unwrap();
        upsert_messages(&conn, "acct", "Archive", &[message(9, "z", "z@x.com", false)], &[]).unwrap();
        // No set_unread, no sync: the folders still report 0 in the snapshot (plus whatever the
        // seeded folder carried), which is exactly the bug being pinned.
        assert!(folders(&conn, "acct").unwrap().iter().all(|f| f.unread == 0));
        // ...but the live count is right.
        assert_eq!(folder_unread_count(&conn, "acct", "INBOX").unwrap(), 2);
        assert_eq!(folder_unread_count(&conn, "acct", "Archive").unwrap(), 1);
        let by_role = unread_by_role(&conn).unwrap();
        assert_eq!(by_role.inbox, 2, "inbox must count the cached unread mail");
        assert_eq!(by_role.archive, 1);
        assert_eq!(unread_by_role_for_account(&conn, Some("acct")).unwrap(), by_role);
        assert_eq!(badge_unread(&conn).unwrap(), 3);
        assert_eq!(unread_by_role_for_account(&conn, Some("nobody")).unwrap(), UnreadByRole::default());
    }

    #[test]
    fn marking_one_read_drops_the_count_by_one_and_never_below_zero() {
        let conn = seeded();
        upsert_messages(
            &conn,
            "acct",
            "INBOX",
            &[message(1, "a", "a@x.com", false), message(2, "b", "b@x.com", false)],
            &[],
        )
        .unwrap();
        assert_eq!(badge_unread(&conn).unwrap(), 2);
        set_local_seen(&conn, "acct", "INBOX", 1).unwrap();
        assert_eq!(badge_unread(&conn).unwrap(), 1);
        assert_eq!(folder_unread_count(&conn, "acct", "INBOX").unwrap(), 1);
        // Marking the same message again must not subtract twice.
        set_local_seen(&conn, "acct", "INBOX", 1).unwrap();
        assert_eq!(badge_unread(&conn).unwrap(), 1);
        set_local_seen(&conn, "acct", "INBOX", 2).unwrap();
        assert_eq!(badge_unread(&conn).unwrap(), 0);
        // Clearing it again (and an unknown uid) cannot drive the count negative.
        set_local_seen(&conn, "acct", "INBOX", 2).unwrap();
        set_local_seen(&conn, "acct", "INBOX", 999).unwrap();
        assert_eq!(badge_unread(&conn).unwrap(), 0);
        assert_eq!(folder_unread_count(&conn, "acct", "INBOX").unwrap(), 0);
    }

    #[test]
    fn a_folder_with_messages_but_no_folder_row_is_invisible_until_the_row_exists() {
        // `unread_by_role` resolves each folder's role through `mail_folders`. A folder whose only
        // trace is messages therefore counts for nothing — which is why the mail_list cold path
        // writes the folder row (`Vault::mail_ensure_folder`) before storing the page.
        let conn = open_memory().unwrap();
        upsert_messages(&conn, "acct", "Lists", &[message(1, "a", "a@x.com", false)], &[]).unwrap();
        assert_eq!(unread_by_role(&conn).unwrap(), UnreadByRole::default());
        // Once the row exists, the same messages are counted under their role.
        save_folders(&conn, "acct", &[("Lists".into(), "other".into(), Some(1))]).unwrap();
        assert_eq!(unread_by_role(&conn).unwrap().other, 1);
        assert_eq!(badge_unread(&conn).unwrap(), 0, "other is not a badge role");
    }

    #[test]
    fn a_server_count_the_cache_cannot_reach_does_not_leave_a_stuck_badge() {
        // The server says 5 unread but only 2 of them are cached. If the number tracked the
        // server, the user could clear 2 and still stare at 3 they cannot open. Live counting
        // reports what is actually reachable, and the next refresh raises it.
        let conn = seeded();
        set_unread(&conn, "acct", "INBOX", 5).unwrap();
        upsert_messages(
            &conn,
            "acct",
            "INBOX",
            &[message(1, "a", "a@x.com", false), message(2, "b", "b@x.com", false)],
            &[],
        )
        .unwrap();
        assert_eq!(badge_unread(&conn).unwrap(), 2);
        set_local_seen(&conn, "acct", "INBOX", 1).unwrap();
        set_local_seen(&conn, "acct", "INBOX", 2).unwrap();
        assert_eq!(badge_unread(&conn).unwrap(), 0);
        // The server's own figure is still kept, for comparisons, and never feeds the badge.
        assert_eq!(folders(&conn, "acct").unwrap().iter().find(|f| f.name == "INBOX").unwrap().unread, 5);
    }

    #[test]
    fn a_teaser_is_clamped_to_the_preview_limit() {
        let short = "报销单据请查收";
        assert_eq!(clamp_preview(short), short);
        // Cut at a character boundary, never mid-character.
        let long = "字".repeat(PREVIEW_LIMIT + 40);
        let clamped = clamp_preview(&long);
        assert_eq!(clamped.chars().count(), PREVIEW_LIMIT);
        assert_eq!(clamped, "字".repeat(PREVIEW_LIMIT));
        assert_eq!(clamp_preview(""), "");
    }

    #[test]
    fn listing_a_folder_never_invents_a_teaser() {
        // A live page carries no teaser; the store must not turn that into one.
        let conn = seeded();
        let live = vec![message(1, "Subject", "a@x.com", false)];
        upsert_messages(&conn, "acct", "INBOX", &live, &[String::new()]).unwrap();
        let row = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::All, "").unwrap();
        assert_eq!(row[0].preview, "");
    }

    #[test]
    fn a_saved_body_writes_a_teaser_inside_the_limit() {
        let conn = seeded_inbox(&[1]);
        let body = MailBody { text: "  你好   世界  ".into(), html: None, truncated: false };
        save_body(&conn, "acct", "INBOX", 1, &body, PREVIEW_LIMIT).unwrap();
        let row = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::All, "").unwrap();
        assert_eq!(row[0].preview, "你好 世界");
        // A re-list must not wipe the teaser the body fetch produced.
        upsert_messages(&conn, "acct", "INBOX", &[message(1, "Sub", "a@x.com", false)], &[]).unwrap();
        let row = list_local(&conn, "acct", "INBOX", None, 10, LocalFilter::All, "").unwrap();
        assert_eq!(row[0].preview, "你好 世界");
    }

    #[test]
    fn local_filter_parsing_matches_the_server_filter_names() {
        for value in ["all", "unread", "attached", "flagged", ""] {
            assert!(LocalFilter::parse(value).is_some());
        }
        assert_eq!(LocalFilter::parse("unread"), Some(LocalFilter::Unread));
        assert_eq!(LocalFilter::parse("bogus"), None);
    }
}
