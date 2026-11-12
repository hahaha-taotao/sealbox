//! Mailbox folders and server-side filtering.
//!
//! Providers expose the same five concepts under different names and usually under different
//! hierarchy delimiters: QQ has "Sent Messages", 163 has 已发送, Gmail nests everything under
//! "[Gmail]/". This module normalises all of that into one fixed vocabulary so the reader can
//! always present the same five folders.

pub use crate::mail::{MailFolder, MailMessage};

/// Roles in the order the UI always shows them.
pub const ROLE_ORDER: [&str; 5] = ["inbox", "sent", "drafts", "archive", "trash"];

pub fn role_display(role: &str) -> &'static str {
    match role {
        "inbox" => "收件箱",
        "sent" => "已发送",
        "drafts" => "草稿",
        "archive" => "归档",
        "trash" => "垃圾箱",
        _ => "",
    }
}

/// Maps a server folder name to a normalised role.
///
/// Matching is on the full name and on the last hierarchy segment, lower-cased, so
/// "[Gmail]/Sent Mail" and "Folder/已发送" both reach the same role.
pub fn folder_role(name: &str) -> &'static str {
    let lower = name.trim().to_ascii_lowercase();
    let bare = lower.rsplit('/').next().unwrap_or(&lower);
    let has = |values: &[&str]| values.contains(&lower.as_str()) || values.contains(&bare);
    if has(&["inbox"]) {
        "inbox"
    } else if has(&["sent", "sent messages", "sent items", "sent mail", "已发送", "已发送邮件"]) {
        "sent"
    } else if has(&["drafts", "draft", "草稿", "草稿箱"]) {
        "drafts"
    } else if has(&["archive", "archives", "all mail", "归档", "全部邮件", "所有邮件"]) {
        "archive"
    } else if has(&["trash", "deleted", "deleted messages", "deleted items", "已删除", "已删除邮件", "垃圾箱", "废纸篓"]) {
        "trash"
    } else {
        "other"
    }
}

/// Server-side narrowing of a folder listing. Each variant maps to a standard IMAP SEARCH key,
/// so a filter covers the whole folder rather than the page currently loaded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MailFilter {
    #[default]
    All,
    Unread,
    Attached,
    Flagged,
}

pub const MAX_KEYWORD_CHARS: usize = 200;

impl MailFilter {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "" | "all" => Some(Self::All),
            "unread" => Some(Self::Unread),
            "attached" => Some(Self::Attached),
            "flagged" => Some(Self::Flagged),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Unread => "unread",
            Self::Attached => "attached",
            Self::Flagged => "flagged",
        }
    }

    fn key(&self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Unread => Some("UNSEEN"),
            Self::Flagged => Some("FLAGGED"),
            // ATTACHMENT is a widely supported capability extension, not core RFC 3501. Callers
            // retry with a local filter when the server rejects the whole SEARCH.
            Self::Attached => Some("ATTACHMENT"),
        }
    }
}

/// Builds the argument of `UID SEARCH`. `keyword` matches subject or sender.
///
/// Returns [`crate::mail::MailFailure::Protocol`] for a keyword that is too long or carries a
/// control character, so a search term can never break out of its quoted string.
pub(crate) fn search_command(filter: MailFilter, keyword: &str) -> Result<String, crate::mail::MailFailure> {
    let keyword = keyword.trim();
    if keyword.chars().count() > MAX_KEYWORD_CHARS || keyword.chars().any(|ch| matches!(ch, '\r' | '\n' | '\0')) {
        return Err(crate::mail::MailFailure::Protocol);
    }
    let flag = filter.key();
    let mut keys: Vec<String> = Vec::new();
    if let Some(flag) = flag {
        keys.push(flag.to_string());
    }
    if !keyword.is_empty() {
        // Both terms are alternatives; a present flag must also hold.
        let quoted = crate::mail::quote_for_search(keyword);
        keys.push(format!("OR HEADER SUBJECT {quoted} HEADER FROM {quoted}"));
    }
    if keys.is_empty() {
        Ok("UID SEARCH ALL".into())
    } else {
        Ok(format!("UID SEARCH {}", keys.join(" ")))
    }
}

/// Parses a `* LIST` reply into folders, de-duplicated and sorted into [`ROLE_ORDER`].
pub fn parse_folders(raw: &str) -> Result<Vec<MailFolder>, crate::mail::MailFailure> {
    // A literal folder name carries its own newline inside the `{n}` payload, so it cannot be
    // recovered after splitting on lines. Take those out first and substitute a placeholder that
    // `parse_list_line` resolves back to the name.
    let (raw, literals) = hoist_literals(raw);
    let mut folders: Vec<MailFolder> = Vec::new();
    let mut completed = false;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("* LIST ").or_else(|| line.strip_prefix("* XLIST ")) {
            let name = match resolve_placeholder(rest, &literals) {
                Some(name) => Some(name),
                None => parse_list_line(rest),
            };
            if let Some(name) = name.filter(|name| !name.is_empty()) {
                if folders.iter().any(|folder| folder.name == name) {
                    continue;
                }
                let role = folder_role(&name);
                folders.push(MailFolder { name, role, display: role_display(role), unread: 0 });
            }
            continue;
        }
        let mut tokens = line.split_ascii_whitespace();
        let (Some(tag), Some(status)) = (tokens.next(), tokens.next()) else { continue };
        match (tag, status.to_ascii_uppercase().as_str()) {
            ("*" | "+", _) => {}
            (_, "OK") => completed = true,
            (_, "NO" | "BAD") => return Err(crate::mail::MailFailure::Protocol),
            _ => {}
        }
    }
    if !completed {
        return Err(crate::mail::MailFailure::Protocol);
    }
    folders.sort_by_key(|folder| {
        ROLE_ORDER
            .iter()
            .position(|role| *role == folder.role)
            .unwrap_or(ROLE_ORDER.len())
    });
    Ok(folders)
}

/// Parses the body of a `* LIST` line — `(flags) delimiter name` — and returns the name.
///
/// The delimiter is skipped rather than interpreted: every later command reuses the server's own
/// folder name verbatim, so the delimiter never has to be reassembled. Literal names were
/// already replaced by a `\0literal:<index>` placeholder in [`parse_folders`].
fn parse_list_line(rest: &str) -> Option<String> {
    let rest = rest.trim_start();
    let after_flags = rest.strip_prefix('(')?;
    let flags_end = after_flags.find(')')?;
    let mut cursor = after_flags[flags_end + 1..].trim_start();
    // `delimiter` — a quoted character, `NIL`, or a bare character.
    if let Some(quoted) = cursor.strip_prefix('"') {
        let end = quoted.find('"')?;
        cursor = &quoted[end + 1..];
    } else if cursor.get(..3).is_some_and(|head| head.eq_ignore_ascii_case("NIL")) {
        cursor = &cursor[3..];
    } else {
        let mut chars = cursor.char_indices();
        chars.next()?;
        cursor = match chars.next() {
            Some((at, _)) => &cursor[at..],
            None => "",
        };
    }
    let cursor = cursor.trim_start();
    if let Some(quoted) = cursor.strip_prefix('"') {
        let mut out = String::new();
        let mut escaped = false;
        for ch in quoted.chars() {
            match (escaped, ch) {
                (true, ch) => {
                    out.push(ch);
                    escaped = false;
                }
                (false, '\\') => escaped = true,
                (false, '"') => break,
                (false, ch) => out.push(ch),
            }
        }
        return Some(out).filter(|name| !name.is_empty());
    }
    let atom = cursor.split_whitespace().next()?;
    Some(atom.to_string())
}

/// Resolves a `\0literal:<index>` placeholder left by [`hoist_literals`], whatever precedes it.
fn resolve_placeholder(rest: &str, literals: &[String]) -> Option<String> {
    let at = rest.find("\0literal:")?;
    let digits: String = rest[at + "\0literal:".len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    let index: usize = digits.parse().ok()?;
    literals.get(index).cloned()
}

/// Pulls `{n}\r\n<payload>` literals out of a raw `LIST` reply and replaces each with
/// `\0literal:<index>`, so the rest of the parser can stay line-oriented.
fn hoist_literals(raw: &str) -> (String, Vec<String>) {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut literals: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            // `{digits}` at a token boundary, followed by CRLF or LF.
            if let Some(len) = literal_len(bytes, i) {
                // `literal_len` already returns an absolute offset past the closing brace.
                let after_brace = len.0;
                let payload_start = match bytes.get(after_brace) {
                    Some(b'\r') if bytes.get(after_brace + 1) == Some(&b'\n') => after_brace + 2,
                    Some(b'\n') => after_brace + 1,
                    _ => {
                        out.push('{');
                        i += 1;
                        continue;
                    }
                };
                let end = payload_start.saturating_add(len.1).min(bytes.len());
                // The count covers the whole payload including its trailing CRLF, if any, but the
                // folder name itself does not include it.
                let mut trimmed = end;
                while trimmed > payload_start && matches!(bytes[trimmed - 1], b'\r' | b'\n') {
                    trimmed -= 1;
                }
                literals.push(String::from_utf8_lossy(&bytes[payload_start..trimmed]).into_owned());
                out.push('\0');
                out.push_str("literal:");
                out.push_str(&(literals.len() - 1).to_string());
                i = end;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    (out, literals)
}

/// `(index_of_closing_brace_plus_one, byte_length)` for a `{digits}` token starting at `at`.
fn literal_len(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut end = at + 1;
    let digits_start = end;
    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    if end == digits_start || end - digits_start > 9 || bytes.get(end) != Some(&b'}') {
        return None;
    }
    let len = std::str::from_utf8(&bytes[digits_start..end]).ok()?.parse().ok()?;
    Some((end + 1, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_name_the_same_five_folders_differently() {
        assert_eq!(folder_role("INBOX"), "inbox");
        assert_eq!(folder_role("Inbox"), "inbox");
        assert_eq!(folder_role("Sent Messages"), "sent");
        assert_eq!(folder_role("已发送"), "sent");
        assert_eq!(folder_role("[Gmail]/Sent Mail"), "sent");
        assert_eq!(folder_role("[Gmail]/Drafts"), "drafts");
        assert_eq!(folder_role("草稿箱"), "drafts");
        assert_eq!(folder_role("Archive"), "archive");
        assert_eq!(folder_role("[Gmail]/All Mail"), "archive");
        assert_eq!(folder_role("已删除"), "trash");
        assert_eq!(folder_role("Deleted Messages"), "trash");
        assert_eq!(folder_role("Trash"), "trash");
        assert_eq!(folder_role("Some/Custom/已发送"), "sent");
        assert_eq!(folder_role("Newsletters"), "other");
        assert_eq!(folder_role(""), "other");
    }

    #[test]
    fn list_reply_is_sorted_into_the_fixed_order() {
        let raw = "* LIST (\\HasNoChildren) \"/\" \"Trash\"\r\n\
                   * LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n\
                   * LIST (\\HasChildren) \"/\" \"[Gmail]\"\r\n\
                   * LIST (\\HasNoChildren) \"/\" \"[Gmail]/Sent Mail\"\r\n\
                   * LIST (\\HasNoChildren) \"/\" \"Newsletters\"\r\n\
                   A2 OK LIST completed\r\n";
        let folders = parse_folders(raw).unwrap();
        let roles: Vec<&str> = folders.iter().map(|folder| folder.role).collect();
        // "[Gmail]" is a real container mailbox, so it stays as an extra "other" folder.
        assert_eq!(roles, vec!["inbox", "sent", "trash", "other", "other"]);
        assert_eq!(folders[0].name, "INBOX");
        assert_eq!(folders[1].name, "[Gmail]/Sent Mail");
        assert_eq!(folders[1].display, "已发送");
        assert_eq!(folders[2].name, "Trash");
        assert_eq!(folders[4].name, "Newsletters");
        assert_eq!(folders[4].display, "");
    }

    #[test]
    fn list_reply_handles_quoted_atoms_nil_delimiters_and_literals() {
        // A single literal, not a `\`-continued one: continuation strips the leading whitespace
        // of the next line, which would hide a literal-name parsing bug. The `{11}` byte count
        // also covers the LF after "Sent Items", exactly as a server would send it.
        let raw = "* LIST () NIL \"Drafts\"\r\n* LIST (\\Seen) \".\" Archive\r\n* LIST () \"/\" {11}\r\nSent Items\r\nA2 OK done\r\n";
        let folders = parse_folders(raw).unwrap();
        let names: Vec<&str> = folders.iter().map(|folder| folder.name.as_str()).collect();
        // Role order puts "sent" ahead of "drafts", whichever order the server listed them in.
        assert_eq!(names, vec!["Sent Items", "Drafts", "Archive"]);
    }

    #[test]
    fn list_ignores_duplicates_and_requires_completion() {
        let raw = "* LIST () \"/\" \"INBOX\"\r\n* LIST () \"/\" \"INBOX\"\r\nA2 OK\r\n";
        assert_eq!(parse_folders(raw).unwrap().len(), 1);
        assert!(parse_folders("* LIST () \"/\" \"INBOX\"\r\n").is_err());
        assert!(parse_folders("* LIST () \"/\" \"INBOX\"\r\nA2 NO denied\r\n").is_err());
    }

    #[test]
    fn search_commands_use_server_side_keys() {
        assert_eq!(search_command(MailFilter::All, "").unwrap(), "UID SEARCH ALL");
        assert_eq!(search_command(MailFilter::Unread, "").unwrap(), "UID SEARCH UNSEEN");
        assert_eq!(search_command(MailFilter::Flagged, "").unwrap(), "UID SEARCH FLAGGED");
        assert_eq!(search_command(MailFilter::Attached, "").unwrap(), "UID SEARCH ATTACHMENT");
        assert_eq!(
            search_command(MailFilter::All, "报销").unwrap(),
            "UID SEARCH OR HEADER SUBJECT \"报销\" HEADER FROM \"报销\""
        );
        assert_eq!(
            search_command(MailFilter::Unread, "报销").unwrap(),
            "UID SEARCH UNSEEN OR HEADER SUBJECT \"报销\" HEADER FROM \"报销\""
        );
    }

    #[test]
    fn search_terms_cannot_break_out_of_the_quoted_string() {
        // A quote and a backslash are escaped by the quoting helper.
        let quoted = search_command(MailFilter::All, "a\"b\\c").unwrap();
        assert!(quoted.contains("\"a\\\"b\\\\c\""), "{quoted}");
        // Control characters and over-long terms are rejected outright.
        assert!(search_command(MailFilter::All, "a\r\nB4 DELETE x").is_err());
        assert!(search_command(MailFilter::All, "a\0b").is_err());
        assert!(search_command(MailFilter::All, &"x".repeat(MAX_KEYWORD_CHARS + 1)).is_err());
        assert!(search_command(MailFilter::All, &"x".repeat(MAX_KEYWORD_CHARS)).is_ok());
    }

    #[test]
    fn filter_parsing_round_trips() {
        for filter in [MailFilter::All, MailFilter::Unread, MailFilter::Attached, MailFilter::Flagged] {
            assert_eq!(MailFilter::parse(filter.as_str()), Some(filter));
        }
        assert_eq!(MailFilter::parse(""), Some(MailFilter::All));
        assert_eq!(MailFilter::parse("bogus"), None);
    }

    #[test]
    fn literals_are_hoisted_out_of_the_reply_before_line_splitting() {
        let raw = "* LIST () \"/\" {11}\r\nSent Items\r\nA2 OK\r\n";
        let (hoisted, literals) = hoist_literals(raw);
        assert_eq!(hoisted, "* LIST () \"/\" \0literal:0\nA2 OK\r\n");
        assert_eq!(literals, vec!["Sent Items".to_string()]);
    }

    #[test]
    fn literal_len_scans_digits_and_brace() {
        let bytes = b"{11}\r\nSent Items";
        assert_eq!(literal_len(bytes, 0), Some((4, 11)));
        assert_eq!(literal_len(b"{x}", 0), None);
        assert_eq!(literal_len(b"{}", 0), None);
    }
}
