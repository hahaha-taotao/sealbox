use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailFailure {
    Login,
    Timeout,
    EmptyText,
    Protocol,
    Unsupported,
}

pub fn endpoint(provider: &str) -> Option<(&'static str, u16)> {
    match provider {
        "qq" => Some(("imap.qq.com", 993)),
        "gmail" => Some(("imap.gmail.com", 993)),
        _ => None,
    }
}

pub fn recent_uids(mut uids: Vec<u32>, before: Option<u32>, limit: usize) -> Vec<u32> {
    uids.sort_unstable();
    uids.dedup();
    if let Some(bound) = before {
        uids.retain(|uid| *uid < bound);
    }
    let start = uids.len().saturating_sub(limit);
    uids.split_off(start)
}

pub fn failure_message(failure: MailFailure) -> &'static str {
    match failure {
        MailFailure::Login => "登录失败，请检查授权码和 IMAP 是否已开启",
        MailFailure::Timeout | MailFailure::Protocol => "连接超时，请稍后重试",
        MailFailure::EmptyText => "这封邮件没有可显示的文本",
        MailFailure::Unsupported => "首版不支持",
    }
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "nbsp" => Some(' '),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let code = if let Some(hex) = entity.strip_prefix("#x").or_else(|| entity.strip_prefix("#X")) {
                u32::from_str_radix(hex, 16).ok()?
            } else if let Some(dec) = entity.strip_prefix('#') {
                dec.parse().ok()?
            } else {
                return None;
            };
            char::from_u32(code)
        }
    }
}

pub fn html_to_text(input: &str) -> String {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    let mut skipping = false;
    while let Some(ch) = chars.next() {
        if ch == '<' {
            let mut tag = String::new();
            for next in chars.by_ref() {
                if next == '>' {
                    break;
                }
                tag.push(next);
            }
            let name = tag
                .trim()
                .trim_start_matches('/')
                .split_whitespace()
                .next()
                .unwrap_or("");
            let name = name.trim_start_matches('/').to_ascii_lowercase();
            if name == "script" || name == "style" {
                skipping = !tag.trim_start().starts_with('/');
            }
            if !skipping && matches!(name.as_str(), "br" | "p" | "div" | "tr" | "li") {
                out.push('\n');
            }
            continue;
        }
        if skipping {
            continue;
        }
        if ch == '&' {
            let mut entity = String::new();
            while let Some(next) = chars.peek().copied() {
                if next == ';' || entity.len() > 12 {
                    break;
                }
                entity.push(next);
                chars.next();
            }
            if chars.peek() != Some(&';') {
                out.push('&');
                out.push_str(&entity);
                continue;
            }
            chars.next();
            if let Some(decoded) = decode_entity(&entity) {
                out.push(decoded);
            } else {
                out.push('&');
                out.push_str(&entity);
                out.push(';');
            }
            continue;
        }
        out.push(ch);
    }
    out.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailMessage {
    pub uid: u32,
    pub from: String,
    pub subject: String,
    pub date: String,
    pub has_attachment: bool,
}

/// Splits an IMAP status line into its tag and upper-cased status word.
fn status_of(line: &str) -> Option<(&str, String)> {
    let mut tokens = line.split_ascii_whitespace();
    Some((tokens.next()?, tokens.next()?.to_ascii_uppercase()))
}

fn is_number(token: &[u8]) -> bool {
    !token.is_empty() && token.iter().all(u8::is_ascii_digit)
}

pub fn parse_search(raw: &str) -> Result<Vec<u32>, MailFailure> {
    let mut uids = Vec::new();
    let mut found = false;
    let mut completed = false;
    let mut untagged_failure = false;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("* SEARCH") {
            if !(rest.is_empty() || rest.starts_with(' ')) {
                return Err(MailFailure::Protocol);
            }
            for token in rest.split_ascii_whitespace() {
                if !is_number(token.as_bytes()) {
                    return Err(MailFailure::Protocol);
                }
                uids.push(token.parse::<u32>().map_err(|_| MailFailure::Protocol)?);
            }
            found = true;
            continue;
        }
        let Some((tag, status)) = status_of(line) else { continue };
        match (tag, status.as_str()) {
            ("*" | "+", "NO" | "BAD") => untagged_failure = true,
            ("*" | "+", _) => {}
            (_, "OK") => completed = true,
            (_, "NO" | "BAD") => return Err(MailFailure::Login),
            _ => {}
        }
    }
    match (completed, found) {
        (true, true) => Ok(uids),
        (false, _) if untagged_failure => Err(MailFailure::Login),
        _ => Err(MailFailure::Protocol),
    }
}

/// A parsed IMAP value. Unquoted `NIL` is `Nil`; atoms, quoted strings and literals are `Str`.
enum Item {
    Nil,
    Str(Vec<u8>),
    List(Vec<Item>),
}

/// Server responses are untrusted; cap nesting so a hostile reply cannot overflow the stack.
const MAX_DEPTH: usize = 64;

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn next_byte(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn eat(&mut self, prefix: &[u8]) -> bool {
        if self.buf[self.pos..].starts_with(prefix) {
            self.pos += prefix.len();
            true
        } else {
            false
        }
    }

    fn skip_spaces(&mut self) {
        while self.peek() == Some(b' ') {
            self.pos += 1;
        }
    }

    /// Consumes up to and including the next newline.
    fn rest_of_line(&mut self) -> &'a [u8] {
        let buf = self.buf;
        let start = self.pos;
        while let Some(byte) = self.next_byte() {
            if byte == b'\n' {
                break;
            }
        }
        &buf[start..self.pos]
    }

    /// At a line start: if the line is `* N FETCH (...)`, parses and returns the list items.
    fn fetch_list(&mut self) -> Result<Option<Vec<Item>>, MailFailure> {
        let rest = &self.buf[self.pos..];
        if !rest.starts_with(b"* ") {
            return Ok(None);
        }
        let digits = rest[2..].iter().take_while(|b| b.is_ascii_digit()).count();
        let keyword = &rest[2 + digits..];
        if digits == 0 || keyword.len() < 7 || !keyword[..7].eq_ignore_ascii_case(b" FETCH ") {
            return Ok(None);
        }
        self.pos += 2 + digits + 7;
        self.skip_spaces();
        if self.peek() != Some(b'(') {
            return Err(MailFailure::Protocol);
        }
        let Item::List(items) = self.value(0)? else {
            return Err(MailFailure::Protocol);
        };
        self.skip_spaces();
        if !(self.eat(b"\r\n") || self.eat(b"\n") || self.pos == self.buf.len()) {
            return Err(MailFailure::Protocol);
        }
        Ok(Some(items))
    }

    fn value(&mut self, depth: usize) -> Result<Item, MailFailure> {
        if depth > MAX_DEPTH {
            return Err(MailFailure::Protocol);
        }
        self.skip_spaces();
        match self.peek().ok_or(MailFailure::Protocol)? {
            b'(' => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_spaces();
                    match self.peek() {
                        Some(b')') => {
                            self.pos += 1;
                            return Ok(Item::List(items));
                        }
                        Some(_) => items.push(self.value(depth + 1)?),
                        None => return Err(MailFailure::Protocol),
                    }
                }
            }
            b'"' => self.quoted(),
            b'{' => self.literal(),
            b')' | b'\r' | b'\n' => Err(MailFailure::Protocol),
            _ => self.atom(),
        }
    }

    fn quoted(&mut self) -> Result<Item, MailFailure> {
        self.pos += 1;
        let mut out = Vec::new();
        loop {
            match self.next_byte().ok_or(MailFailure::Protocol)? {
                b'"' => return Ok(Item::Str(out)),
                b'\\' => out.push(self.next_byte().ok_or(MailFailure::Protocol)?),
                b'\r' | b'\n' => return Err(MailFailure::Protocol),
                byte => out.push(byte),
            }
        }
    }

    /// `{n}\r\n` followed by exactly n bytes.
    fn literal(&mut self) -> Result<Item, MailFailure> {
        self.pos += 1;
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let digits = &self.buf[start..self.pos];
        if digits.is_empty() || digits.len() > 9 {
            return Err(MailFailure::Protocol);
        }
        let len: usize = std::str::from_utf8(digits)
            .ok()
            .and_then(|text| text.parse().ok())
            .ok_or(MailFailure::Protocol)?;
        if !self.eat(b"}") || !(self.eat(b"\r\n") || self.eat(b"\n")) {
            return Err(MailFailure::Protocol);
        }
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.buf.len())
            .ok_or(MailFailure::Protocol)?;
        let data = self.buf[self.pos..end].to_vec();
        self.pos = end;
        Ok(Item::Str(data))
    }

    /// A run of non-space bytes. Brackets may contain spaces and parentheses, as in
    /// `BODY[HEADER.FIELDS (FROM)]`.
    fn atom(&mut self) -> Result<Item, MailFailure> {
        let start = self.pos;
        let mut brackets = 0usize;
        while let Some(byte) = self.peek() {
            match byte {
                b'\r' | b'\n' => break,
                b' ' | b'(' | b')' if brackets == 0 => break,
                b'[' => brackets += 1,
                b']' => brackets = brackets.saturating_sub(1),
                _ => {}
            }
            self.pos += 1;
        }
        let token = &self.buf[start..self.pos];
        if token.is_empty() {
            return Err(MailFailure::Protocol);
        }
        if token.eq_ignore_ascii_case(b"NIL") {
            Ok(Item::Nil)
        } else {
            Ok(Item::Str(token.to_vec()))
        }
    }
}

fn text(item: &Item) -> String {
    match item {
        Item::Str(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        _ => String::new(),
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

fn decode_q(payload: &str) -> Result<Vec<u8>, ()> {
    let bytes = payload.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'_' => {
                out.push(b' ');
                i += 1;
            }
            b'=' => {
                let high = bytes.get(i + 1).copied().and_then(hex_digit).ok_or(())?;
                let low = bytes.get(i + 2).copied().and_then(hex_digit).ok_or(())?;
                out.push((high << 4) | low);
                i += 3;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Recognises a UTF-8 RFC 2047 encoded word at the start of `s`.
/// `Ok(None)`: not a UTF-8 encoded word. `Err`: a UTF-8 encoded word with a malformed payload.
fn encoded_word(s: &str) -> Result<Option<(usize, Vec<u8>)>, ()> {
    let Some(body) = s.strip_prefix("=?") else { return Ok(None) };
    let Some(charset_end) = body.find('?') else { return Ok(None) };
    let charset = &body[..charset_end];
    let after = &body[charset_end + 1..];
    let Some(encoding) = after.as_bytes().first().map(u8::to_ascii_uppercase) else {
        return Ok(None);
    };
    let Some(after_encoding) = after.get(1..).and_then(|rest| rest.strip_prefix('?')) else {
        return Ok(None);
    };
    let Some(payload_end) = after_encoding.find("?=") else { return Ok(None) };
    let payload = &after_encoding[..payload_end];
    if charset.is_empty() || charset.contains(char::is_whitespace) || payload.contains(char::is_whitespace) {
        return Ok(None);
    }
    // RFC 2231 allows a language suffix: `UTF-8*en`.
    let charset = charset.split('*').next().unwrap_or("");
    if !charset.eq_ignore_ascii_case("UTF-8") && !charset.eq_ignore_ascii_case("UTF8") {
        return Ok(None);
    }
    let bytes = match encoding {
        b'B' => {
            let mut padded = payload.to_string();
            while padded.len() % 4 != 0 {
                padded.push('=');
            }
            base64::engine::general_purpose::STANDARD
                .decode(padded)
                .map_err(|_| ())?
        }
        b'Q' => decode_q(payload)?,
        _ => return Ok(None),
    };
    // "=?" + charset + "?" + encoding + "?" + payload + "?="
    let len = 2 + charset_end + 3 + payload_end + 2;
    Ok(Some((len, bytes)))
}

fn decode_header_words(raw: &str) -> Result<String, ()> {
    let mut out = String::new();
    let mut rest = raw;
    while let Some(ch) = rest.chars().next() {
        if let Some((len, mut bytes)) = encoded_word(rest)? {
            rest = &rest[len..];
            // Whitespace between adjacent encoded words is dropped. Their bytes are joined
            // so a character split across two words still decodes.
            loop {
                let next = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
                match encoded_word(next)? {
                    Some((len, more)) => {
                        bytes.extend_from_slice(&more);
                        rest = &next[len..];
                    }
                    None => break,
                }
            }
            out.push_str(std::str::from_utf8(&bytes).map_err(|_| ())?);
            continue;
        }
        out.push(ch);
        rest = &rest[ch.len_utf8()..];
    }
    Ok(out)
}

/// Decodes UTF-8 `=?UTF-8?B?...?=` / `=?UTF-8?Q?...?=` words; keeps the raw text if decoding fails.
fn decode_header(raw: &str) -> String {
    decode_header_words(raw).unwrap_or_else(|_| raw.to_string())
}

/// Formats an envelope address `(display adl mailbox host)`.
fn format_address(fields: &[Item]) -> Option<String> {
    // A NIL host marks a group start or end, not a mailbox.
    if !matches!(fields.get(3)?, Item::Str(_)) {
        return None;
    }
    let mailbox = text(&fields[2]);
    if mailbox.is_empty() {
        return None;
    }
    let address = format!("{mailbox}@{}", text(&fields[3]));
    let display = decode_header(&text(&fields[0]));
    let display = display.trim();
    Some(if display.is_empty() {
        address
    } else {
        format!("{display} <{address}>")
    })
}

fn first_address(item: &Item) -> String {
    let Item::List(addresses) = item else { return String::new() };
    addresses
        .iter()
        .find_map(|address| match address {
            Item::List(fields) => format_address(fields),
            _ => None,
        })
        .unwrap_or_default()
}

const ATTACHMENT_TYPES: [&[u8]; 4] = [b"APPLICATION", b"IMAGE", b"AUDIO", b"VIDEO"];

fn has_attachment(body: &Item) -> bool {
    let Item::List(fields) = body else { return false };
    match fields.first() {
        // Multipart: leading lists are the parts, followed by the subtype and extension data.
        Some(Item::List(_)) => fields
            .iter()
            .take_while(|field| matches!(field, Item::List(_)))
            .any(has_attachment),
        Some(Item::Str(media)) => ATTACHMENT_TYPES.iter().any(|kind| media.eq_ignore_ascii_case(kind)),
        _ => false,
    }
}

fn message_from_fetch(items: &[Item]) -> Result<Option<MailMessage>, MailFailure> {
    if items.len() % 2 != 0 {
        return Err(MailFailure::Protocol);
    }
    let mut uid = None;
    let mut envelope = None;
    let mut body = None;
    for pair in items.chunks(2) {
        let Item::Str(key) = &pair[0] else {
            return Err(MailFailure::Protocol);
        };
        if key.eq_ignore_ascii_case(b"UID") {
            let Item::Str(value) = &pair[1] else {
                return Err(MailFailure::Protocol);
            };
            if !is_number(value) {
                return Err(MailFailure::Protocol);
            }
            let parsed = std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or(MailFailure::Protocol)?;
            uid = Some(parsed);
        } else if key.eq_ignore_ascii_case(b"ENVELOPE") {
            envelope = Some(&pair[1]);
        } else if key.eq_ignore_ascii_case(b"BODYSTRUCTURE") {
            body = Some(&pair[1]);
        }
    }
    // Unsolicited updates such as `* 5 FETCH (FLAGS (\Seen))` carry no envelope; skip them.
    let (Some(uid), Some(envelope)) = (uid, envelope) else {
        return Ok(None);
    };
    let Item::List(envelope) = envelope else {
        return Err(MailFailure::Protocol);
    };
    if envelope.len() < 3 {
        return Err(MailFailure::Protocol);
    }
    Ok(Some(MailMessage {
        uid,
        from: first_address(&envelope[2]),
        subject: decode_header(&text(&envelope[1])),
        date: text(&envelope[0]),
        has_attachment: body.is_some_and(has_attachment),
    }))
}

pub fn parse_fetch(raw: &str) -> Result<Vec<MailMessage>, MailFailure> {
    let mut cursor = Cursor { buf: raw.as_bytes(), pos: 0 };
    let mut messages = Vec::new();
    let mut completed = false;
    while cursor.pos < cursor.buf.len() {
        if let Some(items) = cursor.fetch_list()? {
            if let Some(message) = message_from_fetch(&items)? {
                messages.push(message);
            }
            continue;
        }
        let line = String::from_utf8_lossy(cursor.rest_of_line());
        let Some((tag, status)) = status_of(&line) else { continue };
        if tag == "*" || tag == "+" {
            continue;
        }
        match status.as_str() {
            "OK" => completed = true,
            "NO" | "BAD" => return Err(MailFailure::Protocol),
            _ => {}
        }
    }
    if completed {
        Ok(messages)
    } else {
        Err(MailFailure::Protocol)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailAccount {
    pub id: String,
    pub title: String,
    pub email: String,
    pub provider: String,
    pub supported: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailBody {
    /// Always populated: the decoded text/plain part, or the HTML part flattened to text.
    pub text: String,
    /// The decoded text/html part, verbatim, when the message had one. The desktop renders it
    /// in a sandboxed frame, so it must not be flattened here.
    pub html: Option<String>,
    pub truncated: bool,
}

/// One IMAP round trip. `command` is a single tagged command line without the trailing CRLF;
/// the implementation sends it and returns everything the server replied, up to and including
/// the tagged completion line.
pub trait ImapIo {
    fn transact(&mut self, command: &str) -> Result<String, MailFailure>;
}

const MAX_BODY_BYTES: usize = 200 * 1024;

/// IMAP quoted string. CR, LF and NUL cannot appear in a quoted string, so callers reject them first.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        if ch == '\\' || ch == '"' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

/// Checks the tagged completion line for `tag`. The completion is the last line of the reply,
/// so the search runs backwards and message content earlier in the reply cannot spoof it.
fn check_completion(response: &str, tag: &str, failure: MailFailure) -> Result<(), MailFailure> {
    for line in response.lines().rev() {
        let Some((line_tag, status)) = status_of(line) else { continue };
        if line_tag == tag {
            return match status.as_str() {
                "OK" => Ok(()),
                "NO" | "BAD" => Err(failure),
                _ => Err(MailFailure::Protocol),
            };
        }
    }
    Err(MailFailure::Protocol)
}

/// Sends `A1 LOGIN` and `A2 EXAMINE INBOX`. EXAMINE opens the mailbox read-only so nothing is marked seen.
fn open_inbox(io: &mut impl ImapIo, email: &str, auth: &str) -> Result<(), MailFailure> {
    let unsafe_char = |ch: char| matches!(ch, '\r' | '\n' | '\0');
    if email.contains(unsafe_char) || auth.contains(unsafe_char) {
        return Err(MailFailure::Login);
    }
    let login = io.transact(&format!("A1 LOGIN {} {}", quote(email), quote(auth)))?;
    check_completion(&login, "A1", MailFailure::Login)?;
    let examine = io.transact("A2 EXAMINE INBOX")?;
    check_completion(&examine, "A2", MailFailure::Protocol)
}

pub fn list_inbox(
    io: &mut impl ImapIo,
    email: &str,
    auth: &str,
    before: Option<u32>,
    limit: usize,
) -> Result<Vec<MailMessage>, MailFailure> {
    open_inbox(io, email, auth)?;
    let search = io.transact("A3 UID SEARCH ALL")?;
    check_completion(&search, "A3", MailFailure::Protocol)?;
    let uids = recent_uids(parse_search(&search)?, before, limit);
    if uids.is_empty() {
        return Ok(Vec::new());
    }
    let set = uids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
    let fetch = io.transact(&format!("A4 UID FETCH {set} (UID ENVELOPE BODYSTRUCTURE)"))?;
    check_completion(&fetch, "A4", MailFailure::Protocol)?;
    parse_fetch(&fetch)
}

/// Returns the `BODY[]` value of the FETCH response for `uid`.
fn body_literal(raw: &str, uid: u32) -> Result<Vec<u8>, MailFailure> {
    let mut cursor = Cursor { buf: raw.as_bytes(), pos: 0 };
    while cursor.pos < cursor.buf.len() {
        let Some(items) = cursor.fetch_list()? else {
            cursor.rest_of_line();
            continue;
        };
        if items.len() % 2 != 0 {
            return Err(MailFailure::Protocol);
        }
        let mut found_uid = None;
        let mut body = None;
        for pair in items.chunks(2) {
            let Item::Str(key) = &pair[0] else {
                return Err(MailFailure::Protocol);
            };
            if key.eq_ignore_ascii_case(b"UID") {
                found_uid = std::str::from_utf8(&text(&pair[1]).into_bytes())
                    .ok()
                    .and_then(|value| value.parse::<u32>().ok());
            } else if key.eq_ignore_ascii_case(b"BODY[]") {
                body = Some(match &pair[1] {
                    Item::Str(bytes) => bytes.clone(),
                    Item::Nil => Vec::new(),
                    Item::List(_) => return Err(MailFailure::Protocol),
                });
            }
        }
        // Skip unsolicited updates for other messages.
        if found_uid.is_some_and(|found| found != uid) {
            continue;
        }
        if let Some(body) = body {
            return Ok(body);
        }
    }
    Err(MailFailure::Protocol)
}

/// Splits a raw message on the first blank line into (headers, body).
fn split_message(message: &[u8]) -> (&[u8], &[u8]) {
    if let Some(body) = message.strip_prefix(b"\r\n").or_else(|| message.strip_prefix(b"\n")) {
        return (&[], body);
    }
    let find = |needle: &[u8]| message.windows(needle.len()).position(|window| window == needle);
    let split = match (find(b"\r\n\r\n"), find(b"\n\n")) {
        (Some(crlf), Some(lf)) if lf < crlf => Some((lf, 2)),
        (Some(crlf), _) => Some((crlf, 4)),
        (None, Some(lf)) => Some((lf, 2)),
        (None, None) => None,
    };
    match split {
        Some((at, gap)) => (&message[..at], &message[at + gap..]),
        None => (message, &[]),
    }
}

/// Mail is untrusted input, so nesting is capped: a hostile message cannot recurse the stack away.
const MAX_MIME_DEPTH: usize = 8;

/// Header block split into `(lower-case name, unfolded value)` pairs. A continuation line keeps
/// its leading whitespace, which is what MIME unfolding is specified to leave behind, so
/// `boundary=` split across two lines still parses.
fn parse_header_fields(headers: &str) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in headers.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some(last) = fields.last_mut() {
                last.1.push_str(line);
                continue;
            }
        }
        if let Some((name, value)) = line.split_once(':') {
            fields.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    fields
}

fn header_value(fields: &[(String, String)], name: &str) -> Option<String> {
    fields
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
}

/// `(type, subtype)` of a Content-Type value, lower-cased. RFC 2045 makes text/plain the default,
/// which is also what a message without a Content-Type header means.
fn media_type(value: &str) -> (String, String) {
    let head = value.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    match head.split_once('/') {
        Some((kind, subtype)) => (kind.trim().to_string(), subtype.trim().to_string()),
        None => ("text".to_string(), "plain".to_string()),
    }
}

/// A MIME parameter such as `boundary` or `charset`, with quotes and backslash escapes removed.
fn media_param(value: &str, name: &str) -> Option<String> {
    for segment in value.split(';').skip(1) {
        let Some((key, raw)) = segment.split_once('=') else { continue };
        if !key.trim().eq_ignore_ascii_case(name) {
            continue;
        }
        let raw = raw.trim();
        let inner = raw
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or(raw);
        let mut out = String::with_capacity(inner.len());
        let mut escaped = false;
        for ch in inner.chars() {
            match (escaped, ch) {
                (true, ch) => {
                    out.push(ch);
                    escaped = false;
                }
                (false, '\\') => escaped = true,
                (false, ch) => out.push(ch),
            }
        }
        if !out.is_empty() {
            return Some(out);
        }
    }
    None
}

/// Parts marked as attachments are file payloads; they are never shown as body text.
fn is_attachment(fields: &[(String, String)]) -> bool {
    header_value(fields, "content-disposition").is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("attachment"))
    })
}

/// The byte ranges of every body part between `--boundary` lines. The preamble before the first
/// delimiter and the `--boundary--` epilogue are not parts. A truncated message (no closing
/// delimiter) still yields its last fragment so a half-downloaded body is readable.
fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let marker = format!("--{boundary}");
    let marker = marker.as_bytes();
    let mut parts = Vec::new();
    let mut open: Option<usize> = None;
    let mut search = 0;
    loop {
        let Some(at) = find_boundary_line(body, marker, search) else { break };
        let line_end = line_end_after(body, at + marker.len());
        if let Some(start) = open.take() {
            parts.push(trim_trailing_newline(&body[start..at]));
        }
        // `--boundary--` closes the multipart; anything after it is the epilogue.
        if body[at + marker.len()..line_end].starts_with(b"--") {
            return parts;
        }
        open = Some(line_end);
        search = line_end;
        if search >= body.len() {
            break;
        }
    }
    if let Some(start) = open {
        if start < body.len() {
            parts.push(trim_trailing_newline(&body[start..]));
        }
    }
    parts
}

fn find_boundary_line(body: &[u8], marker: &[u8], from: usize) -> Option<usize> {
    let mut index = from;
    while index + marker.len() <= body.len() {
        // A delimiter only counts at the start of a line, so quoted `--boundary` text in a body
        // cannot fabricate a part.
        if body[index..].starts_with(marker) && (index == 0 || body[index - 1] == b'\n') {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn line_end_after(body: &[u8], from: usize) -> usize {
    match body.get(from..) {
        Some(rest) => rest.iter().position(|byte| *byte == b'\n').map_or(body.len(), |at| from + at + 1),
        None => body.len(),
    }
}

/// The newline that terminates the delimiter line belongs to the delimiter, not to the part.
fn trim_trailing_newline(part: &[u8]) -> &[u8] {
    let part = part.strip_suffix(b"\n").unwrap_or(part);
    part.strip_suffix(b"\r").unwrap_or(part)
}

fn decode_base64(body: &[u8]) -> Vec<u8> {
    let filtered: Vec<u8> = body
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let engine = base64::engine::general_purpose::STANDARD;
    if let Ok(decoded) = engine.decode(&filtered) {
        return decoded;
    }
    // A truncated payload: keep the whole quanta that do decode, so most of the body survives
    // instead of the whole part disappearing.
    let usable = filtered.len() - filtered.len() % 4;
    engine.decode(&filtered[..usable]).unwrap_or_default()
}

fn decode_quoted_printable(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut index = 0;
    while index < body.len() {
        if body[index] != b'=' {
            out.push(body[index]);
            index += 1;
            continue;
        }
        // `=` right before a line break is a soft break: the pair joins two logical lines.
        // `index < body.len()`, so `index + 1` is still a valid slice start.
        let rest = &body[index + 1..];
        if rest.starts_with(b"\r\n") {
            index += 3;
            continue;
        }
        if rest.starts_with(b"\n") {
            index += 2;
            continue;
        }
        let decoded = rest
            .first()
            .copied()
            .and_then(hex_digit)
            .zip(rest.get(1).copied().and_then(hex_digit));
        match decoded {
            Some((high, low)) => {
                out.push((high << 4) | low);
                index += 3;
            }
            // A stray `=` is literal text in lenient decoders; keeping it beats dropping the tail.
            None => {
                out.push(b'=');
                index += 1;
            }
        }
    }
    out
}

/// `Content-Transfer-Encoding` handling. Unknown encodings (7bit/8bit/binary included) mean the
/// body is already the literal bytes.
fn decode_transfer_encoding(body: &[u8], encoding: &str) -> Vec<u8> {
    let encoding = encoding.trim().trim_matches('"').to_ascii_lowercase();
    match encoding.as_str() {
        "base64" => decode_base64(body),
        "quoted-printable" => decode_quoted_printable(body),
        _ => body.to_vec(),
    }
}

/// Converts the decoded octets into a Rust string. Real mail carries every charset there is, and
/// an unknown label must not lose the message: UTF-8 lossy is always readable-ish.
fn decode_charset(bytes: &[u8], charset: Option<&str>) -> String {
    let Some(label) = charset.map(str::trim).filter(|label| !label.is_empty()) else {
        return String::from_utf8_lossy(bytes).into_owned();
    };
    let label = label.to_ascii_lowercase();
    if matches!(label.as_str(), "utf-8" | "utf8" | "us-ascii" | "ascii") {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    match encoding_rs::Encoding::for_label(label.as_bytes()) {
        Some(encoding) => encoding.decode(bytes).0.into_owned(),
        None => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// The two renderings of one message. `plain` is only used for the text field; `html` is what the
/// desktop renders, and is present only when the message really had a text/html part.
#[derive(Default)]
struct TextParts {
    plain: Option<String>,
    html: Option<String>,
}

/// Fills one text slot. `prefer_later` is set for multipart/alternative, where each part is a
/// richer version of the previous one; in every other multipart the first text part is the body
/// itself and any later one is a footer or a forwarded copy.
fn merge_slot(slot: &mut Option<String>, value: Option<String>, prefer_later: bool) {
    let Some(value) = value else { return };
    if slot.is_none() || prefer_later {
        *slot = Some(value);
    }
}

fn merge_parts(into: &mut TextParts, from: TextParts, prefer_later: bool) {
    merge_slot(&mut into.plain, from.plain, prefer_later);
    merge_slot(&mut into.html, from.html, prefer_later);
}

/// Walks the MIME tree and records the leaf text parts.
fn collect_text_parts(part: &[u8], depth: usize, out: &mut TextParts) {
    if depth > MAX_MIME_DEPTH {
        return;
    }
    let (headers, body) = split_message(part);
    let fields = parse_header_fields(&String::from_utf8_lossy(headers));
    if is_attachment(&fields) {
        return;
    }
    let content_type = header_value(&fields, "content-type").unwrap_or_default();
    let (kind, subtype) = media_type(&content_type);
    if kind == "multipart" {
        let boundary = media_param(&content_type, "boundary").unwrap_or_default();
        let children = if boundary.is_empty() {
            Vec::new()
        } else {
            split_multipart(body, &boundary)
        };
        if !children.is_empty() {
            let prefer_later = subtype == "alternative";
            for child in children {
                let mut child_parts = TextParts::default();
                collect_text_parts(child, depth + 1, &mut child_parts);
                merge_parts(out, child_parts, prefer_later);
            }
            return;
        }
        // A multipart header we cannot honour (no boundary, or a truncated one). The body is
        // still the only text there is, so fall through and decode it as one leaf part.
    } else if kind != "text" || !matches!(subtype.as_str(), "plain" | "html") {
        // Attachments (`image/*`, `application/*`, `message/*`) and exotic `text/*` subtypes are
        // not body text.
        return;
    }
    let encoding = header_value(&fields, "content-transfer-encoding").unwrap_or_default();
    let bytes = decode_transfer_encoding(body, &encoding);
    let decoded = decode_charset(&bytes, media_param(&content_type, "charset").as_deref());
    if decoded.trim().is_empty() {
        return;
    }
    if subtype == "html" {
        out.html = Some(decoded);
    } else {
        out.plain = Some(decoded);
    }
}

/// Cuts `value` to `limit` bytes without splitting a character. Returns whether anything was cut.
fn truncate_at_boundary(value: &mut String, limit: usize) -> bool {
    if value.len() <= limit {
        return false;
    }
    let mut end = limit;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    true
}

/// Decodes a whole RFC 822 message into `(text, html)`; `html` stays `None` when no text/html
/// part exists, so the desktop can fall back to the plain rendering.
fn extract_body(message: &[u8]) -> (String, Option<String>) {
    let mut parts = TextParts::default();
    collect_text_parts(message, 0, &mut parts);
    let html = parts
        .html
        // A body that ends at the end of the message keeps its final CRLF; the frame does not need it.
        .map(|html| html.trim_end().to_string())
        .filter(|html| !html.is_empty());
    let text = match parts.plain {
        // Plain mail is shown as written, minus the CRLFs that would otherwise double up.
        Some(plain) => plain.replace("\r\n", "\n").replace('\r', "\n").trim_end().to_string(),
        None => html.as_deref().map(html_to_text).unwrap_or_default(),
    };
    (text, html)
}

pub fn fetch_body(io: &mut impl ImapIo, email: &str, auth: &str, uid: u32) -> Result<MailBody, MailFailure> {
    open_inbox(io, email, auth)?;
    let fetch = io.transact(&format!("A3 UID FETCH {uid} (BODY.PEEK[])"))?;
    check_completion(&fetch, "A3", MailFailure::Protocol)?;
    let message = body_literal(&fetch, uid)?;
    let (mut text, mut html) = extract_body(&message);
    if text.trim().is_empty() && html.is_none() {
        return Err(MailFailure::EmptyText);
    }
    let text_cut = truncate_at_boundary(&mut text, MAX_BODY_BYTES);
    let html_cut = html
        .as_mut()
        .is_some_and(|value| truncate_at_boundary(value, MAX_BODY_BYTES));
    Ok(MailBody { text, html, truncated: text_cut || html_cut })
}

fn map_io(err: std::io::Error) -> MailFailure {
    if err.kind() == std::io::ErrorKind::TimedOut || err.kind() == std::io::ErrorKind::WouldBlock {
        MailFailure::Timeout
    } else {
        MailFailure::Timeout
    }
}

fn literal_length(line: &[u8]) -> Option<usize> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let start = line.iter().rposition(|byte| *byte == b'{')?;
    if line.last() != Some(&b'}') || start + 1 >= line.len() {
        return None;
    }
    std::str::from_utf8(&line[start + 1..line.len() - 1]).ok()?.parse().ok()
}

fn response_complete(buf: &[u8], tag: &str) -> bool {
    let tag = tag.as_bytes();
    let mut index = 0;
    while index < buf.len() {
        let start = index;
        let Some(end) = buf[index..].iter().position(|byte| *byte == b'\n') else {
            return false;
        };
        let line_end = index + end;
        let line = &buf[start..line_end];
        if let Some(length) = literal_length(line) {
            let after = line_end + 1;
            if buf.len() < after + length {
                return false;
            }
            index = after + length;
            continue;
        }
        if line.starts_with(tag) && line.len() > tag.len() && line[tag.len()] == b' ' {
            let rest = &line[tag.len() + 1..];
            if rest.starts_with(b"OK") || rest.starts_with(b"NO") || rest.starts_with(b"BAD") {
                return true;
            }
        }
        index = line_end + 1;
    }
    false
}

fn transact_io(stream: &mut impl WriteRead, command: &str, timeout: Duration) -> Result<String, MailFailure> {
    let tag = command.split_whitespace().next().ok_or(MailFailure::Protocol)?;
    let mut bytes = command.as_bytes().to_vec();
    bytes.extend_from_slice(b"\r\n");
    stream.write_all(&bytes).map_err(map_io)?;
    stream.flush().map_err(map_io)?;
    let started = Instant::now();
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 4096];
    loop {
        if started.elapsed() > timeout {
            return Err(MailFailure::Timeout);
        }
        match stream.read(&mut tmp) {
            Ok(0) => return Err(MailFailure::Protocol),
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if response_complete(&buf, tag) {
                    return Ok(String::from_utf8_lossy(&buf).into_owned());
                }
            }
            Err(err) => return Err(map_io(err)),
        }
    }
}

trait WriteRead: Read + Write {}
impl<T: Read + Write> WriteRead for T {}

pub fn transact_stream(stream: &mut TcpStream, command: &str, timeout: Duration) -> Result<String, MailFailure> {
    stream.set_read_timeout(Some(timeout)).map_err(|_| MailFailure::Timeout)?;
    stream.set_write_timeout(Some(timeout)).map_err(|_| MailFailure::Timeout)?;
    transact_io(stream, command, timeout)
}

pub struct TlsImap {
    conn: rustls::ClientConnection,
    sock: TcpStream,
    timeout: Duration,
}

impl ImapIo for TlsImap {
    fn transact(&mut self, command: &str) -> Result<String, MailFailure> {
        self.sock.set_read_timeout(Some(self.timeout)).map_err(|_| MailFailure::Timeout)?;
        self.sock.set_write_timeout(Some(self.timeout)).map_err(|_| MailFailure::Timeout)?;
        let mut stream = rustls::Stream::new(&mut self.conn, &mut self.sock);
        transact_io(&mut stream, command, self.timeout)
    }
}

pub fn connect_tls(host: &str, port: u16, timeout: Duration) -> Result<TlsImap, MailFailure> {
    if endpoint("qq") != Some((host, port)) && endpoint("gmail") != Some((host, port)) {
        return Err(MailFailure::Unsupported);
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| MailFailure::Protocol)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| MailFailure::Protocol)?;
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|_| MailFailure::Timeout)?
        .next()
        .ok_or(MailFailure::Timeout)?;
    let sock = TcpStream::connect_timeout(&addr, timeout).map_err(|_| MailFailure::Timeout)?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|_| MailFailure::Protocol)?;
    Ok(TlsImap { conn, sock, timeout })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_are_fixed_for_qq_and_gmail_only() {
        assert_eq!(endpoint("qq"), Some(("imap.qq.com", 993)));
        assert_eq!(endpoint("gmail"), Some(("imap.gmail.com", 993)));
        assert_eq!(endpoint("163"), None);
        assert_eq!(endpoint("outlook"), None);
        assert_eq!(endpoint("custom"), None);
    }

    #[test]
    fn recent_uids_take_the_newest_page_without_the_bound() {
        let uids = vec![90, 10, 70, 70, 40];
        assert_eq!(recent_uids(uids.clone(), None, 2), vec![70, 90]);
        assert_eq!(recent_uids(uids, Some(70), 2), vec![10, 40]);
        assert_eq!(recent_uids(vec![5], Some(5), 50), Vec::<u32>::new());
    }

    #[test]
    fn public_errors_are_fixed_chinese_and_hide_secrets() {
        let secret = "qq-auth-SECRET";
        for failure in [MailFailure::Login, MailFailure::Timeout, MailFailure::EmptyText] {
            let text = failure_message(failure);
            assert!(!text.contains(secret));
            assert!(!text.contains("imap"));
        }
        assert_eq!(failure_message(MailFailure::Login), "登录失败，请检查授权码和 IMAP 是否已开启");
        assert_eq!(failure_message(MailFailure::Timeout), "连接超时，请稍后重试");
        assert_eq!(failure_message(MailFailure::EmptyText), "这封邮件没有可显示的文本");
    }

    #[test]
    fn html_becomes_plain_text() {
        let text = html_to_text("<p>你好&nbsp;<b>报销</b><br>第二行</p><script>secret()</script>");
        assert_eq!(text, "你好 报销\n第二行");
        assert_eq!(html_to_text("<style>a{}</style><div></div>"), "");
        assert_eq!(html_to_text("Tom & Jerry"), "Tom & Jerry");
        assert_eq!(html_to_text("A&amp;B&#39;C"), "A&B'C");
    }

    #[test]
    fn search_response_yields_uids() {
        let raw = "* SEARCH 64 70 81\r\nA3 OK done\r\n";
        assert_eq!(parse_search(raw).unwrap(), vec![64, 70, 81]);
        assert!(parse_search("* NO blocked\r\n").is_err());
    }

    #[test]
    fn fetch_reads_envelope_and_attachment_flag() {
        let raw = "* 1 FETCH (UID 90 ENVELOPE (\"27 Oct 2026 09:12:00 +0800\" \"=?UTF-8?B?5oql6ZSA?=\" ((NIL NIL \"finance\" \"example.com\")) NIL NIL NIL NIL NIL NIL) BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"8BIT\" 12 1 NIL NIL NIL NIL))\r\nA4 OK done\r\n";
        let messages = parse_fetch(raw).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].uid, 90);
        assert_eq!(messages[0].from, "finance@example.com");
        assert_eq!(messages[0].subject, "报销");
        assert!(!messages[0].has_attachment);
    }

    #[test]
    fn multipart_with_pdf_is_an_attachment() {
        let raw = "* 1 FETCH (UID 8 ENVELOPE (NIL \"Hi\" ((\"Ada\" NIL \"ada\" \"ex.com\")) NIL NIL NIL NIL NIL NIL) BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" NIL NIL NIL \"8BIT\" 1 1 NIL NIL NIL NIL)(\"APPLICATION\" \"PDF\" NIL NIL NIL \"BASE64\" 10 NIL (\"ATTACHMENT\" (\"FILENAME\" \"a.pdf\")) NIL NIL) \"MIXED\" NIL NIL NIL))\r\nA4 OK done\r\n";
        let messages = parse_fetch(raw).unwrap();
        assert!(messages[0].has_attachment);
        assert_eq!(messages[0].from, "Ada <ada@ex.com>");
    }

    struct ScriptIo {
        steps: Vec<(&'static str, &'static str)>,
        seen: Vec<String>,
    }

    impl ImapIo for ScriptIo {
        fn transact(&mut self, command: &str) -> Result<String, MailFailure> {
            self.seen.push(command.to_string());
            let (expect, response) = self.steps.remove(0);
            assert!(command.contains(expect), "{command}");
            Ok(response.to_string())
        }
    }

    #[test]
    fn list_examines_inbox_and_fetches_only_the_newest_uids() {
        let mut io = ScriptIo {
            steps: vec![
                ("LOGIN", "A1 OK\r\n"),
                ("EXAMINE INBOX", "* FLAGS (\\Seen)\r\nA2 OK [READ-ONLY]\r\n"),
                ("UID SEARCH ALL", "* SEARCH 1 2 3\r\nA3 OK\r\n"),
                ("UID FETCH 2,3 (", "* 1 FETCH (UID 2 ENVELOPE (NIL \"One\" ((NIL NIL \"a\" \"b.com\")) NIL NIL NIL NIL NIL NIL) BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"8BIT\" 1 1 NIL NIL NIL NIL))\r\n* 2 FETCH (UID 3 ENVELOPE (NIL \"Two\" ((NIL NIL \"c\" \"d.com\")) NIL NIL NIL NIL NIL NIL) BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"8BIT\" 1 1 NIL NIL NIL NIL))\r\nA4 OK\r\n"),
            ],
            seen: vec![],
        };
        let page = list_inbox(&mut io, "me@qq.com", "auth-SECRET", None, 2).unwrap();
        assert_eq!(page.iter().map(|message| message.uid).collect::<Vec<_>>(), vec![2, 3]);
        assert!(io.seen.iter().all(|line| !line.contains("SELECT")));
        assert!(io.seen[0].starts_with("A1 LOGIN"));
        assert!(io.seen[1].contains("EXAMINE INBOX"));
    }

    #[test]
    fn body_peeks_and_strips_html() {
        let mut io = ScriptIo {
            steps: vec![
                ("LOGIN", "A1 OK\r\n"),
                ("EXAMINE INBOX", "A2 OK [READ-ONLY]\r\n"),
                ("BODY.PEEK[]", "* 1 FETCH (UID 9 BODY[] {40}\r\nContent-Type: text/html\r\n\r\n<p>你好</p>)\r\nA3 OK\r\n"),
            ],
            seen: vec![],
        };
        let body = fetch_body(&mut io, "me@gmail.com", "auth-SECRET", 9).unwrap();
        assert_eq!(body.text, "你好");
        assert!(!body.truncated);
        assert!(io.seen.iter().any(|line| line.contains("BODY.PEEK[]")));
        assert!(io.seen.iter().all(|line| !line.contains("BODY[]")));
    }

    #[test]
    fn login_no_becomes_the_fixed_login_message() {
        let mut io = ScriptIo {
            steps: vec![("LOGIN", "A1 NO [AUTHENTICATIONFAILED]\r\n")],
            seen: vec![],
        };
        let err = list_inbox(&mut io, "me@qq.com", "auth-SECRET", None, 50).unwrap_err();
        assert_eq!(failure_message(err), "登录失败，请检查授权码和 IMAP 是否已开启");
        assert!(!failure_message(err).contains("auth-SECRET"));
    }

    #[test]
    fn tcp_roundtrip_reads_a_tagged_ok() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.write_all(b"* OK ready\r\n").unwrap();
            let mut buf = [0_u8; 128];
            let n = socket.read(&mut buf).unwrap();
            assert!(std::str::from_utf8(&buf[..n]).unwrap().contains("EXAMINE"));
            socket.write_all(b"A2 OK [READ-ONLY]\r\n").unwrap();
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let response = transact_stream(&mut client, "A2 EXAMINE INBOX", Duration::from_secs(2)).unwrap();
        assert!(response.contains("[READ-ONLY]"));
        server.join().unwrap();
    }

    #[test]
    fn tcp_timeout_uses_the_public_timeout_sentence() {
        use std::net::TcpListener;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (_socket, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(800));
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let err = transact_stream(&mut client, "A2 EXAMINE INBOX", Duration::from_millis(200)).unwrap_err();
        assert_eq!(failure_message(err), "连接超时，请稍后重试");
        server.join().unwrap();
    }

    #[test]
    fn connect_rejects_hosts_outside_qq_and_gmail() {
        use std::time::Duration;
        assert_eq!(
            connect_tls("imap.163.com", 993, Duration::from_millis(50)).err(),
            Some(MailFailure::Unsupported)
        );
    }

    /// Assembles a CRLF-terminated message from its logical lines, so MIME fixtures read like the wire.
    fn wire(lines: &[&str]) -> Vec<u8> {
        let mut out = String::new();
        for line in lines {
            out.push_str(line);
            out.push_str("\r\n");
        }
        out.into_bytes()
    }

    fn base64_of(text: &str) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, text.as_bytes())
    }

    /// The FETCH response for `uid` carrying `message` as one `BODY[]` literal.
    fn fetch_response(message: &str, uid: u32) -> &'static str {
        let response = format!("* 1 FETCH (UID {uid} BODY[] {{{}}}\r\n{message})\r\nA3 OK\r\n", message.len());
        Box::leak(response.into_boxed_str())
    }

    fn peek_response(message: &str) -> ScriptIo {
        ScriptIo {
            steps: vec![
                ("LOGIN", "A1 OK\r\n"),
                ("EXAMINE INBOX", "A2 OK [READ-ONLY]\r\n"),
                ("BODY.PEEK[]", fetch_response(message, 9)),
            ],
            seen: vec![],
        }
    }

    #[test]
    fn multipart_alternative_decodes_quoted_printable_html_and_base64_plain() {
        let plain = base64_of("纯文本正文\n第二行");
        let raw = wire(&[
            "Content-Type: multipart/alternative; boundary=\"part-1\"",
            "",
            "preamble that must be ignored",
            "--part-1",
            "Content-Type: text/plain; charset=utf-8",
            "Content-Transfer-Encoding: base64",
            "",
            plain.as_str(),
            "--part-1",
            "Content-Type: text/html; charset=utf-8",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "<p>=E4=BD=A0=E5=A5=BD =3D ok</p>",
            "--part-1--",
        ]);
        let (text, html) = extract_body(&raw);
        assert_eq!(html.as_deref(), Some("<p>你好 = ok</p>"));
        assert_eq!(text, "纯文本正文\n第二行");
    }

    #[test]
    fn nested_mixed_and_alternative_reach_the_text_leaves() {
        let raw = wire(&[
            "Content-Type: multipart/mixed; boundary=mixed-b",
            "",
            "This is a multi-part message in MIME format.",
            "--mixed-b",
            "Content-Type: multipart/alternative; boundary=alt-b",
            "",
            "--alt-b",
            "Content-Type: text/plain; charset=us-ascii",
            "",
            "plain body",
            "--alt-b",
            "Content-Type: text/html; charset=utf-8",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "<b>=E4=BD=A0</b>",
            "--alt-b--",
            "--mixed-b--",
        ]);
        let (text, html) = extract_body(&raw);
        assert_eq!(html.as_deref(), Some("<b>你</b>"));
        assert_eq!(text, "plain body");
    }

    #[test]
    fn a_plain_footer_does_not_replace_the_real_body() {
        let raw = wire(&[
            "Content-Type: multipart/mixed; boundary=m",
            "",
            "--m",
            "Content-Type: multipart/alternative; boundary=a",
            "",
            "--a",
            "Content-Type: text/plain",
            "",
            "the real body",
            "--a",
            "Content-Type: text/html",
            "",
            "<p>the real body</p>",
            "--a--",
            "--m",
            "Content-Type: text/plain",
            "",
            "footer",
            "--m--",
        ]);
        let (text, html) = extract_body(&raw);
        assert_eq!(text, "the real body");
        assert_eq!(html.as_deref(), Some("<p>the real body</p>"));
    }

    #[test]
    fn attachment_parts_are_ignored() {
        let raw = wire(&[
            "Content-Type: multipart/mixed; boundary=b1",
            "",
            "--b1",
            "Content-Type: text/plain",
            "",
            "正文在这里",
            "--b1",
            "Content-Type: application/pdf; name=\"a.pdf\"",
            "Content-Disposition: attachment; filename=\"a.pdf\"",
            "Content-Transfer-Encoding: base64",
            "",
            "JVBERi0xLjQK",
            "--b1--",
        ]);
        let (text, html) = extract_body(&raw);
        assert_eq!(text, "正文在这里");
        assert!(html.is_none());
        assert!(!text.contains("JVBERi0xLjQK"));
    }

    #[test]
    fn gbk_charset_body_decodes_to_chinese() {
        let (encoded, _, unencodable) = encoding_rs::GBK.encode("你好，仓库盘点完成");
        assert!(!unencodable);
        let mut raw = wire(&[
            "Content-Type: text/plain; charset=gbk",
            "Content-Transfer-Encoding: 8bit",
            "",
        ]);
        raw.extend_from_slice(&encoded);
        let (text, html) = extract_body(&raw);
        assert_eq!(text, "你好，仓库盘点完成");
        assert!(html.is_none());
    }

    #[test]
    fn folded_content_type_header_keeps_its_boundary() {
        let raw = wire(&[
            "Content-Type: multipart/alternative;",
            "\tboundary=\"folded\"",
            "",
            "--folded",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "只有纯文本",
            "--folded--",
        ]);
        let (text, html) = extract_body(&raw);
        assert_eq!(text, "只有纯文本");
        assert!(html.is_none());
    }

    #[test]
    fn single_html_part_still_becomes_text_and_html() {
        let raw = wire(&["Content-Type: text/html; charset=utf-8", "", "<p>你好&nbsp;<b>报销</b></p>"]);
        let (text, html) = extract_body(&raw);
        assert_eq!(text, "你好 报销");
        assert_eq!(html.as_deref(), Some("<p>你好&nbsp;<b>报销</b></p>"));
    }

    #[test]
    fn body_json_keeps_camel_case_and_nulls_html() {
        let plain = MailBody { text: "hi".to_string(), html: None, truncated: false };
        assert_eq!(
            serde_json::to_string(&plain).unwrap(),
            r#"{"text":"hi","html":null,"truncated":false}"#
        );
        let rich = MailBody { text: "hi".to_string(), html: Some("<b>hi</b>".to_string()), truncated: true };
        assert_eq!(
            serde_json::to_string(&rich).unwrap(),
            r#"{"text":"hi","html":"<b>hi</b>","truncated":true}"#
        );
    }

    #[test]
    fn truncated_multipart_keeps_the_fragment_it_has() {
        let raw = wire(&[
            "Content-Type: multipart/mixed; boundary=x",
            "",
            "--x",
            "Content-Type: text/plain",
            "",
            "half a message",
        ]);
        let (text, html) = extract_body(&raw);
        assert_eq!(text, "half a message");
        assert!(html.is_none());
    }

    #[test]
    fn malformed_messages_never_panic() {
        let mut cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"\r\n\r\n".to_vec(),
            b"Content-Type: multipart/mixed\r\n\r\nno boundary anywhere".to_vec(),
            b"Content-Type: multipart/mixed; boundary=\"\"\r\n\r\n--\r\n--".to_vec(),
            b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\r\n--x--\r\n--x--".to_vec(),
            b"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!not base64!!!".to_vec(),
            b"Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=ZZ=3".to_vec(),
            b"Content-Type: text/plain; charset=no-such-charset\r\n\r\nhello".to_vec(),
            b"\xff\xfe\x00binary junk".to_vec(),
            b"Content-Disposition: attachment\r\n\r\nfile payload".to_vec(),
        ];
        // Nested deeper than MAX_MIME_DEPTH: the cap must stop the walk instead of recursing.
        let mut deep = String::new();
        for level in 0..24 {
            deep.push_str(&format!("Content-Type: multipart/mixed; boundary=b{level}\r\n\r\n--b{level}\r\n"));
        }
        deep.push_str("Content-Type: text/plain\r\n\r\ndeep\r\n");
        for level in (0..24).rev() {
            deep.push_str(&format!("--b{level}--\r\n"));
        }
        cases.push(deep.into_bytes());
        for case in cases {
            // The contract is only "no panic": no MIME framing may leak into the rendered text.
            let (text, html) = extract_body(&case);
            assert!(!text.contains("Content-Type"), "{text}");
            assert!(!text.contains("Content-Transfer-Encoding"), "{text}");
            assert!(html.map_or(true, |html| !html.contains("Content-Type")));
        }
    }

    #[test]
    fn truncation_never_splits_a_character() {
        let mut text = "你".repeat(MAX_BODY_BYTES);
        assert!(truncate_at_boundary(&mut text, MAX_BODY_BYTES));
        assert!(text.len() <= MAX_BODY_BYTES);
        assert!(text.len() > MAX_BODY_BYTES - 3);
        assert!(text.chars().all(|ch| ch == '你'));
        let mut short = String::from("短");
        assert!(!truncate_at_boundary(&mut short, MAX_BODY_BYTES));
    }

    #[test]
    fn oversized_body_sets_truncated_through_fetch_body() {
        let filler = "a".repeat(MAX_BODY_BYTES + 16);
        let message = format!("Content-Type: text/plain\r\n\r\n{filler}");
        let mut io = peek_response(&message);
        let body = fetch_body(&mut io, "me@qq.com", "auth-SECRET", 9).unwrap();
        assert!(body.truncated);
        assert_eq!(body.text.len(), MAX_BODY_BYTES);
        assert!(body.html.is_none());

        // The html part is capped on its own, so an oversized body cannot inflate the render.
        let message = format!("Content-Type: text/html\r\n\r\n<p>{filler}</p>");
        let mut io = peek_response(&message);
        let body = fetch_body(&mut io, "me@qq.com", "auth-SECRET", 9).unwrap();
        assert!(body.truncated);
        assert_eq!(body.html.as_deref().map(str::len), Some(MAX_BODY_BYTES));
        assert!(body.text.len() <= MAX_BODY_BYTES);
    }

    #[test]
    fn body_peeks_multipart_and_returns_text_plus_html() {
        let message = String::from_utf8(wire(&[
            "Content-Type: multipart/alternative; boundary=bb",
            "",
            "--bb",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "纯文本",
            "--bb",
            "Content-Type: text/html; charset=utf-8",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "<p>=E4=BD=A0=E5=A5=BD</p>",
            "--bb--",
        ]))
        .unwrap();
        let mut io = peek_response(&message);
        let body = fetch_body(&mut io, "me@gmail.com", "auth-SECRET", 9).unwrap();
        assert_eq!(body.text, "纯文本");
        assert_eq!(body.html.as_deref(), Some("<p>你好</p>"));
        assert!(!body.truncated);
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains(r#""html":"<p>你好</p>""#), "{json}");
        assert!(json.contains(r#""truncated":false"#), "{json}");
    }

    #[test]
    fn empty_message_is_still_empty_text() {
        let mut io = peek_response("Content-Type: text/plain\r\n\r\n   \r\n");
        let err = fetch_body(&mut io, "me@qq.com", "auth-SECRET", 9).unwrap_err();
        assert_eq!(failure_message(err), "这封邮件没有可显示的文本");
    }
}
