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
    TooLarge,
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
        MailFailure::TooLarge => "附件过大，已拒绝下载",
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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailAttachment {
    pub part: String,
    pub filename: String,
    pub mime: String,
    pub size: Option<u32>,
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
    /// `multipart/related` payloads the html cites with `cid:`, already turned into `data:` URLs so
    /// the render never needs the network (the desktop frame only allows `data:` images).
    resources: Vec<InlineResource>,
}

/// One inline part the html may cite by `Content-ID`. `cid` is the folded key both sides compare
/// on: angle brackets and surrounding whitespace gone, percent escapes decoded, lower-cased.
struct InlineResource {
    cid: String,
    url: String,
}

/// Inlining is bounded: a message must not be able to inflate the render without limit. Parts past
/// either cap are not inlined at all, and their `cid:` reference in the html stays as it was.
const MAX_INLINE_IMAGES: usize = 32;
const MAX_INLINE_BYTES: usize = 4 * 1024 * 1024;

/// Running total for those caps. It is shared by the whole MIME walk, so a nested multipart cannot
/// reset what its siblings already spent.
#[derive(Default)]
struct InlineBudget {
    images: usize,
    bytes: usize,
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
    // Every inline part is usable whatever branch it came from: a reference is resolved by cid, so
    // the alternative that wins the html slot can still cite a payload collected elsewhere.
    into.resources.extend(from.resources);
}

/// Walks the MIME tree and records the leaf text parts, plus the inline images the html may cite.
fn collect_text_parts(part: &[u8], depth: usize, out: &mut TextParts, budget: &mut InlineBudget) {
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
                collect_text_parts(child, depth + 1, &mut child_parts, budget);
                merge_parts(out, child_parts, prefer_later);
            }
            return;
        }
        // A multipart header we cannot honour (no boundary, or a truncated one). The body is
        // still the only text there is, so fall through and decode it as one leaf part.
    } else if kind == "image" {
        collect_inline_resource(&fields, &subtype, body, out, budget);
        return;
    } else if kind != "text" || !matches!(subtype.as_str(), "plain" | "html") {
        // Attachments (`application/*`, `message/*`) and exotic `text/*` subtypes are not body text.
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

/// The raster formats the desktop frame may inline, mapped to their canonical label; `jpeg` and
/// `jpg` are the same format. `image/svg+xml` is deliberately absent: it is a scriptable document,
/// not a picture, and the frame only whitelists `data:` images.
fn inline_image_mime(subtype: &str) -> Option<&'static str> {
    match subtype {
        "png" => Some("image/png"),
        "jpeg" | "jpg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "bmp" => Some("image/bmp"),
        _ => None,
    }
}

/// Turns one `image/*` leaf into a `data:` URL filed under its `Content-ID`, unless the caps are
/// already spent. A part without a usable id is dropped: nothing in the html could cite it.
fn collect_inline_resource(
    fields: &[(String, String)],
    subtype: &str,
    body: &[u8],
    out: &mut TextParts,
    budget: &mut InlineBudget,
) {
    if budget.images >= MAX_INLINE_IMAGES {
        return;
    }
    let Some(mime) = inline_image_mime(subtype) else { return };
    let Some(cid) = header_value(fields, "content-id")
        .map(|value| normalize_cid(&value))
        .filter(|cid| !cid.is_empty())
    else {
        return;
    };
    let encoding = header_value(fields, "content-transfer-encoding").unwrap_or_default();
    let bytes = decode_transfer_encoding(body, &encoding);
    if bytes.is_empty() || budget.bytes.saturating_add(bytes.len()) > MAX_INLINE_BYTES {
        return;
    }
    budget.images += 1;
    budget.bytes += bytes.len();
    let payload = base64::engine::general_purpose::STANDARD.encode(&bytes);
    out.resources.push(InlineResource { cid, url: format!("data:{mime};base64,{payload}") });
}

/// Folds a `Content-ID` header value or a `cid:` reference to the key both sides compare on: the
/// angle brackets around an id are not part of it, and `cid:` values may be percent-escaped.
fn normalize_cid(raw: &str) -> String {
    let mut inner = raw.trim();
    if let Some(rest) = inner.strip_prefix('<') {
        inner = rest;
    }
    if let Some(rest) = inner.strip_suffix('>') {
        inner = rest;
    }
    percent_decode(inner.trim()).trim().to_ascii_lowercase()
}

/// `%xx` escapes in a `cid:` reference, decoded as bytes; anything malformed stays literal.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let pair = bytes
                .get(index + 1..index + 3)
                .and_then(|pair| hex_digit(pair[0]).zip(hex_digit(pair[1])));
            if let Some((high, low)) = pair {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The attributes that may point at an inline part.
const INLINE_ATTRIBUTES: [&str; 2] = ["src", "background"];

/// Characters that make up an attribute name. A match has to be a whole name, so `srcset` and
/// `data-src` are not mistaken for `src`.
fn is_attribute_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':')
}

/// Whether `at` starts the attribute `name` rather than the tail or head of a longer one.
fn attribute_name_matches(bytes: &[u8], at: usize, name: &str) -> bool {
    let end = at.saturating_add(name.len());
    if end > bytes.len() || !bytes[at..end].eq_ignore_ascii_case(name.as_bytes()) {
        return false;
    }
    let starts_name = at == 0 || !is_attribute_name_byte(bytes[at - 1]);
    let ends_name = !matches!(bytes.get(end), Some(&byte) if is_attribute_name_byte(byte));
    starts_name && ends_name
}

/// The byte range of one `src`/`background` value at or after `at`, plus where the scan may resume.
/// `lowercase` must be a case-folded copy of the html being rewritten, which keeps the offsets
/// valid for both. A value that cannot be delimited cleanly yields `None`.
fn cid_value_at(lowercase: &str, at: usize) -> Option<(usize, usize, usize)> {
    let bytes = lowercase.as_bytes();
    let name_len = INLINE_ATTRIBUTES
        .iter()
        .find(|name| attribute_name_matches(bytes, at, name))?
        .len();
    let mut cursor = at + name_len;
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'=') {
        return None;
    }
    cursor += 1;
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    match bytes.get(cursor).copied() {
        Some(quote) if quote == b'"' || quote == b'\'' => {
            let start = cursor + 1;
            let len = bytes.get(start..)?.iter().position(|byte| *byte == quote)?;
            Some((start, start + len, start + len + 1))
        }
        // An unquoted value ends at whitespace or at the end of the tag.
        Some(_) => {
            let start = cursor;
            let len = bytes[start..]
                .iter()
                .position(|byte| byte.is_ascii_whitespace() || *byte == b'>')
                .unwrap_or(bytes.len() - start);
            Some((start, start + len, start + len))
        }
        None => None,
    }
}

/// Rewrites every `src="cid:..."` / `background='cid:...'` that names a collected part into its
/// `data:` URL. Only the attribute value changes: quotes and every other byte are copied through,
/// and a reference with no matching part is left exactly as it was. Returns the rewritten html and
/// how many bytes of `data:` URLs were spliced in.
fn inline_cid_references(html: &str, resources: &[InlineResource]) -> (String, usize) {
    if resources.is_empty() || html.is_empty() {
        return (html.to_string(), 0);
    }
    // Folding only ASCII keeps every byte offset addressing the original, so the scan can be
    // case-insensitive while the rewrite still slices the untouched html.
    let lowercase = html.to_ascii_lowercase();
    let bytes = lowercase.as_bytes();
    let mut out = String::with_capacity(html.len());
    let mut copied = 0;
    let mut inlined = 0;
    let mut index = 0;
    while index < bytes.len() {
        let Some((value_start, value_end, resume)) = cid_value_at(&lowercase, index) else {
            index += 1;
            continue;
        };
        index = resume.max(index + 1);
        let value = &html[value_start..value_end];
        let trimmed = value.trim();
        // `get(..4)` rejects both a shorter value and one whose fourth byte is mid-character.
        if !trimmed.get(..4).is_some_and(|scheme| scheme.eq_ignore_ascii_case("cid:")) {
            continue;
        }
        let key = normalize_cid(&trimmed[4..]);
        let Some(resource) = resources.iter().find(|resource| resource.cid == key) else {
            continue;
        };
        out.push_str(&html[copied..value_start]);
        out.push_str(&resource.url);
        copied = value_end;
        inlined += resource.url.len();
    }
    out.push_str(&html[copied..]);
    (out, inlined)
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
/// part exists, so the desktop can fall back to the plain rendering. Only the tests want the body
/// without a render cap to apply, so the inline-byte count is dropped here.
#[cfg(test)]
fn extract_body(message: &[u8]) -> (String, Option<String>) {
    let (text, html, _) = extract_body_with_inline(message);
    (text, html)
}

/// Like `extract_body`, plus how many bytes of `data:` URLs were spliced into the html, so the
/// caller can widen its render cap by exactly that much instead of truncating the images away.
fn extract_body_with_inline(message: &[u8]) -> (String, Option<String>, usize) {
    let mut parts = TextParts::default();
    collect_text_parts(message, 0, &mut parts, &mut InlineBudget::default());
    let resources = parts.resources.as_slice();
    let mut inlined = 0;
    let html = parts
        .html
        // A body that ends at the end of the message keeps its final CRLF; the frame does not need it.
        .map(|html| {
            let (html, bytes) = inline_cid_references(html.trim_end(), resources);
            inlined = bytes;
            html
        })
        .filter(|html| !html.is_empty());
    let text = match parts.plain {
        // Plain mail is shown as written, minus the CRLFs that would otherwise double up.
        Some(plain) => plain.replace("\r\n", "\n").replace('\r', "\n").trim_end().to_string(),
        None => html.as_deref().map(html_to_text).unwrap_or_default(),
    };
    (text, html, inlined)
}

pub fn fetch_body(io: &mut impl ImapIo, email: &str, auth: &str, uid: u32) -> Result<MailBody, MailFailure> {
    open_inbox(io, email, auth)?;
    let fetch = io.transact(&format!("A3 UID FETCH {uid} (BODY.PEEK[])"))?;
    check_completion(&fetch, "A3", MailFailure::Protocol)?;
    let message = body_literal(&fetch, uid)?;
    let (mut text, mut html, inlined) = extract_body_with_inline(&message);
    if text.trim().is_empty() && html.is_none() {
        return Err(MailFailure::EmptyText);
    }
    let text_cut = truncate_at_boundary(&mut text, MAX_BODY_BYTES);
    // The inline images are already capped by their own budget, so their bytes ride on top of the
    // text limit. Otherwise a mail with pictures would be cut in the middle of a `data:` URL.
    let html_limit = MAX_BODY_BYTES.saturating_add(inlined);
    let html_cut = html.as_mut().is_some_and(|value| truncate_at_boundary(value, html_limit));
    Ok(MailBody { text, html, truncated: text_cut || html_cut })
}

const MAX_ATTACHMENT_BYTES: usize = 20 * 1024 * 1024;

fn child_part(parent: &str, index: u32) -> String {
    if parent.is_empty() {
        index.to_string()
    } else {
        format!("{parent}.{index}")
    }
}

fn media_pair(fields: &[Item]) -> Option<(String, String)> {
    let Item::Str(_) = fields.first()? else {
        return None;
    };
    let kind = text(&fields[0]);
    if kind.is_empty() {
        return None;
    }
    let subtype = fields.get(1).map(text).unwrap_or_default();
    Some((kind, subtype))
}

fn octets(fields: &[Item]) -> Option<u32> {
    let Item::Str(bytes) = fields.get(6)? else {
        return None;
    };
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn param_value(item: &Item, name: &str) -> Option<String> {
    let Item::List(pairs) = item else {
        return None;
    };
    let mut index = 0;
    while index + 1 < pairs.len() {
        if text(&pairs[index]).eq_ignore_ascii_case(name) {
            let value = decode_header(&text(&pairs[index + 1]));
            if !value.is_empty() {
                return Some(value);
            }
        }
        index += 2;
    }
    None
}

fn find_disposition(fields: &[Item]) -> Option<(String, Item)> {
    for field in fields {
        let Item::List(pair) = field else {
            continue;
        };
        let Some(Item::Str(kind)) = pair.first() else {
            continue;
        };
        let kind = String::from_utf8_lossy(kind).to_ascii_lowercase();
        if kind == "attachment" || kind == "inline" {
            let params = pair.get(1).map(clone_item).unwrap_or(Item::Nil);
            return Some((kind, params));
        }
    }
    None
}

fn attachment_filename(part: &str, fields: &[Item], disposition: Option<&(String, Item)>) -> String {
    let from_disposition = disposition.and_then(|(_, params)| param_value(params, "filename"));
    let from_type = fields.get(2).and_then(|params| param_value(params, "name"));
    from_disposition
        .filter(|name| !name.trim().is_empty())
        .or(from_type)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| format!("attachment-{part}"))
}

fn attachment_of(part: &str, fields: &[Item]) -> Option<MailAttachment> {
    let (kind, subtype) = media_pair(fields)?;
    let kind_up = kind.to_ascii_uppercase();
    let subtype_l = subtype.to_ascii_lowercase();
    if kind_up == "TEXT" && matches!(subtype_l.as_str(), "plain" | "html") {
        return None;
    }
    let disposition = find_disposition(fields);
    let marked = disposition.as_ref().is_some_and(|(kind, _)| kind == "attachment");
    let typed = matches!(kind_up.as_str(), "APPLICATION" | "IMAGE" | "AUDIO" | "VIDEO");
    if !marked && !typed {
        return None;
    }
    Some(MailAttachment {
        part: part.to_string(),
        filename: attachment_filename(part, fields, disposition.as_ref()),
        mime: format!("{}/{}", kind.to_ascii_lowercase(), subtype_l),
        size: octets(fields),
    })
}

fn each_leaf(item: &Item, part: &str, visit: &mut dyn FnMut(&str, &[Item])) {
    let Item::List(fields) = item else {
        return;
    };
    if matches!(fields.first(), Some(Item::List(_))) {
        let mut index = 0u32;
        for field in fields {
            if !matches!(field, Item::List(_)) {
                break;
            }
            index += 1;
            let child = child_part(part, index);
            each_leaf(field, &child, visit);
        }
        return;
    }
    if let Some((kind, subtype)) = media_pair(fields) {
        if kind.eq_ignore_ascii_case("message") && subtype.eq_ignore_ascii_case("rfc822") {
            if let Some(nested) = fields.get(8) {
                let nested_is_multipart = matches!(nested, Item::List(inner) if matches!(inner.first(), Some(Item::List(_))));
                if nested_is_multipart {
                    each_leaf(nested, part, visit);
                } else {
                    let child = child_part(part, 1);
                    each_leaf(nested, &child, visit);
                }
            }
        }
    }
    if !part.is_empty() {
        visit(part, fields);
    }
}

fn walk_body(body: &Item, visit: &mut dyn FnMut(&str, &[Item])) {
    let Item::List(fields) = body else {
        return;
    };
    let root = if matches!(fields.first(), Some(Item::List(_))) {
        ""
    } else {
        "1"
    };
    each_leaf(body, root, visit);
}

fn clone_item(item: &Item) -> Item {
    match item {
        Item::Nil => Item::Nil,
        Item::Str(bytes) => Item::Str(bytes.clone()),
        Item::List(items) => Item::List(items.iter().map(clone_item).collect()),
    }
}

fn fetch_item(raw: &str, uid: u32, mut key_is: impl FnMut(&[u8]) -> bool) -> Result<Option<Item>, MailFailure> {
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
        let mut matched = None;
        for pair in items.chunks(2) {
            let Item::Str(key) = &pair[0] else {
                return Err(MailFailure::Protocol);
            };
            if key.eq_ignore_ascii_case(b"UID") {
                found_uid = std::str::from_utf8(&text(&pair[1]).into_bytes())
                    .ok()
                    .and_then(|value| value.parse::<u32>().ok());
            } else if key_is(key) {
                matched = Some(clone_item(&pair[1]));
            }
        }
        if found_uid.is_some_and(|found| found != uid) {
            continue;
        }
        if matched.is_some() {
            return Ok(matched);
        }
    }
    Ok(None)
}

fn item_bytes(item: Item) -> Result<Vec<u8>, MailFailure> {
    match item {
        Item::Str(bytes) => Ok(bytes),
        Item::Nil => Ok(Vec::new()),
        Item::List(_) => Err(MailFailure::Protocol),
    }
}

fn read_structure(io: &mut impl ImapIo, email: &str, auth: &str, uid: u32) -> Result<Item, MailFailure> {
    open_inbox(io, email, auth)?;
    let response = io.transact(&format!("A3 UID FETCH {uid} (BODYSTRUCTURE)"))?;
    check_completion(&response, "A3", MailFailure::Protocol)?;
    fetch_item(&response, uid, |key| key.eq_ignore_ascii_case(b"BODYSTRUCTURE"))?
        .ok_or(MailFailure::Protocol)
}

pub fn list_attachments(
    io: &mut impl ImapIo,
    email: &str,
    auth: &str,
    uid: u32,
) -> Result<Vec<MailAttachment>, MailFailure> {
    let structure = read_structure(io, email, auth, uid)?;
    let mut attachments = Vec::new();
    walk_body(&structure, &mut |part, fields| {
        if let Some(attachment) = attachment_of(part, fields) {
            attachments.push(attachment);
        }
    });
    Ok(attachments)
}

fn valid_section(part: &str) -> bool {
    let mut segments = 0usize;
    if part.is_empty() {
        return false;
    }
    for segment in part.split('.') {
        segments += 1;
        let bytes = segment.as_bytes();
        if !(1..=4).contains(&bytes.len()) || bytes[0] == b'0' || !bytes.iter().all(u8::is_ascii_digit) {
            return false;
        }
    }
    (1..=6).contains(&segments)
}

fn leaf_size(body: &Item, part: &str) -> Option<u32> {
    let mut found = None;
    walk_body(body, &mut |current, fields| {
        if current == part {
            found = octets(fields);
        }
    });
    found
}

fn ensure_attachment_len(len: usize) -> Result<(), MailFailure> {
    if len > MAX_ATTACHMENT_BYTES {
        Err(MailFailure::TooLarge)
    } else {
        Ok(())
    }
}

pub fn fetch_attachment(
    io: &mut impl ImapIo,
    email: &str,
    auth: &str,
    uid: u32,
    part: &str,
) -> Result<Vec<u8>, MailFailure> {
    if !valid_section(part) {
        return Err(MailFailure::Protocol);
    }
    let structure = read_structure(io, email, auth, uid)?;
    if leaf_size(&structure, part).is_some_and(|size| size as usize > MAX_ATTACHMENT_BYTES) {
        return Err(MailFailure::TooLarge);
    }
    let response = io.transact(&format!(
        "A4 UID FETCH {uid} (BODY.PEEK[{part}] BODY.PEEK[{part}.MIME])"
    ))?;
    check_completion(&response, "A4", MailFailure::Protocol)?;
    let body_key = format!("BODY[{part}]");
    let mime_key = format!("BODY[{part}.MIME]");
    let body = fetch_item(&response, uid, |key| key.eq_ignore_ascii_case(body_key.as_bytes()))?
        .ok_or(MailFailure::Protocol)?;
    let bytes = item_bytes(body)?;
    ensure_attachment_len(bytes.len())?;
    let headers = match fetch_item(&response, uid, |key| key.eq_ignore_ascii_case(mime_key.as_bytes()))? {
        Some(item) => item_bytes(item)?,
        None => Vec::new(),
    };
    let fields = parse_header_fields(&String::from_utf8_lossy(&headers));
    let encoding = header_value(&fields, "content-transfer-encoding").unwrap_or_default();
    let decoded = decode_transfer_encoding(&bytes, &encoding);
    ensure_attachment_len(decoded.len())?;
    Ok(decoded)
}

/// Writes `bytes` to a new absolute file. The parent must already exist and the destination must not.
/// Bytes land in a sibling temporary file first and are renamed into place. Failures use a fixed
/// sentence so the caller never sees a path or an OS error.
pub fn write_exclusive(path: &str, bytes: &[u8]) -> Result<u64, &'static str> {
    let path = std::path::Path::new(path);
    if !path.is_absolute() || path.components().any(|component| matches!(component, std::path::Component::ParentDir)) {
        return Err("无法保存附件");
    }
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).ok_or("无法保存附件")?;
    if !parent.is_dir() || path.exists() || path.file_name().is_none() {
        return Err("无法保存附件");
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let tmp = parent.join(format!(".{nonce}.{}.sealbox-part", std::process::id()));
    let write_result = (|| {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err("无法保存附件");
    }
    if path.exists() || std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err("无法保存附件");
    }
    Ok(bytes.len() as u64)
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

    /// A `multipart/related` message: one text/html part plus the image parts it may cite.
    fn related_message(html: &str, images: &[(&str, &str)]) -> Vec<u8> {
        let mut out = String::from("Content-Type: multipart/related; boundary=rel\r\n\r\n--rel\r\n");
        out.push_str("Content-Type: text/html; charset=utf-8\r\n\r\n");
        out.push_str(html);
        out.push_str("\r\n");
        for (cid, payload) in images {
            out.push_str("--rel\r\nContent-Type: image/png\r\n");
            out.push_str(&format!("Content-ID: <{cid}>\r\n"));
            out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
            out.push_str(&base64_of(payload));
            out.push_str("\r\n");
        }
        out.push_str("--rel--\r\n");
        out.into_bytes()
    }

    #[test]
    fn multipart_related_inlines_a_cid_image_as_a_data_url() {
        let logo = base64_of("png-logo-bytes");
        let raw = wire(&[
            "Content-Type: multipart/related; boundary=rel",
            "",
            "--rel",
            "Content-Type: text/html; charset=utf-8",
            "",
            "<p>活动预告</p><img src=\"cid:logo@x\">",
            "--rel",
            "Content-Type: image/png; name=\"logo.png\"",
            "Content-ID: <logo@x>",
            "Content-Transfer-Encoding: base64",
            "",
            logo.as_str(),
            "--rel--",
        ]);
        let (text, html) = extract_body(&raw);
        // Only the attribute value is rewritten; the rest of the html is byte-identical.
        let expected = format!("<p>活动预告</p><img src=\"data:image/png;base64,{logo}\">");
        assert_eq!(html.as_deref(), Some(expected.as_str()));
        assert_eq!(text, "活动预告");
    }

    #[test]
    fn every_cid_spelling_hits_the_same_part_but_data_src_is_ignored() {
        let logo = base64_of("logo-bytes");
        let raw = wire(&[
            "Content-Type: multipart/related; boundary=rel",
            "",
            "--rel",
            "Content-Type: text/html",
            "",
            "<IMG SRC=\"CID:Logo@X\"><td background='cid:logo@x'></td><img src= cid:logo%40x><img data-src=\"cid:logo@x\">",
            "--rel",
            "Content-Type: image/png",
            "Content-ID: <LOGO@x>",
            "Content-Transfer-Encoding: base64",
            "",
            logo.as_str(),
            "--rel--",
        ]);
        let (_, html) = extract_body(&raw);
        let url = format!("data:image/png;base64,{logo}");
        let expected = format!(
            "<IMG SRC=\"{url}\"><td background='{url}'></td><img src= {url}><img data-src=\"cid:logo@x\">"
        );
        assert_eq!(html.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn an_unmatched_cid_reference_is_left_as_it_was() {
        let raw = related_message("<img src=\"cid:missing@x\"><p>正文</p>", &[("other@x", "bytes")]);
        let (_, html) = extract_body(&raw);
        assert_eq!(html.as_deref(), Some("<img src=\"cid:missing@x\"><p>正文</p>"));
    }

    #[test]
    fn svg_and_other_types_are_never_inlined() {
        let svg = base64_of("<svg xmlns=\"http://www.w3.org/2000/svg\"/>");
        let raw = wire(&[
            "Content-Type: multipart/related; boundary=rel",
            "",
            "--rel",
            "Content-Type: text/html",
            "",
            "<img src=\"cid:icon@x\">",
            "--rel",
            "Content-Type: image/svg+xml",
            "Content-ID: <icon@x>",
            "Content-Transfer-Encoding: base64",
            "",
            svg.as_str(),
            "--rel--",
        ]);
        let (_, html) = extract_body(&raw);
        assert_eq!(html.as_deref(), Some("<img src=\"cid:icon@x\">"));
    }

    #[test]
    fn the_image_count_cap_keeps_the_first_thirty_two() {
        let images: Vec<(String, String)> =
            (0..33).map(|index| (format!("img{index}@x"), format!("payload-{index}"))).collect();
        let refs: Vec<(&str, &str)> =
            images.iter().map(|(cid, payload)| (cid.as_str(), payload.as_str())).collect();
        let mut html = String::new();
        for index in 0..33 {
            html.push_str(&format!("<img src=\"cid:img{index}@x\">"));
        }
        let raw = related_message(&html, &refs);
        let (_, html) = extract_body(&raw);
        let html = html.unwrap_or_default();
        assert_eq!(html.matches("data:image/png;base64,").count(), MAX_INLINE_IMAGES);
        assert!(html.contains("src=\"cid:img32@x\""), "{html}");
        assert!(!html.contains("src=\"cid:img31@x\""));
    }

    #[test]
    fn the_byte_cap_stops_inlining_without_panicking() {
        // Two 2 MiB parts fill the 4 MiB budget; the third would overflow it and is skipped.
        let chunk = "a".repeat(2 * 1024 * 1024);
        let refs = [("a@x", chunk.as_str()), ("b@x", chunk.as_str()), ("c@x", chunk.as_str())];
        let raw = related_message("<img src=\"cid:a@x\"><img src=\"cid:b@x\"><img src=\"cid:c@x\">", &refs);
        let (_, html) = extract_body(&raw);
        let html = html.unwrap_or_default();
        assert_eq!(html.matches("data:image/png;base64,").count(), 2);
        assert!(html.contains("src=\"cid:c@x\""));

        // One part larger than the whole budget cannot be inlined either.
        let huge = "b".repeat(MAX_INLINE_BYTES + 1);
        let raw = related_message("<img src=\"cid:big@x\">", &[("big@x", huge.as_str())]);
        let (_, html) = extract_body(&raw);
        assert_eq!(html.as_deref(), Some("<img src=\"cid:big@x\">"));
    }

    #[test]
    fn quoted_printable_html_is_decoded_before_the_cid_substitution() {
        let logo = base64_of("logo");
        let raw = wire(&[
            "Content-Type: multipart/related; boundary=rel",
            "",
            "--rel",
            "Content-Type: text/html; charset=utf-8",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "<p>=E4=BD=A0=E5=A5=BD</p><img src=3D\"cid:logo@x\">",
            "--rel",
            "Content-Type: image/png",
            "Content-ID: <logo@x>",
            "Content-Transfer-Encoding: base64",
            "",
            logo.as_str(),
            "--rel--",
        ]);
        let (_, html) = extract_body(&raw);
        let expected = format!("<p>你好</p><img src=\"data:image/png;base64,{logo}\">");
        assert_eq!(html.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn inlined_images_do_not_eat_the_html_budget() {
        let payload = "x".repeat(3 * 1024);
        let filler = "y".repeat(MAX_BODY_BYTES - 1024);
        let html = format!("<p>{filler}</p><img src=\"cid:logo@x\">");
        let message = format!(
            "Content-Type: multipart/related; boundary=rel\r\n\r\n--rel\r\nContent-Type: text/html\r\n\r\n{html}\r\n--rel\r\nContent-Type: image/png\r\nContent-ID: <logo@x>\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--rel--\r\n",
            base64_of(&payload)
        );
        let mut io = peek_response(&message);
        let body = fetch_body(&mut io, "me@qq.com", "auth-SECRET", 9).unwrap();
        assert!(!body.truncated);
        let html = body.html.unwrap_or_default();
        // The data URL is complete: the body cap must not cut it in the middle.
        assert!(
            html.ends_with(&format!("src=\"data:image/png;base64,{}\">", base64_of(&payload))),
            "{html}"
        );
    }

    struct OwnedIo {
        steps: Vec<(String, String)>,
        seen: Vec<String>,
    }

    impl ImapIo for OwnedIo {
        fn transact(&mut self, command: &str) -> Result<String, MailFailure> {
            self.seen.push(command.to_string());
            let (expect, response) = self.steps.remove(0);
            assert!(command.contains(&expect), "{command} vs {expect}");
            Ok(response)
        }
    }

    fn logged_in(extra: Vec<(&str, &str)>) -> OwnedIo {
        let mut steps = vec![
            ("LOGIN".to_string(), "A1 OK\r\n".to_string()),
            ("EXAMINE INBOX".to_string(), "A2 OK [READ-ONLY]\r\n".to_string()),
        ];
        for (expect, response) in extra {
            steps.push((expect.to_string(), response.to_string()));
        }
        OwnedIo { steps, seen: Vec::new() }
    }

    #[test]
    fn multipart_pdf_lists_and_decodes_the_attachment() {
        let original = b"Hello PDF";
        let encoded = base64::engine::general_purpose::STANDARD.encode(original);
        let structure = "* 1 FETCH (UID 9 BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 2 1 NIL NIL NIL NIL)(\"APPLICATION\" \"PDF\" (\"NAME\" \"other.pdf\") NIL NIL \"BASE64\" 4 NIL (\"ATTACHMENT\" (\"FILENAME\" \"note.pdf\")) NIL NIL) \"MIXED\"))\r\nA3 OK\r\n";
        let mut listed = logged_in(vec![("BODYSTRUCTURE", structure)]);
        let attachments = list_attachments(&mut listed, "me@qq.com", "auth-SECRET", 9).unwrap();
        assert_eq!(
            attachments,
            vec![MailAttachment {
                part: "2".into(),
                filename: "note.pdf".into(),
                mime: "application/pdf".into(),
                size: Some(4),
            }]
        );
        assert!(listed.seen.iter().all(|line| !line.contains("SELECT")));
        let mime = b"Content-Transfer-Encoding: base64\r\n\r\n";
        let fetch = format!(
            "* 1 FETCH (UID 9 BODY[2] {{{}}}\r\n{encoded} BODY[2.MIME] {{{mime_len}}}\r\n{mime_text})\r\nA4 OK\r\n",
            encoded.len(),
            mime_len = mime.len(),
            mime_text = std::str::from_utf8(mime).unwrap(),
        );
        let mut io = logged_in(vec![
            ("BODYSTRUCTURE", structure),
            ("BODY.PEEK[2]", &fetch),
        ]);
        let bytes = fetch_attachment(&mut io, "me@qq.com", "auth-SECRET", 9, "2").unwrap();
        assert_eq!(bytes, original);
        assert!(io.seen.iter().all(|line| !line.contains("SELECT") && !line.contains("STORE")));
        assert!(!failure_message(MailFailure::TooLarge).contains("auth-SECRET"));
    }

    #[test]
    fn nested_attachment_part_is_dotted() {
        let structure = "* 1 FETCH (UID 9 BODYSTRUCTURE (((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 1 1 NIL NIL NIL NIL)(\"APPLICATION\" \"PDF\" NIL NIL NIL \"BASE64\" 4 NIL (\"ATTACHMENT\" (\"FILENAME\" \"inner.pdf\")) NIL NIL) \"MIXED\") \"MIXED\"))\r\nA3 OK\r\n";
        let mut io = logged_in(vec![("BODYSTRUCTURE", structure)]);
        let attachments = list_attachments(&mut io, "me@qq.com", "auth-SECRET", 9).unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].part, "1.2");
        assert_eq!(attachments[0].filename, "inner.pdf");
    }

    #[test]
    fn illegal_attachment_parts_are_rejected() {
        for part in ["", "0", "..", "a", "1.02", "01"] {
            let mut io = OwnedIo { steps: Vec::new(), seen: Vec::new() };
            let err = fetch_attachment(&mut io, "me@qq.com", "auth-SECRET", 1, part).unwrap_err();
            assert_eq!(err, MailFailure::Protocol, "{part}");
            assert!(io.seen.is_empty(), "{part}");
        }
    }

    #[test]
    fn attachment_over_20_mib_is_rejected() {
        let structure = "* 1 FETCH (UID 9 BODYSTRUCTURE (\"APPLICATION\" \"PDF\" NIL NIL NIL \"BASE64\" 20971521 NIL (\"ATTACHMENT\" (\"FILENAME\" \"big.pdf\")) NIL NIL))\r\nA3 OK\r\n";
        let mut io = logged_in(vec![("BODYSTRUCTURE", structure)]);
        let err = fetch_attachment(&mut io, "me@qq.com", "auth-SECRET", 9, "1").unwrap_err();
        assert_eq!(failure_message(err), "附件过大，已拒绝下载");
        assert!(!failure_message(err).contains("auth-SECRET"));
        assert!(io.seen.iter().all(|line| !line.contains("BODY.PEEK") && !line.contains("SELECT")));
    }

    #[test]
    fn write_exclusive_refuses_to_replace_or_escape() {
        let dir = std::env::temp_dir().join(format!("sealbox-attach-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("note.pdf");
        let path = dest.to_str().unwrap();
        assert_eq!(write_exclusive(path, b"Hello PDF").unwrap(), 9);
        assert_eq!(std::fs::read(&dest).unwrap(), b"Hello PDF");
        assert_eq!(write_exclusive(path, b"nope").unwrap_err(), "无法保存附件");
        assert_eq!(std::fs::read(&dest).unwrap(), b"Hello PDF");
        let escaped = dir.join("..").join("escaped.bin");
        assert_eq!(write_exclusive(escaped.to_str().unwrap(), b"x").unwrap_err(), "无法保存附件");
        assert_eq!(write_exclusive("note.pdf", b"x").unwrap_err(), "无法保存附件");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
