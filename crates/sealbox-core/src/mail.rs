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
}
