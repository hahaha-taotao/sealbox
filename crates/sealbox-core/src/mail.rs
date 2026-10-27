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
}
