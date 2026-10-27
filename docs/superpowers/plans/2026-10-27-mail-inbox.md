# 只读邮箱收件箱 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 删除内置助手，并用金库里的 QQ / Gmail 授权码只读打开收件箱：最近 50 封列表，点开再取纯文本正文。

**Architecture:** 解析、主机映射和 IMAP 会话放在 `crates/sealbox-core/src/mail.rs`，因为 Android 不链接桌面 crate，而 `sealbox-core` 已依赖 rustls 0.23。桌面和移动的 Tauri 命令只负责解锁、读取授权码、审计和调用这个模块。每次命令单独连接，用完断开。不写邮件库，不下载附件，不用 `SELECT`。

**Tech Stack:** Rust、rustls 0.23、Tauri 2 同步命令、Vue 3、现有 `sealbox-core` 金库。

规格：`docs/superpowers/specs/2026-10-27-mail-inbox-design.md`。规格里的路径 `src-tauri/src/mail.rs` 改到共享 crate，原因是两端必须共用同一实现。

---

### Task 1: 删除桌面助手后端

**Files:**
- Delete: `src-tauri/src/assistant.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/commands.rs`

- [ ] **Step 1: 去掉模块和命令注册**

在 `src-tauri/src/lib.rs` 删除 `pub mod assistant;`。

在 `generate_handler![]` 删除这四行：

```rust
commands::assistant_config_get,
commands::assistant_config_set,
commands::assistant_mcp_probe,
commands::assistant_chat,
```

- [ ] **Step 2: 删除命令实现**

在 `src-tauri/src/commands.rs` 删除 `use crate::assistant;`，以及 `assistant_config_get`、`assistant_config_set`、`assistant_mcp_probe`、`assistant_chat` 四个函数。删除 `src-tauri/src/assistant.rs`。

- [ ] **Step 3: 确认桌面 crate 能编译**

Run: `cargo check --manifest-path src-tauri/Cargo.toml`

Expected: 成功，且输出里没有 `assistant` 未定义错误。

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/lib.rs src-tauri/src/commands.rs src-tauri/src/assistant.rs
git commit -m "删除内置助手后端"
```

### Task 2: 删除助手界面和 README

**Files:**
- Modify: `src/lib/tauri.ts`
- Modify: `src/App.vue`
- Modify: `README.md`

- [ ] **Step 1: 删除前端 API**

在 `src/lib/tauri.ts` 删除 `AssistantConfigView`、`AssistantConfigInput`、`AssistantToolSummary`、`AssistantMcpProbe`、`AssistantMessage`、`AssistantToolTrace`、`AssistantChatResponse`，以及 `api` 对象末尾的 `assistantConfigGet`、`assistantConfigSet`、`assistantMcpProbe`、`assistantChat`。

- [ ] **Step 2: 删除页面**

在 `src/App.vue`：

- `Page` 类型去掉 `"assistant"`。
- 删除 `assistantConfig` 到 `assistantTraces` 的 ref，以及 `refreshAssistantConfig`、`openAssistant`、`saveAssistantConfig`、`probeAssistantMcp`、`clearAssistantChat`、`sendAssistantMessage`。
- 锁定清理处删除对 `assistantApiKey`、`assistantInput`、`assistantMessages`、`assistantTraces`、`assistantMcp`、`assistantError` 的赋值。
- 删除侧栏「助手」按钮和 `page === 'assistant'` 的整段 `<section>`。
- 标题函数里删除 `if (page.value === "assistant") return "助手";`。

- [ ] **Step 3: 改 README**

删除功能列表中的「助手 Assistant」那一条。

把 MCP 段这句：

```markdown
侧栏助手只调用只读低风险工具。Token 不会返回给模型。
```

改成：

```markdown
Token 不会返回给模型。
```

删除整个 `## 助手 Assistant` 小节，直到 `## 插件 Plugin` 之前。不要改 `docs/superpowers/` 里的旧规格。

- [ ] **Step 4: 类型检查**

Run: `npx vue-tsc --noEmit`

Expected: 成功，且没有 `assistant` 标识符残留报错。

- [ ] **Step 5: Commit**

```bash
git add src/lib/tauri.ts src/App.vue README.md
git commit -m "删除内置助手页面和说明"
```

### Task 3: 主机、UID 窗口、错误文案、HTML 转文本

**Files:**
- Create: `crates/sealbox-core/src/mail.rs`
- Modify: `crates/sealbox-core/src/lib.rs`
- Test: `crates/sealbox-core/src/mail.rs` 模块内测试

- [ ] **Step 1: 写失败测试**

在 `crates/sealbox-core/src/lib.rs` 加 `pub mod mail;`。新建 `mail.rs`，只放下面的测试：

```rust
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
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test --manifest-path crates/sealbox-core/Cargo.toml mail::tests -- --test-threads=1`

Expected: FAIL，`endpoint` 等函数不存在。

- [ ] **Step 3: 最小实现**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailFailure {
    Login,
    Timeout,
    EmptyText,
    Protocol,
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
        MailFailure::Timeout => "连接超时，请稍后重试",
        MailFailure::EmptyText => "这封邮件没有可显示的文本",
        MailFailure::Protocol => "连接超时，请稍后重试",
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
            let name = tag.trim().trim_start_matches('/').split_whitespace().next().unwrap_or("");
            let name = name.trim_start_matches('/').to_ascii_lowercase();
            if name == "script" || name == "style" {
                skipping = !tag.starts_with('/');
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
                if next == ';' || entity.len() > 8 {
                    break;
                }
                entity.push(next);
                chars.next();
            }
            if chars.peek() == Some(&';') {
                chars.next();
            }
            out.push(match entity.as_str() {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "nbsp" => ' ',
                "quot" => '"',
                _ => ' ',
            });
            continue;
        }
        out.push(ch);
    }
    out.lines().map(str::trim).filter(|line| !line.is_empty()).collect::<Vec<_>>().join("\n")
}
```

`MailFailure::Protocol` 对界面使用和超时相同的句子，避免把服务器原文交出去。

- [ ] **Step 4: 测试通过**

Run: `cargo test --manifest-path crates/sealbox-core/Cargo.toml mail::tests -- --test-threads=1`

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add crates/sealbox-core/src/lib.rs crates/sealbox-core/src/mail.rs
git commit -m "添加邮箱主机映射和正文清洗"
```

### Task 4: 解析 SEARCH 和 FETCH

**Files:**
- Modify: `crates/sealbox-core/src/mail.rs`
- Test: 同文件

- [ ] **Step 1: 写失败测试**

```rust
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
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test --manifest-path crates/sealbox-core/Cargo.toml mail::tests::search_response -- --test-threads=1`

Expected: FAIL，`parse_search` 不存在。

- [ ] **Step 3: 实现解析**

公开结构：

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailMessage {
    pub uid: u32,
    pub from: String,
    pub subject: String,
    pub date: String,
    pub has_attachment: bool,
}
```

`parse_search` 只接受包含 `* SEARCH` 且最后完成行以 ` OK ` 结尾的响应。UID 按出现顺序收集。`NO` 或 `BAD` 返回 `MailFailure::Login`。

`parse_fetch` 用一个 IMAP 列表解析器读取每个 `FETCH (` 后的列表。规则：

- 原子是非空白、非括号的连续字符，或双引号字符串。
- `NIL` 是空。
- 括号是子列表。
- 遇到 `{n}` 字面量时，向后读取恰好 n 个字节，再继续。测试夹具可以不使用字面量。
- `UID` 后的数字是 uid。
- `ENVELOPE` 后的列表按 RFC 3501 顺序：日期、主题、from。地址是 `(display NIL mailbox host)`。有 display 且不是 `NIL` 时格式为 `display <mailbox@host>`，否则 `mailbox@host`。
- 主题用 RFC 2047 的 `=?UTF-8?B?...?=` 和 `=?UTF-8?Q?...?=`。Q 编码把 `_` 当空格。无法解码时保留原始主题。
- `BODYSTRUCTURE` 里若某个媒体类型是 `APPLICATION`、`IMAGE`、`AUDIO` 或 `VIDEO`，`has_attachment` 为 true。只有 `TEXT` 和 `MULTIPART` 时为 false。

解析失败返回 `MailFailure::Protocol`，不要把原始响应放进错误。

- [ ] **Step 4: 测试通过**

Run: `cargo test --manifest-path crates/sealbox-core/Cargo.toml mail::tests -- --test-threads=1`

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add crates/sealbox-core/src/mail.rs
git commit -m "解析 IMAP 收件箱列表"
```

### Task 5: 用脚本化 IO 完成登录、列表和正文

**Files:**
- Modify: `crates/sealbox-core/src/mail.rs`
- Test: 同文件

- [ ] **Step 1: 写失败测试**

```rust
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
    assert_eq!(page.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![2, 3]);
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
    let mut io = ScriptIo { steps: vec![("LOGIN", "A1 NO [AUTHENTICATIONFAILED]\r\n")], seen: vec![] };
    let err = list_inbox(&mut io, "me@qq.com", "auth-SECRET", None, 50).unwrap_err();
    assert_eq!(failure_message(err), "登录失败，请检查授权码和 IMAP 是否已开启");
    assert!(!failure_message(err).contains("auth-SECRET"));
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test --manifest-path crates/sealbox-core/Cargo.toml mail::tests::list_examines_inbox -- --test-threads=1`

Expected: FAIL，`ImapIo` 不存在。

- [ ] **Step 3: 实现会话**

```rust
pub struct MailBody {
    pub text: String,
    pub truncated: bool,
}

pub trait ImapIo {
    fn transact(&mut self, command: &str) -> Result<String, MailFailure>;
}

fn quote_imap(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        if ch == '\\' || ch == '"' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}
```

`list_inbox` 顺序发送：

1. `A1 LOGIN {quoted email} {quoted auth}`
2. `A2 EXAMINE INBOX`
3. `A3 UID SEARCH ALL`
4. 用 `recent_uids(..., before, limit)` 选出 UID。空列表直接返回空 Vec，不再 FETCH。
5. `A4 UID FETCH {uid,uid} (UID ENVELOPE BODYSTRUCTURE)`

完成行含 ` NO ` 或 ` BAD ` 时：LOGIN 返回 `MailFailure::Login`，其他返回 `MailFailure::Protocol`。

`fetch_body` 同样 LOGIN 和 EXAMINE，然后 `A3 UID FETCH {uid} (BODY.PEEK[])`。从字面量里取 header 和 body。`Content-Type` 含 `text/html` 时走 `html_to_text`，否则用正文原文。结果为空返回 `MailFailure::EmptyText`。UTF-8 字节超过 200 * 1024 时截断到该边界以内的合法字符，`truncated = true`。

命令标签只使用 `A1` 到 `A4`。不要在 `Debug` 或错误里保留授权码。

- [ ] **Step 4: 测试通过**

Run: `cargo test --manifest-path crates/sealbox-core/Cargo.toml mail::tests -- --test-threads=1`

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add crates/sealbox-core/src/mail.rs
git commit -m "用只读 IMAP 会话列出邮件并取正文"
```

### Task 6: TCP 读写和 rustls 连接

**Files:**
- Modify: `crates/sealbox-core/src/mail.rs`
- Test: 同文件

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn tcp_roundtrip_reads_a_tagged_ok() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
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
        let (socket, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(500));
        drop(socket);
    });
    let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let err = transact_stream(&mut client, "A2 EXAMINE INBOX", Duration::from_millis(200)).unwrap_err();
    assert_eq!(failure_message(err), "连接超时，请稍后重试");
    server.join().unwrap();
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cargo test --manifest-path crates/sealbox-core/Cargo.toml mail::tests::tcp_roundtrip -- --test-threads=1`

Expected: FAIL，`transact_stream` 不存在。

- [ ] **Step 3: 实现字节层**

`transact_stream(stream, command, timeout)`：

- 设置读写超时。
- 写出 `command + "\r\n"`。
- 读到以该命令标签加 ` OK`、` NO` 或 ` BAD` 结尾的行。
- 识别 `{n}` 字面量并继续读满 n 个字节。
- 超时返回 `MailFailure::Timeout`。

`connect_tls(host, port, timeout)` 使用 `sealbox-core` 已有的 rustls 0.23 `ClientConfig`，安装 webpki 根证书，服务器名必须等于 `endpoint()` 返回的主机。不要提供传入任意主机的公开函数。生产超时 20 秒。这个函数不在单元测试里连真实邮箱。

`TlsImap` 实现 `ImapIo`，内部调用 `transact_stream`。

- [ ] **Step 4: 测试通过**

Run: `cargo test --manifest-path crates/sealbox-core/Cargo.toml mail::tests -- --test-threads=1`

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add crates/sealbox-core/src/mail.rs
git commit -m "连接 IMAP 时使用固定主机和读写超时"
```

### Task 7: 桌面命令

**Files:**
- Modify: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/lib.rs`

- [ ] **Step 1: 增加三个命令**

```rust
#[derive(serde::Deserialize)]
pub struct MailListRequest {
    pub entry_id: String,
    pub before_uid: Option<u32>,
}

#[derive(serde::Deserialize)]
pub struct MailBodyRequest {
    pub entry_id: String,
    pub uid: u32,
}

fn load_mail_auth(state: &AppState, id: &str) -> Result<(String, String, String), String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let payload = session
        .vault()
        .map_err(map_err)?
        .get_active_secret(&dek, id)
        .map_err(map_err)?;
    match payload {
        SecretPayload::MailAuth { email, provider, auth_code } => Ok((email, provider, auth_code)),
        _ => Err("不是邮箱授权码".into()),
    }
}

#[tauri::command]
pub fn mail_accounts(state: State<AppState>) -> Result<Vec<sealbox_core::mail::MailAccount>, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let filter = ListFilter { kind: Some(EntryKind::MailAuth), ..ListFilter::default() };
    let entries = vault.list_entries(&filter).map_err(map_err)?;
    entries
        .into_iter()
        .map(|entry| {
            let payload = vault.get_active_secret(&dek, &entry.id).map_err(map_err)?;
            let SecretPayload::MailAuth { email, provider, .. } = payload else {
                return Err("不是邮箱授权码".into());
            };
            Ok(sealbox_core::mail::MailAccount {
                id: entry.id,
                title: entry.title,
                email,
                provider: provider.clone(),
                supported: sealbox_core::mail::endpoint(&provider).is_some(),
            })
        })
        .collect()
}

#[tauri::command]
pub fn mail_list(
    state: State<AppState>,
    request: MailListRequest,
) -> Result<Vec<sealbox_core::mail::MailMessage>, String> {
    let (email, provider, auth_code) = load_mail_auth(&state, &request.entry_id)?;
    let Some((host, port)) = sealbox_core::mail::endpoint(&provider) else {
        return Err(sealbox_core::mail::failure_message(sealbox_core::mail::MailFailure::Unsupported).into());
    };
    let mut io = sealbox_core::mail::connect_tls(host, port, std::time::Duration::from_secs(20))
        .map_err(sealbox_core::mail::failure_message)?;
    let messages = sealbox_core::mail::list_inbox(&mut io, &email, &auth_code, request.before_uid, 50)
        .map_err(sealbox_core::mail::failure_message)?;
    drop(auth_code);
    let mut session = lock_session(&state.session);
    session.vault().map_err(map_err)?.audit("mail_list", Some(&request.entry_id), "").map_err(map_err)?;
    Ok(messages)
}

#[tauri::command]
pub fn mail_body(
    state: State<AppState>,
    request: MailBodyRequest,
) -> Result<sealbox_core::mail::MailBody, String> {
    let (email, provider, auth_code) = load_mail_auth(&state, &request.entry_id)?;
    let Some((host, port)) = sealbox_core::mail::endpoint(&provider) else {
        return Err(sealbox_core::mail::failure_message(sealbox_core::mail::MailFailure::Unsupported).into());
    };
    let mut io = sealbox_core::mail::connect_tls(host, port, std::time::Duration::from_secs(20))
        .map_err(sealbox_core::mail::failure_message)?;
    let body = sealbox_core::mail::fetch_body(&mut io, &email, &auth_code, request.uid)
        .map_err(sealbox_core::mail::failure_message)?;
    drop(auth_code);
    let mut session = lock_session(&state.session);
    session.vault().map_err(map_err)?.audit("mail_body", Some(&request.entry_id), "").map_err(map_err)?;
    Ok(body)
}
```

`MailAccount` 在 `mail.rs` 定义为：

```rust
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailAccount {
    pub id: String,
    pub title: String,
    pub email: String,
    pub provider: String,
    pub supported: bool,
}
```

`MailMessage` 和 `MailBody` 同样加 `#[serde(rename_all = "camelCase")]`。`MailFailure` 增加 `Unsupported`，`failure_message` 返回「首版不支持」。`map_err(failure_message)` 要求 `connect_tls`、`list_inbox` 和 `fetch_body` 的错误类型就是 `MailFailure`。

`mail_accounts` 不写审计，也不返回 `auth_code`。网络调用发生在会话锁释放之后。

在 `src-tauri/src/lib.rs` 的 `generate_handler![]` 注册这三个命令。

- [ ] **Step 2: 编译**

Run: `cargo check --manifest-path src-tauri/Cargo.toml`

Expected: 成功。

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/commands.rs src-tauri/src/lib.rs crates/sealbox-core/src/mail.rs
git commit -m "桌面端增加只读邮箱命令"
```

### Task 8: Android 命令

**Files:**
- Modify: `src-tauri-mobile/src/commands.rs`
- Modify: `src-tauri-mobile/src/lib.rs`

- [ ] **Step 1: 注册相同命令**

把 Task 7 的三个命令以同样的函数名、参数名和返回类型加到移动端 `commands.rs`。使用移动端已有的 `State<AppState>`、`lock_session` 和 `map_err`。在 `src-tauri-mobile/src/lib.rs` 的 `generate_handler![]` 注册 `mail_accounts`、`mail_list`、`mail_body`。

不要把助手命令加到移动端。移动端本来没有助手。

- [ ] **Step 2: 编译**

Run: `cargo check --manifest-path src-tauri-mobile/Cargo.toml`

Expected: 成功。

- [ ] **Step 3: Commit**

```bash
git add src-tauri-mobile/src/commands.rs src-tauri-mobile/src/lib.rs
git commit -m "Android 增加只读邮箱命令"
```

### Task 9: 邮箱页

**Files:**
- Modify: `src/lib/tauri.ts`
- Modify: `src/App.vue`
- Modify: `src/styles.css`
- Modify: `README.md`

- [ ] **Step 1: 前端类型和 API**

在 `src/lib/tauri.ts` 增加：

```typescript
export interface MailAccount {
  id: string;
  title: string;
  email: string;
  provider: string;
  supported: boolean;
}

export interface MailMessage {
  uid: number;
  from: string;
  subject: string;
  date: string;
  hasAttachment: boolean;
}

export interface MailBody {
  text: string;
  truncated: boolean;
}
```

Tauri 返回 serde 的 snake_case 还是 camelCase 必须和结构体的 serde 重命名一致。在 Rust 结构体上使用 `#[serde(rename_all = "camelCase")]`，使 `has_attachment` 变成 `hasAttachment`，`before_uid` 请求仍由命令参数的 serde 默认接受前端传入的 `beforeUid`。请求结构体也加 `#[serde(rename_all = "camelCase")]`。

`api` 增加：

```typescript
mailAccounts: () => invoke<MailAccount[]>("mail_accounts"),
mailList: (request: { entryId: string; beforeUid?: number | null }) =>
  invoke<MailMessage[]>("mail_list", { request }),
mailBody: (request: { entryId: string; uid: number }) =>
  invoke<MailBody>("mail_body", { request }),
```

- [ ] **Step 2: 页面状态**

`Page` 增加 `"mail"`。侧栏在「插件」和弹性空白之间放「邮箱」按钮，选中时 `page === 'mail'`。点击调用 `openMail()`：`goPage("mail")`，然后 `mailAccounts()`。

状态：

```typescript
const mailAccounts = ref<MailAccount[]>([]);
const mailAccountId = ref("");
const mailMessages = ref<MailMessage[]>([]);
const mailBody = ref<MailBody | null>(null);
const mailBusy = ref(false);
const mailError = ref("");
const mailSelectedUid = ref<number | null>(null);
```

`loadMailList(beforeUid)` 调用 `mailList`。失败时保留当前列表和正文，只把 `mailError` 设为命令返回的字符串。没有 `beforeUid` 且成功时替换列表并清空正文；有 `beforeUid` 且成功时把返回追加到现有列表。`openMailMessage(uid)` 调用 `mailBody`。切换账号时清空正文和选中 UID。不支持的账号按钮 `disabled`。列表为空显示「收件箱是空的」。`truncated` 为 true 时在正文末尾加一行「正文已截断」。底部按钮在 `mailBusy` 或最后一次返回少于 50 封时禁用，文案分别为「加载中…」和「没有更早的信」，否则「加载更早」。

布局按 `docs/prototypes/mail-inbox.png`：左账号、中列表、右正文。窄屏用 CSS 改成纵向。不要加写信、删除、标已读或下载附件。

锁定时清空上述 ref。

- [ ] **Step 3: README**

在功能列表用下面这一条替换已经删掉的助手条目：

```markdown
- **邮箱 Mail** — 侧栏「插件」下方。用 QQ 或 Gmail 授权码只读打开收件箱，最近 50 封，点开看纯文本。不下载附件，不把邮件写入金库
```

- [ ] **Step 4: 类型检查**

Run: `npx vue-tsc --noEmit`

Expected: 成功。

- [ ] **Step 5: Commit**

```bash
git add src/lib/tauri.ts src/App.vue src/styles.css README.md
git commit -m "增加只读邮箱页面"
```

### Task 10: 总验证

- [ ] **Step 1: 跑共享库测试和两端编译**

Run:

```bash
cargo test --manifest-path crates/sealbox-core/Cargo.toml mail::
cargo check --manifest-path src-tauri/Cargo.toml
cargo check --manifest-path src-tauri-mobile/Cargo.toml
npx vue-tsc --noEmit
```

Expected: 全部成功。

- [ ] **Step 2: 搜残留**

Run: `rg -n "assistant_chat|openAssistant|page === 'assistant'" src src-tauri src-tauri-mobile README.md`

Expected: 无匹配。`docs/superpowers/` 里的历史文档可以继续提到助手。

- [ ] **Step 3: 人工看页面**

桌面 `npm run dev`，解锁后打开「邮箱」。不支持的授权码是灰色。QQ 或 Gmail 能列出收件箱；点一封只看到纯文本；有附件只显示标记。不需要在自动测试里连真实邮箱。
