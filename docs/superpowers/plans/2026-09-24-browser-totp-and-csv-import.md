# Browser TOTP Fill and CSV Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 登录页一次点击即可填入账号、密码和当前 TOTP；解锁后可从浏览器 / Bitwarden / 1Password CSV 预览并导入网站条目。

**Architecture:** TOTP 码只在 Rust `reveal_for_fill` 里生成，经现有 `/fill/secret` 传给扩展，扩展永不拿到 `totp_secret`。CSV 在 Rust 读盘、探测表头、预览脱敏、提交时重读文件后写入 `SecretPayload::Website`。Vue 只拿元数据和计数。

**Tech Stack:** 现有 Tauri 2 + Vue 3 + Rust（`totp_rs`、`rusqlite`）、Chrome MV3 扩展、`node --test`。

**Spec:** `docs/superpowers/specs/2026-09-24-browser-totp-and-import-design.md`

---

## File map

| File | Responsibility |
|---|---|
| Modify `src-tauri/src/totp.rs` | 解析裸 Base32 / `otpauth://totp`，规范化密钥 |
| Modify `src-tauri/src/fill.rs` | match 带 `has_totp`；secret 带当前码；保存可写 totp |
| Create `src-tauri/src/csv_import.rs` | 探测、解析、预览、提交 |
| Modify `src-tauri/src/lib.rs` | `pub mod csv_import`；注册 preview/commit |
| Modify `src-tauri/src/commands.rs` | 两个薄 command |
| Modify `src-tauri/src/vault.rs` | 保存前规范化 totp（走 totp::normalize） |
| Modify `extension/fill-logic.cjs` | 验证码框启发式、pending TOTP TTL |
| Modify `extension/fill-logic.test.js` | 对应单测 |
| Modify `extension/page-fill.js` | 填验证码框；`fill(username, password, totp)` |
| Modify `extension/background.js` | 传 totp、session 暂存、同站补填 |
| Modify `extension/overlay.js` | 「有验证码」标记，不展示码 |
| Modify `src/lib/tauri.ts` | 导入类型与 invoke |
| Modify `src/App.vue` | CSV 导入对话框；TOTP 输入接受 otpauth |
| Modify `README.md` | 填表 TOTP + CSV 导入 |

不要改 MCP、不要读 Chrome `Login Data`、不要把 totp_secret 返回给扩展。

---

### Task 1: 规范化 TOTP 密钥

**Files:**
- Modify: `src-tauri/src/totp.rs`

- [ ] **Step 1: 在 `totp.rs` 测试模块追加失败测试**

在 `src-tauri/src/totp.rs` 的 `mod tests` 末尾追加：

```rust
    #[test]
    fn normalize_accepts_otpauth_and_spaces() {
        let secret = super::normalize_totp_secret(
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        )
        .unwrap();
        assert_eq!(secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(
            super::normalize_totp_secret("jbsw y3dp ehpk 3pxp").unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
        assert!(super::normalize_totp_secret("").is_err());
        assert!(super::normalize_totp_secret(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8"
        )
        .is_err());
        assert!(super::normalize_totp_secret("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
    }

    #[test]
    fn totp_now_accepts_normalized_secret() {
        let secret = super::normalize_totp_secret("JBSWY3DPEHPK3PXP").unwrap();
        let code = super::totp_now(&secret).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
```

- [ ] **Step 2: 跑测试确认失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml totp::tests::normalize_accepts_otpauth_and_spaces --offline
```

Expected: 编译失败，`normalize_totp_secret` 不存在。

- [ ] **Step 3: 实现规范化**

在 `src-tauri/src/totp.rs` 的 `totp_now` 之前插入：

```rust
pub fn normalize_totp_secret(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("TOTP 密钥不能为空".into());
    }
    let secret = if let Some(rest) = trimmed.strip_prefix("otpauth://") {
        parse_otpauth(rest)?
    } else {
        compact_base32(trimmed)?
    };
    Secret::Encoded(secret.clone())
        .to_bytes()
        .map_err(|_| "TOTP 密钥不是有效 Base32".to_string())?;
    Ok(secret)
}

fn parse_otpauth(rest: &str) -> Result<String, String> {
    let (kind, query_src) = rest.split_once('?').ok_or("otpauth URI 缺少参数")?;
    if !kind.to_ascii_lowercase().starts_with("totp/") {
        return Err("只支持 otpauth://totp".into());
    }
    let mut secret = None;
    for pair in query_src.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let key = k.to_ascii_lowercase();
        match key.as_str() {
            "secret" => secret = Some(compact_base32(&urlencoding_decode(v))?),
            "digits" if v != "6" => return Err("只支持 6 位 TOTP".into()),
            "period" if v != "30" => return Err("只支持 30 秒周期".into()),
            "algorithm" if !v.eq_ignore_ascii_case("sha1") => {
                return Err("只支持 SHA1 TOTP".into())
            }
            _ => {}
        }
    }
    secret.ok_or_else(|| "otpauth URI 缺少 secret".into())
}

fn compact_base32(raw: &str) -> Result<String, String> {
    let compact: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if compact.len() < 8 || compact.len() > 128 {
        return Err("TOTP 密钥长度不合法".into());
    }
    if !compact
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | '2'..='7' | '='))
    {
        return Err("TOTP 密钥不是有效 Base32".into());
    }
    Ok(compact)
}

fn urlencoding_decode(value: &str) -> String {
    let mut out = String::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}
```

把 `totp_now` 改成先规范化：

```rust
pub fn totp_now(secret: &str) -> Result<String, String> {
    let secret = normalize_totp_secret(secret)?;
    let secret = Secret::Encoded(secret)
        .to_bytes()
        .map_err(|e| e.to_string())?;
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret, None, "Sealbox".into())
        .map_err(|e| e.to_string())?;
    totp.generate_current().map_err(|e| e.to_string())
}
```

- [ ] **Step 4: 跑测试确认通过**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml totp::tests --offline
```

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/totp.rs
git commit -m "$(cat <<'EOF'
feat(totp): normalize otpauth and Base32 secrets

EOF
)"
```

---

### Task 2: 保存网站条目时规范化 TOTP

**Files:**
- Modify: `src-tauri/src/vault.rs`

- [ ] **Step 1: 在 `vault.rs` 的测试里追加（若该文件无 tests 模块，在文件末尾新建 `#[cfg(test)] mod tests`）**

找到 `upsert_entry` 测试附近或文件末尾，加入：

```rust
    #[test]
    fn upsert_normalizes_website_totp() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let entry = vault
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
                        password: "pw".into(),
                        totp_secret: Some("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP".into()),
                    },
                },
            )
            .unwrap();
        match vault.get_secret(&dek, &entry.id).unwrap() {
            SecretPayload::Website {
                totp_secret: Some(secret),
                ..
            } => assert_eq!(secret, "JBSWY3DPEHPK3PXP"),
            other => panic!("{other:?}"),
        }
        assert!(entry.has_totp);
    }
```

- [ ] **Step 2: 跑测试确认失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml upsert_normalizes_website_totp --offline
```

Expected: FAIL，存进去的仍是整段 otpauth。

- [ ] **Step 3: 在 `upsert_entry` 写库前规范化**

在 `src-tauri/src/vault.rs` 的 `upsert_entry` 里，计算 `has_totp` 之前，对 `input.secret` 做：

```rust
        let mut input = input;
        if let SecretPayload::Website {
            totp_secret: Some(raw),
            ..
        } = &mut input.secret
        {
            if raw.trim().is_empty() {
                *raw = String::new();
            } else {
                *raw = crate::totp::normalize_totp_secret(raw)?;
            }
        }
        if let SecretPayload::Website {
            totp_secret: Some(raw),
            ..
        } = &input.secret
        {
            if raw.is_empty() {
                if let SecretPayload::Website { totp_secret, .. } = &mut input.secret {
                    *totp_secret = None;
                }
            }
        }
```

若 `VaultError` 没有字符串转换，给 `totp` 错误加：

```rust
    #[error("{0}")]
    InvalidTotp(String),
```

并 `map_err(VaultError::InvalidTotp)`。

空字符串 TOTP 视为未配置（`has_totp = false`）。

- [ ] **Step 4: 跑测试确认通过**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml upsert_normalizes_website_totp --offline
```

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/vault.rs
git commit -m "$(cat <<'EOF'
feat(vault): store normalized TOTP secrets

EOF
)"
```

---

### Task 3: `/fill/match` 与 `/fill/secret` 带 TOTP 码

**Files:**
- Modify: `src-tauri/src/fill.rs`

- [ ] **Step 1: 改测试夹具并追加失败测试**

把 `unlocked_github` 里 `totp_secret: None` 改成 `Some("JBSWY3DPEHPK3PXP".into())` 会破坏现有断言。保留原夹具，另加：

```rust
    fn unlocked_github_totp() -> Mutex<Session> {
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
                        totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
                    },
                },
            )
            .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        Mutex::new(session)
    }

    #[test]
    fn match_and_secret_include_totp_code_not_secret() {
        let mutex = unlocked_github_totp();
        let hits = match_websites(&mutex, "https://github.com/login").unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].has_totp);
        let body = format!(
            r#"{{"id":"{}","url":"https://github.com/login"}}"#,
            hits[0].id
        );
        let json = handle_fill_http(&mutex, "/fill/secret", body.as_bytes()).unwrap();
        let entry = &json["entry"];
        assert_eq!(entry["password"], "gh-pass");
        let code = entry["totp"].as_str().unwrap();
        assert_eq!(code.len(), 6);
        assert!(entry["totp_secret"].is_null() || entry.get("totp_secret").is_none());
        let remaining = entry["totp_period_remaining"].as_u64().unwrap();
        assert!(remaining >= 1 && remaining <= 30);
        let dumped = json.to_string();
        assert!(!dumped.contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn secret_without_totp_returns_null_code() {
        let mutex = unlocked_github();
        let hits = match_websites(&mutex, "https://github.com/login").unwrap();
        assert!(!hits[0].has_totp);
        let sec = reveal_for_fill(&mutex, &hits[0].id, "https://github.com/login").unwrap();
        assert!(sec.totp.is_none());
    }
```

- [ ] **Step 2: 跑测试确认失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml fill::tests::match_and_secret_include_totp_code_not_secret --offline
```

Expected: FAIL，`FillMatch` 没有 `has_totp`。

- [ ] **Step 3: 扩展 DTO 与 reveal**

`FillMatch` 增加 `pub has_totp: bool`。

`FillSecret` 改为：

```rust
#[derive(Serialize)]
pub struct FillSecret {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
    pub totp_period_remaining: Option<u8>,
}
```

`match_websites` 填充时 `has_totp: e.has_totp`。

`reveal_for_fill` 中匹配 `SecretPayload::Website` 时：

```rust
    let SecretPayload::Website {
        username,
        password,
        totp_secret,
        ..
    } = payload
    else {
        return Err("not a website entry".into());
    };
    let (totp, totp_period_remaining) = match totp_secret.as_deref() {
        Some(secret) if !secret.is_empty() => {
            let code = crate::totp::totp_now(secret).map_err(|e| e.to_string())?;
            let remaining = 30 - (chrono::Utc::now().timestamp().rem_euclid(30) as u8);
            (Some(code), Some(remaining.max(1)))
        }
        _ => (None, None),
    };
```

返回时带上这两个字段。`save_from_browser_with_notes` 保持不改 totp（更新密码时保留原密钥，现有逻辑已 `totp_secret = t`）。

- [ ] **Step 4: 跑 fill 测试**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml fill::tests --offline
```

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/fill.rs
git commit -m "$(cat <<'EOF'
feat(fill): return current TOTP code to the extension

EOF
)"
```

---

### Task 4: 扩展识别验证码框并填充

**Files:**
- Modify: `extension/fill-logic.cjs`
- Modify: `extension/fill-logic.test.js`
- Modify: `extension/page-fill.js`
- Modify: `extension/background.js`
- Modify: `extension/overlay.js`

- [ ] **Step 1: 写 fill-logic 失败测试**

在 `extension/fill-logic.test.js` 末尾追加：

```javascript
test("isOtpField matches common 2FA inputs and rejects passwords", () => {
  assert.equal(fill.isOtpField({ type: "text", autocomplete: "one-time-code", maxlength: "6" }), true);
  assert.equal(fill.isOtpField({ type: "tel", name: "totp", maxlength: "6" }), true);
  assert.equal(fill.isOtpField({ type: "text", placeholder: "验证码", maxlength: "6" }), true);
  assert.equal(fill.isOtpField({ type: "password", name: "otp" }), false);
  assert.equal(fill.isOtpField({ type: "text", name: "username" }), false);
});

test("pendingTotpPlan expires with remaining seconds", () => {
  const now = 1_000_000;
  assert.deepEqual(fill.pendingTotpPlan({ totp: "123456", totp_period_remaining: 8 }, now), {
    code: "123456",
    expiresAt: now + 8000,
  });
  assert.equal(fill.pendingTotpPlan({ totp: null }, now), null);
  assert.equal(fill.isPendingTotpExpired({ expiresAt: now - 1 }, now), true);
  assert.equal(fill.isPendingTotpExpired({ expiresAt: now + 1000 }, now), false);
});
```

- [ ] **Step 2: 跑测试确认失败**

Run:

```bash
node --test extension/fill-logic.test.js
```

Expected: FAIL，`isOtpField` 未导出。

- [ ] **Step 3: 实现启发式并接到 page-fill / background**

在 `extension/fill-logic.cjs` 的 `api` 对象前加入：

```javascript
  function isOtpField(field) {
    if (!field) return false;
    const type = String(field.type || "").toLowerCase();
    if (type === "password" || type === "hidden" || type === "submit") return false;
    const auto = String(field.autocomplete || "").toLowerCase();
    if (auto === "one-time-code") return true;
    const a = `${field.name || ""} ${field.id || ""} ${field.placeholder || ""} ${field.ariaLabel || ""} ${field.className || ""}`;
    if (!/otp|totp|2fa|mfa|one[-_ ]?time|verification|验证码|动态码|校验码/i.test(a)) return false;
    const max = Number(field.maxlength || field.maxLength || 0);
    return !max || max === 6 || max === 8;
  }

  function pendingTotpPlan(entry, now) {
    const code = String(entry?.totp || "");
    if (!/^\d{6}$/.test(code)) return null;
    const remaining = Math.min(30, Math.max(1, Number(entry.totp_period_remaining) || 30));
    return { code, expiresAt: (now == null ? Date.now() : now) + remaining * 1000 };
  }

  function isPendingTotpExpired(pending, now) {
    if (!pending || !pending.expiresAt) return true;
    return (now == null ? Date.now() : now) >= Number(pending.expiresAt);
  }
```

把这三个函数挂到 `api`。

`page-fill.js`：

- `snapshot` 增加 `maxlength: el.getAttribute?.("maxlength") || el.maxLength || ""`
- `findOtpField`：对 inputs 做 snapshot，用 `Fill.isOtpField` 找第一个 rendered 且非 password 的框
- `fill(username, password, totp)`：先填账号密码；若 `totp` 有值且找到 otp 框则写入，返回 `{ ok: true, filledTotp: Boolean }`

`background.js`：

- `fillFunc` 增加第三参 `totp`，用与 `isOtpField` 相同的正则找框（keep 内联，因 executeScript 不能闭包 fill-logic）
- `applySecretToTab` 把 `entry.totp || ""` 传下去
- `rememberFill` 额外存 `pendingTotp`（用 `Fill.pendingTotpPlan`），并带 `url`/`username`
- 新增 `applyPendingTotpIfNeeded(tab)`：读 session `pendingTotp`，过期则删；同源则 `executeScript` 只填 otp，成功后 `sessionRemove`
- `showOverlayOnTab` 成功后调用 `applyPendingTotpIfNeeded`
- overlay 渲染前给 match 加 `badge: m.has_totp ? "验证码" : ""`，不要加码

`overlay.js` 的按钮若 `m.has_totp` 或 `m.badge`，在 note 旁加灰色小字「验证码」。

- [ ] **Step 4: 跑扩展测试**

Run:

```bash
node --test extension/fill-logic.test.js
```

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add extension/fill-logic.cjs extension/fill-logic.test.js extension/page-fill.js extension/background.js extension/overlay.js
git commit -m "$(cat <<'EOF'
feat(extension): fill TOTP codes on login and 2FA pages

EOF
)"
```

---

### Task 5: CSV 解析与预览（纯 Rust）

**Files:**
- Create: `src-tauri/src/csv_import.rs`
- Modify: `src-tauri/src/lib.rs`

- [ ] **Step 1: 声明模块并写失败测试**

在 `src-tauri/src/lib.rs` 的 `pub mod crypto;` 后插入 `pub mod csv_import;`。

创建 `src-tauri/src/csv_import.rs`，先放测试：

```rust
use crate::vault::{EntryKind, ListFilter, SecretPayload, SortBy, UpsertEntry, Vault};

const MAX_BYTES: usize = 5 * 1024 * 1024;
const MAX_ROWS: usize = 5000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_chrome_and_bitwarden_headers() {
        assert_eq!(
            detect_format("name,url,username,password").unwrap(),
            CsvFormat::Chrome
        );
        assert_eq!(
            detect_format("\u{feff}login_uri,login_username,login_password,login_totp")
                .unwrap(),
            CsvFormat::Bitwarden
        );
        assert_eq!(
            detect_format("Title,Url,Username,Password,OTPAuth").unwrap(),
            CsvFormat::OnePassword
        );
        assert!(detect_format("foo,bar").is_err());
    }

    #[test]
    fn preview_redacts_secrets_and_commit_writes_website() {
        let csv = "name,url,username,password\nGitHub,https://github.com,octocat,s3cret\n";
        let preview = parse_preview(csv.as_bytes()).unwrap();
        assert_eq!(preview.format, "chrome");
        assert_eq!(preview.importable, 1);
        assert_eq!(preview.sample[0].title, "GitHub");
        assert!(preview.sample[0].has_password);
        assert!(!serde_json::to_string(&preview).unwrap().contains("s3cret"));

        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let result = commit_rows(&vault, &dek, csv.as_bytes(), false).unwrap();
        assert_eq!(result.inserted, 1);
        let list = vault
            .list_entries(&ListFilter {
                kind: Some(EntryKind::Website),
                kinds: vec![EntryKind::Website],
                sort: SortBy::Title,
                ..Default::default()
            })
            .unwrap();
        match vault.get_secret(&dek, &list[0].id).unwrap() {
            SecretPayload::Website { password, totp_secret, .. } => {
                assert_eq!(password, "s3cret");
                assert!(totp_secret.is_none());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn commit_skips_existing_unless_overwrite() {
        let csv = "title,url,username,password,totp\nGitHub,https://github.com,octocat,new,JBSWY3DPEHPK3PXP\n";
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
                        password: "old".into(),
                        totp_secret: None,
                    },
                },
            )
            .unwrap();
        let skipped = commit_rows(&vault, &dek, csv.as_bytes(), false).unwrap();
        assert_eq!(skipped.inserted, 0);
        assert_eq!(skipped.skipped_existing, 1);
        let overwritten = commit_rows(&vault, &dek, csv.as_bytes(), true).unwrap();
        assert_eq!(overwritten.updated, 1);
        let id = vault
            .list_entries(&ListFilter {
                kind: Some(EntryKind::Website),
                ..Default::default()
            })
            .unwrap()[0]
            .id
            .clone();
        match vault.get_secret(&dek, &id).unwrap() {
            SecretPayload::Website {
                password,
                totp_secret: Some(t),
                ..
            } => {
                assert_eq!(password, "new");
                assert_eq!(t, "JBSWY3DPEHPK3PXP");
            }
            other => panic!("{other:?}"),
        }
    }
}
```

- [ ] **Step 2: 跑测试确认失败**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml csv_import --offline
```

Expected: 编译失败。

- [ ] **Step 3: 实现解析器**

同一文件补全（CSV 用简单状态机，支持引号与 `""` 转义，不引依赖）：

```rust
use serde::Serialize;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsvFormat {
    Chrome,
    Bitwarden,
    OnePassword,
    Sealbox,
}

impl CsvFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Bitwarden => "bitwarden",
            Self::OnePassword => "onepassword",
            Self::Sealbox => "sealbox",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CsvImportSample {
    pub title: String,
    pub url: String,
    pub username: String,
    pub has_password: bool,
    pub has_totp: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CsvImportPreview {
    pub format: String,
    pub total: usize,
    pub importable: usize,
    pub skipped_existing: usize,
    pub skipped_invalid: usize,
    pub sample: Vec<CsvImportSample>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CsvImportResult {
    pub format: String,
    pub inserted: usize,
    pub updated: usize,
    pub skipped_existing: usize,
    pub skipped_invalid: usize,
}

struct CsvRow {
    title: String,
    url: String,
    username: String,
    password: String,
    totp: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
}

pub fn detect_format(header_line: &str) -> Result<CsvFormat, String> {
    let header = header_line.trim_start_matches('\u{feff}').to_ascii_lowercase();
    let names = parse_csv_line(&header);
    let has = |n: &str| names.iter().any(|c| c == n);
    if has("login_uri") && has("login_username") && has("login_password") {
        return Ok(CsvFormat::Bitwarden);
    }
    if has("otpauth") && has("title") && has("url") && has("username") {
        return Ok(CsvFormat::OnePassword);
    }
    if has("name") && has("url") && has("username") && has("password") {
        return Ok(CsvFormat::Chrome);
    }
    if has("title") && has("url") && has("username") && has("password") {
        return Ok(CsvFormat::Sealbox);
    }
    Err("无法识别的 CSV 表头".into())
}
```

实现要点：

- `parse_csv_line` / `parse_csv`：逗号分隔，`"` 引用，`""` 转义，`\n` / `\r\n` 分行。
- `map_row(format, headers, fields)`：按列名取值。Bitwarden 若有 `type` 且不是 `login`（大小写不敏感）则跳过。Chrome 的 `name` → title。1Password 的 `OTPAuth` → totp。
- 无 url 或不含 `.` 的跳过。无 password 且 totp 空的跳过。超长字段跳过。
- `parse_preview(bytes)`：检查 `MAX_BYTES`；解析；`sample` 最多 20 条；`skipped_existing` 在无 vault 时为 0。
- `commit_rows(vault, dek, bytes, overwrite)`：解析后对每行 `origin+username` 在现有 website 列表里匹配（复用 `crate::fill` 的 origin 比较：可把 `origin_of` 改成 `pub(crate)`）。匹配到且 `!overwrite` → skipped_existing；匹配到且 overwrite → `upsert_entry` 带原 id，保留 notes 若 CSV notes 为空。新建用 title 或 host。totp 走 vault 规范化。
- 预览 struct 用 `Serialize`，密码字段根本不要出现。

把 `fill.rs` 的 `origin_of` 改为 `pub(crate) fn origin_of`。

- [ ] **Step 4: 跑测试**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml csv_import --offline
```

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/csv_import.rs src-tauri/src/lib.rs src-tauri/src/fill.rs
git commit -m "$(cat <<'EOF'
feat(import): parse Chrome Bitwarden and 1Password CSV

EOF
)"
```

---

### Task 6: Tauri 命令与保险库入口

**Files:**
- Modify: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src/lib/tauri.ts`
- Modify: `src/App.vue`
- Modify: `README.md`

- [ ] **Step 1: 命令 + 前端类型**

`commands.rs` 增加：

```rust
#[tauri::command]
pub fn import_csv_preview(
    state: State<AppState>,
    path: String,
) -> Result<crate::csv_import::CsvImportPreview, String> {
    let session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let dek = session.dek().map_err(map_err)?;
    crate::csv_import::preview_file(vault, dek, &path).map_err(map_err)
}

#[tauri::command]
pub fn import_csv_commit(
    state: State<AppState>,
    path: String,
    overwrite: bool,
) -> Result<crate::csv_import::CsvImportResult, String> {
    let session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let dek = *session.dek().map_err(map_err)?;
    let result = crate::csv_import::commit_file(vault, &dek, &path, overwrite).map_err(map_err)?;
    let _ = vault.audit(
        "import_csv",
        None,
        &format!(
            "format={} inserted={} updated={} skipped={} overwrite={}",
            result.format, result.inserted, result.updated, result.skipped_existing, overwrite
        ),
    );
    Ok(result)
}
```

`preview_file` / `commit_file` 读 `std::fs::read`，检查大小后调用 Task 5 的解析。路径必须是绝对路径，拒绝 `..`。

`lib.rs` 的 `generate_handler!` 加上这两个命令。

`tauri.ts`：

```typescript
export interface CsvImportSample {
  title: string;
  url: string;
  username: string;
  has_password: boolean;
  has_totp: boolean;
}
export interface CsvImportPreview {
  format: string;
  total: number;
  importable: number;
  skipped_existing: number;
  skipped_invalid: number;
  sample: CsvImportSample[];
}
export interface CsvImportResult {
  format: string;
  inserted: number;
  updated: number;
  skipped_existing: number;
  skipped_invalid: number;
}
```

`api.importCsvPreview(path)` / `api.importCsvCommit(path, overwrite)`。

- [ ] **Step 2: 保险库 UI**

`App.vue` 侧栏「备份 / 还原」下增加按钮「从 CSV 导入」，打开对话框：选 `.csv` 文件 → 调 preview → 展示 format、计数、最多 20 行元数据表格 → 勾选「覆盖已有同站同账号」→ 确认提交。成功 toast：`导入 n 条，跳过 m 条`。错误展示 Rust 返回文案。

网站表单 TOTP 输入的 placeholder 改为 `Base32 或 otpauth://totp/...`。

- [ ] **Step 3: README**

「插件」节补一句：有 TOTP 的条目会在登录页或下一页验证码框填入当前 6 位码，扩展拿不到密钥。

「功能」或备份节补：可从 Chrome / Edge / Bitwarden / 1Password 导出的 UTF-8 CSV 导入网站账号，默认跳过已有同站同账号。

- [ ] **Step 4: 全量测试**

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml --offline
node --test extension/fill-logic.test.js
```

Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/commands.rs src-tauri/src/lib.rs src-tauri/src/csv_import.rs src/lib/tauri.ts src/App.vue README.md
git commit -m "$(cat <<'EOF'
feat(import): add vault CSV import with redacted preview

EOF
)"
```

---

## 验收

- 手工：给 github.com 条目贴 otpauth，扩展在 github.com/login 点填充，密码框有密码；若页面有 6 位框则同时填入。
- 手工：从 Chrome 导出 CSV，预览无密码列，导入后能填充。
- 回归：无 TOTP 的旧条目填充行为不变。
