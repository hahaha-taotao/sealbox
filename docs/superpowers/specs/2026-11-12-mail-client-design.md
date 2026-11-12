# 邮箱客户端补齐 — 设计

日期：2026-11-12
状态：已实现（0.19.0），详见 README 的「邮箱 Mail」
产品：Sealbox（印盒）
对标参考：Sigil 掌玺「邮件」功能（https://sigil.ruoyi.plus/features/mail.html）

## 1. 目标

现有邮箱页只支持 QQ / Gmail 两家、只看收件箱、只读最近 50 封、不改已读、没有搜索和后台收信，手机端则完全没有邮箱页面。本设计把邮箱补成**能日常使用的只读邮件客户端**，并为后续发信打好地基。

前提是 `src-tauri/Cargo.toml` 那个同父进程下遗留的 `cargo check --target x86_64-pc-windows-msvc` 已被清理（它一直持有 cargo 锁，导致测试挂死），本设计不涉及它。

## 2. 已确认决策

| 项 | 选择 |
|---|---|
| 范围 | 方案 A：多账号 + 多文件夹 + 搜索筛选 + 未读 + 后台收信 + 手机端；**不发信** |
| 手机端 | 只读，与桌面现有能力对齐（列表 / 正文 / 附件） |
| 发信 | 本版不做。`smtp` 相关字段保持「存在但不使用」，为下一版留位 |
| MCP | 保持只读能力面，**不新增 `send_mail`**；新增的 action 也全部只读 |
| 收信 | 后台定时拉取，写本地缓存；失败静默，不弹错误通知 |
| 缓存 | 本地 SQLite，存列表元数据和正文；**不存附件字节** |

Sigil 的 18 家预设、自动探测、多账户、五个标准文件夹、筛选、搜索、单封操作、未读徽章、后台自动收信全部纳入。定时发送、签名模板、富文本、导入 Markdown、Outlook OAuth、代发邮件（`send_mail`）**明确不做**。

## 3. 现状缺口

| # | 缺什么 | 代码位置 |
|---|---|---|
| 1 | 账号只有 `qq` / `gmail` | `mail.rs` `endpoint()` 白名单 |
| 2 | `custom` 主机存了但连接层拒绝 | `mail.rs` `connect_tls()` 也写死放行两家 |
| 3 | `mailbox` 类型完全没接（有 imap/smtp 主机+密码） | `commands.rs` `mail_accounts` 只列 `MailAuth` |
| 4 | 只有 `EXAMINE INBOX`，无文件夹 | `mail.rs` `open_inbox()` |
| 5 | 无筛选/搜索，只能「加载更早」翻页 | `App.vue` `loadOlderMail()` |
| 6 | 无未读状态（`MailMessage` 没有 flags） | `mail.rs` `MailMessage` |
| 7 | 无后台收信/通知/未读角标 | 不存在 |
| 8 | 无「测试连接」 | 不存在 |
| 9 | 手机端无邮箱页 | `apps/mobile/src/App.vue` 无 mail 代码 |

已具备、本设计沿用：HTML 沙箱渲染、CID 内嵌图、远程图片按需放开、附件列表与保存、链接转发系统浏览器、正文截断（200KB）、解析器（`Cursor`/`Item`、RFC 2047、multipart、charset）。

## 4. 数据模型

### 4.1 账号来源

邮箱账号有两个来源，统一成一个 `MailAccount` DTO：

- `mail_auth` 类型：`provider` 命中内置预设（qq/163/126/gmail/outlook/yahoo/icloud/sina/sohu/aliyun/139/yeah/ftqq/yandex/mailru/zoho/aol/fastmail）。
- `mailbox` 类型：用户自带的 IMAP 主机 + 密码。`imap_host` 为 `Some` 时就地生效；为 `None` 时按邮箱域名走自动探测。

**IMAP 主机不可能由调用方随便传**：`mail_auth` 的 provider 只能选枚举值，`mailbox` 的主机来自金库条目、且必须是 DNS 可解析的普通主机名。这样保持「不接受 MCP 调用方指定任意主机」的原有安全承诺，同时让自建邮箱能用。

### 4.2 自动探测

按 Sigil 的三级顺序，全部在 Rust 端完成：

1. **内置预设**：18 家硬编码 `(imap_host, imap_port)`，命中即用。
2. **公共配置库**：查 Thunderbird 的 `autoconfig`（`https://autoconfig.thunderbird.net/v1.1/<domain>`），用已有 `ureq`，超时 5 秒，返回 `imap` 的 `hostname/port`。
3. **启发式**：`imap.<domain>` / `mail.<domain>`，交给用户核对。

探测结果**不落盘猜测**，只作为表单预填；用户确认后存入条目。探测失败不阻断保存，留给「测试连接」报错。

### 4.3 文件夹

`MailAccount` 增加 `folders: Vec<MailFolder>`，每次打开账号时用 `LIST` 拿一次：

```rust
pub struct MailFolder {
    pub name: String,      // 服务器原名，如 "Sent Messages"、"[Gmail]/Sent Mail"
    pub role: String,      // 归一角色：inbox/sent/drafts/archive/trash/other
    pub display: String,   // 给界面的中文/原名
}
```

角色对齐规则（按顺序匹配，第一个命中为准）：

| 角色 | 匹配 |
|---|---|
| `inbox` | `INBOX`（大小写不敏感） |
| `sent` | `sent`、`已发送`、`sent messages`、`sent items`、`\[gmail\]/sent mail` |
| `drafts` | `drafts`、`草稿`、`草稿箱`、`\[gmail\]/drafts` |
| `archive` | `archive`、`archives`、`归档`、`全部邮件`、`\[gmail\]/all mail` |
| `trash` | `trash`、`deleted`、`deleted messages`、`已删除`、`垃圾箱`、`\[gmail\]/trash` |

未命中的进 `other`，界面只在「更多文件夹」里展开。QQ 的 "Sent Messages"、163 的「已发送」、Gmail 的 `[Gmail]/Sent Mail` 因此都归到「已发送」，用户看到的始终是这五个名字。

**只读约束不变**：所有文件夹都用 `EXAMINE` 打开，不用 `SELECT`；正文一律 `BODY.PEEK`。已发送/草稿/垃圾箱同样只读，不标已读、不删除、不移动。

### 4.4 消息与标志位

`MailMessage` 增加：

```rust
pub struct MailMessage {
    pub uid: u32,
    pub from: String,
    pub subject: String,
    pub date: String,
    pub has_attachment: bool,
    pub seen: bool,      // \Seen
    pub flagged: bool,   // \Flagged
    pub preview: String, // 正文前 ~120 字，来自缓存的 BODY.PEEK[TEXT] 片段
}
```

`\Seen` / `\Flagged` 通过 `FETCH (UID ENVELOPE BODYSTRUCTURE FLAGS)` 一次取到，不额外往返。

### 4.5 搜索与筛选

`list` 增加参数：`folder`、`filter`（`all` / `unread` / `attached` / `flagged`）、`keyword`。

- 筛选与关键词先落到 **IMAP SEARCH**（`UID SEARCH UNSEEN`、`UID SEARCH FLAGGED`、`UID SEARCH HEADER SUBJECT/FROM "<kw>"`），服务器端过滤后再分页，避免只在本地 50 封里搜。
- 关键词经过 `quote()` 转义，拒绝 CR/LF/NUL。
- 服务器不支持某个 SEARCH 键时降级为本地过滤，并在结果里标注「该服务商不支持服务器搜索，只搜了已加载的邮件」。

## 5. 本地缓存

新增 `crates/sealbox-core/src/mail_store.rs`，用现有 `db.rs` 的迁移机制加三张表（挂在同一个金库 SQLite 上，天然跟着整库加密）：

```sql
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
  subject TEXT NOT NULL,
  from_addr TEXT NOT NULL,
  to_addr TEXT,
  date TEXT NOT NULL,
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
```

要点：

- 正文**按需缓存**：列表只存元数据和 preview；用户点开才取完整正文并回写。后台收信不批量拉正文，避免流量和隐私面放大。
- `uid_validity` 变化（服务器重建文件夹）时**清空该文件夹缓存**再重拉，否则 UID 会错位。
- 账号条目被删时，缓存随 `account_id` 级联清理（在 `delete_entries` 里顺手删）。
- 缓存只读不写远端，不产生任何「标已读」副作用。

## 6. 后台自动收信

- 间隔：关闭 / 1 / 3 / 5 / 10 / 30 分钟，默认 5 分钟。存 `settings` 表（`mail_auto_sync_secs`），与现有 `clipboard_secs` 同一套读写。
- 实现：桌面用已有的窗口/托盘事件循环起一个 `tokio` 任务，逐账号逐文件夹拉**最近一页**（不是全量），写入缓存，比对新增 UID 数。
- 通知：新增 Tauri 官方通知插件（`tauri-plugin-notification`）。
  - 1 封 → 发件人 + 主题；多封 → 总数 + 最多 2 封摘要；应用锁屏时**只报数量**。
  - 单账号失败只写日志和审计，不弹错误通知，不影响其他账号。
- 未读角标：侧栏数字 = 所有账号 `inbox` + `archive` 的 `unseen` 之和。已发送/草稿/垃圾箱不计入（服务器普遍不带已读标记，会挂一个点不掉的底数）。

> Android 端本轮不做后台常驻收信（系统限制多、耗电，且用户选择的是「手机端只读对齐桌面现有能力」），只做前台收信。桌面端才挂后台任务。

## 7. 命令面

### 7.1 桌面 `src-tauri/src/commands.rs` 与移动 `src-tauri-mobile/src/commands.rs`

两端共用同一组签名（移动端可少注册后台相关项）：

| 命令 | 说明 |
|---|---|
| `mail_accounts` | 账号列表，含 `folders`、未读数、是否可用 |
| `mail_folders` | 单账号的文件夹列表（刷新） |
| `mail_list` | 参数：`entryId`、`folder`、`beforeUid`、`filter`、`keyword` |
| `mail_body` | 取正文，命中缓存直接返回 |
| `mail_attachments` | 附件清单 |
| `mail_save_attachment` | 另存附件 |
| `mail_probe` | 按邮箱地址探测 IMAP 主机/端口（不落盘） |
| `mail_test` | 用给定账号实际连一次，返回中文「原因 + 下一步」 |
| `mail_sync` | 后台同步一次，返回各账号新增数（供手动刷新与定时任务共用） |
| `mail_unread_count` | 未读总数，侧栏角标用 |

### 7.2 MCP

`mail` 工具保持只读，action 从 4 个扩到 6 个：

| action | 新增 | 说明 |
|---|---|---|
| `accounts` | | 已存在 |
| `list` | 扩展 | 新增 `folder` / `filter` / `keyword`，读缓存优先 |
| `read` | | 已存在 |
| `save` | | 已存在 |
| `search` | **新增** | 在已同步缓存里按主题/发件人搜 |
| `folders` | **新增** | 列出账号的文件夹与角色 |

`search` 只读本地缓存（与 Sigil 一致，AI 不触发联网收信），`list` 在缓存为空时才联网。**不加 `send_mail`**。

## 8. 界面

### 8.1 桌面

沿用现有侧栏 + 邮箱页，重排为经典三栏：

- **左：账号 + 文件夹**。账号单击切换、右键编辑/设为默认；下面是五个标准文件夹（带未读数）；「全部收件箱」聚合所有账号。
- **中：列表**。顶部筛选条（全部 / 未读 / 带附件 / 星标）+ 搜索框；行内显示发件人、时间、主题、有附件标记、未读加粗。
- **右：正文**。保持现有 HTML 沙箱 + 附件 + 远程图片提示。

未读角标挂在侧栏「邮箱」入口上。

### 8.2 手机端

新增 `apps/mobile` 的邮箱页，页面栈加 `mail`：

- 账号选择（顶部下拉）→ 文件夹 → 列表 → 点开正文（全屏 push）。
- 附件点击走已有 SAF `document_save`。
- 正文渲染复用桌面 `src/lib/mail-html.ts` 的 `buildMailDocument`（手机端已 import 桌面的 `entry-options`，同一路径可行）。

## 9. 错误处理

沿用「固定中文、不含授权码/服务器原文」原则，扩表：

| 情况 | 界面 |
|---|---|
| 探测不到服务器 | 自动探测没找到，请手动填写 IMAP 主机 |
| 授权码错误 / IMAP 未开启 | 登录失败，请检查授权码和 IMAP 是否已开启（**不变**） |
| 超时 | 连接超时，请稍后重试（**不变**） |
| 文件夹不可读 | 这个文件夹打不开，已保留其他文件夹 |
| 服务商不支持服务器搜索 | 该服务商不支持服务器搜索，只搜了已加载的邮件 |
| 缓存为空且离线 | 还没下载过这个文件夹，请联网后重试 |

## 10. 测试

全部用固定 IMAP 响应样本，**不连真实邮箱**：

- 18 家预设映射；`custom` 主机放行、非主机名拒绝
- 探测三级顺序：预设命中 → 配置库 → 启发式；配置库超时降级
- 文件夹角色归一（QQ / 163 / Gmail 三种命名）
- FLAGS 解析出 `\Seen` / `\Flagged`
- SEARCH 键构造与关键词转义，CR/LF 被拒
- 缓存读写、`uid_validity` 变化清空、正文按需回写
- 级联清理：删条目后缓存消失
- 任意错误字符串不包含授权码

界面按原型人工看，不写浏览器自动化。

## 11. 明确不做

- 发信、回复、转发、`send_mail`（含 SMTP 客户端、富文本、签名、定时发送）
- 标已读/未读、加星标回写服务器（只读，本地只显示服务器给的标志）
- 删除、归档、移动到其他文件夹
- Outlook OAuth 授权登录
- Android 后台常驻收信
- 存附件字节或全文索引

这些留给后续规格，不在本版顺手加。
