# Sealbox 印盒

本地凭据金库。主密码（可选 Windows Hello）解锁；网站账号、API Token、SSH、邮箱、服务器和数据库凭据加密存放；复制后定时清空剪贴板；支持 `.svbak` 加密备份。可选本机 MCP，让 Cursor / Claude Code 使用凭据但看不到明文。也提供 Chrome / Edge 填表扩展。

A local credential vault for Windows. Unlock with a master password (optional Windows Hello). Website logins, API tokens, SSH keys, mailboxes, servers, and databases stay encrypted on disk. Copied secrets are cleared from the clipboard on a timer. Encrypted `.svbak` backups can be exported and imported. An optional localhost MCP lets Cursor / Claude Code use credentials without seeing plaintext. A Chrome / Edge extension can fill or save website logins.

> 数据只存本机，不做云同步。  
> Secrets stay on this machine. There is no cloud sync.

设计见 [`docs/superpowers/specs/2026-09-11-local-credential-vault-design.md`](docs/superpowers/specs/2026-09-11-local-credential-vault-design.md).

## 功能 Features

- **保险库 Vault** — 网站账号、API Token、SSH、邮箱、邮箱授权码、服务器、数据库
- **解锁 Unlock** — 主密码为根；可选 Windows Hello 作为第二把钥匙
- **速查 Quick search** — 默认全局热键 `Ctrl+Shift+Space`，回车复制主秘密
- **安全习惯 Hygiene** — 空闲自动锁定、审计日志（不记明文）、回收站、置顶、标签、文件夹
- **备份 Backup** — 加密 `.svbak` 导出 / 导入（默认合并，覆盖需确认）
- **MCP** — 本机 `127.0.0.1` 代理，模型只看到名称；`http_request` 只向凭据绑定的 origin 注入 Authorization，并拒绝内网 / 云元数据
- **插件 Plugin** — Chrome / Edge 按当前网址填充或一键登记；在侧栏「插件」页配对

## 安全模型 Security

| 项 Item | 说明 Notes |
|---|---|
| 存储 Storage | SQLite 金库 `%APPDATA%\com.sealbox.app\vault.db`。不写 `fill.json` |
| 加密 Encryption | Argon2id 派生主密钥，AES-256-GCM 加密条目秘密；MCP / 填表 Token 也用 DEK 加密后写入 settings |
| 列表 List | 列表、搜索、审计、MCP 都不返回密码 / Token / 私钥 |
| 剪贴板 Clipboard | 复制条目秘密、MCP / 填表 Token 和 MCP 配置后约 20 秒，若仍是那条内容则清空；锁定会立刻清掉本应用写入的秘密 |
| 锁定 Lock | 空闲超时、标题栏或托盘锁定都会丢掉 DEK、清已复制秘密、关掉编辑框和明文显示 |
| 备份 Backup | `.svbak` 用导出密码加密；Windows Hello 解不开备份文件 |
| 网络 Network | MCP / 填表只监听 `127.0.0.1`，默认端口 `17891`。`http_request` 只向凭据绑定 origin 注入 Authorization，并拒绝回环 / 内网 / 云元数据 |
| 插件 Extension | 登录页右下角弹出填充条；一站点多账号可点选。`Alt+Shift+F` 也可打开选择器。填充条在 closed Shadow DOM 中，只响应真实用户点击，账号做掩码。提交后询问保存/更新，明文只暂存在 `chrome.storage.session`。扩展仅申请 `127.0.0.1` 主机权限；填表 Token 只放 session，启动时清掉 local 残留 |

## 环境 Requirements

- Windows
- [Rust](https://rustup.rs/)
- [Node.js](https://nodejs.org/)（含 npm）

## 开始使用 Getting started

```bash
npm install
npm run tauri dev
```

首次启动设主密码（至少 10 位）。关闭窗口进入托盘，退出才锁库。全局热键默认 `Ctrl+Shift+Space`。

On first launch, set a master password (at least 10 characters). Closing the window hides it to the tray; quitting the app locks the vault. The default global hotkey is `Ctrl+Shift+Space`.

数据文件 Data file: `%APPDATA%\com.sealbox.app\vault.db`

## MCP

1. 解锁金库 / Unlock the vault.
2. 左侧 **MCP** → **启动**（仅 `127.0.0.1`，默认端口 17891） / Click **MCP** → **Start**.
3. 复制页面上的配置到 Cursor / Claude Code / Paste the snippet into Cursor or Claude Code.

工具 Tools:

- `list_credentials` — 只返回名称、类型、账号，不含秘密 / metadata only, never secrets
- `http_request` — 本机代填 Authorization，仅当目标 origin 与凭据绑定网址/服务一致；拒绝回环、内网、链路本地和云元数据；不跟随重定向。模型永远看不到响应正文（只有状态码、长度、SHA256），不靠扫描金库做脱敏。完整响应只在 MCP 页查看 / Authorization is injected only for the credential’s bound origin; loopback, private, link-local, and cloud-metadata addresses are refused; redirects are not followed. The model never sees the response body (status, length, SHA256 only); vault-wide redaction is not used. The body is only in the MCP page
- `copy_secret` — 复制到本机剪贴板，不把明文返回给模型 / copies to clipboard, not to the model

金库锁定时工具会失败并提示先解锁。Token 可在页面轮换。  
Tools fail while locked. Tokens can be rotated in the MCP page.

## 插件 Plugin（Chrome / Edge）

扩展在仓库 `extension/` 目录。应用启动后会在 `127.0.0.1:17891` 提供填表接口。配对在侧栏 **插件** 页，不和 MCP 混在一起。

The unpacked extension lives in `extension/`. After the app starts, fill APIs listen on `127.0.0.1:17891`. Pairing is on the **Plugin** page, not MCP.

1. 运行并解锁 Sealbox / Run and unlock Sealbox.
2. 打开 `chrome://extensions`（Edge：`edge://extensions`），打开「开发者模式」，加载已解压的扩展，选择 `extension` 文件夹 / Enable Developer mode and load the unpacked `extension` folder.
3. 在 Sealbox 的 **插件** 页点 **配对**，60 秒内把一次性配对码填进扩展 / On the Plugin page click **Pair**, then enter the one-time code in the extension within 60 seconds.
4. 打开登录页：检测到密码框后右下角会出现匹配账号，点选填充；也可按 `Alt+Shift+F`。卡片优先显示账号，过长标题会缩略；有备注时在账号后显示前几个字。打开插件弹窗时，「登记当前站点」会读当前页已填的账号密码，并可填写备注。登录提交后，若该站点还没有这个账号会询问保存；已有同一账号且密码变了会询问更新；密码没变则不弹。 / Open a login page: after a password field is detected, a bottom-right overlay lists matching accounts. `Alt+Shift+F` also opens the chooser. Buttons show the username first, abbreviate long titles, and append a short note when present. Opening the popup copies the page’s current username and password into the save form, with an optional note. After submit, Sealbox asks to save a new login, or update when the same account’s password changed. Unchanged passwords are not prompted.

金库锁定时无法填充或登记。配对码一次性有效；填表 Token 只存在 `chrome.storage.session`（关浏览器即失效），不写入 `chrome.storage.local`；升级后会把旧的 local 残留清掉。与 MCP Token 分开，可单独轮换。读取明文和写入条目都会按当前页面网址复核。提交后采集的账号密码只暂存在会话存储，确认保存才写入金库，拒绝或超时会清掉。填充选择器在 closed Shadow DOM 里，只响应真实用户点击，账号做掩码。扩展只申请访问 `127.0.0.1`。可在弹窗里配置站点排除列表。  
Fill and save require an unlocked vault. Pairing codes are one-shot. The fill token lives only in session storage (cleared when the browser quits) and is never written to `chrome.storage.local`; leftover local copies are deleted on upgrade. It is separate from the MCP token. Secret reveal and save are bound to the current page URL. Captured logins stay in session storage until you confirm save, then they are cleared. The chooser uses a closed Shadow DOM, requires a real user gesture, and masks usernames. The extension only requests host access to `127.0.0.1`. Sites can be excluded in the popup.

匹配规则：按协议、主机和端口匹配（与 Chrome 网页登录相同），路径只用来排序，不挡同站账号。  
Matches require the same scheme, host, and port as Chrome web logins. Path only ranks results.

## 开发 Development

```bash
npm install
npm run tauri dev
```

打包 Build:

```bash
npm run tauri build
```

技术栈 Stack: Tauri 2 + Vue 3 + Rust（AES-256-GCM / Argon2id / rusqlite）。

## 测试 Tests

```bash
cargo test --manifest-path src-tauri/Cargo.toml
node --test extension/fill-logic.test.js
```

## 许可 License

个人本地工具，源码按仓库现状提供。使用前请自行评估风险；请勿把主密码、金库文件或 `.svbak` 备份提交到 Git。

This is a personal local tool. Review the code before relying on it. Never commit the master password, `vault.db`, or `.svbak` backups.
