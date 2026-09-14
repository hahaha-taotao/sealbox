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
- **MCP** — 本机 `127.0.0.1` 代理，模型只看到名称，HTTP 由本机代签并脱敏
- **浏览器插件 Extension** — Chrome / Edge 按当前网址填充或一键登记

## 安全模型 Security

| 项 Item | 说明 Notes |
|---|---|
| 存储 Storage | SQLite 金库 `%APPDATA%\com.sealbox.app\vault.db` |
| 加密 Encryption | Argon2id 派生主密钥，AES-256-GCM 加密条目秘密 |
| 列表 List | 列表、搜索、审计、MCP 都不返回密码 / Token / 私钥 |
| 剪贴板 Clipboard | 复制后约 20 秒，若仍是那条秘密则清空 |
| 锁定 Lock | 空闲超时或手动锁定后，复制和显示都须重新解锁 |
| 备份 Backup | `.svbak` 用导出密码加密；Windows Hello 解不开备份文件 |
| 网络 Network | MCP / 填表只监听 `127.0.0.1`，默认端口 `17891` |

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
- `http_request` — 本机代填 Authorization，响应脱敏 / local signed request, redacted response
- `copy_secret` — 复制到本机剪贴板，不把明文返回给模型 / copies to clipboard, not to the model

金库锁定时工具会失败并提示先解锁。Token 可在页面轮换。  
Tools fail while locked. Tokens can be rotated in the MCP page.

## 浏览器插件 Browser extension（Chrome / Edge）

扩展在仓库 `extension/` 目录。应用启动后会在 `127.0.0.1:17891` 提供填表接口。

The unpacked extension lives in `extension/`. After the app starts, fill APIs listen on `127.0.0.1:17891`.

1. 运行并解锁 Sealbox / Run and unlock Sealbox.
2. 打开 `chrome://extensions`（Edge：`edge://extensions`），打开「开发者模式」，加载已解压的扩展，选择 `extension` 文件夹 / Enable Developer mode and load the unpacked `extension` folder.
3. 解锁金库后打开插件，会自动连接本机，不必填写 Token / The extension auto-pairs; you do not paste a token.
4. 打开登录页：右下角会出现匹配条目，点「填充」；或在插件里「一键登记到金库」 / Fill from the page overlay, or save the current login into the vault.

金库锁定时无法填充或登记。填表 Token 与 MCP Token 分开，可单独轮换。  
Fill and save require an unlocked vault. The fill token is separate from the MCP token.

匹配规则：按网址的主机和端口精确匹配，避免把凭据填到错误站点。  
Matches require the exact host and port of the stored URL.

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
```

## 许可 License

个人本地工具，源码按仓库现状提供。使用前请自行评估风险；请勿把主密码、金库文件或 `.svbak` 备份提交到 Git。

This is a personal local tool. Review the code before relying on it. Never commit the master password, `vault.db`, or `.svbak` backups.
