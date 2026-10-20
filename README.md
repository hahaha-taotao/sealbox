# Sealbox 印盒

本地凭据金库。主密码解锁；网站账号、API Token、SSH、邮箱、服务器和数据库凭据加密存放；复制后定时清空剪贴板；支持 `.svbak` 加密备份。可选本机 MCP，让 Cursor / Claude Code 使用凭据但看不到明文。也提供 Chrome / Edge 填表扩展。

A local credential vault for Windows. Unlock with a master password. Website logins, API tokens, SSH keys, mailboxes, servers, and databases stay encrypted on disk. Copied secrets are cleared from the clipboard on a timer. Encrypted `.svbak` backups can be exported and imported. An optional localhost MCP lets Cursor / Claude Code use credentials without seeing plaintext. A Chrome / Edge extension can fill or save website logins.

当前版本 Current version: **v0.6.1** (`0.6.1`)

### 当前范围口径 Scope of this release

当前实现以 `v0.6.1` 的代码和本文档为准。`docs/superpowers/specs/2026-09-11-local-credential-vault-design.md` 是 9 月 11 日的初始基线；后续 9 月 17 日、18 日、20 日和 24 日的规格对冲突部分作了增量修订，尤其是 Chrome / Edge 填充、TOTP、CSV 导入、本地 Git 和受控 GitHub MCP。9 月 28 日的 QR 入库与页面 OTP 候选仍是待审阅提案，不属于当前版本。

The `v0.2.4` code and this README define the current shipped scope. The September 11 design is the original baseline; later dated specifications supersede conflicting parts, including Chrome / Edge fill, TOTP, CSV import, local Git, and guarded GitHub MCP. The September 28 QR-enrollment and page-OTP proposals are not shipped.

## 在线更新 Online updates

在「设置」底部的「关于 Sealbox」中点击「检查更新」，应用会查询固定的 HTTPS Tauri updater endpoint。发现更新后，应用会在窗口内下载并校验签名，显示下载进度；下载完成后确认安装，签名 NSIS 安装器会接管替换并重启应用。若签名元数据暂不可用，仍可打开 GitHub 发布页手动安装。

发布工作流同时上传 Windows 安装包、Tauri updater 元数据 `latest.json` 和对应的 `.sig` 签名文件。现有 v0.1.4 及更早安装包没有应用内签名安装能力，首次升级到已启用 Tauri updater 的版本必须手动运行一次安装包。升级后金库文件仍留在原数据目录，不会随程序安装目录移动。

## 首次手动升级 First manual upgrade

1. 打开 [GitHub Releases](https://github.com/hahaha-taotao/sealbox/releases/latest)，下载对应版本的 `Sealbox_<version>_x64-setup.exe`。
2. 退出 Sealbox 后运行安装包，按向导选择当前用户或所有用户，并选择安装盘符与目录。
3. 安装完成后重新启动 Sealbox；如果浏览器扩展提示内置文件已更新，到「插件」页重新安装本机扩展，再回浏览器扩展页点击刷新。
4. 首次手动升级完成后，后续支持 Tauri updater 的版本可使用其签名元数据进行更新；遇到检查失败时仍可从发布页手动安装。

安装程序只替换应用文件，不会删除或搬移金库。金库路径是 `%APPDATA%\\com.sealbox.app\\vault.db`；升级前仍建议先导出 `.svbak` 加密备份。

> 可选 WebDAV / S3 同步。远端只保存用同步密钥加密的快照，不保存明文，也解不开主密码。
> Optional WebDAV / S3 sync stores an encrypted snapshot. The remote never sees plaintext and cannot unlock the master password.

> 当前工作区的在线更新实现已经支持签名下载、进度展示和安装确认；v0.1.4 及更早安装包仍需按上面的步骤手动升级一次。请只从本项目的 GitHub Releases 下载，并核对版本号与签名元数据。

设计见 [`docs/superpowers/specs/2026-09-11-local-credential-vault-design.md`](docs/superpowers/specs/2026-09-11-local-credential-vault-design.md).

## 安装 Install

Windows x64 使用 NSIS 安装包 `Sealbox_0.6.1_x64-setup.exe`。向导会让你选择：

1. 安装范围：当前用户，或所有用户（后者需要管理员权限）
2. **安装盘符与目录**，例如 `D:\Sealbox`；默认在当前用户下是 `%LOCALAPPDATA%\Sealbox`，在所有用户下是 `C:\Program Files\Sealbox`

金库文件仍写在 `%APPDATA%\com.sealbox.app\vault.db`，不会跟着安装盘一起搬家。

The Windows x64 setup wizard lets you pick per-user or per-machine install, then choose the drive and folder. Vault data stays in `%APPDATA%\com.sealbox.app\`, not next to the exe.

从源码打包 Build the installer:

```bash
npm install
npm run tauri build
```

产物在 `src-tauri/target/release/bundle/nsis/`。

## 功能 Features

- **保险库 Vault** — 网站账号、API Token、SSH、邮箱、邮箱授权码、服务器、数据库、客户端证书
- **解锁 Unlock** — 主密码为根
- **速查 Quick search** — 默认全局热键 `Ctrl+Shift+Space`，回车复制主秘密
- **安全习惯 Hygiene** — 空闲自动锁定、审计日志（不记明文）、回收站、置顶、标签、单层文件夹；文件夹可重命名、删除（条目变为未归类）或合并，标签可重命名、删除或合并
- **备份与导入 Backup & import** — 加密 `.svbak` 导出 / 导入（默认合并，覆盖需确认）；可从 Chrome / Edge、Bitwarden、1Password 导出的 UTF-8 CSV 导入网站账号，默认跳过已有同站同账号
- **MCP** — 本机 `127.0.0.1` 服务；GitHub MCP 提供只读 API、本地 git 和工作区短名；Issue、PR、Release、文件、ref、Actions 和 secret 写入另有独立开关，且每次弹出桌面确认。ZoomKey 提供受限的 JIRA / CRM 只读工具。模型可用 Token 标题或默认凭据，不必先抄 UUID
- **客户端证书 Client cert** — 保险库里可以导入 mTLS 用的客户端证书与私钥（PEM），由 Rust 侧限长、解析并校验证书/私钥匹配后加密保存，随金库一起备份；列表和速查不会显示或复制私钥，锁定时会清理 TLS 运行时缓存
- **助手 Assistant** — 位于「插件」下方的 OpenAI 兼容对话页；可测试本机 MCP 连通性，并让模型调用当前暴露的低风险只读工具
- **插件 Plugin** — Chrome / Edge 从客户端安装后按当前网址填充、填 TOTP 或一键登记；在侧栏「插件」页配对

## 安全模型 Security

### 当前明确不做 Current non-goals

- 不做多用户、账号系统或定时自动上传。可选的 WebDAV / S3 同步只上传加密快照，不上传明文金库或 `.svbak`。
- 不做 Firefox / Safari / Brave 适配、浏览器商店上架、`.crx`、注册表强制安装或静默加载；当前扩展只支持 Chrome / Edge 的本机加载流程。
- 不读 Chrome `Login Data` 或其他浏览器凭据数据库，不使用 DPAPI，不做 Passkey、HIBP、扫描导入或 QR 入库；2026-09-28 的 QR TOTP 与页面 OTP 候选仍是待审阅提案。
- 不提供任意 HTTP、任意 URL / 方法 / 请求头 / 原始请求体；不把 Token、主密码、备份、Authorization header 或完整远端响应交给模型。
- 不实现删除 GitHub 仓库、分支保护、协作者、deploy key、Actions 总开关或 workflow 默认 Token 权限。

| 项 Item | 说明 Notes |
|---|---|
| 存储 Storage | SQLite 金库 `%APPDATA%\com.sealbox.app\vault.db`。不写 `fill.json` |
| 加密 Encryption | Argon2id 派生主密钥，AES-256-GCM 加密条目秘密；MCP / 填表 Token 也用 DEK 加密后写入 settings |
| 列表 List | 列表、搜索、审计、MCP 都不返回密码 / Token / 私钥 |
| 剪贴板 Clipboard | 复制条目秘密、MCP / 填表 Token 和 MCP 配置后约 20 秒，若仍是那条内容则清空；锁定会立刻清掉本应用写入的秘密 |
| 锁定 Lock | 空闲超时、标题栏或托盘锁定都会丢掉 DEK、清已复制秘密、关掉编辑框和明文显示 |
| 备份 Backup | `.svbak` 用导出密码加密 |
| 网络 Network | MCP / 填表 API 只监听 `127.0.0.1`，默认端口 `17891`。GitHub 工具只访问 `https://api.github.com:443`，Release 资产上传只访问 `https://uploads.github.com:443`，统一拒绝重定向和内网目标。ZoomKey 仅访问精确白名单内网主机，使用 mTLS、固定路径和只读工具策略 |
| 插件 Extension | 登录页右下角弹出填充条；一站点多账号可点选。`Alt+Shift+F` 也可打开选择器。填充条在 open Shadow DOM 中，只响应真实用户点击。提交后询问保存/更新，明文只暂存在 `chrome.storage.session`。扩展为检测和填充当前网页而申请 `http://*/*` 与 `https://*/*` 页面权限，Sealbox API 本身仍仅访问 `127.0.0.1`；填表 Token 写入 `chrome.storage.local`，关掉浏览器仍有效，只有轮换后才需要重新配对 |

## 环境 Requirements

- Windows
- [Rust](https://rustup.rs/)
- [Node.js](https://nodejs.org/)（含 npm）

已安装的 Windows 用户直接运行安装包即可，不需要 Rust / Node。

## 发布 Release

发布只接受形如 `v0.6.0` 的 Git tag。`.github/workflows/release.yml` 在 Windows runner 上依次执行 `npm ci`、版本一致性校验、Rust 测试、前端构建和扩展测试，全部通过后由 `tauri-apps/tauri-action` 构建并发布 NSIS 安装包、`latest.json` 和对应的 `.sig` updater 签名文件。

版本号必须同时匹配以下文件：`package.json`、`package-lock.json`（根版本和 `packages[""].version`）、`src-tauri/Cargo.toml`、`src-tauri/tauri.conf.json`、`extension/manifest.json`。本地可在打 tag 前运行：

```bash
node scripts/check-version.mjs v0.6.0
```

GitHub Actions 只从 Secrets 注入签名材料，不会把私钥写入仓库或工作区。请在仓库 Settings → Secrets and variables → Actions 中配置：

- `TAURI_SIGNING_PRIVATE_KEY`：Tauri updater 私钥原文
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`：生成私钥时设置的密码；没有密码时可配置为空值

`GITHUB_TOKEN` 使用 Actions 自动提供的 token，workflow 通过 `permissions: contents: write` 上传 Release 资产。不要把私钥、密码、`.sig` 生成输入或本地签名文件提交到 Git；轮换签名密钥前请先评估已发布版本的 updater 兼容性。

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
2. 打开侧栏 **MCP**，在 GitHub MCP 卡片中点击“启用 GitHub MCP”。服务只监听 `127.0.0.1`，默认端口 17891。
3. 复制页面上的配置到 Cursor / Claude Code / Paste the snippet into Cursor or Claude Code.

默认工具 Tools:

- `github_list_credentials` — 列出活动 GitHub Token 的标题和账号，不含 Token
- `github_user_info`（旧名 `github_get_authenticated_user`）— 当前 Token 对应账号
- `github_repo_list` / `github_repo_get` — 当前 Token 可见的仓库，以及单个仓库的默认分支、是否私有和描述
- `github_git` — 本机仓库。`action` 为 `status` / `diff` / `log` / `branches` / `fetch` / `pull` / `commit` / `push` / `clone`。`path` 是仓库绝对路径；`clone` 时 `path` 是已存在的父目录，另传 `repo="owner/repo"`。`commit` 可带 `files` 或 `all=true`，暂存和提交只确认一次。`fetch` 只更新远端跟踪。`push` 可指定 `remote`、`branch`、`tag`、`tags`、`force_with_lease`
- `github_release` — 版本管理。`action` 为 `list` / `get` / `notes` / `create` / `publish`。`create` 默认草稿
- `github_pr` — `action` 为 `list` / `get` / `create` / `merge`。`create` 默认草稿，`merge` 必须带编号
- `github_issue` — `action` 为 `list` / `get` / `create` / `comment` / `close`

GitHub MCP 默认停用。启用后只开放上面这些工具。凭据可传标题（`credential="agentos"`）；金库里只有一条 GitHub Token 时自动选用。仓库用 `repo="owner/repo"`，本地 git 用本机绝对路径。写入每次弹出桌面确认。不提供搜索仓库、读远端文件、Actions、变量、secret、下载产物、建仓、改 ref 或删仓库。侧栏助手只调用只读低风险工具。Token 不会返回给模型。

停用时这些工具都不会出现在 `tools/list`，直接调用也会被拒绝。模型收到的是结构化字段或截断后的 git 输出，不包含 Token、请求头、Release body 或完整远端响应。金库锁定时工具会失败。后续接口规划见 [`docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md`](docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md)。MCP Token 可在页面轮换。

## 助手 Assistant

「助手」位于侧栏「插件」下方。它使用 OpenAI Chat Completions 兼容协议，可填写 Base URL、模型和 API Key；API Key 使用加密金库存储，前端不会读取或回显明文。API Key 可以留空，用于不需要密钥的本地兼容服务。

点击「测试 MCP」会通过真实的本机 HTTP MCP 接口执行初始化和工具发现。GitHub MCP 启用时，助手自动使用当前 MCP 暴露的低风险 GitHub 工具；停用时不会发现或调用这些工具。首版使用非流式请求，不支持外部 MCP Server、stdio 或 SSE transport。

The Assistant page is below Plugin in the sidebar. It uses an OpenAI Chat Completions-compatible endpoint, stores the API key encrypted in the vault, probes the real local MCP HTTP endpoint, and automatically follows the single GitHub MCP enable/disable switch. The first version is non-streaming and does not support external MCP servers or stdio/SSE transports.

GitHub MCP is disabled by default. When enabled, the assistant discovers the low-risk read-only tools. Writes for local git, releases, pull requests, and issues stay behind desktop confirmation and are not offered to the assistant. The server does not search repositories, read remote files, control Actions, manage variables or secrets, download artifacts, create repositories, or edit refs.

## 插件 Plugin（Chrome / Edge）

应用启动后会在 `127.0.0.1:17891` 提供填表接口。配对和扩展安装都在侧栏 **插件** 页，不和 MCP 混在一起。开发调试仍可直接加载仓库里的 `extension/`。

After the app starts, fill APIs listen on `127.0.0.1:17891`. Install and pairing are on the **Plugin** page, not MCP. Developers can still load the repo `extension/` folder unpacked.

1. 运行 Sealbox（安装扩展不要求解锁）/ Run Sealbox. Installing the extension does not require an unlocked vault.
2. 打开侧栏 **插件**，点 **安装到本机并打开目录**。扩展写到 `%LOCALAPPDATA%\com.sealbox.app\extension\`。再点 **打开 Chrome 扩展页** 或 **打开 Edge 扩展页**，打开开发者模式，加载刚打开的文件夹 / On **Plugin**, click install. The files go to `%LOCALAPPDATA%\com.sealbox.app\extension\`. Then open the Chrome or Edge extensions page and load that unpacked folder.
3. 解锁后点 **配对**，60 秒内把一次性配对码填进扩展 / Unlock, click **Pair**, then enter the one-time code in the extension within 60 seconds.
4. 打开登录页：检测到密码框后右下角会出现匹配账号，点选填充；也可按 `Alt+Shift+F`。卡片优先显示账号，过长标题会缩略；有备注时在账号后显示前几个字。含 TOTP 的条目会在登录页或下一页验证码框填入当前 6 位码，扩展拿不到 TOTP 密钥。打开插件弹窗时，「登记当前站点」会读当前页已填的账号密码，并可填写备注。登录提交后，若该站点还没有这个账号会询问保存；已有同一账号且密码变了会询问更新；密码没变则不弹。 / Open a login page: after a password field is detected, a bottom-right overlay lists matching accounts. `Alt+Shift+F` also opens the chooser. Buttons show the username first, abbreviate long titles, and append a short note when present. Entries with TOTP fill the current six-digit code on the login page or the following verification-code page; the extension never receives the TOTP secret. Opening the popup copies the page’s current username and password into the save form, with an optional note. After submit, Sealbox asks to save a new login, or update when the same account’s password changed. Unchanged passwords are not prompted.

金库锁定时无法填充或登记。配对码一次性有效；填表 Token 写入 `chrome.storage.local`，关掉浏览器后仍然有效，旧的 session 副本会在启动时迁过来并删掉。与 MCP Token 分开，可单独轮换；轮换后扩展会清掉失效 Token 并要求重新配对。读取明文和写入条目都会按当前页面网址复核。提交后采集的账号密码只暂存在会话存储，确认保存才写入金库，拒绝或超时会清掉。填充选择器在 open Shadow DOM 里，只响应真实用户点击。扩展需要访问当前网页以检测和填充登录字段，因此声明 `http://*/*` 与 `https://*/*` 页面权限；Sealbox 本地接口仍只访问 `127.0.0.1`。可在弹窗里配置站点排除列表。
Fill and save require an unlocked vault. Pairing codes are one-shot. The fill token is stored in `chrome.storage.local` and survives closing the browser; a leftover session copy is migrated and deleted on startup. It is separate from the MCP token and can be rotated on its own. After rotation the extension drops the rejected token and asks to pair again. Secret reveal and save are bound to the current page URL. Captured logins stay in session storage until you confirm save, then they are cleared. The chooser uses an open Shadow DOM and requires a real user gesture. The extension needs `http://*/*` and `https://*/*` page access to detect and fill login fields; Sealbox's local API remains limited to `127.0.0.1`. Sites can be excluded in the popup.

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
