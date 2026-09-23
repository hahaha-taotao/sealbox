# Sealbox 印盒

本地凭据金库。主密码（可选 Windows Hello）解锁；网站账号、API Token、SSH、邮箱、服务器和数据库凭据加密存放；复制后定时清空剪贴板；支持 `.svbak` 加密备份。可选本机 MCP，让 Cursor / Claude Code 使用凭据但看不到明文。也提供 Chrome / Edge 填表扩展。

A local credential vault for Windows. Unlock with a master password (optional Windows Hello). Website logins, API tokens, SSH keys, mailboxes, servers, and databases stay encrypted on disk. Copied secrets are cleared from the clipboard on a timer. Encrypted `.svbak` backups can be exported and imported. An optional localhost MCP lets Cursor / Claude Code use credentials without seeing plaintext. A Chrome / Edge extension can fill or save website logins.

当前版本 Current version: **v0.1.5** (`0.1.5`)

## 在线更新 Online updates

在「设置」底部的「关于 Sealbox」中点击「检查更新」，应用会查询固定的 HTTPS Tauri updater endpoint。发现更新后，应用会在窗口内下载并校验签名，显示下载进度；下载完成后确认安装，签名 NSIS 安装器会接管替换并重启应用。若签名元数据暂不可用，仍可打开 GitHub 发布页手动安装。

发布工作流同时上传 Windows 安装包、Tauri updater 元数据 `latest.json` 和对应的 `.sig` 签名文件。现有 v0.1.4 及更早安装包没有应用内签名安装能力，首次升级到已启用 Tauri updater 的版本必须手动运行一次安装包。升级后金库文件仍留在原数据目录，不会随程序安装目录移动。

## 首次手动升级 First manual upgrade

1. 打开 [GitHub Releases](https://github.com/hahaha-taotao/sealbox/releases/latest)，下载对应版本的 `Sealbox_<version>_x64-setup.exe`。
2. 退出 Sealbox 后运行安装包，按向导选择当前用户或所有用户，并选择安装盘符与目录。
3. 安装完成后重新启动 Sealbox；如果浏览器扩展提示内置文件已更新，到「插件」页重新安装本机扩展，再回浏览器扩展页点击刷新。
4. 首次手动升级完成后，后续支持 Tauri updater 的版本可使用其签名元数据进行更新；遇到检查失败时仍可从发布页手动安装。

安装程序只替换应用文件，不会删除或搬移金库。金库路径是 `%APPDATA%\\com.sealbox.app\\vault.db`；升级前仍建议先导出 `.svbak` 加密备份。

> 数据只存本机，不做云同步。
> Secrets stay on this machine. There is no cloud sync.

> 当前工作区的在线更新实现已经支持签名下载、进度展示和安装确认；v0.1.4 及更早安装包仍需按上面的步骤手动升级一次。请只从本项目的 GitHub Releases 下载，并核对版本号与签名元数据。

设计见 [`docs/superpowers/specs/2026-09-11-local-credential-vault-design.md`](docs/superpowers/specs/2026-09-11-local-credential-vault-design.md).

## 安装 Install

Windows x64 使用 NSIS 安装包 `Sealbox_0.1.5_x64-setup.exe`。向导会让你选择：

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

- **保险库 Vault** — 网站账号、API Token、SSH、邮箱、邮箱授权码、服务器、数据库
- **解锁 Unlock** — 主密码为根；可选 Windows Hello 作为第二把钥匙
- **速查 Quick search** — 默认全局热键 `Ctrl+Shift+Space`，回车复制主秘密
- **安全习惯 Hygiene** — 空闲自动锁定、审计日志（不记明文）、回收站、置顶、标签、文件夹
- **备份 Backup** — 加密 `.svbak` 导出 / 导入（默认合并，覆盖需确认）
- **MCP** — 本机 `127.0.0.1` 服务；GitHub MCP 提供只读 API、本地 git 和工作区短名；Issue / PR / Release 写入另有独立开关，且每次弹出桌面确认。模型可用 Token 标题或默认凭据，不必先抄 UUID
- **客户端证书 Client cert** — 保险库里可以导入 mTLS 用的客户端证书与私钥（PEM），由 Rust 侧限长、解析并校验证书/私钥匹配后加密保存，随金库一起备份；列表和速查不会显示或复制私钥，锁定时会清理 TLS 运行时缓存
- **助手 Assistant** — 位于「插件」下方的 OpenAI 兼容对话页；可测试本机 MCP 连通性，并让模型调用当前暴露的 GitHub 只读工具
- **插件 Plugin** — Chrome / Edge 从客户端安装后按当前网址填充或一键登记；在侧栏「插件」页配对

## 安全模型 Security

| 项 Item | 说明 Notes |
|---|---|
| 存储 Storage | SQLite 金库 `%APPDATA%\com.sealbox.app\vault.db`。不写 `fill.json` |
| 加密 Encryption | Argon2id 派生主密钥，AES-256-GCM 加密条目秘密；MCP / 填表 Token 也用 DEK 加密后写入 settings |
| 列表 List | 列表、搜索、审计、MCP 都不返回密码 / Token / 私钥 |
| 剪贴板 Clipboard | 复制条目秘密、MCP / 填表 Token 和 MCP 配置后约 20 秒，若仍是那条内容则清空；锁定会立刻清掉本应用写入的秘密 |
| 锁定 Lock | 空闲超时、标题栏或托盘锁定都会丢掉 DEK、清已复制秘密、关掉编辑框和明文显示 |
| 备份 Backup | `.svbak` 用导出密码加密；Windows Hello 解不开备份文件 |
| 网络 Network | MCP / 填表只监听 `127.0.0.1`，默认端口 `17891`。GitHub 读取工具只访问 `https://api.github.com:443`，固定 GET；Release 写入使用独立、受控的 POST，统一拒绝重定向和内网目标 |
| 插件 Extension | 登录页右下角弹出填充条；一站点多账号可点选。`Alt+Shift+F` 也可打开选择器。填充条在 closed Shadow DOM 中，只响应真实用户点击，账号做掩码。提交后询问保存/更新，明文只暂存在 `chrome.storage.session`。扩展仅申请 `127.0.0.1` 主机权限；填表 Token 只放 session，启动时清掉 local 残留 |

## 环境 Requirements

- Windows
- [Rust](https://rustup.rs/)
- [Node.js](https://nodejs.org/)（含 npm）

已安装的 Windows 用户直接运行安装包即可，不需要 Rust / Node。

## 发布 Release

发布只接受形如 `v0.1.5` 的 Git tag。`.github/workflows/release.yml` 在 Windows runner 上依次执行 `npm ci`、版本一致性校验、Rust 测试、前端构建和扩展测试，全部通过后由 `tauri-apps/tauri-action` 构建并发布 NSIS 安装包、`latest.json` 和对应的 `.sig` updater 签名文件。

版本号必须同时匹配以下文件：`package.json`、`package-lock.json`（根版本和 `packages[""].version`）、`src-tauri/Cargo.toml`、`src-tauri/tauri.conf.json`、`extension/manifest.json`。本地可在打 tag 前运行：

```bash
node scripts/check-version.mjs v0.1.5
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

- `github_list_credentials` — 列出活动 GitHub Token 的标题、账号和是否为默认凭据，不含 Token
- `github_get_authenticated_user` — 当前 Token 对应账号
- `github_list_repositories` / `github_get_repository` / `github_get_file` — 仓库与文件
- `github_list_issues` / `github_list_pull_requests` / `github_get_pull_request` — Issue / PR，含 head/base、draft、mergeable、assignees
- `github_list_workflow_runs` — 轮询 Actions 状态
- `github_git_workspace_list` / `github_git_workspace_register` — 把本机仓库登记成短名，之后传 `workspace="sealbox"`
- `github_git_status` / `github_git_diff` / `github_git_log` / `github_git_branches` — 本地只读 git
- `github_git_stage` / `github_git_commit` / `github_git_push` / `github_git_pull` / `github_git_clone` — 日常写入；push 可指定 branch、tags、force-with-lease，并区分「已推送 / 远端已是最新」
- `github_create_issue` / `github_create_issue_comment` / `github_create_pull_request` / `github_create_release` — GitHub 写操作，需单独启用 API 写入，且每次弹出桌面确认

GitHub MCP 默认停用。启用后开放只读 API 和 `github_git_*`。凭据可传标题（`credential="agentos"`），也可省略后使用 MCP 页默认 Token；金库里只有一条 GitHub Token 时自动选用。仓库推荐 `repo="owner/repo"`。git 可先登记工作区短名，不必每次传绝对路径。GitHub API 写入由 `api_write_enabled` 控制；打开后会出现 Issue / 评论 / Draft PR / Release，但每一次仍要桌面确认。侧栏助手只调用只读低风险工具。

停用时这些工具都不会出现在 `tools/list`，直接调用也会被拒绝。模型收到的是结构化字段或截断后的 git 输出，不包含 Token、请求头、Release body 或完整远端响应。金库锁定时工具会失败。后续接口规划见 [`docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md`](docs/superpowers/specs/2026-09-20-github-mcp-roadmap.md)。MCP Token 可在页面轮换。

## 助手 Assistant

「助手」位于侧栏「插件」下方。它使用 OpenAI Chat Completions 兼容协议，可填写 Base URL、模型和 API Key；API Key 使用加密金库存储，前端不会读取或回显明文。API Key 可以留空，用于不需要密钥的本地兼容服务。

点击「测试 MCP」会通过真实的本机 HTTP MCP 接口执行初始化和工具发现。GitHub MCP 启用时，助手自动使用当前 MCP 暴露的低风险 GitHub 工具；停用时不会发现或调用这些工具。首版使用非流式请求，不支持外部 MCP Server、stdio 或 SSE transport。

The Assistant page is below Plugin in the sidebar. It uses an OpenAI Chat Completions-compatible endpoint, stores the API key encrypted in the vault, probes the real local MCP HTTP endpoint, and automatically follows the single GitHub MCP enable/disable switch. The first version is non-streaming and does not support external MCP servers or stdio/SSE transports.

GitHub MCP is disabled by default. When enabled, the assistant discovers the low-risk read-only GitHub and local-git tools; write tools such as commit, push, PR and Release stay behind desktop confirmation and are not offered to the assistant. GitHub API reads remain fixed GET calls to `https://api.github.com:443`; the separate API-write switch exposes allowlisted Issue / PR / Release POSTs and never accepts arbitrary URLs, headers, bodies, or methods.

## 插件 Plugin（Chrome / Edge）

应用启动后会在 `127.0.0.1:17891` 提供填表接口。配对和扩展安装都在侧栏 **插件** 页，不和 MCP 混在一起。开发调试仍可直接加载仓库里的 `extension/`。

After the app starts, fill APIs listen on `127.0.0.1:17891`. Install and pairing are on the **Plugin** page, not MCP. Developers can still load the repo `extension/` folder unpacked.

1. 运行 Sealbox（安装扩展不要求解锁）/ Run Sealbox. Installing the extension does not require an unlocked vault.
2. 打开侧栏 **插件**，点 **安装到本机并打开目录**。扩展写到 `%LOCALAPPDATA%\com.sealbox.app\extension\`。再点 **打开 Chrome 扩展页** 或 **打开 Edge 扩展页**，打开开发者模式，加载刚打开的文件夹 / On **Plugin**, click install. The files go to `%LOCALAPPDATA%\com.sealbox.app\extension\`. Then open the Chrome or Edge extensions page and load that unpacked folder.
3. 解锁后点 **配对**，60 秒内把一次性配对码填进扩展 / Unlock, click **Pair**, then enter the one-time code in the extension within 60 seconds.
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
