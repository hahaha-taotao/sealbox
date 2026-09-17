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
- **MCP** — 本机 `127.0.0.1` 服务；只有一个 GitHub MCP 启用/停用开关，启用后提供 GitHub 只读工具，固定访问 `api.github.com`；模型按 Token ID 选择活动 GitHub Token
- **ZoomKey JIRA / CRM** — 可选的内网只读工具，挂在同一个 MCP 上。走强制双向 TLS，账号密码 / AccessKey 从金库的 API Token 条目取，客户端私钥从金库的「客户端证书」条目取；默认关闭，需显式打开「允许访问内网地址」并确认主机白名单
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
| 网络 Network | MCP / 填表只监听 `127.0.0.1`，默认端口 `17891`。GitHub 工具只访问 `https://api.github.com:443`，固定 GET、拒绝重定向和内网目标 |
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
2. 打开侧栏 **MCP**，在 GitHub 只读能力卡片中点击“启用 GitHub MCP”。服务只监听 `127.0.0.1`，默认端口 17891。
3. 复制页面上的配置到 Cursor / Claude Code / Paste the snippet into Cursor or Claude Code.

默认工具 Tools:

- `github_list_credentials` — 列出活动 GitHub API Token 的 ID、名称和账号，不含 Token
- `github_get_authenticated_user` — 读取指定 Token 对应账号的公开资料
- `github_list_repositories` — 列出该 Token 可见的仓库元数据
- `github_get_repository` — 查看仓库元数据
- `github_get_file` — 读取仓库中的文本文件，带大小和二进制限制
- `github_list_issues` — 列出仓库的 Issue
- `github_list_pull_requests` — 列出仓库的 Pull Request 元数据

GitHub MCP 默认停用。启用后七个只读工具全部可用；模型先调用 `github_list_credentials`，再通过 `credential_id` 选择要使用的活动 GitHub Token。工具只访问 `https://api.github.com:443`，固定使用 GET，不接受模型传入 URL、Header、Body 或任意 HTTP 方法。GitHub Token 在 GitHub 侧的权限仍可能导致 API 返回 403。

停用时七个工具都不会出现在 `tools/list`，直接调用也会被拒绝。模型收到的是每个工具定义好的结构化字段，不包含 Token、Authorization、响应头或任意原始响应。金库锁定时工具会失败。MCP Token 可在页面轮换。

## ZoomKey JIRA / CRM

把众齐内网的 JIRA 与 CRM 查询能力开放给本机 MCP 客户端，工具挂在同一个 MCP 服务上，各自独立开关。

**前置：两个站点都在 `172.16.x.x` 内网，且强制要求客户端证书（mTLS）。**

启用步骤：

1. 保险库 → 新建一条 **API Token**：服务填 `zoomkey-jira`，账号填 JIRA 用户名，密钥填 JIRA 密码。
2. 保险库 → 新建一条 **API Token**：服务填 `zoomkey-crm`，账号填 CRM 用户名，密钥填 Vtiger AccessKey（不是登录密码）。
3. 保险库 → 新建一条 **客户端证书**：分别选择 `client-cert.pem` 与 `client-key.pem` 文件。文件只在 Rust 侧读取、校验并加密保存；不会保存原始路径，也不会把私钥回显到界面。两个站点可以共用同一份证书。
4. 侧栏 **MCP** → **ZoomKey JIRA / CRM**：打开「允许访问内网地址」，勾选要启用的端，选好凭据与证书条目，填 CA bundle 路径（含 Root + SubCA 的 PEM），保存。只有配置完整的端点才会出现在 MCP `tools/list`。
5. 点 **测试连接** 验证 CA、客户端证书、账号三段链路。

工具 Tools：

- JIRA：`zoomkey_jira_nav`、`zoomkey_jira_connection_status`、`zoomkey_jira_list_projects`、`zoomkey_jira_project_statuses`、`zoomkey_jira_field_map`、`zoomkey_jira_search_issues`、`zoomkey_jira_get_issue`、`zoomkey_jira_my_open_issues`、`zoomkey_jira_project_unfinished`、`zoomkey_jira_preset_unfinished`
- CRM：`zoomkey_crm_nav`、`zoomkey_crm_connection_status`、`zoomkey_crm_describe_module`、`zoomkey_crm_field_map`、`zoomkey_crm_find_account`、`zoomkey_crm_find_project`、`zoomkey_crm_list_service_contracts`、`zoomkey_crm_project_members`、`zoomkey_crm_query`、`zoomkey_crm_retrieve`

两个 `field_map` 默认只返回**内置结构地图**（JIRA 的状态清单/字段/预设/查询剧本，CRM 的 ID 前缀/关联主线/模块核心字段），不联网即可用；传 `live=true` 才去在线拉元数据。参数与源插件对齐：JIRA 用 `section`（`overview`/`status`/`issuetype`/`fields`/`presets`/`playbooks`/`crm-bridge`），CRM 用 `module`。

内网例外是刻意开的口子，收得很紧：只对策略里列出的**精确主机名**放行；解析出的地址会被钉住再使用，避免 DNS 重绑定；回环、链路本地、云元数据地址（`169.254.169.254` / `100.100.100.200`）永远拒绝；不开「允许访问内网地址」时全部拒绝。GitHub 那条路径完全不受影响，仍然只走公网守卫。

模型可控面同样收窄：不接受模型传入 URL、Host、Header 或 HTTP 方法，路径由代码按固定模板拼装。少数确实需要模型输入的字符串都先过校验才使用——`search_issues` / `get_issue` 的 `fields` 只接受逗号分隔的字段名（字母、数字、下划线、点、连字符，最多 64 个），`list_projects` 的 `query` 仅用于本地过滤，`field_map` 的 `section` 走固定枚举、`module` 只匹配内置表。非法值直接拒绝，不回显原值。JIRA 只发 GET；CRM 只发 GET 与表单 POST，且只指向配置的 webservice 地址。`zoomkey_crm_query` 只放行单条 `select`，写操作与多语句会被拒绝。返回体统一脱敏，密码、AccessKey 与 Vtiger `sessionName` 不会出现在输出或审计里。

源插件里的 `configure`（写凭证）与 `insecureSkipTlsVerify`（跳过 TLS 校验）**不移植**。客户端私钥必须是**无口令**的 PEM；带口令的私钥请先解密：

```bash
openssl pkcs8 -topk8 -nocrypt -in client-key.pem -out client-key-plain.pem
```

设计见 [`docs/superpowers/specs/2026-09-17-zoomkey-mcp-design.md`](docs/superpowers/specs/2026-09-17-zoomkey-mcp-design.md)。

## 助手 Assistant

「助手」位于侧栏「插件」下方。它使用 OpenAI Chat Completions 兼容协议，可填写 Base URL、模型和 API Key；API Key 使用加密金库存储，前端不会读取或回显明文。API Key 可以留空，用于不需要密钥的本地兼容服务。

点击「测试 MCP」会通过真实的本机 HTTP MCP 接口执行初始化和工具发现。GitHub MCP 启用时，助手自动使用当前 MCP 暴露的低风险 GitHub 工具；停用时不会发现或调用这些工具。首版使用非流式请求，不支持外部 MCP Server、stdio 或 SSE transport。

The Assistant page is below Plugin in the sidebar. It uses an OpenAI Chat Completions-compatible endpoint, stores the API key encrypted in the vault, probes the real local MCP HTTP endpoint, and automatically follows the single GitHub MCP enable/disable switch. The first version is non-streaming and does not support external MCP servers or stdio/SSE transports.

GitHub MCP is disabled by default. When enabled, the assistant discovers one credential metadata tool and six read-only GitHub tools. The model selects an active GitHub token by ID; requests remain fixed GET calls to `https://api.github.com:443` and never accept arbitrary URLs, headers, bodies, or methods.

## 插件 Plugin（Chrome / Edge）

应用启动后会在 `127.0.0.1:17891` 提供填表接口。配对和扩展安装都在侧栏 **插件** 页，不和 MCP 混在一起。开发调试仍可直接加载仓库里的 `extension/`。

After the app starts, fill APIs listen on `127.0.0.1:17891`. Install and pairing are on the **Plugin** page, not MCP. Developers can still load the repo `extension/` folder unpacked.

1. 运行 Sealbox（安装扩展不要求解锁）/ Run Sealbox. Installing the extension does not require an unlocked vault.
2. 打开侧栏 **插件**，点 **安装到本机并打开目录**。扩展写到 `%LOCALAPPDATA%\com.sealbox.app\extension\`。再打开 `chrome://extensions` 或 `edge://extensions`，打开开发者模式，加载已解压的扩展，选刚打开的文件夹 / On **Plugin**, click install. The files go to `%LOCALAPPDATA%\com.sealbox.app\extension\`. Load that unpacked folder in Chrome or Edge.
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
