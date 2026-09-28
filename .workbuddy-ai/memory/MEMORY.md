# Sealbox 印盒 — 项目长期笔记

本地凭据金库桌面应用。技术栈：Tauri 2 + Vue 3 + Rust（AES-256-GCM / Argon2id / rusqlite）。
金库库文件：`%APPDATA%\com.sealbox.app\vault.db`。

## 在 Windows 上编译 / 测试 Rust（必读）

Git Bash 的 `/usr/bin/link.exe`（GNU coreutils）会遮蔽 MSVC 链接器，导致 `cargo test` 报
`link: missing operand after '\377\376'` 或 `LNK1181: 无法打开输入文件"advapi32.lib"`。

所有 cargo 命令前必须加上：

```bash
MSVC='C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.50.35717'
SDK='C:\Program Files (x86)\Windows Kits\10'
export PATH="/c/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64:$PATH"
export LIB="$SDK\\Lib\\10.0.26100.0\\um\\x64;$SDK\\Lib\\10.0.26100.0\\ucrt\\x64;$MSVC\\lib\\x64"
```

不要并行跑多条 cargo 命令，会 `Blocking waiting for file lock on build directory`。

**构建前先关掉正在运行的 sealbox**。应用运行时锁住 `target\debug\deps\sealbox.exe`，
`cargo build` 会报 `LNK1104: 无法打开文件 sealbox.exe` 与 `os error 5 拒绝访问`。
这不是代码问题，结束进程再构建即可（`MSYS_NO_PATHCONV=1 taskkill /F /PID <pid>`，
Git Bash 里直接写 `/F` 会被转成路径）。

**应用运行时构建还会污染增量编译缓存**：反复出现 `error copying object file ... os error 5` 之后，
`cargo build`（非 test）可能直接 ICE：
`thread 'rustc' panicked at rustc_metadata\src\rmeta\encoder.rs: ... no entry found for key`。
这不是代码错误，用 `CARGO_INCREMENTAL=0 cargo build --lib` 可立即验证代码本身没问题；
根治办法是关掉应用后删掉 `src-tauri/target/debug/incremental`（约 760M，cargo 会自动重建）。
`cargo test --lib` 走的是另一套 metadata，通常不受影响。

## clippy 现状

历史代码带若干 clippy 警告（`commands.rs` 的 `AppState` 缺 `Default`、`github_mcp.rs` 的
`large_enum_variant` 等），项目不是 clippy-clean。新增代码应保持**零新增警告**，
不要为了清历史警告扩大改动面。

## 常用命令

- Rust 测试：`cd src-tauri && cargo test --lib`
- 前端类型检查 + 构建：`npm run build`（即 `vue-tsc --noEmit && vite build`）

## 代码约定

- 金库条目类型集中在 `src-tauri/src/vault.rs` 的 `EntryKind` + `SecretPayload`。新增一种类型需要同步改动：
  `vault.rs`（种类 / payload / upsert / Counts）、`commands.rs`（`primary_secret` / `account_of`）、
  `redact.rs`（脱敏）、`http_guard.rs`（bind_origins）、`backup.rs`（备份往返测试）、
  `src/lib/tauri.ts`（TS 类型）、`src/App.vue`（表单）、`src/styles.css`（pill 样式）。
- MCP 工具遵循「策略开关 → 凭证绑定 → 固定目标请求 → 审计 → 脱敏」五段式，参考 `github_mcp.rs` 与 `zoomkey/mod.rs`。
- 对接外部 HTTP 服务一律用 `ureq` + `rustls`（ring 后端），不依赖系统 TLS，避免 Schannel 读不了 PEM 的坑。
  **每个 ureq agent 都要显式 `.max_idle_connections(0)`**：ureq 只在响应头整串等于 `close` 时才判定连接不可复用，
  遇到 `Connection: Upgrade, close` 这类多 token 写法会把服务端正在拆除的连接放回池里，
  下一个请求复用它就报 `Network Error: Unexpected EOF`（ZoomKey CRM 就是这么挂的）。
- **调试 ureq 时记住它会自动重试幂等请求**（`Unit::is_retryable`：DELETE/GET/HEAD/OPTIONS/PUT/TRACE + 空 body），
  所以连接复用类 bug 用 GET 探测会被悄悄重试掉、看不出来，**必须用带 body 的 POST** 才能暴露。
  相关回归测试：`zoomkey::tests::agent_does_not_reuse_a_connection_the_server_closed`。
- 排查 mTLS / 内网连通性用 `src-tauri/examples/zoomkey_probe.rs`（`cargo run --example zoomkey_probe -- <ca> <cert> <key> <url>`），
  支持 `PROBE_FLOW` / `PROBE_REPEAT` / `PROBE_POOL` 三个环境变量做对照实验。
- 定位「这句错误到底谁抛的」时，直接在 `~/.cargo/registry/src/` 里 grep 精确错误串，
  比猜 rustls / ureq / 服务端快得多。
- 判断「服务端有没有关 TCP」不能只看应用层 recv 是否返回空（TLS close_notify 也会让 recv 返回空），
  要看底层 socket：`ss.detach()` 拿 fd → `socket.socket(fileno=fd)` → `recv(1, MSG_PEEK)`
  （Windows 上 Python 没有 `socket.peek`）。
- 对外 MCP 工具一律不接受模型传入的 URL / Host / Header / HTTP 方法，路径由代码按固定模板拼装。
- **系统文件选择框会夺焦**：`tauri-plugin-dialog` 的 `open()` / `save()` 弹的是应用窗口的子窗口，
  弹出瞬间窗口必然失焦。凡是挂在失焦上的逻辑（`hideVisibleSecrets()` 会 `closeForm()`）都会被打断 ——
  新增任何「点按钮选文件」的功能，都要用 `withNativeDialog()` 包住调用（见 `src/App.vue`）。

## 已实现的外部 MCP 能力

- `github_mcp.rs` — GitHub 只读工具
- `zoomkey/{mod,target,tls,jira,crm}.rs` — ZoomKey JIRA / CRM，20 个只读工具，内网 + mTLS

## 移植外部能力的验收清单

从别的插件/服务移植工具时，编译通过 + 单测全绿 **不等于**移植完整。必须逐工具对比源实现：

- **参数名**（最易错：源插件用 `issueKey` 而我写成 `key`、源用 `module` 而我写成 `elementType`）
- 参数默认值、上下限、是否有 `includeXxx` / `recentProjects` 之类的开关
- JQL / SQL 模板的每个细节：`ORDER BY`、`limit`、结尾分号、字段投影白名单
- 源插件里的**内置静态数据**（状态表、字段地图、查询剧本、ID 前缀）——容易被整块漏掉
- 名称不一致时以**源插件**为准，因为调用方按源插件的文档写参数
