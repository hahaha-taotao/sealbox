# GitHub MCP 本地 git 工作区 — 设计

日期：2026-09-18  
状态：**已确认**

## 0. 已确认决策

| # | 决策点 | 结论 |
|---|---|---|
| 1 | 分组 / 开关 | 本地 git 继续共用 `GithubMcpPolicy.enabled`；GitHub API 写入另有 `api_write_enabled` |
| 2 | 提交路径 | 本地 `git` CLI，不是 GitHub Contents PUT |
| 3 | 人闸 | 仅启用时确认一次；stage / commit / push / pull / clone 不再逐次审批 |
| 4 | 工具命名 | 本地 git 用 `github_git_*`；现有 `github_*` API 工具名不变 |
| 5 | 工具范围 | 只读 status / diff / log / branches；写入 stage / commit / push / pull / clone |
| 6 | 路径 | Agent 传入本机绝对路径。不登记工作区白名单，不配置 clone 根目录 |
| 7 | 明确不做 | force、amend、创建/删除分支、push tag、SSH 注入、Gitee/GitLab、助手页调用写工具 |

## 1. 目标

让 Cursor / Claude Code 能通过 Sealbox 在 Agent 给出的本地 git 仓库里看状态、暂存、提交，并用金库里的 GitHub Token **push / pull / clone**。Token 只在 Rust 进程内注入，永不返回给模型，也不写入 `.git/config`。

这是对 2026-09-11 设计里本地 Git 工作区边界的有意开口：只开本机 git CLI + HTTPS `github.com`，不开任意 HTTP；GitHub API 写入由独立的 `api_write_enabled` 和单独的 Release 工具路线控制。

## 2. 架构

```
外部 MCP 客户端
   │  Bearer <mcp_token>
   ▼
Sealbox 本机 MCP (127.0.0.1:17891)
   ├── github_mcp（同一开关）
   │     ├── 现有 7 个 GET api.github.com 工具（github_*）
   │     └── 本地 git（github_git_*）← git_workspace.rs
   └── zoomkey（不动）
```

`github_mcp.rs` 继续管 API GET 与策略读写。`git_workspace.rs` 管 git 子进程与 Token 注入。`tools/list` 在 `enabled=true` 时合并两组定义。

## 3. 策略

金库 secret setting 仍是 `github_mcp_policy`：

```json
{
  "enabled": false
}
```

- 旧 JSON 里多出来的 `clone_parent` / `workspaces` 会被忽略。
- 仍含 `credential_id` / `scopes` / `allowed_repositories` 的更旧格式继续视为损坏，整份策略按关闭处理。
- 启用时 MCP 页 confirm：将开放 GitHub 只读 API，并允许在模型给出的本地路径上执行 git（含 commit / push / pull / clone）；GitHub API 写入另需单独确认和 `api_write_enabled` 开关。
- git 工具的 `path` 必须是本机绝对路径；`credential_id` 必须指向活动的 `ApiToken { service: "github" }`。

## 4. 工具

现有 API 工具保持不变。新增：

| 工具 | 读写 | git |
|---|---|---|
| `github_git_status` | 只读 | `status --porcelain=v1 -b` |
| `github_git_diff` | 只读 | `diff` / `diff --cached`，默认 stat |
| `github_git_log` | 只读 | `log --oneline`，默认 20、上限 50 |
| `github_git_branches` | 只读 | `branch --list` |
| `github_git_stage` | 写入 | `add`；`all=true` 才 `add -A` |
| `github_git_commit` | 写入 | `commit -m`，message 必填 |
| `github_git_push` | 写入 | `push` 当前分支到 origin |
| `github_git_pull` | 写入 | `pull` origin 当前分支；脏工作区拒绝 |
| `github_git_clone` | 写入 | `clone` 到 Agent 给出的绝对父目录 |

写工具 `readOnly: false`，`risk: "high"`。助手过滤器仍是 `readOnly && risk==low`，因此助手只看得到只读 `github_git_*`。

`github_git_clone`：`path`（已存在的绝对父目录）+ `credential_id` + `owner` + `repo`，可选 `name`（单层 `[A-Za-z0-9._-]+`）。目标必须尚不存在。remote 必须是 `https://github.com/{owner}/{repo}.git`。

`github_git_pull`：无 rebase / force。有未提交改动则拒绝。

## 5. Token 注入

仅 `push` / `pull` / `clone`：

1. 从金库取出 GitHub Token。
2. `GIT_TERMINAL_PROMPT=0`，禁用 credential helper。
3. 一次性 askpass（环境变量交给短生命周期 helper），Token 不进 argv、不写 remote URL。
4. 跑完清环境、删 helper。
5. stdout/stderr 过 `redact_text`。
6. 审计只记 path、host、branch、exit code、credential 指纹。

`stage` / `commit` 不碰 Token。SSH 或非 `github.com` HTTPS 直接拒绝。

## 6. 安全边界

- 仍只监听 `127.0.0.1`，Bearer `mcp_token`。
- 金库锁定则全部失败。
- `path` 必须是本机绝对路径；仓库操作要求该路径落在某个 git 仓库内。
- 仓库内相对路径（`file`）禁止 `..` 与绝对路径。
- 不改 `user.name` / remote / credential.helper。
- 会跑仓库已有 hooks（日常 git 行为）。
- 本机 PATH 必须有 `git`。

## 7. UI

仍是 MCP 页的 GitHub 卡：一个启用/停用按钮。不再配置工作区白名单或 clone 根目录。

## 8. 测试

- `enabled=false`：API 与 `github_git_*` 都不出现。
- 相对路径 / 非 github.com / SSH → 拒绝。
- 输出无 Token；push 后 remote URL 未改。
- 脏工作区拒绝 pull。
- 助手定义不含写工具。
