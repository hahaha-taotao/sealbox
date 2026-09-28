# Sealbox GitHub MCP 扩展：本地 git 工作区（第一版）

**目标：** 现有 GitHub MCP **同一个开关**下，除 `api.github.com` 只读 GET 外，再开放已登记本地仓库的日常 git。Token 只在 Rust 里注入，永不回给模型，不写入 `.git/config`。

**人闸：只有启用开关。** stage / commit / push / pull / clone 直接执行，不再每次弹窗。

## 已确认决策

| 项 | 结论 |
|---|---|
| 分组 / 开关 | 并进 GitHub MCP，共用 `GithubMcpPolicy.enabled` |
| 提交路径 | 本地 `git` CLI，不是 GitHub Contents PUT |
| 人闸 | **仅启用时确认一次**；写工具本身不再审批 |
| 工具命名 | 本地 git 用 **`github_git_*`**；现有 `github_list_repositories` 等 API 名不变 |
| 工具范围 | 只读：list / status / diff / log / branches；写入：stage / commit / push / pull / clone |
| 明确不做 | force、amend、创建/删除分支、push tag、SSH 注入、Gitee/GitLab |

## 架构

```
Cursor / Claude Code
   │  Bearer mcp_token
   ▼
Sealbox MCP 127.0.0.1:17891
   ├── github_mcp（同一开关）
   │     ├── 现有 7 个 GET api.github.com（github_*）
   │     └── 本地 git（github_git_*，新模块 git_workspace.rs）
   └── zoomkey（不动）
```

对外一张卡、一个按钮、一份 `github_mcp_policy`。内部拆文件：`github_mcp.rs` 管 API GET；`git_workspace.rs` 管 CLI、路径白名单、Token 注入。

## 策略（扩展现有 `github_mcp_policy`）

```json
{
  "enabled": false,
  "clone_parent": "E:\\project",
  "workspaces": [
    {
      "id": "uuid",
      "name": "sealbox",
      "path": "E:\\project\\密码管理器",
      "credential_id": "<ApiToken id, service=github>"
    }
  ]
}
```

- `enabled=true`：7 个 API 工具 **和** `github_git_*` 一起进 `tools/list`
- 启用时 `confirm()`：将开放 GitHub 只读 API，并允许在已登记仓库直接执行 git（含 commit / push / pull / clone）
- `path` 必须绝对路径、canonicalize 后仍等于登记值、目录内有 `.git`
- `credential_id`：活动 `ApiToken { service: "github" }`；push / pull / clone 用它
- `clone_parent`：clone 只允许落到这个父目录下
- 旧策略只有 `{ enabled }`：`workspaces=[]`，API 只读不变；git 除 list 外因未登记失败

模型不能传任意磁盘路径或 Token，只能传已登记 `workspace` id（clone 除外）。

## MCP 工具名（`github_git_*`）

现有 API 工具保持：`github_list_credentials`、`github_get_authenticated_user`、`github_list_repositories`、`github_get_repository`、`github_get_file`、`github_list_issues`、`github_list_pull_requests`。

新增：

| 工具 | 作用 | git |
|---|---|---|
| `github_git_list` | 已登记工作区（id / name / 当前分支） | — |
| `github_git_status` | 分支 + porcelain | `status --porcelain=v1 -b` |
| `github_git_diff` | 默认 stat | `diff` / `diff --cached` |
| `github_git_log` | 默认 20，上限 50 | `log --oneline` |
| `github_git_branches` | 本地分支 | `branch --list` |
| `github_git_stage` | 相对路径；`all=true` → `add -A` | `add` |
| `github_git_commit` | `message` 必填 | `commit -m` |
| `github_git_push` | 当前分支 → origin | `push` |
| `github_git_pull` | 从 origin 拉并合并 | `pull`（无 rebase/force） |
| `github_git_clone` | 克隆到 `clone_parent/<name>` | `clone` |

约束：相对路径禁止 `..`；输出截断并脱敏；remote 必须 `https://github.com/...`；本机要有 `git`。

**clone：** `credential_id` + `owner` + `repo`，可选 `name`（单层 `[A-Za-z0-9._-]+`）。目标必须尚不存在。成功后自动登记为 workspace。未配 `clone_parent` 则失败。

**pull：** 只 pull 当前分支的 origin。工作区有未提交改动则拒绝。无 force / rebase。

写工具：`readOnly: false`，`risk: "high"`。

助手过滤器仍是 `readOnly && risk==low` 且 `name.starts_with("github_")`，因此 **助手能看见只读 `github_git_*`，不会调用写工具**。写工具只给 Cursor / Claude Code。

## Token 注入（push / pull / clone）

- 不改 `.git/config` remote URL
- Token 不进 argv、不回 MCP / 审计
- `GIT_TERMINAL_PROMPT=0` + 一次性 askpass / 环境交给短生命周期 helper
- 跑完清环境
- 审计：workspace id、host、branch、exit code、credential 指纹

`stage` / `commit` 不碰 Token。

## 人闸

**不做：** 每次写操作的桌面确认、oneshot、给 `mcp::start` 接 `AppHandle`。

**只做：**

1. GitHub MCP 启用时一次 `confirm()`（开关现在附带写入）
2. 金库锁定 → 全部失败
3. 路径白名单 + github.com HTTPS + 输出脱敏
4. 助手不调用写工具

误调用会真的改仓库、真的 push。靠「先登记仓库 + 开关默认关 + 助手不写」收口。

## UI（仍是现在这张 GitHub 卡）

- 说明改为：只读 API + 已登记本地仓库的 `github_git_*`
- 启用时 confirm
- 工作区列表：名称、路径、绑定 Token
- 「添加仓库」：`open({ directory: true })` + `withNativeDialog`
- 「Clone 根目录」：同样的目录选择器
- 「保存」把 workspaces / clone_parent 写回同一 policy

## 安全边界

- 仍只 `127.0.0.1` + Bearer
- 模型不能传 URL、Token、任意路径、任意 git 子命令
- 只在登记仓库根或 `clone_parent` 下新目录执行 `git`
- canonicalize，拒绝 symlink 逃逸
- 不改 `user.name` / remote / credential.helper

## 主要改动

- 新增 `src-tauri/src/git_workspace.rs`
- 扩展 `GithubMcpPolicy`；`tool_definitions()` 合并 `github_git_*`
- `mcp.rs` 路由（无确认通道）
- `commands.rs` 仍走 `github_mcp_policy_*`
- `src/lib/tauri.ts`、`src/App.vue`：GitHub 卡加工作区 / clone 根目录 / 启用确认
- spec：`docs/superpowers/specs/2026-09-18-git-workspace-mcp-design.md`，并改 2026-09-11 里「不做 Git 工作区 / MCP 写入 GitHub」
- `README.md`

## 测试

- `enabled=false`：API 与 `github_git_*` 都不出现
- 无 workspace：API 在，git 除 list 外失败
- 路径逃逸 / 非 github.com / SSH → 拒绝
- 输出无 Token；push 后 remote URL 未改
- 脏工作区拒绝 pull
- clone 写出 `clone_parent` 之外 → 拒绝
- 助手定义不含 stage/commit/push/pull/clone

## 实施顺序

1. 写 spec 并提交
2. 扩展 policy + 登记 + 路径校验
3. 只读：`github_git_list/status/diff/log/branches`
4. `github_git_stage` / `github_git_commit`
5. `github_git_push` / `github_git_pull` + Token 注入
6. `github_git_clone` + 自动登记
7. GitHub 卡 UI、启用 confirm、README
