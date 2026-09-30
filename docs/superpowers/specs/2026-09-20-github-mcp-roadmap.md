# GitHub MCP 扩展路线

日期：2026-09-20  
状态：本文件是历史台账。当前范围以 [`docs/superpowers/specs/2026-09-30-github-mcp-sigil-refactor-design.md`](2026-09-30-github-mcp-sigil-refactor-design.md) 为准。

## 当前能力

GitHub MCP 仍默认停用，并继续只访问固定的 `https://api.github.com:443`（Release 资产上传走 `uploads.github.com:443`）。启用后提供：

- 只读 API（`risk: low`）：仓库搜索与元数据、提交、分支、ref、Actions 计费、Release notes 生成、Actions 产物清单、变量（含值）、secret 名称。也包括用户、文件、Issue、Pull Request（含文件 / 提交 / review / 行内评论 / combined status）、Release 与资产清单、tag、compare、workflow 定义、单次 run 和 jobs。secret 列表不返回值；产物清单不返回下载地址
- 本地 `github_git_*`：工作区短名、status / diff / log / branches，以及 stage / commit / push / pull / clone
- 凭据可用标题匹配或 MCP 页默认 Token；仓库推荐 `owner/repo`。部分旧工具名仍保留别名（如 `github_user_info`、`github_repo_list`、`github_issue_create`），与 canonical 名指向同一实现
- 通过独立的 `api_write_enabled` 开关控制 GitHub API 写入和中风险下载；每次操作弹出桌面确认
- 写入（`risk: high`，不进入内置助手自动列表）：Issue 创建 / 更新 / 评论；PR 创建（默认草稿）与合并；只建私有仓库、更新仓库设置（拒绝改为公开）；文件创建或更新、文件删除；ref 创建与删除；Release 创建（默认草稿）、发布、删除、上传资产；workflow_dispatch 与 repository_dispatch；重跑整次 run、只重跑失败 job、取消 run；Actions 变量创建或更新、删除；secret 创建或更新
- 下载（`risk: medium`，同样受 API 写入开关和桌面确认约束）：Release 资产、Actions artifact zip、run 日志 zip。写到调用方给出的本地绝对路径，返回 path、bytes、sha256，确认框不含文件内容

写工具的安全约束：

- 工具标记为 `readOnly: false`，高风险为 `risk: "high"`，中风险下载为 `risk: "medium"`，都不会进入内置助手的自动只读工具列表
- `enabled` 和 `api_write_enabled` 两个开关都必须开启
- 默认 `draft=true`，但草稿仍会在远程仓库创建 Release 或 PR 对象
- 请求只接受白名单字段，不接受任意 URL、HTTP 方法、请求头或原始 JSON
- 只使用金库中活动的 GitHub API Token；Token、请求头、Release body、文件内容和完整响应不写入审计或返回给模型
- 固定使用 HTTPS、无重定向、公共地址解析、请求/响应大小限制和超时
- 创建类成功必须返回预期状态码；审计记录仓库、对象标识、状态码和凭据指纹

## 明确未实现

以下能力没有工具定义，文档和 UI 都不应声称它们存在：

- 删除仓库
- 分支保护
- 添加协作者
- deploy key
- Actions 启用 / 停用开关
- workflow 默认 GITHUB_TOKEN 权限

也不提供：

- 任意 HTTP、任意 URL、任意请求头、任意方法或任意原始请求体
- 把 GitHub Token、主密码、金库备份、Authorization header、secret 值或完整远端响应返回给模型
- 裸 force push（本地 git push 仅可选 force-with-lease）
- 把高风险写工具或中风险下载加入内置助手的自动调用白名单
