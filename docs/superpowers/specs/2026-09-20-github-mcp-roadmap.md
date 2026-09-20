# GitHub MCP 扩展路线

日期：2026-09-20  
状态：已实现 `github_create_release`，其余接口为路线规划

## 当前能力

GitHub MCP 仍默认停用，并继续只访问固定的 `https://api.github.com:443`。启用后提供：

- 7 个低风险只读 API 工具：用户、仓库、文件、Issue、Pull Request 和凭据元数据
- 本地 `github_git_*` 工具：受限的 status / diff / log / branches 读取，以及 stage / commit / push / pull / clone 写入
- 通过独立的 `api_write_enabled` 开关控制 GitHub API 写入
- `github_create_release`：固定 POST `/repos/{owner}/{repo}/releases`

`github_create_release` 的安全约束：

- 工具标记为 `readOnly: false`、`risk: "high"`，不会进入内置助手的自动只读工具列表
- `enabled` 和 `api_write_enabled` 两个开关都必须开启
- 默认 `draft=true`，但草稿仍会在远程仓库创建 Release 对象
- 请求只接受白名单字段，不接受任意 URL、HTTP 方法、请求头或原始 JSON
- 只使用金库中活动的 GitHub API Token；Token、请求头、Release body 和完整响应不写入审计或返回给模型
- 固定使用 HTTPS、无重定向、公共地址解析、请求/响应大小限制和超时
- 创建成功必须返回 HTTP 201；审计记录仓库、tag、状态码和凭据指纹

## P0：优先补齐只读上下文

这些接口不产生远端写入，适合先增加并纳入只读工具测试：

- `github_get_pull_request`
- `github_list_pull_request_files`
- `github_list_pull_request_commits`
- `github_list_pull_request_reviews`
- `github_list_pull_request_comments`
- `github_get_pull_request_status`
- `github_list_releases`
- `github_get_release`
- `github_list_release_assets`
- `github_list_tags`
- `github_compare_commits`
- `github_list_workflows`
- `github_list_workflow_runs`
- `github_get_workflow_run`
- `github_list_workflow_jobs`

Workflow 日志和 Artifacts 即使是 GET，也可能包含部署信息或意外泄露的 Secret，建议标为 `risk: "medium"`，不要自动提供给内置助手。

## P1：普通写入

在独立写入开关和审计基础上，可以考虑：

- `github_create_pull_request`：默认 Draft，不自动合并
- `github_create_issue`
- `github_create_issue_comment`
- `github_create_pr_comment`
- `github_update_issue`

这些操作会触发通知或 Webhook，仍需明确说明和参数白名单。

## 高风险写入

以下能力必须单独设计逐次确认、仓库白名单和更完整的 HTTP mock 测试：

- `github_publish_release`
- `github_upload_release_asset` / `github_delete_release_asset`
- `github_create_tag` / `github_delete_tag`
- `github_dispatch_workflow` / `github_rerun_workflow` / `github_cancel_workflow_run`
- `github_merge_pull_request`
- GitHub Contents / Git Data 写入
- 分支、分支保护、Secrets、Webhooks 管理

Release asset 上传尤其需要单独的 `uploads.github.com:443` 域名、二进制大小限制、文件路径约束和敏感文件防泄露检查，不能复用 JSON GET/POST helper。

## 明确不做

- 不提供任意 HTTP、任意 URL、任意请求头、任意方法或任意原始请求体
- 不把 GitHub Token、主密码、金库备份、Authorization header 或完整远端响应返回给模型
- 不自动合并 PR、不 force push、不 push tag、不修改远端分支保护
- 不把高风险写工具加入内置助手的自动调用白名单
