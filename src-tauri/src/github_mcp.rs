use crate::http_guard::{assert_public_target, parse_http_url, sha256_hex, PublicResolver};
use crate::redact::redact_text;
use crate::session::Session;
use crate::vault::{SecretPayload, Vault};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::io::Read;
use std::time::Duration;

const POLICY_KEY: &str = "github_mcp_policy";
const API_BASE: &str = "https://api.github.com";
const API_VERSION: &str = "2022-11-28";
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_CONTENT_BYTES: usize = 64 * 1024;
const MAX_FILE_PUT_BYTES: usize = 48 * 1024;
const MAX_DESCRIPTION_BYTES: usize = 2 * 1024;
const MAX_RELEASE_BODY_BYTES: usize = 64 * 1024;
const MAX_RELEASE_TAG_CHARS: usize = 200;
const MAX_PAGE_SIZE: u64 = 50;
const ELLIPSIS: &str = "…";

#[derive(Clone, Debug, Default)]
pub struct GithubAuditContext {
    pub repository: Option<String>,
    pub path: Option<String>,
    pub reference: Option<String>,
}

#[derive(Clone, Debug)]
pub struct GithubCallResult {
    pub text: String,
    pub status: u16,
    pub result_count: Option<usize>,
    pub credential_fingerprint: String,
    pub context: GithubAuditContext,
}

#[derive(Clone, Debug)]
pub struct GithubCallError {
    pub message: String,
    pub status: Option<u16>,
    pub reason: &'static str,
    pub credential_fingerprint: Option<String>,
    pub context: GithubAuditContext,
}

impl GithubCallError {
    fn validation(message: impl Into<String>, context: GithubAuditContext) -> Self {
        Self {
            message: message.into(),
            status: None,
            reason: "validation",
            credential_fingerprint: None,
            context,
        }
    }
}

impl From<String> for GithubCallError {
    fn from(message: String) -> Self {
        Self::validation(message, GithubAuditContext::default())
    }
}

impl From<&str> for GithubCallError {
    fn from(message: &str) -> Self {
        Self::validation(message, GithubAuditContext::default())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GithubWorkspace {
    pub name: String,
    pub path: String,
    pub default_credential_id: Option<String>,
}

impl Default for GithubWorkspace {
    fn default() -> Self {
        Self {
            name: String::new(),
            path: String::new(),
            default_credential_id: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GithubMcpPolicy {
    pub enabled: bool,
    pub api_write_enabled: bool,
    pub default_credential_id: Option<String>,
    pub workspaces: Vec<GithubWorkspace>,
}

impl Default for GithubMcpPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            api_write_enabled: false,
            default_credential_id: None,
            workspaces: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct GithubCredentialMeta {
    pub id: String,
    pub title: String,
    pub account: Option<String>,
    pub is_default: bool,
}

#[derive(Clone, Debug)]
pub struct ResolvedGithubCredential {
    pub id: String,
    pub title: String,
    pub token: String,
}

fn credential_prop() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 100,
        "description": "GitHub Token 的标题、账号或 ID。可省略：使用 MCP 页的默认 Token；若金库里只有一个 GitHub Token 则自动选用。"
    })
}

fn credential_id_prop() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 100,
        "description": "兼容旧参数，等同于 credential。"
    })
}

fn repo_prop() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 201,
        "description": "仓库，推荐 owner/repo，例如 hahaha-taotao/sealbox。也兼容 https://github.com/owner/repo，或与 owner 字段拆开填写。"
    })
}

#[derive(Clone, Debug, Serialize)]
struct GithubUserDto {
    id: Option<i64>,
    login: Option<String>,
    name: Option<String>,
    company: Option<String>,
    blog: Option<String>,
    html_url: Option<String>,
    public_repos: Option<i64>,
    private_repos: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubOwnerDto {
    login: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubRepositoryDto {
    id: Option<i64>,
    full_name: Option<String>,
    name: Option<String>,
    owner: GithubOwnerDto,
    private: Option<bool>,
    fork: Option<bool>,
    default_branch: Option<String>,
    html_url: Option<String>,
    description: Option<String>,
    updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubIssueDto {
    number: Option<i64>,
    title: Option<String>,
    state: Option<String>,
    html_url: Option<String>,
    user: GithubOwnerDto,
    labels: Vec<String>,
    assignees: Vec<String>,
    comments: Option<i64>,
    created_at: Option<String>,
    updated_at: Option<String>,
    closed_at: Option<String>,
    body: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubRefDto {
    #[serde(rename = "ref")]
    git_ref: Option<String>,
    sha: Option<String>,
    repo: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubPullDto {
    number: Option<i64>,
    title: Option<String>,
    state: Option<String>,
    html_url: Option<String>,
    user: GithubOwnerDto,
    labels: Vec<String>,
    assignees: Vec<String>,
    requested_reviewers: Vec<String>,
    draft: Option<bool>,
    mergeable: Option<bool>,
    mergeable_state: Option<String>,
    head: GithubRefDto,
    base: GithubRefDto,
    created_at: Option<String>,
    updated_at: Option<String>,
    body: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubWorkflowRunDto {
    id: Option<i64>,
    name: Option<String>,
    display_title: Option<String>,
    status: Option<String>,
    conclusion: Option<String>,
    event: Option<String>,
    head_branch: Option<String>,
    head_sha: Option<String>,
    html_url: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubFileDto {
    path: Option<String>,
    sha: Option<String>,
    size: Option<u64>,
    content: Option<String>,
    is_binary: bool,
    truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
struct GithubPullFileDto {
    filename: Option<String>,
    status: Option<String>,
    additions: Option<i64>,
    deletions: Option<i64>,
    changes: Option<i64>,
    sha: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubCommitDto {
    sha: Option<String>,
    message: Option<String>,
    author: Option<String>,
    html_url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubReviewDto {
    id: Option<i64>,
    user: Option<String>,
    state: Option<String>,
    submitted_at: Option<String>,
    body: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubReviewCommentDto {
    id: Option<i64>,
    user: Option<String>,
    path: Option<String>,
    line: Option<i64>,
    side: Option<String>,
    body: Option<String>,
    html_url: Option<String>,
    created_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubStatusContextDto {
    context: Option<String>,
    state: Option<String>,
    description: Option<String>,
    target_url: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubTagDto {
    name: Option<String>,
    sha: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubReleaseAssetDto {
    id: Option<i64>,
    name: Option<String>,
    size: Option<i64>,
    content_type: Option<String>,
    download_count: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubWorkflowDto {
    id: Option<i64>,
    name: Option<String>,
    path: Option<String>,
    state: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubWorkflowStepDto {
    name: Option<String>,
    status: Option<String>,
    conclusion: Option<String>,
    number: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubWorkflowJobDto {
    id: Option<i64>,
    name: Option<String>,
    status: Option<String>,
    conclusion: Option<String>,
    html_url: Option<String>,
    steps: Vec<GithubWorkflowStepDto>,
}

#[derive(Clone, Debug, Serialize)]
struct GithubReleaseDto {
    id: Option<i64>,
    tag_name: Option<String>,
    name: Option<String>,
    target_commitish: Option<String>,
    draft: Option<bool>,
    prerelease: Option<bool>,
    html_url: Option<String>,
    created_at: Option<String>,
    published_at: Option<String>,
}

pub fn canonical_tool_name(name: &str) -> &str {
    match name {
        "github_get_authenticated_user" => "github_user_info",
        "github_list_repositories" => "github_repo_list",
        "github_get_repository" => "github_repo_get",
        "github_get_file" => "github_file_get",
        "github_list_issues" => "github_issues_list",
        "github_list_pull_requests" => "github_pulls_list",
        "github_create_issue" => "github_issue_create",
        "github_create_issue_comment" => "github_issue_comment",
        "github_create_pull_request" => "github_pr_create",
        "github_create_release" => "github_release_create",
        "github_list_releases" => "github_release_list",
        "github_get_release" => "github_release_get",
        "github_list_tags" => "github_tags_list",
        "github_list_workflows" => "github_workflow_list",
        "github_list_workflow_runs" => "github_runs_list",
        "github_get_workflow_run" => "github_run_get",
        "github_list_workflow_jobs" => "github_run_jobs",
        other => other,
    }
}

pub fn api_tool_definitions() -> Vec<Value> {
    with_legacy_aliases(vec![
        tool(
            "github_list_credentials",
            "列出本地活动 GitHub Token 的标题、账号和是否为默认凭据。回答「我有哪些 GitHub Token / 该用哪条凭据」时调用。日常读写不必先调这个：可直接传标题，或省略后使用默认 Token。永不返回 Token 明文。",
            schema(&[], &[]),
        ),
        tool(
            "github_get_authenticated_user",
            "读取当前 GitHub 账号的 login、姓名、公开/私有仓库数。回答「我是谁 / 这个 Token 属于哪个账号」时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                ],
                &[],
            ),
        ),
        tool(
            "github_list_repositories",
            "列出当前 Token 可见的仓库（full_name、默认分支、私有与否）。回答「我有多少 GitHub 仓库 / 列出我的仓库」时调用。默认只看自己拥有的仓库。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("type", json!({"type":"string","enum":["all","owner","public","private","member"],"description":"仓库范围，原样传给 GitHub type 参数"})),
                    ("visibility", json!({"type":"string","enum":["all","public","private"],"default":"all"})),
                    ("affiliation", json!({"type":"string","enum":["owner","collaborator","organization_member"],"default":"owner"})),
                    ("sort", json!({"type":"string","enum":["created","updated","pushed","full_name"]})),
                    ("direction", json!({"type":"string","enum":["asc","desc"]})),
                    ("name_contains", string_schema(1, 200)),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &[],
            ),
        ),
        tool(
            "github_repo_search",
            "按关键词搜索 GitHub 仓库（服务端搜索）。回答「有没有叫 X 的仓库」时调用。只返回仓库摘要，不含源码。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("q", string_schema(1, 256)),
                    ("sort", json!({"type":"string","enum":["stars","forks","help-wanted-issues","updated"]})),
                    ("order", json!({"type":"string","enum":["asc","desc"]})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["q"],
            ),
        ),
        tool(
            "github_get_repository",
            "读取单个仓库的元数据：默认分支、是否私有、描述、更新时间。需要确认某个 owner/repo 是否存在或默认分支是什么时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_get_file",
            "读取 GitHub 仓库里的单个文本文件（README、工作流 YAML 等）。需要看远端文件内容而不是本地工作区时调用。目录会报错。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("path", string_schema(1, 500)),
                    ("ref", string_schema(1, 200)),
                ],
                &["repo", "path"],
            ),
        ),
        tool(
            "github_list_issues",
            "列出仓库 Issue（不含 PR）：编号、标题、状态、标签、指派人、评论数。回答「这个仓库有哪些未关闭 Issue」时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("state", json!({"type":"string","enum":["open","closed","all"],"default":"open"})),
                    ("labels", string_schema(1, 400)),
                    ("assignee", string_schema(1, 100)),
                    ("creator", string_schema(1, 100)),
                    ("since", string_schema(1, 40)),
                    ("sort", json!({"type":"string","enum":["created","updated","comments"]})),
                    ("direction", json!({"type":"string","enum":["asc","desc"]})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_commits_list",
            "列出仓库提交：SHA、截断后的说明、作者登录名和链接。需要看某条分支最近提交时调用。不含 patch。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("sha", string_schema(1, 200)),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_branches_list",
            "列出仓库分支名、顶端 SHA 和是否受保护。不含提交内容。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_ref_get",
            "读取一个 git ref 指向的 commit SHA。git_ref 用 heads/main 或 tags/v1.0.0，也可带 refs/ 前缀。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("git_ref", string_schema(1, 200)),
                ],
                &["repo", "git_ref"],
            ),
        ),
        tool(
            "github_billing_actions",
            "查询 GitHub Actions 用量。不传 year 和 month 时是本年至今，不是当月；要当月用量必须同时传 year 和 month。没有剩余分钟数字段。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("account", string_schema(1, 100)),
                    ("is_org", json!({"type":"boolean","default":false})),
                    ("year", json!({"type":"integer","minimum":2020,"maximum":2100})),
                    ("month", json!({"type":"integer","minimum":1,"maximum":12})),
                ],
                &[],
            ),
        ),
        tool(
            "github_list_pull_requests",
            "列出仓库 Pull Request：编号、标题、draft、head/base、mergeable、指派人和 requested reviewers。回答「有哪些未合并 PR / 这个 PR 能不能合」时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("state", json!({"type":"string","enum":["open","closed","all"],"default":"open"})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_get_pull_request",
            "读取单个 PR 的完整协作状态：draft、head/base SHA、mergeable、reviewers。需要判断某个 PR 能否合并或当前基于哪条分支时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                ],
                &["repo", "number"],
            ),
        ),
        tool(
            "github_list_workflow_runs",
            "列出仓库最近的 GitHub Actions 运行：status、conclusion、head_branch、html_url。轮询 CI / 发布流水线状态时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("branch", string_schema(1, 200)),
                    ("status", json!({"type":"string","enum":["queued","in_progress","completed"]})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":20})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_list_pull_request_files",
            "列出某个 PR 改了哪些文件：filename、status、增删行数、blob SHA。看 diff 范围时调用。不含 patch 全文。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo", "number"],
            ),
        ),
        tool(
            "github_list_pull_request_commits",
            "列出某个 PR 的 commit SHA、标题和作者。需要把 PR 和本地提交对上时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo", "number"],
            ),
        ),
        tool(
            "github_list_pull_request_reviews",
            "列出某个 PR 的 review：state、提交者、提交时间。判断谁批准或要求修改时调用。不含 review 正文全文。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo", "number"],
            ),
        ),
        tool(
            "github_list_pull_request_comments",
            "列出某个 PR 的行内评论：path、line、用户、截断后的正文。看 review 讨论时调用。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo", "number"],
            ),
        ),
        tool(
            "github_get_pull_request_status",
            "读取 PR head 或指定 ref 的 combined status：state 与各 context。判断 CI 是否通过时调用。不返回日志。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("ref", string_schema(1, 200)),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_list_releases",
            "列出仓库 Release：tag、名称、是否草稿、是否预发布、html_url。不含 body 全文，也不含资产文件。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_get_release",
            "读取单个 Release 的元数据。传 id 或 tag_name 之一。不含 body，不含资产二进制。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                    ("tag_name", string_schema(1, 200)),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_list_release_assets",
            "列出某个 Release 的资产名、大小、content_type 和下载次数。不下载文件。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                ],
                &["repo", "id"],
            ),
        ),
        tool(
            "github_list_tags",
            "列出仓库 tag 名和对应 commit SHA。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_compare_commits",
            "比较 base 与 head：ahead/behind、提交数和文件名列表。不含 patch 全文。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("base", string_schema(1, 200)),
                    ("head", string_schema(1, 200)),
                ],
                &["repo", "base", "head"],
            ),
        ),
        tool(
            "github_list_workflows",
            "列出仓库 Actions workflow：id、name、path、state。不含 workflow 文件内容。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("page", json!({"type":"integer","minimum":1,"maximum":100,"default":1})),
                    ("per_page", json!({"type":"integer","minimum":1,"maximum":50,"default":30})),
                ],
                &["repo"],
            ),
        ),
        tool(
            "github_get_workflow_run",
            "读取单次 workflow run：status、conclusion、head_sha、head_branch、html_url。不含日志。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("run_id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                ],
                &["repo", "run_id"],
            ),
        ),
        tool(
            "github_list_workflow_jobs",
            "列出某次 run 的 jobs：name、status、conclusion，以及各 step 的名称和结论。不含日志。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("run_id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                ],
                &["repo", "run_id"],
            ),
        ),
        write_tool(
            "github_create_issue",
            "在仓库创建 Issue。用户说「帮我开一个 bug / 功能单」时调用。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("title", string_schema(1, 256)),
                    ("body", string_schema(0, MAX_RELEASE_BODY_BYTES as u64)),
                    ("labels", json!({"type":"string","minLength":1,"maxLength":400,"description":"逗号分隔的标签名"})),
                ],
                &["repo", "title"],
            ),
        ),
        write_tool(
            "github_create_issue_comment",
            "在已有 Issue 或 PR 下追加一条评论。需要回复 Issue/PR 时调用。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("body", string_schema(1, MAX_RELEASE_BODY_BYTES as u64)),
                ],
                &["repo", "number", "body"],
            ),
        ),
        write_tool(
            "github_create_pull_request",
            "从 head 分支向 base 开 PR。用户说「帮我提 PR」时调用。默认 draft=true。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("title", string_schema(1, 256)),
                    ("head", string_schema(1, 200)),
                    ("base", string_schema(1, 200)),
                    ("body", string_schema(0, MAX_RELEASE_BODY_BYTES as u64)),
                    ("draft", json!({"type":"boolean","default":true})),
                ],
                &["repo", "title", "head", "base"],
            ),
        ),
        write_tool(
            "github_issue_update",
            "更新已有 Issue 的状态、标题、正文或标签。只发送调用方提供的字段。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("state", json!({"type":"string","enum":["open","closed"]})),
                    ("title", string_schema(1, 256)),
                    ("body", string_schema(0, MAX_RELEASE_BODY_BYTES as u64)),
                    ("labels", json!({"type":"string","minLength":1,"maxLength":400,"description":"逗号分隔的标签名"})),
                ],
                &["repo", "number"],
            ),
        ),
        write_tool(
            "github_pr_merge",
            "合并一个 Pull Request。merge_method 只能是 merge、squash 或 rebase，默认 merge。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("number", json!({"type":"integer","minimum":1,"maximum":1000000000})),
                    ("merge_method", json!({"type":"string","enum":["merge","squash","rebase"],"default":"merge"})),
                ],
                &["repo", "number"],
            ),
        ),
        write_tool(
            "github_repo_create",
            "在当前账号下创建私有仓库。拒绝 private=false。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("name", string_schema(1, 100)),
                    ("description", string_schema(0, 2048)),
                    ("private", json!({"type":"boolean"})),
                ],
                &["name"],
            ),
        ),
        write_tool(
            "github_repo_update",
            "更新仓库设置。只发送调用方提供的字段。拒绝把仓库改为公开。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("description", string_schema(0, 2048)),
                    ("homepage", string_schema(0, 2048)),
                    ("default_branch", string_schema(1, 200)),
                    ("private", json!({"type":"boolean"})),
                    ("has_issues", json!({"type":"boolean"})),
                    ("has_wiki", json!({"type":"boolean"})),
                    ("has_projects", json!({"type":"boolean"})),
                    ("archived", json!({"type":"boolean"})),
                ],
                &["repo"],
            ),
        ),
        write_tool(
            "github_file_put",
            "创建或更新仓库文件（PUT /repos/{owner}/{repo}/contents/{path}）。content 为明文，最多 48 KiB，会编码成 Base64 再提交。新建不要传 sha；更新必须传 40 位 sha；空字符串会拒绝。每次都会弹出 Sealbox 桌面确认，确认框不含文件内容。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("path", string_schema(1, 500)),
                    ("content", string_schema(0, MAX_FILE_PUT_BYTES as u64)),
                    ("message", string_schema(1, 256)),
                    ("sha", string_schema(40, 40)),
                    ("branch", string_schema(1, 200)),
                ],
                &["repo", "path", "content", "message"],
            ),
        ),
        write_tool(
            "github_file_delete",
            "删除仓库文件（DELETE /repos/{owner}/{repo}/contents/{path}）。必须提供当前文件的 40 位 sha。每次都会弹出 Sealbox 桌面确认，确认框不含文件内容。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("path", string_schema(1, 500)),
                    ("message", string_schema(1, 256)),
                    ("sha", string_schema(40, 40)),
                    ("branch", string_schema(1, 200)),
                ],
                &["repo", "path", "message", "sha"],
            ),
        ),
        write_tool(
            "github_ref_create",
            "创建 git ref（POST /repos/{owner}/{repo}/git/refs）。git_ref 为 heads/分支 或 tags/标签，也可带 refs/ 前缀。sha 必须是 40 位十六进制。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("git_ref", string_schema(1, 200)),
                    ("sha", string_schema(40, 40)),
                ],
                &["repo", "git_ref", "sha"],
            ),
        ),
        write_tool(
            "github_ref_delete",
            "删除 git ref（DELETE /repos/{owner}/{repo}/git/refs/{ref}）。git_ref 为 heads/分支 或 tags/标签。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("git_ref", string_schema(1, 200)),
                ],
                &["repo", "git_ref"],
            ),
        ),
        tool(
            "github_release_generate_notes",
            "根据 tag 生成建议的 Release 标题和正文，不会创建 Release。body 最多返回 64 KiB。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("tag_name", string_schema(1, MAX_RELEASE_TAG_CHARS as u64)),
                    ("previous_tag_name", string_schema(1, MAX_RELEASE_TAG_CHARS as u64)),
                    ("target_commitish", string_schema(1, 200)),
                ],
                &["repo", "tag_name"],
            ),
        ),
        tool(
            "github_run_artifacts",
            "列出某次 Actions run 的产物：id、名称、字节数、是否过期。不返回下载地址。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("run_id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                ],
                &["repo", "run_id"],
            ),
        ),
        tool(
            "github_repo_variable_list",
            "列出仓库 Actions 变量的名称、值和更新时间。变量是非机密配置。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                ],
                &["repo"],
            ),
        ),
        write_tool(
            "github_release_publish",
            "把草稿 Release 正式发布（draft=false）。可同时改名称、正文或 prerelease。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                    ("name", string_schema(1, 200)),
                    ("body", string_schema(0, MAX_RELEASE_BODY_BYTES as u64)),
                    ("prerelease", json!({"type":"boolean"})),
                ],
                &["repo", "id"],
            ),
        ),
        write_tool(
            "github_release_delete",
            "删除一个 Release，不删除对应 tag。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                ],
                &["repo", "id"],
            ),
        ),
        write_tool(
            "github_release_asset_upload",
            "把本地文件上传为 Release 资产。文件名只允许字母、数字、点、下划线和连字符。每次都会弹出 Sealbox 桌面确认，确认框不含文件内容。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                    ("file_path", string_schema(1, 1024)),
                    ("file_name", string_schema(1, 120)),
                    ("content_type", string_schema(1, 200)),
                ],
                &["repo", "id", "file_path"],
            ),
        ),
        write_tool(
            "github_workflow_dispatch",
            "手动触发 workflow_dispatch。workflow 是文件名或数字 id。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("workflow", string_schema(1, 200)),
                    ("git_ref", string_schema(1, 200)),
                    ("inputs", json!({"type":"object"})),
                ],
                &["repo", "workflow", "git_ref"],
            ),
        ),
        write_tool(
            "github_repository_dispatch",
            "发送 repository_dispatch 事件。每次都会弹出 Sealbox 桌面确认，确认框不含 payload。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("event_type", string_schema(1, 100)),
                    ("client_payload", json!({"type":"object"})),
                ],
                &["repo", "event_type"],
            ),
        ),
        write_tool(
            "github_run_rerun",
            "重跑某次 GitHub Actions run。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("run_id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                ],
                &["repo", "run_id"],
            ),
        ),
        write_tool(
            "github_rerun_failed_jobs",
            "只重跑某次 Actions run 里失败的 job。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("run_id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                ],
                &["repo", "run_id"],
            ),
        ),
        write_tool(
            "github_run_cancel",
            "取消正在运行的 Actions run。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("run_id", json!({"type":"integer","minimum":1,"maximum":9007199254740991u64})),
                ],
                &["repo", "run_id"],
            ),
        ),
        write_tool(
            "github_repo_variable_set",
            "创建或更新仓库 Actions 变量。已存在则更新，不存在则创建。每次都会弹出 Sealbox 桌面确认，确认框不含变量值。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("name", string_schema(1, 64)),
                    ("value", string_schema(0, 4096)),
                ],
                &["repo", "name", "value"],
            ),
        ),
        write_tool(
            "github_repo_variable_delete",
            "删除仓库 Actions 变量。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("name", string_schema(1, 64)),
                ],
                &["repo", "name"],
            ),
        ),
        write_tool(
            "github_create_release",
            "在仓库创建 Release。用户说「打一个 GitHub Release」时调用。默认 draft=true。每次都会弹出 Sealbox 桌面确认。",
            schema(
                &[
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", repo_prop()),
                    ("owner", string_schema(1, 100)),
                    ("tag_name", string_schema(1, MAX_RELEASE_TAG_CHARS as u64)),
                    ("target_commitish", string_schema(1, 200)),
                    ("name", string_schema(1, 200)),
                    ("body", string_schema(0, MAX_RELEASE_BODY_BYTES as u64)),
                    ("draft", json!({"type":"boolean","default":true})),
                    ("prerelease", json!({"type":"boolean","default":false})),
                    ("generate_release_notes", json!({"type":"boolean","default":false})),
                    ("make_latest", json!({"type":"string","enum":["true","false","legacy"],"default":"legacy"})),
                ],
                &["repo", "tag_name"],
            ),
        ),
    ])
}

fn with_legacy_aliases(definitions: Vec<Value>) -> Vec<Value> {
    let mut tools = Vec::with_capacity(definitions.len() * 2);
    for definition in definitions {
        let name = definition
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let canonical = canonical_tool_name(&name);
        if canonical != name {
            let mut alias = definition.clone();
            alias["name"] = Value::String(canonical.to_string());
            tools.push(alias);
        }
        tools.push(definition);
    }
    tools
}

pub fn tool_definitions() -> Vec<Value> {
    let mut tools = api_tool_definitions();
    tools.extend(crate::git_workspace::tool_definitions());
    tools
}

pub fn tool_definitions_for_policy(policy: &GithubMcpPolicy) -> Vec<Value> {
    let mut tools = crate::git_workspace::tool_definitions();
    tools.extend(api_tool_definitions().into_iter().filter(|definition| {
        definition["readOnly"].as_bool().unwrap_or(false) || policy.api_write_enabled
    }));
    tools
}

fn string_schema(minimum: u64, maximum: u64) -> Value {
    json!({"type":"string","minLength":minimum,"maxLength":maximum})
}

fn schema(properties: &[(&str, Value)], required: &[&str]) -> Value {
    let mut props = Map::new();
    for (name, value) in properties {
        props.insert((*name).to_string(), value.clone());
    }
    json!({
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": false
    })
}

pub(crate) fn annotations(read_only: bool, destructive: bool) -> Value {
    json!({
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": read_only,
        "openWorldHint": true
    })
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "readOnly": true,
        "risk": "low",
        "annotations": annotations(true, false)
    })
}

fn write_tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "readOnly": false,
        "risk": "high",
        "annotations": annotations(false, true)
    })
}

pub fn is_github_api_tool(name: &str) -> bool {
    api_tool_definitions()
        .iter()
        .any(|definition| definition.get("name").and_then(Value::as_str) == Some(name))
}

pub fn is_github_tool(name: &str) -> bool {
    is_github_api_tool(name) || crate::git_workspace::is_git_tool(name)
}

pub fn load_policy(vault: &Vault, dek: &[u8; 32]) -> GithubMcpPolicy {
    let Some(raw) = vault.get_secret_setting(dek, POLICY_KEY).ok().flatten() else {
        return GithubMcpPolicy::default();
    };
    let Ok(value) = serde_json::from_str::<Value>(&raw) else {
        return GithubMcpPolicy::default();
    };
    if value.get("scopes").is_some() || value.get("allowed_repositories").is_some() {
        return GithubMcpPolicy::default();
    }
    let mut value = value;
    if value.get("default_credential_id").is_none() {
        if let Some(legacy) = value.get("credential_id").cloned() {
            if let Some(object) = value.as_object_mut() {
                object.insert("default_credential_id".into(), legacy);
            }
        }
    }
    normalize_policy(serde_json::from_value(value).unwrap_or_default()).unwrap_or_default()
}

pub fn save_policy(vault: &Vault, dek: &[u8; 32], policy: &GithubMcpPolicy) -> Result<(), String> {
    let normalized = normalize_policy(policy.clone())?;
    let raw = serde_json::to_string(&normalized).map_err(|e| e.to_string())?;
    vault
        .set_secret_setting(dek, POLICY_KEY, &raw)
        .map_err(|e| e.to_string())
}

pub fn normalize_policy(policy: GithubMcpPolicy) -> Result<GithubMcpPolicy, String> {
    let mut names = std::collections::HashSet::new();
    let mut workspaces = Vec::new();
    for workspace in policy.workspaces {
        let name = normalize_workspace_name(&workspace.name)?;
        if !names.insert(name.clone()) {
            return Err(format!("工作区短名重复：{name}"));
        }
        let path = workspace.path.trim().to_string();
        if path.is_empty() {
            return Err(format!("工作区 {name} 缺少绝对路径"));
        }
        let path_buf = std::path::PathBuf::from(&path);
        if !path_buf.is_absolute() {
            return Err(format!("工作区 {name} 的 path 必须是绝对路径"));
        }
        let default_credential_id = workspace
            .default_credential_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        workspaces.push(GithubWorkspace {
            name,
            path,
            default_credential_id,
        });
    }
    let default_credential_id = policy
        .default_credential_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    Ok(GithubMcpPolicy {
        enabled: policy.enabled,
        api_write_enabled: policy.enabled && policy.api_write_enabled,
        default_credential_id,
        workspaces,
    })
}

pub fn normalize_workspace_name(raw: &str) -> Result<String, String> {
    let name = raw.trim();
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return Err("工作区短名只能是字母、数字、下划线或连字符".into());
    }
    Ok(name.to_string())
}

pub fn list_credentials(session: &Session) -> Result<Vec<GithubCredentialMeta>, String> {
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    let entries = vault
        .list_entries(&crate::vault::ListFilter {
            kind: Some(crate::vault::EntryKind::ApiToken),
            ..Default::default()
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for entry in entries {
        let Ok(SecretPayload::ApiToken {
            service, account, ..
        }) = vault.get_active_secret(dek, &entry.id)
        else {
            continue;
        };
        if service.trim().eq_ignore_ascii_case("github") {
            out.push(GithubCredentialMeta {
                id: entry.id,
                title: entry.title,
                account,
                is_default: false,
            });
        }
    }
    if let Ok(policy) = session
        .vault()
        .and_then(|vault| session.dek().map(|dek| load_policy(vault, dek)))
    {
        if let Some(default_id) = policy.default_credential_id.as_deref() {
            for item in &mut out {
                item.is_default = item.id == default_id;
            }
        } else if out.len() == 1 {
            out[0].is_default = true;
        }
    }
    Ok(out)
}

pub fn resolve_github_credential(
    session: &Session,
    args: &Value,
) -> Result<ResolvedGithubCredential, String> {
    let requested = args
        .get("credential")
        .or_else(|| args.get("credential_id"))
        .or_else(|| args.get("credential_name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let credentials = list_credentials(session)?;
    if credentials.is_empty() {
        return Err(
            "金库里没有活动的 GitHub API Token。请先在保险库新建一条服务为 github 的 API Token。"
                .into(),
        );
    }
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    let policy = load_policy(vault, dek);
    let selected = if let Some(requested) = requested {
        match_credential(&credentials, requested)?
    } else if let Some(default_id) = policy.default_credential_id.as_deref() {
        credentials
            .iter()
            .find(|item| item.id == default_id)
            .ok_or_else(|| "MCP 页选择的默认 GitHub Token 已不存在，请重新选择".to_string())?
    } else if credentials.len() == 1 {
        &credentials[0]
    } else {
        let titles = credentials
            .iter()
            .map(|item| {
                if item.account.as_deref().unwrap_or("").is_empty() {
                    item.title.clone()
                } else {
                    format!("{} ({})", item.title, item.account.as_deref().unwrap_or(""))
                }
            })
            .collect::<Vec<_>>()
            .join("、");
        return Err(format!(
            "有多条 GitHub Token，请传 credential=标题，或在 Sealbox MCP 页选定默认 Token。可选：{titles}"
        ));
    };
    token_from_id(session, &selected.id).map(|token| ResolvedGithubCredential {
        id: selected.id.clone(),
        title: selected.title.clone(),
        token,
    })
}

fn match_credential<'a>(
    credentials: &'a [GithubCredentialMeta],
    requested: &str,
) -> Result<&'a GithubCredentialMeta, String> {
    if let Some(exact_id) = credentials.iter().find(|item| item.id == requested) {
        return Ok(exact_id);
    }
    let lowered = requested.to_ascii_lowercase();
    let mut matches = credentials
        .iter()
        .filter(|item| {
            item.title.eq_ignore_ascii_case(requested)
                || item
                    .account
                    .as_deref()
                    .is_some_and(|account| account.eq_ignore_ascii_case(requested))
        })
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        return Ok(matches[0]);
    }
    if matches.is_empty() {
        matches = credentials
            .iter()
            .filter(|item| {
                item.title.to_ascii_lowercase().contains(&lowered)
                    || item
                        .account
                        .as_deref()
                        .is_some_and(|account| account.to_ascii_lowercase().contains(&lowered))
            })
            .collect();
    }
    match matches.as_slice() {
        [only] => Ok(*only),
        [] => Err(format!(
            "找不到 GitHub Token「{requested}」。先调 github_list_credentials，或在 MCP 页选定默认 Token。"
        )),
        many => {
            let titles = many
                .iter()
                .map(|item| item.title.as_str())
                .collect::<Vec<_>>()
                .join("、");
            Err(format!("有多条 GitHub Token 匹配「{requested}」：{titles}。请改用更精确的标题或 ID。"))
        }
    }
}

pub fn token_from_id(session: &Session, credential_id: &str) -> Result<String, String> {
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    let payload = vault
        .get_active_secret(dek, credential_id)
        .map_err(|_| "GitHub Token 不存在或已在回收站".to_string())?;
    let SecretPayload::ApiToken { service, token, .. } = payload else {
        return Err("凭据必须是 GitHub API Token".into());
    };
    if !service.trim().eq_ignore_ascii_case("github") {
        return Err("凭据不是 GitHub API Token".into());
    }
    if token.trim().is_empty() {
        return Err("GitHub Token 不能为空".into());
    }
    Ok(token)
}

pub fn call_tool(session: &mut Session, name: &str, args: Value) -> Result<String, String> {
    call_tool_detailed(session, name, args)
        .map(|result| result.text)
        .map_err(|error| error.message)
}

pub fn call_tool_detailed(
    session: &mut Session,
    name: &str,
    args: Value,
) -> Result<GithubCallResult, GithubCallError> {
    let context = audit_context(&args);
    let fingerprint = github_credential_fingerprint(session, &args);
    match call_tool_text(session, name, args) {
        Ok((status, text)) => {
            let result_count = serde_json::from_str::<Value>(&text).ok().and_then(|value| {
                value
                    .get("items")
                    .or_else(|| value.get("repositories"))
                    .or_else(|| value.get("workflow_runs"))
                    .and_then(Value::as_array)
                    .map(Vec::len)
            });
            Ok(GithubCallResult {
                text,
                status,
                result_count,
                credential_fingerprint: fingerprint.unwrap_or_default(),
                context,
            })
        }
        Err(raw) => {
            let (status, parsed_reason, message) = parse_call_error(&raw);
            let reason = if raw == "GitHub MCP 能力未启用" {
                "disabled"
            } else if raw.contains("用户拒绝") {
                "denied"
            } else {
                parsed_reason
            };
            Err(GithubCallError {
                message,
                status,
                reason,
                credential_fingerprint: fingerprint,
                context,
            })
        }
    }
}

fn call_tool_text(session: &mut Session, name: &str, args: Value) -> Result<(u16, String), String> {
    if crate::git_workspace::is_git_tool(name) {
        return crate::git_workspace::call_tool_text(session, name, args).map(|text| (200, text));
    }
    if name == "github_list_credentials" {
        let definition = tool_definitions()
            .into_iter()
            .find(|definition| definition.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| "未知 GitHub 工具".to_string())?;
        validate_arguments(&definition["inputSchema"], &args)?;
        let vault = session.vault().map_err(|e| e.to_string())?;
        let dek = session.dek().map_err(|e| e.to_string())?;
        if !load_policy(vault, dek).enabled {
            return Err("GitHub MCP 能力未启用".into());
        }
        let credentials = list_credentials(session)?;
        session.touch();
        return serde_json::to_string_pretty(&credentials)
            .map(|text| (200, text))
            .map_err(|e| e.to_string());
    }
    let name = if name.starts_with("github_git_") {
        name
    } else {
        canonical_tool_name(name)
    };
    let (token, credential_label) = prepare(session, name, &args)?;
    let (status, result) = match name {
        "github_release_generate_notes" => {
            let repository = repository_args(&args)?;
            let tag_name = release_tag_arg(&args)?;
            let previous = optional_release_tag(&args, "previous_tag_name")?;
            let target = optional_release_string(&args, "target_commitish", 200)?;
            if let Some(value) = target.as_deref() {
                reject_dot_dot(value, "target_commitish")?;
            }
            let mut request = Map::new();
            request.insert("tag_name".into(), Value::String(tag_name));
            if let Some(value) = previous {
                request.insert("previous_tag_name".into(), Value::String(value));
            }
            if let Some(value) = target {
                request.insert("target_commitish".into(), Value::String(value));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path: format!("/repos/{repository}/releases/generate-notes"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(Value::Object(request))),
                    ok: &[200],
                    allow_missing_confirm: true,
                },
                None,
            )?;
            Ok((status, generate_notes_dto(&value)))
        }
        "github_release_publish" => {
            let repository = repository_args(&args)?;
            let id = positive_id(&args, "id")?;
            let name = optional_release_string(&args, "name", 200)?;
            let body = optional_release_body(&args)?;
            let mut request = Map::new();
            request.insert("draft".into(), Value::Bool(false));
            if let Some(value) = name {
                request.insert("name".into(), Value::String(value));
            }
            if let Some(value) = body {
                request.insert("body".into(), Value::String(value));
            }
            if args.get("prerelease").is_some() {
                request.insert("prerelease".into(), Value::Bool(bool_arg(&args, "prerelease", false)?));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Patch,
                    path: format!("/repos/{repository}/releases/{id}"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(Value::Object(request))),
                    ok: &[200],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "发布 GitHub Release".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("release id".into(), id.to_string()),
                    ],
                }),
            )?;
            let dto = release_dto(&value).ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
            Ok((status, dto))
        }
        "github_release_delete" => {
            let repository = repository_args(&args)?;
            let id = positive_id(&args, "id")?;
            let (status, _value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Delete,
                    path: format!("/repos/{repository}/releases/{id}"),
                    query: Vec::new(),
                    body: None,
                    ok: &[204],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "删除 GitHub Release".into(),
                    prompt: "允许这次 GitHub 写操作？不会删除对应 tag。".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("release id".into(), id.to_string()),
                    ],
                }),
            )?;
            Ok((status, json!({"deleted": true})))
        }
        "github_release_asset_upload" => {
            let repository = repository_args(&args)?;
            let id = positive_id(&args, "id")?;
            let file_path = args
                .get("file_path")
                .and_then(Value::as_str)
                .ok_or_else(|| "缺少参数 file_path".to_string())?;
            let path = std::path::Path::new(file_path);
            let file_name = match args.get("file_name").and_then(Value::as_str) {
                Some(name) => asset_file_name(name)?,
                None => path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| "无法从路径得到文件名".to_string())
                    .and_then(asset_file_name)?,
            };
            let content_type = optional_content_type(&args)?;
            let bytes = std::fs::metadata(path)
                .map(|meta| meta.len())
                .unwrap_or(0);
            let encoded = percent_encode(&file_name, false);
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).upload(
                path,
                &format!("/repos/{repository}/releases/{id}/assets?name={encoded}"),
                &content_type,
                &[201],
                Some(&crate::github_api::Confirm {
                    title: "上传 GitHub Release 资产".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("release id".into(), id.to_string()),
                        ("文件名".into(), file_name),
                        ("字节数".into(), bytes.to_string()),
                    ],
                }),
            )?;
            Ok((status, uploaded_asset_dto(&value)))
        }
        "github_workflow_dispatch" => {
            let repository = repository_args(&args)?;
            let workflow = workflow_selector(&args)?;
            let git_ref = dispatch_ref(&args)?;
            let inputs = dispatch_inputs(&args)?;
            let mut request = Map::new();
            request.insert("ref".into(), Value::String(git_ref.clone()));
            if let Some(inputs) = inputs {
                request.insert("inputs".into(), inputs);
            }
            let (status, _value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path: format!("/repos/{repository}/actions/workflows/{workflow}/dispatches"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(Value::Object(request))),
                    ok: &[204],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "触发 GitHub workflow".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("workflow".into(), workflow),
                        ("ref".into(), git_ref),
                    ],
                }),
            )?;
            Ok((status, json!({"dispatched": true})))
        }
        "github_repository_dispatch" => {
            let repository = repository_args(&args)?;
            let event_type = event_type_arg(&args)?;
            let payload = client_payload(&args)?;
            let mut request = Map::new();
            request.insert("event_type".into(), Value::String(event_type.clone()));
            if let Some(payload) = payload {
                request.insert("client_payload".into(), payload);
            }
            let (status, _value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path: format!("/repos/{repository}/dispatches"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(Value::Object(request))),
                    ok: &[204],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "发送 GitHub repository_dispatch".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("event_type".into(), event_type),
                    ],
                }),
            )?;
            Ok((status, json!({"dispatched": true})))
        }
        "github_run_rerun" => run_action(
            &token,
            &credential_label,
            &args,
            "rerun",
            &[201, 204],
            json!({"rerun": true}),
            "重跑 GitHub Actions",
        ),
        "github_rerun_failed_jobs" => run_action(
            &token,
            &credential_label,
            &args,
            "rerun-failed-jobs",
            &[201, 204],
            json!({"rerun": true}),
            "重跑失败的 GitHub Actions job",
        ),
        "github_run_cancel" => run_action(
            &token,
            &credential_label,
            &args,
            "cancel",
            &[202, 204],
            json!({"cancelled": true}),
            "取消 GitHub Actions run",
        ),
        "github_repo_variable_set" => {
            let repository = repository_args(&args)?;
            let name = variable_name_arg(&args)?;
            let value = variable_value_arg(&args)?;
            let encoded = percent_encode(&name, false);
            let github = crate::github_api::Github::open(token.clone(), credential_label.clone());
            let (exists_status, _) = github.send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Get,
                    path: format!("/repos/{repository}/actions/variables/{encoded}"),
                    query: Vec::new(),
                    body: None,
                    ok: &[200, 404],
                    allow_missing_confirm: true,
                },
                None,
            )?;
            let creating = exists_status == 404;
            let confirm = crate::github_api::Confirm {
                title: if creating {
                    "创建 GitHub Actions 变量".into()
                } else {
                    "更新 GitHub Actions 变量".into()
                },
                prompt: "允许这次 GitHub 写操作？".into(),
                fields: variable_confirm_fields(&repository, &name, &value),
            };
            let body = crate::github_api::Body::Json(json!({"name": name, "value": value}));
            let (status, _) = if creating {
                github.send(
                    &crate::github_api::Call {
                        method: crate::github_api::Method::Post,
                        path: format!("/repos/{repository}/actions/variables"),
                        query: Vec::new(),
                        body: Some(body),
                        ok: &[201],
                        allow_missing_confirm: false,
                    },
                    Some(&confirm),
                )?
            } else {
                github.send(
                    &crate::github_api::Call {
                        method: crate::github_api::Method::Patch,
                        path: format!("/repos/{repository}/actions/variables/{encoded}"),
                        query: Vec::new(),
                        body: Some(body),
                        ok: &[204],
                        allow_missing_confirm: false,
                    },
                    Some(&confirm),
                )?
            };
            Ok((status, json!({"name": name, "updated": true})))
        }
        "github_repo_variable_delete" => {
            let repository = repository_args(&args)?;
            let name = variable_name_arg(&args)?;
            let encoded = percent_encode(&name, false);
            let (status, _value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Delete,
                    path: format!("/repos/{repository}/actions/variables/{encoded}"),
                    query: Vec::new(),
                    body: None,
                    ok: &[204],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "删除 GitHub Actions 变量".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: variable_confirm_fields(&repository, &name, ""),
                }),
            )?;
            Ok((status, json!({"deleted": true})))
        }
        "github_release_create" => {
            let repository = repository_args(&args)?;
            let tag_name = release_tag_arg(&args)?;
            let target_commitish = optional_release_string(&args, "target_commitish", 200)?;
            let name = optional_release_string(&args, "name", 200)?;
            let body = optional_release_body(&args)?;
            let draft = bool_arg(&args, "draft", true)?;
            let prerelease = bool_arg(&args, "prerelease", false)?;
            let generate_release_notes = bool_arg(&args, "generate_release_notes", false)?;
            let make_latest =
                enum_arg(&args, "make_latest", &["true", "false", "legacy"], "legacy")?;
            let payload = github_confirm_payload(
                "创建 GitHub Release",
                "允许这次 GitHub 写操作？",
                &[
                    ("仓库", repository.clone()),
                    ("标签", tag_name.clone()),
                    ("草稿", if draft { "是".into() } else { "否".into() }),
                    ("凭据", credential_label.clone()),
                ],
            );
            if !crate::confirm::ask_payload(&payload) {
                return Err("用户拒绝了这次 GitHub 写操作".into());
            }
            let mut request = Map::new();
            request.insert("tag_name".into(), Value::String(tag_name));
            if let Some(value) = target_commitish {
                request.insert("target_commitish".into(), Value::String(value));
            }
            if let Some(value) = name {
                request.insert("name".into(), Value::String(value));
            }
            if let Some(value) = body {
                request.insert("body".into(), Value::String(value));
            }
            request.insert("draft".into(), Value::Bool(draft));
            request.insert("prerelease".into(), Value::Bool(prerelease));
            request.insert(
                "generate_release_notes".into(),
                Value::Bool(generate_release_notes),
            );
            request.insert("make_latest".into(), Value::String(make_latest));
            let request = Value::Object(request);
            post_json(
                &token,
                &format!("/repos/{repository}/releases"),
                &request,
                |value| release_dto(value).ok_or_else(|| "GitHub 响应格式不正确".into()),
            )
        }
        "github_issue_create" => {
            let repository = repository_args(&args)?;
            let title = required_text(&args, "title", 256)?;
            let body = optional_release_body(&args)?;
            let labels = optional_csv(&args, "labels")?;
            let mut request = Map::new();
            request.insert("title".into(), Value::String(title.clone()));
            if let Some(value) = body {
                request.insert("body".into(), Value::String(value));
            }
            if !labels.is_empty() {
                request.insert(
                    "labels".into(),
                    Value::Array(labels.into_iter().map(Value::String).collect()),
                );
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path: format!("/repos/{repository}/issues"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(Value::Object(request))),
                    ok: &[201],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "创建 GitHub Issue".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("标题".into(), title),
                        ("凭据".into(), credential_label.clone()),
                    ],
                }),
            )?;
            let dto = issue_dto(&value).ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
            Ok((status, dto))
        }
        "github_issue_comment" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let body = required_text(&args, "body", MAX_RELEASE_BODY_BYTES)?;
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path: format!("/repos/{repository}/issues/{number}/comments"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(json!({"body": body}))),
                    ok: &[201],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "评论 GitHub Issue/PR".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), format!("{repository}#{number}")),
                        ("凭据".into(), credential_label.clone()),
                    ],
                }),
            )?;
            Ok((
                status,
                json!({
                    "id": value.get("id").and_then(Value::as_i64),
                    "html_url": limited_string(value.get("html_url")),
                    "user": limited_string(value.get("user").and_then(|item| item.get("login"))),
                }),
            ))
        }
        "github_pr_create" => {
            let repository = repository_args(&args)?;
            let title = required_text(&args, "title", 256)?;
            let head = required_text(&args, "head", 200)?;
            let base = required_text(&args, "base", 200)?;
            let body = optional_release_body(&args)?;
            let draft = bool_arg(&args, "draft", true)?;
            let mut request = Map::new();
            request.insert("title".into(), Value::String(title.clone()));
            request.insert("head".into(), Value::String(head.clone()));
            request.insert("base".into(), Value::String(base.clone()));
            request.insert("draft".into(), Value::Bool(draft));
            if let Some(value) = body {
                request.insert("body".into(), Value::String(value));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path: format!("/repos/{repository}/pulls"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(Value::Object(request))),
                    ok: &[201],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "创建 GitHub Pull Request".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("分支".into(), format!("{head} → {base}")),
                        ("标题".into(), title),
                        (
                            "草稿".into(),
                            if draft { "是".into() } else { "否".into() },
                        ),
                        ("凭据".into(), credential_label.clone()),
                    ],
                }),
            )?;
            let dto = pull_dto(&value).ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
            Ok((status, dto))
        }
        "github_issue_update" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let request = issue_update_body(&args)?;
            let mut fields = vec![
                ("仓库".into(), repository.clone()),
                ("编号".into(), number.to_string()),
            ];
            if let Some(state) = request.get("state").and_then(Value::as_str) {
                fields.push(("state".into(), state.to_string()));
            } else if let Some(title) = request.get("title").and_then(Value::as_str) {
                fields.push(("title".into(), title.to_string()));
            } else {
                fields.push(("正文".into(), "已提供".into()));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Patch,
                    path: format!("/repos/{repository}/issues/{number}"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(request)),
                    ok: &[200],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "更新 GitHub Issue".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields,
                }),
            )?;
            let dto = issue_dto(&value).ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
            Ok((status, dto))
        }
        "github_pr_merge" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let merge_method = merge_method_arg(&args)?;
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Put,
                    path: format!("/repos/{repository}/pulls/{number}/merge"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(
                        json!({"merge_method": merge_method}),
                    )),
                    ok: &[200],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "合并 GitHub Pull Request".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("编号".into(), number.to_string()),
                        ("方式".into(), merge_method),
                    ],
                }),
            )?;
            Ok((status, merge_dto(&value)?))
        }
        "github_repo_create" => {
            let request = repo_create_body(&args)?;
            let name = request
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path: "/user/repos".into(),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(request)),
                    ok: &[201],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "创建 GitHub 仓库".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![("仓库名".into(), name)],
                }),
            )?;
            let dto = repository_dto(&value).ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
            Ok((status, dto))
        }
        "github_file_put" => {
            let repository = repository_args(&args)?;
            let path = path_arg(&args, "path")?;
            let request = file_put_body(&args)?;
            let branch = request
                .get("branch")
                .and_then(Value::as_str)
                .unwrap_or("默认")
                .to_string();
            let mode = if request.get("sha").is_some() {
                "更新"
            } else {
                "新建"
            };
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Put,
                    path: format!("/repos/{repository}/contents/{path}"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(request)),
                    ok: &[200, 201],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "写入 GitHub 文件".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("路径".into(), path),
                        ("分支".into(), branch),
                        ("操作".into(), mode.into()),
                    ],
                }),
            )?;
            Ok((status, file_write_dto(&value)?))
        }
        "github_file_delete" => {
            let repository = repository_args(&args)?;
            let path = path_arg(&args, "path")?;
            let request = file_delete_body(&args)?;
            let branch = request
                .get("branch")
                .and_then(Value::as_str)
                .unwrap_or("默认")
                .to_string();
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Delete,
                    path: format!("/repos/{repository}/contents/{path}"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(request)),
                    ok: &[200],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "删除 GitHub 文件".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("路径".into(), path.clone()),
                        ("分支".into(), branch),
                    ],
                }),
            )?;
            let sha = value
                .get("commit")
                .and_then(|commit| commit.get("sha"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let mut result = json!({"deleted": true, "path": path});
            if let Some(sha) = sha {
                result["sha"] = Value::String(sha);
            }
            Ok((status, result))
        }
        "github_ref_create" => {
            let repository = repository_args(&args)?;
            let git_ref = args
                .get("git_ref")
                .and_then(Value::as_str)
                .ok_or_else(|| "缺少参数 git_ref".to_string())?;
            let normalized = normalize_git_ref(git_ref)?;
            let full_ref = format!("refs/{normalized}");
            let sha = normalize_full_sha(
                args.get("sha")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "缺少参数 sha".to_string())?,
            )?;
            let preview: String = sha.chars().take(12).collect();
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Post,
                    path: format!("/repos/{repository}/git/refs"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(
                        json!({"ref": full_ref, "sha": sha}),
                    )),
                    ok: &[201],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "创建 GitHub ref".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("ref".into(), full_ref),
                        ("sha".into(), preview),
                    ],
                }),
            )?;
            Ok((
                status,
                json!({
                    "ref": limited_string(value.get("ref")),
                    "sha": limited_string(value.get("object").and_then(|item| item.get("sha")))
                }),
            ))
        }
        "github_ref_delete" => {
            let repository = repository_args(&args)?;
            let git_ref = args
                .get("git_ref")
                .and_then(Value::as_str)
                .ok_or_else(|| "缺少参数 git_ref".to_string())?;
            let normalized = normalize_git_ref(git_ref)?;
            let encoded = percent_encode(&normalized, true);
            let (status, _value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Delete,
                    path: format!("/repos/{repository}/git/refs/{encoded}"),
                    query: Vec::new(),
                    body: None,
                    ok: &[204],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "删除 GitHub ref".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("ref".into(), format!("refs/{normalized}")),
                    ],
                }),
            )?;
            Ok((status, json!({"deleted": true, "ref": normalized})))
        }
        "github_repo_update" => {
            let repository = repository_args(&args)?;
            let request = repo_update_body(&args)?;
            let changed = request
                .as_object()
                .map(|object| object.keys().cloned().collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).send(
                &crate::github_api::Call {
                    method: crate::github_api::Method::Patch,
                    path: format!("/repos/{repository}"),
                    query: Vec::new(),
                    body: Some(crate::github_api::Body::Json(request)),
                    ok: &[200],
                    allow_missing_confirm: false,
                },
                Some(&crate::github_api::Confirm {
                    title: "更新 GitHub 仓库".into(),
                    prompt: "允许这次 GitHub 写操作？".into(),
                    fields: vec![
                        ("仓库".into(), repository),
                        ("字段".into(), changed),
                    ],
                }),
            )?;
            let dto = repository_dto(&value).ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
            Ok((status, dto))
        }
        "github_user_info" => {
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone())
                .get("/user", Vec::new())?;
            let dto = serde_json::to_value(GithubUserDto {
                id: value.get("id").and_then(Value::as_i64),
                login: limited_string(value.get("login")),
                name: limited_string(value.get("name")),
                company: limited_string(value.get("company")),
                blog: limited_string(value.get("blog")),
                html_url: limited_string(value.get("html_url")),
                public_repos: value.get("public_repos").and_then(Value::as_i64),
                private_repos: value.get("total_private_repos").and_then(Value::as_i64),
            })
            .map_err(|e| e.to_string())?;
            Ok((status, dto))
        }
        "github_repo_list" => {
            let visibility = enum_arg(&args, "visibility", &["all", "public", "private"], "all")?;
            let affiliation = enum_arg(
                &args,
                "affiliation",
                &["owner", "collaborator", "organization_member"],
                "owner",
            )?;
            let (page, per_page) = page_args(&args)?;
            let name_contains = optional_query_text(&args, "name_contains", 200)?;
            let mut query = vec![
                ("visibility".to_string(), visibility),
                ("affiliation".to_string(), affiliation),
                ("page".to_string(), page.to_string()),
                ("per_page".to_string(), per_page.to_string()),
            ];
            if let Some(kind) = optional_enum(
                &args,
                "type",
                &["all", "owner", "public", "private", "member"],
            )? {
                query.push(("type".to_string(), kind));
            }
            if let Some(sort) =
                optional_enum(&args, "sort", &["created", "updated", "pushed", "full_name"])?
            {
                query.push(("sort".to_string(), sort));
            }
            if let Some(direction) = optional_enum(&args, "direction", &["asc", "desc"])? {
                query.push(("direction".to_string(), direction));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone())
                .get("/user/repos", query)?;
            let repos = value
                .as_array()
                .ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
            let items: Vec<Value> = repos
                .iter()
                .filter_map(repository_dto)
                .filter(|item| match name_contains.as_deref() {
                    Some(needle) => item
                        .get("full_name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| name.contains(needle)),
                    None => true,
                })
                .take(per_page as usize)
                .collect();
            let count = items.len();
            Ok((status, json!({"repositories": items, "count": count})))
        }
        "github_repo_search" => {
            let query_text = required_text(&args, "q", 256)?;
            let (page, per_page) = page_args(&args)?;
            let mut query = vec![
                ("q".to_string(), query_text),
                ("page".to_string(), page.to_string()),
                ("per_page".to_string(), per_page.to_string()),
            ];
            if let Some(sort) = optional_enum(
                &args,
                "sort",
                &["stars", "forks", "help-wanted-issues", "updated"],
            )? {
                query.push(("sort".to_string(), sort));
            }
            if let Some(order) = optional_enum(&args, "order", &["asc", "desc"])? {
                query.push(("order".to_string(), order));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone())
                .get("/search/repositories", query)?;
            let items = value
                .get("items")
                .and_then(Value::as_array)
                .ok_or_else(|| "GitHub 响应格式不正确".to_string())?
                .iter()
                .filter_map(repository_dto)
                .take(per_page as usize)
                .collect::<Vec<_>>();
            Ok((
                status,
                json!({
                    "total_count": value.get("total_count").and_then(Value::as_i64),
                    "items": items
                }),
            ))
        }
        "github_repo_get" => {
            let repository = repository_args(&args)?;
            request_json(&token, &format!("/repos/{repository}"), |value| {
                repository_dto(value).ok_or_else(|| "GitHub 响应格式不正确".into())
            })
        }
        "github_file_get" => {
            let repository = repository_args(&args)?;
            let path = path_arg(&args, "path")?;
            let reference = optional_ref(&args)?;
            let endpoint = if let Some(reference) = reference {
                format!("/repos/{repository}/contents/{path}?ref={reference}")
            } else {
                format!("/repos/{repository}/contents/{path}")
            };
            request_json(&token, &endpoint, file_dto)
        }
        "github_issues_list" => {
            let repository = repository_args(&args)?;
            let state = enum_arg(&args, "state", &["open", "closed", "all"], "open")?;
            let (page, per_page) = page_args(&args)?;
            let mut query = vec![
                ("state".to_string(), state),
                ("page".to_string(), page.to_string()),
                ("per_page".to_string(), per_page.to_string()),
            ];
            for name in ["labels", "assignee", "creator", "since"] {
                let max = match name {
                    "labels" => 400,
                    "since" => 40,
                    _ => 100,
                };
                if let Some(value) = optional_query_text(&args, name, max)? {
                    query.push((name.to_string(), value));
                }
            }
            if let Some(sort) = optional_enum(&args, "sort", &["created", "updated", "comments"])? {
                query.push(("sort".to_string(), sort));
            }
            if let Some(direction) = optional_enum(&args, "direction", &["asc", "desc"])? {
                query.push(("direction".to_string(), direction));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone())
                .get(&format!("/repos/{repository}/issues"), query)?;
            Ok((status, list_dto(&value, per_page, issue_dto)?))
        }
        "github_commits_list" => {
            let repository = repository_args(&args)?;
            let (page, per_page) = page_args(&args)?;
            let mut query = vec![
                ("page".to_string(), page.to_string()),
                ("per_page".to_string(), per_page.to_string()),
            ];
            if let Some(sha) = optional_query_text(&args, "sha", 200)? {
                query.push(("sha".to_string(), sha));
            }
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone())
                .get(&format!("/repos/{repository}/commits"), query)?;
            let items = value
                .as_array()
                .ok_or_else(|| "GitHub 响应格式不正确".to_string())?
                .iter()
                .filter_map(commit_summary_dto)
                .take(per_page as usize)
                .collect::<Vec<_>>();
            let count = items.len();
            Ok((status, json!({"items": items, "count": count})))
        }
        "github_branches_list" => {
            let repository = repository_args(&args)?;
            let (page, per_page) = page_args(&args)?;
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone())
                .get(
                    &format!("/repos/{repository}/branches"),
                    vec![
                        ("page".to_string(), page.to_string()),
                        ("per_page".to_string(), per_page.to_string()),
                    ],
                )?;
            let items = value
                .as_array()
                .ok_or_else(|| "GitHub 响应格式不正确".to_string())?
                .iter()
                .filter_map(branch_dto)
                .take(per_page as usize)
                .collect::<Vec<_>>();
            let count = items.len();
            Ok((status, json!({"items": items, "count": count})))
        }
        "github_ref_get" => {
            let repository = repository_args(&args)?;
            let git_ref = args
                .get("git_ref")
                .and_then(Value::as_str)
                .ok_or_else(|| "缺少参数 git_ref".to_string())?;
            let normalized = normalize_git_ref(git_ref)?;
            let encoded = percent_encode(&normalized, true);
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone())
                .get(
                    &format!("/repos/{repository}/git/ref/{encoded}"),
                    Vec::new(),
                )?;
            Ok((
                status,
                json!({
                    "ref": limited_string(value.get("ref")),
                    "sha": limited_string(value.get("object").and_then(|item| item.get("sha")))
                }),
            ))
        }
        "github_billing_actions" => {
            let period = billing_query(&args)?;
            let is_org = bool_arg(&args, "is_org", false)?;
            let account = match optional_query_text(&args, "account", 100)? {
                Some(account) => account,
                None => {
                    let (_, user) = crate::github_api::Github::open(token.clone(), credential_label.clone())
                        .get("/user", Vec::new())?;
                    user.get("login")
                        .and_then(Value::as_str)
                        .filter(|login| !login.is_empty())
                        .ok_or_else(|| "GitHub 账号 login 不可用".to_string())?
                        .to_string()
                }
            };
            if !valid_segment(&account) {
                return Err("参数 account 格式不合法".into());
            }
            let scope = if is_org { "orgs" } else { "users" };
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone())
                .get(
                    &format!("/{scope}/{account}/settings/billing/actions"),
                    period,
                )?;
            Ok((status, billing_dto(&value, args.get("month").is_none())?))
        }
        "github_pulls_list" => {
            let repository = repository_args(&args)?;
            let state = enum_arg(&args, "state", &["open", "closed", "all"], "open")?;
            let (page, per_page) = page_args(&args)?;
            let endpoint =
                format!("/repos/{repository}/pulls?state={state}&page={page}&per_page={per_page}");
            request_json(&token, &endpoint, |value| {
                list_dto(value, per_page, pull_dto)
            })
        }
        "github_get_pull_request" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            request_json(
                &token,
                &format!("/repos/{repository}/pulls/{number}"),
                |value| pull_dto(value).ok_or_else(|| "GitHub 响应格式不正确".into()),
            )
        }
        "github_runs_list" => {
            let repository = repository_args(&args)?;
            let (page, per_page) = page_args_with_default(&args, 20)?;
            let mut endpoint =
                format!("/repos/{repository}/actions/runs?page={page}&per_page={per_page}");
            if let Some(branch) = optional_release_string(&args, "branch", 200)? {
                endpoint.push_str("&branch=");
                endpoint.push_str(&percent_encode(&branch, false));
            }
            if let Some(status) = args.get("status").and_then(Value::as_str) {
                let status = enum_arg(
                    &json!({"status": status}),
                    "status",
                    &["queued", "in_progress", "completed"],
                    "completed",
                )?;
                endpoint.push_str("&status=");
                endpoint.push_str(&status);
            }
            request_json(&token, &endpoint, |value| {
                let runs = value
                    .get("workflow_runs")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
                let items: Vec<Value> = runs
                    .iter()
                    .filter_map(workflow_run_dto)
                    .take(per_page as usize)
                    .collect();
                let count = items.len();
                Ok(json!({"workflow_runs": items, "count": count}))
            })
        }
        "github_list_pull_request_files" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint =
                format!("/repos/{repository}/pulls/{number}/files?page={page}&per_page={per_page}");
            request_json(&token, &endpoint, |value| {
                list_dto(value, per_page, pull_file_dto)
            })
        }
        "github_list_pull_request_commits" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint = format!(
                "/repos/{repository}/pulls/{number}/commits?page={page}&per_page={per_page}"
            );
            request_json(&token, &endpoint, |value| {
                list_dto(value, per_page, commit_dto)
            })
        }
        "github_list_pull_request_reviews" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint = format!(
                "/repos/{repository}/pulls/{number}/reviews?page={page}&per_page={per_page}"
            );
            request_json(&token, &endpoint, |value| {
                list_dto(value, per_page, review_dto)
            })
        }
        "github_list_pull_request_comments" => {
            let repository = repository_args(&args)?;
            let number = issue_number(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint = format!(
                "/repos/{repository}/pulls/{number}/comments?page={page}&per_page={per_page}"
            );
            request_json(&token, &endpoint, |value| {
                list_dto(value, per_page, review_comment_dto)
            })
        }
        "github_get_pull_request_status" => {
            let repository = repository_args(&args)?;
            let reference = match pull_status_selector(&args)? {
                PullStatusSelector::Ref(reference) => reference,
                PullStatusSelector::Pull(number) => {
                    let (_, pull) = request_json(
                        &token,
                        &format!("/repos/{repository}/pulls/{number}"),
                        |value| pull_dto(value).ok_or_else(|| "GitHub 响应格式不正确".to_string()),
                    )?;
                    pull.get("head")
                        .and_then(|item| item.get("sha"))
                        .and_then(Value::as_str)
                        .filter(|sha| {
                            !sha.is_empty()
                                && sha.len() <= 200
                                && sha.chars().all(|c| c.is_ascii_hexdigit())
                        })
                        .ok_or_else(|| "PR head SHA 不可用".to_string())?
                        .to_string()
                }
            };
            request_json(
                &token,
                &format!("/repos/{repository}/commits/{reference}/status"),
                combined_status_dto,
            )
        }
        "github_release_list" => {
            let repository = repository_args(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint = format!("/repos/{repository}/releases?page={page}&per_page={per_page}");
            request_json(&token, &endpoint, |value| {
                list_dto(value, per_page, release_list_dto)
            })
        }
        "github_release_get" => {
            let repository = repository_args(&args)?;
            let by_tag = args.get("id").is_none() && args.get("tag_name").is_some();
            let endpoint = if args.get("id").is_some() {
                let id = positive_id(&args, "id")?;
                format!("/repos/{repository}/releases/{id}")
            } else if by_tag {
                let tag = compare_ref_arg(&args, "tag_name")?;
                format!("/repos/{repository}/releases/tags/{tag}")
            } else {
                return Err("缺少参数 id".into());
            };
            match request_json(&token, &endpoint, |value| {
                release_list_dto(value).ok_or_else(|| "GitHub 响应格式不正确".to_string())
            }) {
                Ok(result) => Ok(result),
                Err(error) if by_tag && error.contains("HTTP 404") => {
                    Err(format!("{error}；draft 请用 github_release_list 取 id"))
                }
                Err(error) => Err(error),
            }
        }
        "github_run_artifacts" => {
            let repository = repository_args(&args)?;
            let run_id = positive_id(&args, "run_id")?;
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).get(
                &format!("/repos/{repository}/actions/runs/{run_id}/artifacts"),
                vec![("per_page".into(), MAX_PAGE_SIZE.to_string())],
            )?;
            Ok((status, artifacts_dto(&value)?))
        }
        "github_repo_variable_list" => {
            let repository = repository_args(&args)?;
            let (status, value) = crate::github_api::Github::open(token.clone(), credential_label.clone()).get(
                &format!("/repos/{repository}/actions/variables"),
                vec![("per_page".into(), MAX_PAGE_SIZE.to_string())],
            )?;
            Ok((status, variables_dto(&value)?))
        }
        "github_list_release_assets" => {
            let repository = repository_args(&args)?;
            let id = positive_id(&args, "id")?;
            request_json(
                &token,
                &format!("/repos/{repository}/releases/{id}/assets?per_page={MAX_PAGE_SIZE}"),
                |value| list_dto(value, MAX_PAGE_SIZE, release_asset_dto),
            )
        }
        "github_tags_list" => {
            let repository = repository_args(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint = format!("/repos/{repository}/tags?page={page}&per_page={per_page}");
            request_json(&token, &endpoint, |value| {
                list_dto(value, per_page, tag_dto)
            })
        }
        "github_compare_commits" => {
            let repository = repository_args(&args)?;
            let base = compare_ref_arg(&args, "base")?;
            let head = compare_ref_arg(&args, "head")?;
            let endpoint = compare_endpoint(&repository, &base, &head)?;
            request_json(&token, &endpoint, compare_dto)
        }
        "github_workflow_list" => {
            let repository = repository_args(&args)?;
            let (page, per_page) = page_args(&args)?;
            let endpoint =
                format!("/repos/{repository}/actions/workflows?page={page}&per_page={per_page}");
            request_json(&token, &endpoint, |value| {
                object_list_dto(value, "workflows", per_page, workflow_summary_dto)
            })
        }
        "github_run_get" => {
            let repository = repository_args(&args)?;
            let run_id = positive_id(&args, "run_id")?;
            request_json(
                &token,
                &format!("/repos/{repository}/actions/runs/{run_id}"),
                |value| workflow_run_dto(value).ok_or_else(|| "GitHub 响应格式不正确".to_string()),
            )
        }
        "github_run_jobs" => {
            let repository = repository_args(&args)?;
            let run_id = positive_id(&args, "run_id")?;
            request_json(
                &token,
                &format!("/repos/{repository}/actions/runs/{run_id}/jobs?per_page={MAX_PAGE_SIZE}"),
                workflow_jobs_dto,
            )
        }
        _ => return Err("未知 GitHub 工具".into()),
    }?;
    session.touch();
    let serialized = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
    Ok((status, redact_text(&serialized, &[token.as_str()])))
}

fn prepare(session: &Session, name: &str, args: &Value) -> Result<(String, String), String> {
    let definition = tool_definitions()
        .into_iter()
        .find(|definition| definition.get("name").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| "未知 GitHub 工具".to_string())?;
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    let policy = load_policy(vault, dek);
    if !policy.enabled {
        return Err("GitHub MCP 能力未启用".into());
    }
    if !definition["readOnly"].as_bool().unwrap_or(false) && !policy.api_write_enabled {
        return Err("GitHub API 写入能力未启用".into());
    }
    validate_arguments(&definition["inputSchema"], args)?;
    let resolved = resolve_github_credential(session, args)?;
    Ok((resolved.token, resolved.title))
}

fn github_confirm_payload(
    title: &str,
    prompt: &str,
    fields: &[(&str, String)],
) -> crate::confirm::ConfirmPayload {
    crate::confirm::ConfirmPayload {
        title: title.to_string(),
        prompt: prompt.to_string(),
        fields: fields
            .iter()
            .map(|(label, value)| crate::confirm::ConfirmField {
                label: (*label).to_string(),
                value: value.clone(),
            })
            .collect(),
    }
}

fn audit_context(args: &Value) -> GithubAuditContext {
    let repository = repository_args(args).ok().or_else(|| {
        args.get("repo")
            .and_then(Value::as_str)
            .map(|value| truncate(value, 201))
    });
    GithubAuditContext {
        repository,
        path: args.get("path").and_then(Value::as_str).map(str::to_string),
        reference: args
            .get("ref")
            .or_else(|| args.get("tag_name"))
            .or_else(|| args.get("head"))
            .and_then(Value::as_str)
            .map(|value| truncate(value, MAX_RELEASE_TAG_CHARS).replace(['\r', '\n'], " ")),
    }
}

fn github_credential_fingerprint(session: &Session, args: &Value) -> Option<String> {
    let resolved = resolve_github_credential(session, args).ok()?;
    Some(sha256_hex(resolved.id.as_bytes())[..12].to_string())
}

fn parse_call_error(raw: &str) -> (Option<u16>, &'static str, String) {
    if let Some(rest) = raw.strip_prefix("GitHub HTTP ") {
        let status = rest
            .split(':')
            .next()
            .and_then(|value| value.parse::<u16>().ok());
        return (status, "github_http", raw.to_string());
    }
    if raw == "GitHub 网络请求失败" {
        return (None, "network", raw.to_string());
    }
    (None, "validation", raw.to_string())
}

pub(crate) fn validate_tool_arguments(schema: &Value, args: &Value) -> Result<(), String> {
    validate_arguments(schema, args)
}

fn validate_arguments(schema: &Value, args: &Value) -> Result<(), String> {
    let object = args
        .as_object()
        .ok_or_else(|| "工具参数必须是对象".to_string())?;
    let schema = schema
        .as_object()
        .ok_or_else(|| "工具 schema 无效".to_string())?;
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for key in required.iter().filter_map(Value::as_str) {
            if !object.contains_key(key) {
                return Err(format!("缺少参数 {key}"));
            }
        }
    }
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| "工具 schema 缺少 properties".to_string())?;
    for (key, value) in object {
        let definition = properties
            .get(key)
            .ok_or_else(|| format!("不支持的参数 {key}"))?;
        validate_value(key, value, definition)?;
    }
    Ok(())
}

fn validate_value(name: &str, value: &Value, definition: &Value) -> Result<(), String> {
    if definition.get("type") == Some(&Value::String("string".into())) {
        let value = value
            .as_str()
            .ok_or_else(|| format!("参数 {name} 必须是字符串"))?;
        let min = definition
            .get("minLength")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let max = definition
            .get("maxLength")
            .and_then(Value::as_u64)
            .unwrap_or(usize::MAX as u64) as usize;
        if value.chars().count() < min || value.chars().count() > max {
            return Err(format!("参数 {name} 长度不合法"));
        }
        if let Some(values) = definition.get("enum").and_then(Value::as_array) {
            if !values.iter().any(|item| item.as_str() == Some(value)) {
                return Err(format!("参数 {name} 取值不合法"));
            }
        }
    } else if definition.get("type") == Some(&Value::String("integer".into())) {
        let value = value
            .as_u64()
            .ok_or_else(|| format!("参数 {name} 必须是正整数"))?;
        let min = definition
            .get("minimum")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let max = definition
            .get("maximum")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        if value < min || value > max {
            return Err(format!("参数 {name} 超出范围"));
        }
    } else if definition.get("type") == Some(&Value::String("boolean".into()))
        && !value.is_boolean()
    {
        return Err(format!("参数 {name} 必须是布尔值"));
    }
    Ok(())
}

fn repository_args(args: &Value) -> Result<String, String> {
    if let Some(repo) = args.get("repo").and_then(Value::as_str) {
        let trimmed = repo.trim();
        if trimmed.contains('/') || looks_like_github_url(trimmed) {
            return normalize_repository(trimmed);
        }
        if let Some(owner) = args.get("owner").and_then(Value::as_str) {
            return normalize_repository(&format!("{}/{}", owner.trim(), trimmed));
        }
        return Err("请传 repo=\"owner/repo\"，例如 hahaha-taotao/sealbox".into());
    }
    if let (Some(owner), Some(name)) = (
        args.get("owner").and_then(Value::as_str),
        args.get("name").and_then(Value::as_str),
    ) {
        return normalize_repository(&format!("{}/{}", owner.trim(), name.trim()));
    }
    Err("缺少仓库。请传 repo=\"owner/repo\"".into())
}

fn looks_like_github_url(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.contains("github.com/") || lower.starts_with("https://") || lower.starts_with("http://")
}

pub fn normalize_repository(raw: &str) -> Result<String, String> {
    let mut value = raw.trim().trim_end_matches('/').to_string();
    if value.ends_with(".git") {
        value.truncate(value.len() - 4);
    }
    for prefix in [
        "https://github.com/",
        "http://github.com/",
        "https://www.github.com/",
        "git@github.com:",
    ] {
        if let Some(stripped) = value
            .strip_prefix(prefix)
            .or_else(|| value.strip_prefix(&prefix.to_ascii_uppercase()))
        {
            value = stripped.to_string();
            break;
        }
        let lower = value.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix(prefix) {
            value = value[value.len() - rest.len()..].to_string();
            break;
        }
    }
    if value.len() > 201
        || value.is_empty()
        || value.contains('%')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err("仓库名格式不合法。请使用 owner/repo，例如 hahaha-taotao/sealbox".into());
    }
    let mut parts = value.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    if parts.next().is_some() || !valid_segment(owner) || !valid_segment(repo) {
        return Err("仓库名格式不合法。请使用 owner/repo，例如 hahaha-taotao/sealbox".into());
    }
    Ok(format!("{owner}/{repo}"))
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value != "."
        && value != ".."
        && value
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn path_arg(args: &Value, name: &str) -> Result<String, String> {
    let path = args
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("缺少参数 {name}"))?;
    if path.is_empty()
        || path.len() > 500
        || path.contains('%')
        || path.contains('\\')
        || path.contains('\0')
        || path.chars().any(char::is_control)
    {
        return Err("文件路径格式不合法".into());
    }
    let segments: Vec<&str> = path.split('/').collect();
    if segments
        .iter()
        .any(|segment| segment.is_empty() || *segment == "." || *segment == "..")
    {
        return Err("文件路径格式不合法".into());
    }
    Ok(percent_encode(path, true))
}

fn optional_ref(args: &Value) -> Result<Option<String>, String> {
    let Some(value) = args.get("ref") else {
        return Ok(None);
    };
    let reference = value.as_str().ok_or("参数 ref 必须是字符串")?;
    if reference.is_empty()
        || reference.len() > 200
        || reference.contains('%')
        || reference.contains('\\')
        || reference.chars().any(char::is_control)
        || reference
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err("ref 格式不合法".into());
    }
    Ok(Some(percent_encode(reference, false)))
}

pub(crate) fn normalize_full_sha(value: &str) -> Result<String, String> {
    if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value.to_string())
    } else {
        Err("sha 必须是 40 位十六进制".into())
    }
}

fn optional_branch(args: &Value) -> Result<Option<String>, String> {
    let Some(value) = args.get("branch") else {
        return Ok(None);
    };
    let branch = value
        .as_str()
        .ok_or_else(|| "参数 branch 必须是字符串".to_string())?;
    if branch.is_empty()
        || branch.len() > 200
        || branch.contains("..")
        || branch.contains('%')
        || branch.contains('\\')
        || branch.chars().any(char::is_control)
    {
        return Err("参数 branch 长度或格式不合法".into());
    }
    Ok(Some(branch.to_string()))
}

pub(crate) fn file_put_body(args: &Value) -> Result<Value, String> {
    let sha = match args.get("sha") {
        None => None,
        Some(Value::String(sha)) if sha.is_empty() => {
            return Err("sha 必须是 40 位十六进制".into());
        }
        Some(value) => {
            let sha = value
                .as_str()
                .ok_or_else(|| "参数 sha 必须是字符串".to_string())?;
            Some(normalize_full_sha(sha)?)
        }
    };
    let content = args
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| "缺少参数 content".to_string())?;
    if content.len() > MAX_FILE_PUT_BYTES || content.contains('\0') {
        return Err("参数 content 超过 48 KiB 或格式不合法".into());
    }
    let message = required_text(args, "message", 256)?;
    let mut request = Map::new();
    request.insert("message".into(), Value::String(message));
    request.insert(
        "content".into(),
        Value::String(base64::engine::general_purpose::STANDARD.encode(content.as_bytes())),
    );
    if let Some(sha) = sha {
        request.insert("sha".into(), Value::String(sha));
    }
    if let Some(branch) = optional_branch(args)? {
        request.insert("branch".into(), Value::String(branch));
    }
    Ok(Value::Object(request))
}

fn file_delete_body(args: &Value) -> Result<Value, String> {
    let message = required_text(args, "message", 256)?;
    let sha = args
        .get("sha")
        .and_then(Value::as_str)
        .ok_or_else(|| "缺少参数 sha".to_string())?;
    let mut request = Map::new();
    request.insert("message".into(), Value::String(message));
    request.insert("sha".into(), Value::String(normalize_full_sha(sha)?));
    if let Some(branch) = optional_branch(args)? {
        request.insert("branch".into(), Value::String(branch));
    }
    Ok(Value::Object(request))
}

fn file_write_dto(value: &Value) -> Result<Value, String> {
    let content = value.get("content").unwrap_or(value);
    Ok(json!({
        "path": limited_string(content.get("path").or_else(|| value.get("path"))),
        "sha": limited_string(content.get("sha").or_else(|| value.get("sha"))),
        "html_url": limited_string(content.get("html_url").or_else(|| value.get("html_url"))),
    }))
}

pub(crate) fn normalize_git_ref(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    let reference = trimmed.strip_prefix("refs/").unwrap_or(trimmed);
    if reference.is_empty()
        || reference.len() > 200
        || reference.contains("..")
        || reference.contains('\\')
        || reference.contains('@')
        || reference.contains("://")
        || reference.chars().any(char::is_control)
        || reference
            .split('/')
            .any(|segment| segment.is_empty() || segment == ".")
    {
        return Err("git_ref 格式不合法".into());
    }
    let kind = reference
        .split_once('/')
        .filter(|(_, name)| !name.is_empty())
        .map(|(kind, _)| kind)
        .ok_or_else(|| "git_ref 必须是 heads/分支 或 tags/标签".to_string())?;
    if kind != "heads" && kind != "tags" {
        return Err("git_ref 必须是 heads/分支 或 tags/标签".into());
    }
    Ok(reference.to_string())
}

pub(crate) fn billing_query(args: &Value) -> Result<Vec<(String, String)>, String> {
    let year = args.get("year");
    let month = args.get("month");
    match (year, month) {
        (None, None) => Ok(Vec::new()),
        (Some(year), Some(month)) => {
            let year = year
                .as_u64()
                .filter(|value| (2020..=2100).contains(value))
                .ok_or_else(|| "参数 year 超出范围".to_string())?;
            let month = month
                .as_u64()
                .filter(|value| (1..=12).contains(value))
                .ok_or_else(|| "参数 month 超出范围".to_string())?;
            Ok(vec![
                ("year".to_string(), year.to_string()),
                ("month".to_string(), month.to_string()),
            ])
        }
        _ => Err("year 与 month 必须同时提供".into()),
    }
}

fn optional_enum(args: &Value, name: &str, allowed: &[&str]) -> Result<Option<String>, String> {
    if args.get(name).is_none() {
        return Ok(None);
    }
    enum_arg(args, name, allowed, "").map(Some)
}

fn optional_query_text(args: &Value, name: &str, max: usize) -> Result<Option<String>, String> {
    let Some(value) = args.get(name) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| format!("参数 {name} 必须是字符串"))?;
    if value.is_empty()
        || value.chars().count() > max
        || value.chars().any(|character| character == '\n' || character == '\r' || character == '\0')
    {
        return Err(format!("参数 {name} 长度或格式不合法"));
    }
    Ok(Some(value.to_string()))
}

fn billing_dto(value: &Value, year_to_date: bool) -> Result<Value, String> {
    let mut object = Map::new();
    for key in [
        "total_minutes_used",
        "total_paid_minutes_used",
        "included_minutes",
    ] {
        if let Some(field) = value.get(key) {
            object.insert(key.to_string(), field.clone());
        }
    }
    if year_to_date {
        object.insert("period".to_string(), Value::String("year_to_date".into()));
    }
    Ok(Value::Object(object))
}

fn percent_encode(value: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let safe = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && *byte == b'/');
        if safe {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", byte));
        }
    }
    out
}

fn enum_arg(args: &Value, name: &str, allowed: &[&str], default: &str) -> Result<String, String> {
    let value = args.get(name).and_then(Value::as_str).unwrap_or(default);
    if allowed.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(format!("参数 {name} 取值不合法"))
    }
}

fn page_args(args: &Value) -> Result<(u64, u64), String> {
    page_args_with_default(args, 30)
}

fn page_args_with_default(args: &Value, default_per_page: u64) -> Result<(u64, u64), String> {
    let page = args.get("page").and_then(Value::as_u64).unwrap_or(1);
    let per_page = args
        .get("per_page")
        .and_then(Value::as_u64)
        .unwrap_or(default_per_page);
    if !(1..=100).contains(&page) || !(1..=MAX_PAGE_SIZE).contains(&per_page) {
        return Err("分页参数超出范围".into());
    }
    Ok((page, per_page))
}

fn issue_number(args: &Value) -> Result<u64, String> {
    args.get("number")
        .and_then(Value::as_u64)
        .filter(|value| *value >= 1)
        .ok_or_else(|| "缺少参数 number".to_string())
}

fn positive_id(args: &Value, name: &str) -> Result<u64, String> {
    args.get(name)
        .and_then(Value::as_u64)
        .filter(|value| *value >= 1)
        .ok_or_else(|| format!("缺少参数 {name}"))
}

fn compare_ref_arg(args: &Value, name: &str) -> Result<String, String> {
    let wrapped = json!({ "ref": args.get(name).cloned().unwrap_or(Value::Null) });
    optional_ref(&wrapped)?
        .filter(|value| !value.contains("..."))
        .ok_or_else(|| format!("参数 {name} 格式不合法"))
}

fn compare_endpoint(repository: &str, base: &str, head: &str) -> Result<String, String> {
    if base.contains("...") || head.contains("...") {
        return Err("比较引用不能包含 ...".into());
    }
    Ok(format!("/repos/{repository}/compare/{base}...{head}"))
}

#[derive(Debug, PartialEq, Eq)]
enum PullStatusSelector {
    Ref(String),
    Pull(u64),
}

fn pull_status_selector(args: &Value) -> Result<PullStatusSelector, String> {
    if let Some(reference) = optional_ref(args)? {
        if reference.contains("...") {
            return Err("ref 格式不合法".into());
        }
        return Ok(PullStatusSelector::Ref(reference));
    }
    if args.get("number").is_some() {
        return Ok(PullStatusSelector::Pull(issue_number(args)?));
    }
    Err("缺少参数 number".into())
}

fn required_text(args: &Value, name: &str, max: usize) -> Result<String, String> {
    let value = args
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("缺少参数 {name}"))?;
    if value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(format!("参数 {name} 长度或格式不合法"));
    }
    Ok(value.to_string())
}

fn optional_csv(args: &Value, name: &str) -> Result<Vec<String>, String> {
    let Some(raw) = args.get(name).and_then(Value::as_str) else {
        return Ok(Vec::new());
    };
    let labels = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    if labels.len() > 20 || labels.iter().any(|value| value.chars().count() > 50) {
        return Err(format!("参数 {name} 不合法"));
    }
    Ok(labels)
}

fn bool_arg(args: &Value, name: &str, default: bool) -> Result<bool, String> {
    let Some(value) = args.get(name) else {
        return Ok(default);
    };
    value
        .as_bool()
        .ok_or_else(|| format!("参数 {name} 必须是布尔值"))
}

fn run_action(
    token: &str,
    credential_label: &str,
    args: &Value,
    suffix: &str,
    ok: &'static [u16],
    result: Value,
    title: &str,
) -> Result<(u16, Value), String> {
    let repository = repository_args(args)?;
    let run_id = positive_id(args, "run_id")?;
    let (status, _value) = crate::github_api::Github::open(token, credential_label).send(
        &crate::github_api::Call {
            method: crate::github_api::Method::Post,
            path: format!("/repos/{repository}/actions/runs/{run_id}/{suffix}"),
            query: Vec::new(),
            body: None,
            ok,
            allow_missing_confirm: false,
        },
        Some(&crate::github_api::Confirm {
            title: title.into(),
            prompt: "允许这次 GitHub 写操作？".into(),
            fields: vec![
                ("仓库".into(), repository),
                ("run id".into(), run_id.to_string()),
            ],
        }),
    )?;
    Ok((status, result))
}

pub(crate) fn variable_confirm_fields(
    repository: &str,
    name: &str,
    _value: &str,
) -> Vec<(String, String)> {
    vec![
        ("仓库".into(), repository.to_string()),
        ("变量名".into(), name.to_string()),
    ]
}

pub(crate) fn asset_file_name(name: &str) -> Result<String, String> {
    if (1..=120).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Ok(name.to_string())
    } else {
        Err("文件名只允许字母、数字、点、下划线和连字符，长度 1–120".into())
    }
}

fn optional_content_type(args: &Value) -> Result<String, String> {
    let Some(value) = args.get("content_type") else {
        return Ok("application/octet-stream".into());
    };
    let value = value
        .as_str()
        .ok_or_else(|| "参数 content_type 必须是字符串".to_string())?;
    if value.is_empty() || value.len() > 200 || value.contains('\r') || value.contains('\n') {
        return Err("参数 content_type 长度或格式不合法".into());
    }
    Ok(value.to_string())
}

fn optional_release_tag(args: &Value, name: &str) -> Result<Option<String>, String> {
    if args.get(name).is_none() {
        return Ok(None);
    }
    let wrapped = json!({ "tag_name": args.get(name).cloned().unwrap_or(Value::Null) });
    release_tag_arg(&wrapped).map(Some)
}

fn reject_dot_dot(value: &str, name: &str) -> Result<(), String> {
    if value.contains("..") {
        Err(format!("参数 {name} 格式不合法"))
    } else {
        Ok(())
    }
}

fn workflow_selector(args: &Value) -> Result<String, String> {
    let workflow = required_text(args, "workflow", 200)?;
    if workflow.contains("..") || workflow.contains('/') || workflow.contains('\\') {
        return Err("参数 workflow 格式不合法".into());
    }
    Ok(workflow)
}

fn dispatch_ref(args: &Value) -> Result<String, String> {
    let git_ref = args
        .get("git_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "缺少参数 git_ref".to_string())?;
    if git_ref.is_empty()
        || git_ref.chars().count() > 200
        || git_ref.contains("..")
        || git_ref.chars().any(char::is_control)
    {
        return Err("参数 git_ref 格式不合法".into());
    }
    Ok(git_ref.to_string())
}

fn dispatch_inputs(args: &Value) -> Result<Option<Value>, String> {
    let Some(inputs) = args.get("inputs") else {
        return Ok(None);
    };
    let object = inputs
        .as_object()
        .ok_or_else(|| "参数 inputs 必须是对象".to_string())?;
    if object.len() > 10 {
        return Err("参数 inputs 最多 10 个键".into());
    }
    let mut clean = Map::new();
    for (key, value) in object {
        let text = value
            .as_str()
            .ok_or_else(|| "参数 inputs 的值必须是字符串".to_string())?;
        if text.chars().count() > 256 {
            return Err("参数 inputs 的值最长 256".into());
        }
        clean.insert(key.clone(), Value::String(text.to_string()));
    }
    Ok(Some(Value::Object(clean)))
}

fn event_type_arg(args: &Value) -> Result<String, String> {
    let event_type = required_text(args, "event_type", 100)?;
    if event_type.len() > 100
        || !event_type
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("参数 event_type 格式不合法".into());
    }
    Ok(event_type)
}

fn client_payload(args: &Value) -> Result<Option<Value>, String> {
    let Some(payload) = args.get("client_payload") else {
        return Ok(None);
    };
    let object = payload
        .as_object()
        .ok_or_else(|| "参数 client_payload 必须是对象".to_string())?;
    if object.len() > 10 {
        return Err("参数 client_payload 最多 10 个键".into());
    }
    let encoded = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
    if encoded.len() > 10 * 1024 {
        return Err("参数 client_payload 超过 10 KiB".into());
    }
    Ok(Some(payload.clone()))
}

fn variable_name_arg(args: &Value) -> Result<String, String> {
    let name = required_text(args, "name", 64)?;
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_');
    if !first_ok
        || name.chars().count() > 64
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err("参数 name 格式不合法".into());
    }
    Ok(name)
}

fn variable_value_arg(args: &Value) -> Result<String, String> {
    let value = args
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| "缺少参数 value".to_string())?;
    if value.chars().count() > 4096 {
        return Err("参数 value 最长 4096".into());
    }
    Ok(value.to_string())
}

fn generate_notes_dto(value: &Value) -> Value {
    json!({
        "name": limited_string(value.get("name")),
        "body": limited_string_with_cap(value.get("body"), MAX_RELEASE_BODY_BYTES)
    })
}

fn uploaded_asset_dto(value: &Value) -> Value {
    json!({
        "id": value.get("id").and_then(Value::as_i64),
        "name": limited_string(value.get("name")),
        "size": value.get("size").and_then(Value::as_i64),
        "state": limited_string(value.get("state"))
    })
}

fn artifacts_dto(value: &Value) -> Result<Value, String> {
    let items = value
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| "GitHub 响应格式不正确".to_string())?
        .iter()
        .take(MAX_PAGE_SIZE as usize)
        .map(|item| {
            json!({
                "id": item.get("id").and_then(Value::as_i64),
                "name": limited_string(item.get("name")),
                "size_in_bytes": item.get("size_in_bytes").and_then(Value::as_i64),
                "expired": item.get("expired").and_then(Value::as_bool)
            })
        })
        .collect::<Vec<_>>();
    let count = items.len();
    Ok(json!({"artifacts": items, "count": count}))
}

fn variables_dto(value: &Value) -> Result<Value, String> {
    let items = value
        .get("variables")
        .and_then(Value::as_array)
        .ok_or_else(|| "GitHub 响应格式不正确".to_string())?
        .iter()
        .take(MAX_PAGE_SIZE as usize)
        .map(|item| {
            json!({
                "name": limited_string(item.get("name")),
                "value": limited_string_with_cap(item.get("value"), 4096),
                "updated_at": limited_string(item.get("updated_at"))
            })
        })
        .collect::<Vec<_>>();
    let count = items.len();
    Ok(json!({"variables": items, "count": count}))
}

pub(crate) fn workflow_jobs_dto(value: &Value) -> Result<Value, String> {
    let jobs = value
        .get("jobs")
        .and_then(Value::as_array)
        .ok_or_else(|| "GitHub 响应格式不正确".to_string())?;
    let items = jobs
        .iter()
        .filter_map(workflow_job_dto)
        .take(MAX_PAGE_SIZE as usize)
        .collect::<Vec<_>>();
    let quota = !jobs.is_empty()
        && jobs.iter().all(|job| {
            job.get("conclusion").and_then(Value::as_str) == Some("failure")
                && job
                    .get("steps")
                    .and_then(Value::as_array)
                    .map(|steps| steps.is_empty())
                    .unwrap_or(true)
        });
    let count = items.len();
    let mut object = json!({"jobs": items, "count": count});
    if quota {
        object["quota_exhausted_suspect"] = Value::Bool(true);
    }
    Ok(object)
}

fn release_tag_arg(args: &Value) -> Result<String, String> {
    let tag = args
        .get("tag_name")
        .and_then(Value::as_str)
        .ok_or("缺少参数 tag_name")?;
    if tag.is_empty()
        || tag.chars().count() > MAX_RELEASE_TAG_CHARS
        || tag.chars().any(char::is_control)
        || tag.contains('%')
        || tag.contains('\\')
        || tag
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err("tag_name 格式不合法".into());
    }
    Ok(tag.to_string())
}

fn optional_release_string(args: &Value, name: &str, max: usize) -> Result<Option<String>, String> {
    let Some(value) = args.get(name) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| format!("参数 {name} 必须是字符串"))?;
    if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(format!("参数 {name} 长度或格式不合法"));
    }
    Ok(Some(value.to_string()))
}

pub(crate) fn issue_update_body(args: &Value) -> Result<Value, String> {
    let mut request = Map::new();
    if args.get("state").is_some() {
        let state = args
            .get("state")
            .and_then(Value::as_str)
            .filter(|value| matches!(*value, "open" | "closed"))
            .ok_or_else(|| "参数 state 取值不合法".to_string())?;
        request.insert("state".into(), Value::String(state.to_string()));
    }
    if args.get("title").is_some() {
        request.insert(
            "title".into(),
            Value::String(required_text(args, "title", 256)?),
        );
    }
    if let Some(body) = optional_release_body(args)? {
        request.insert("body".into(), Value::String(body));
    }
    if args.get("labels").is_some() {
        let labels = optional_csv(args, "labels")?;
        request.insert(
            "labels".into(),
            Value::Array(labels.into_iter().map(Value::String).collect()),
        );
    }
    if request.is_empty() {
        return Err("缺少要更新的 Issue 字段".into());
    }
    Ok(Value::Object(request))
}

pub(crate) fn merge_method_arg(args: &Value) -> Result<String, String> {
    let method = args
        .get("merge_method")
        .and_then(Value::as_str)
        .unwrap_or("merge");
    if !matches!(method, "merge" | "squash" | "rebase") {
        return Err("参数 merge_method 取值不合法".into());
    }
    Ok(method.to_string())
}

fn merge_dto(value: &Value) -> Result<Value, String> {
    Ok(json!({
        "sha": limited_string(value.get("sha")),
        "merged": value.get("merged").and_then(Value::as_bool),
        "message": limited_string(value.get("message")),
    }))
}

pub(crate) fn repo_create_body(args: &Value) -> Result<Value, String> {
    if args.get("private") == Some(&Value::Bool(false)) {
        return Err("仓库必须是私有的，拒绝创建公开仓库".into());
    }
    let name = required_text(args, "name", 100)?;
    let mut request = Map::new();
    request.insert("name".into(), Value::String(name));
    request.insert("private".into(), Value::Bool(true));
    if let Some(description) = optional_plain_text(args, "description", 2048)? {
        request.insert("description".into(), Value::String(description));
    }
    Ok(Value::Object(request))
}

pub(crate) fn repo_update_body(args: &Value) -> Result<Value, String> {
    if args.get("private") == Some(&Value::Bool(false)) {
        return Err("仓库必须保持私有，拒绝改为公开".into());
    }
    let mut request = Map::new();
    if args.get("description").is_some() {
        let description = optional_plain_text(args, "description", 2048)?;
        request.insert(
            "description".into(),
            Value::String(description.unwrap_or_default()),
        );
    }
    if args.get("homepage").is_some() {
        let homepage = optional_plain_text(args, "homepage", 2048)?;
        request.insert(
            "homepage".into(),
            Value::String(homepage.unwrap_or_default()),
        );
    }
    if args.get("default_branch").is_some() {
        request.insert(
            "default_branch".into(),
            Value::String(required_text(args, "default_branch", 200)?),
        );
    }
    for name in ["private", "has_issues", "has_wiki", "has_projects", "archived"] {
        if args.get(name).is_some() {
            request.insert(name.into(), Value::Bool(bool_arg(args, name, false)?));
        }
    }
    if request.is_empty() {
        return Err("缺少要更新的仓库字段".into());
    }
    Ok(Value::Object(request))
}

fn optional_plain_text(args: &Value, name: &str, max: usize) -> Result<Option<String>, String> {
    let Some(value) = args.get(name) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| format!("参数 {name} 必须是字符串"))?;
    if value.chars().count() > max || value.contains('\0') {
        return Err(format!("参数 {name} 长度或格式不合法"));
    }
    Ok(Some(value.to_string()))
}

fn optional_release_body(args: &Value) -> Result<Option<String>, String> {
    let Some(value) = args.get("body") else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| "参数 body 必须是字符串".to_string())?;
    if value.chars().count() > MAX_RELEASE_BODY_BYTES
        || value
            .chars()
            .any(|character| matches!(character, '\0' | '\u{000b}' | '\u{000c}'))
    {
        return Err("参数 body 长度或格式不合法".into());
    }
    Ok(Some(value.to_string()))
}

fn request_json<T>(
    token: &str,
    path: &str,
    map: impl FnOnce(&Value) -> Result<T, String>,
) -> Result<(u16, T), String> {
    let target = parse_http_url(&format!("{API_BASE}{path}"), true)?;
    if target.scheme != "https" || target.host != "api.github.com" || target.port != 443 {
        return Err("GitHub API 目标不合法".into());
    }
    assert_public_target(&target)?;
    let agent = ureq::builder()
        .redirects(0)
        .timeout(Duration::from_secs(15))
        .timeout_connect(Duration::from_secs(8))
        .resolver(PublicResolver)
        .user_agent(concat!("Sealbox/", env!("CARGO_PKG_VERSION")))
        .build();
    let response = agent
        .get(&format!("{API_BASE}{path}"))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", API_VERSION)
        .call();
    let (status, body, truncated) = match response {
        Ok(response) => {
            let (status, body, truncated) = read_response(response);
            (status, body, truncated)
        }
        Err(ureq::Error::Status(status, response)) => {
            let (_, body, truncated) = read_response(response);
            return Err(redact_text(
                &github_error(status, &body, truncated),
                &[token],
            ));
        }
        Err(_) => return Err("GitHub 网络请求失败".into()),
    };
    if truncated {
        return Err("GitHub 响应超过安全大小限制".into());
    }
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| "GitHub 响应不是有效 JSON".to_string())?;
    map(&value)
        .map(|value| (status, value))
        .map_err(|error| format!("GitHub 响应处理失败: {error}"))
}

fn post_json<T>(
    token: &str,
    path: &str,
    request: &Value,
    map: impl FnOnce(&Value) -> Result<T, String>,
) -> Result<(u16, T), String> {
    let target = parse_http_url(&format!("{API_BASE}{path}"), true)?;
    if target.scheme != "https" || target.host != "api.github.com" || target.port != 443 {
        return Err("GitHub API 目标不合法".into());
    }
    assert_public_target(&target)?;
    let body = serde_json::to_vec(request).map_err(|_| "GitHub 请求体无效".to_string())?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err("GitHub 请求体超过安全大小限制".into());
    }
    let agent = ureq::builder()
        .redirects(0)
        .timeout(Duration::from_secs(15))
        .timeout_connect(Duration::from_secs(8))
        .resolver(PublicResolver)
        .user_agent(concat!("Sealbox/", env!("CARGO_PKG_VERSION")))
        .build();
    let response = agent
        .post(&format!("{API_BASE}{path}"))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.github+json")
        .set("Content-Type", "application/json")
        .set("X-GitHub-Api-Version", API_VERSION)
        .send_bytes(&body);
    let (status, body, truncated) = match response {
        Ok(response) => read_response(response),
        Err(ureq::Error::Status(status, response)) => {
            let (_, body, truncated) = read_response(response);
            return Err(redact_text(
                &github_error(status, &body, truncated),
                &[token],
            ));
        }
        Err(_) => return Err("GitHub 网络请求失败".into()),
    };
    if status != 201 {
        return Err(format!("GitHub 写入返回异常状态 {status}"));
    }
    if truncated {
        return Err("GitHub 响应超过安全大小限制".into());
    }
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| "GitHub 响应不是有效 JSON".to_string())?;
    map(&value)
        .map(|value| (status, value))
        .map_err(|error| format!("GitHub 响应处理失败: {error}"))
}

fn read_response(response: ureq::Response) -> (u16, Vec<u8>, bool) {
    let status = response.status();
    let mut reader = response.into_reader();
    let mut body = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                let remaining = MAX_RESPONSE_BYTES.saturating_sub(body.len());
                if remaining == 0 {
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&buffer[..n.min(remaining)]);
                if n > remaining {
                    truncated = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (status, body, truncated)
}

fn github_error(status: u16, body: &[u8], truncated: bool) -> String {
    if truncated {
        return format!("GitHub 返回 HTTP {status}，响应过大");
    }
    let message = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .map(|value| truncate(&value, 240))
        .unwrap_or_else(|| "GitHub 请求失败".into());
    format!("GitHub HTTP {status}: {message}")
}

fn release_list_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubReleaseDto {
        id: value.get("id").and_then(Value::as_i64),
        tag_name: limited_string(value.get("tag_name")),
        name: limited_string(value.get("name")),
        target_commitish: limited_string(value.get("target_commitish")),
        draft: value.get("draft").and_then(Value::as_bool),
        prerelease: value.get("prerelease").and_then(Value::as_bool),
        html_url: limited_string(value.get("html_url")),
        created_at: limited_string(value.get("created_at")),
        published_at: limited_string(value.get("published_at")),
    })
    .ok()
}

fn release_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubReleaseDto {
        id: value.get("id").and_then(Value::as_i64),
        tag_name: limited_string_with_cap(value.get("tag_name"), MAX_RELEASE_TAG_CHARS),
        name: limited_string_with_cap(value.get("name"), 200),
        target_commitish: limited_string_with_cap(value.get("target_commitish"), 200),
        draft: value.get("draft").and_then(Value::as_bool),
        prerelease: value.get("prerelease").and_then(Value::as_bool),
        html_url: limited_string(value.get("html_url")),
        created_at: limited_string(value.get("created_at")),
        published_at: limited_string(value.get("published_at")),
    })
    .ok()
}

fn repository_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubRepositoryDto {
        id: value.get("id").and_then(Value::as_i64),
        full_name: limited_string(value.get("full_name")),
        name: limited_string(value.get("name")),
        owner: GithubOwnerDto {
            login: limited_string(value.get("owner").and_then(|v| v.get("login"))),
        },
        private: value.get("private").and_then(Value::as_bool),
        fork: value.get("fork").and_then(Value::as_bool),
        default_branch: limited_string(value.get("default_branch")),
        html_url: limited_string(value.get("html_url")),
        description: limited_string(value.get("description")),
        updated_at: limited_string(value.get("updated_at")),
    })
    .ok()
}

fn login_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .take(20)
                .filter_map(|item| limited_string(item.get("login").or_else(|| item.get("name"))))
                .collect()
        })
        .unwrap_or_default()
}

fn label_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .take(20)
                .filter_map(|item| limited_string(item.get("name")))
                .collect()
        })
        .unwrap_or_default()
}

fn git_ref_dto(value: Option<&Value>) -> GithubRefDto {
    GithubRefDto {
        git_ref: limited_string(value.and_then(|item| item.get("ref"))),
        sha: limited_string(value.and_then(|item| item.get("sha"))),
        repo: limited_string(
            value
                .and_then(|item| item.get("repo"))
                .and_then(|item| item.get("full_name")),
        ),
    }
}

fn issue_dto(value: &Value) -> Option<Value> {
    if value.get("pull_request").is_some() {
        return None;
    }
    serde_json::to_value(GithubIssueDto {
        number: value.get("number").and_then(Value::as_i64),
        title: limited_string(value.get("title")),
        state: limited_string(value.get("state")),
        html_url: limited_string(value.get("html_url")),
        user: GithubOwnerDto {
            login: limited_string(value.get("user").and_then(|v| v.get("login"))),
        },
        labels: label_list(value.get("labels")),
        assignees: login_list(value.get("assignees")),
        comments: value.get("comments").and_then(Value::as_i64),
        created_at: limited_string(value.get("created_at")),
        updated_at: limited_string(value.get("updated_at")),
        closed_at: limited_string(value.get("closed_at")),
        body: limited_string_with_cap(value.get("body"), MAX_DESCRIPTION_BYTES),
    })
    .ok()
}

fn pull_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubPullDto {
        number: value.get("number").and_then(Value::as_i64),
        title: limited_string(value.get("title")),
        state: limited_string(value.get("state")),
        html_url: limited_string(value.get("html_url")),
        user: GithubOwnerDto {
            login: limited_string(value.get("user").and_then(|v| v.get("login"))),
        },
        labels: label_list(value.get("labels")),
        assignees: login_list(value.get("assignees")),
        requested_reviewers: login_list(value.get("requested_reviewers")),
        draft: value.get("draft").and_then(Value::as_bool),
        mergeable: value.get("mergeable").and_then(Value::as_bool),
        mergeable_state: limited_string(value.get("mergeable_state")),
        head: git_ref_dto(value.get("head")),
        base: git_ref_dto(value.get("base")),
        created_at: limited_string(value.get("created_at")),
        updated_at: limited_string(value.get("updated_at")),
        body: limited_string_with_cap(value.get("body"), MAX_DESCRIPTION_BYTES),
    })
    .ok()
}

fn workflow_run_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubWorkflowRunDto {
        id: value.get("id").and_then(Value::as_i64),
        name: limited_string(value.get("name")),
        display_title: limited_string(value.get("display_title")),
        status: limited_string(value.get("status")),
        conclusion: limited_string(value.get("conclusion")),
        event: limited_string(value.get("event")),
        head_branch: limited_string(value.get("head_branch")),
        head_sha: value
            .get("head_sha")
            .and_then(Value::as_str)
            .filter(|sha| {
                !sha.is_empty() && sha.len() <= 64 && sha.chars().all(|c| c.is_ascii_hexdigit())
            })
            .map(str::to_string),
        html_url: limited_string(value.get("html_url")),
        created_at: limited_string(value.get("created_at")),
        updated_at: limited_string(value.get("updated_at")),
    })
    .ok()
}

fn pull_file_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubPullFileDto {
        filename: limited_string(value.get("filename")),
        status: limited_string(value.get("status")),
        additions: value.get("additions").and_then(Value::as_i64),
        deletions: value.get("deletions").and_then(Value::as_i64),
        changes: value.get("changes").and_then(Value::as_i64),
        sha: limited_string(value.get("sha")),
    })
    .ok()
}

fn commit_summary_dto(value: &Value) -> Option<Value> {
    let message = value
        .get("commit")
        .and_then(|item| item.get("message"))
        .and_then(Value::as_str)
        .map(|message| truncate(message, 200));
    serde_json::to_value(GithubCommitDto {
        sha: limited_string(value.get("sha")),
        message,
        author: limited_string(value.get("author").and_then(|item| item.get("login"))),
        html_url: limited_string(value.get("html_url")),
    })
    .ok()
}

fn branch_dto(value: &Value) -> Option<Value> {
    Some(json!({
        "name": limited_string(value.get("name")),
        "sha": limited_string(value.get("commit").and_then(|item| item.get("sha"))),
        "protected": value.get("protected").and_then(Value::as_bool)
    }))
}

fn commit_dto(value: &Value) -> Option<Value> {
    let commit = value.get("commit");
    serde_json::to_value(GithubCommitDto {
        sha: limited_string(value.get("sha")),
        message: limited_string_with_cap(
            commit.and_then(|item| item.get("message")),
            MAX_DESCRIPTION_BYTES,
        ),
        author: limited_string(
            commit
                .and_then(|item| item.get("author"))
                .and_then(|item| item.get("name"))
                .or_else(|| value.get("author").and_then(|item| item.get("login"))),
        ),
        html_url: limited_string(value.get("html_url")),
    })
    .ok()
}

fn review_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubReviewDto {
        id: value.get("id").and_then(Value::as_i64),
        user: limited_string(value.get("user").and_then(|item| item.get("login"))),
        state: limited_string(value.get("state")),
        submitted_at: limited_string(value.get("submitted_at")),
        body: limited_string_with_cap(value.get("body"), MAX_DESCRIPTION_BYTES),
    })
    .ok()
}

fn review_comment_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubReviewCommentDto {
        id: value.get("id").and_then(Value::as_i64),
        user: limited_string(value.get("user").and_then(|item| item.get("login"))),
        path: limited_string(value.get("path")),
        line: value.get("line").and_then(Value::as_i64),
        side: limited_string(value.get("side")),
        body: limited_string_with_cap(value.get("body"), MAX_DESCRIPTION_BYTES),
        html_url: limited_string(value.get("html_url")),
        created_at: limited_string(value.get("created_at")),
    })
    .ok()
}

fn status_context_dto(value: &Value) -> Option<GithubStatusContextDto> {
    Some(GithubStatusContextDto {
        context: limited_string(value.get("context")),
        state: limited_string(value.get("state")),
        description: limited_string(value.get("description")),
        target_url: limited_string(value.get("target_url")),
    })
}

fn tag_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubTagDto {
        name: limited_string(value.get("name")),
        sha: limited_string(value.get("commit").and_then(|item| item.get("sha"))),
    })
    .ok()
}

fn release_asset_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubReleaseAssetDto {
        id: value.get("id").and_then(Value::as_i64),
        name: limited_string(value.get("name")),
        size: value.get("size").and_then(Value::as_i64),
        content_type: limited_string(value.get("content_type")),
        download_count: value.get("download_count").and_then(Value::as_i64),
    })
    .ok()
}

fn workflow_summary_dto(value: &Value) -> Option<Value> {
    serde_json::to_value(GithubWorkflowDto {
        id: value.get("id").and_then(Value::as_i64),
        name: limited_string(value.get("name")),
        path: limited_string(value.get("path")),
        state: limited_string(value.get("state")),
    })
    .ok()
}

fn workflow_job_dto(value: &Value) -> Option<Value> {
    let failed = value.get("conclusion").and_then(Value::as_str) != Some("success");
    let steps = value
        .get("steps")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|step| {
                    !failed || step.get("conclusion").and_then(Value::as_str) != Some("success")
                })
                .take(50)
                .map(|step| GithubWorkflowStepDto {
                    name: limited_string(step.get("name")),
                    status: if failed {
                        None
                    } else {
                        limited_string(step.get("status"))
                    },
                    conclusion: limited_string(step.get("conclusion")),
                    number: if failed {
                        None
                    } else {
                        step.get("number").and_then(Value::as_i64)
                    },
                })
                .collect()
        })
        .unwrap_or_default();
    serde_json::to_value(GithubWorkflowJobDto {
        id: value.get("id").and_then(Value::as_i64),
        name: limited_string(value.get("name")),
        status: limited_string(value.get("status")),
        conclusion: limited_string(value.get("conclusion")),
        html_url: limited_string(value.get("html_url")),
        steps,
    })
    .ok()
}

fn compare_dto(value: &Value) -> Result<Value, String> {
    let files = value
        .get("files")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(pull_file_dto)
                .take(MAX_PAGE_SIZE as usize)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let commits = value
        .get("commits")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(commit_dto)
                .take(MAX_PAGE_SIZE as usize)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(json!({
        "status": limited_string(value.get("status")),
        "ahead_by": value.get("ahead_by").and_then(Value::as_i64),
        "behind_by": value.get("behind_by").and_then(Value::as_i64),
        "total_commits": value.get("total_commits").and_then(Value::as_i64),
        "files": files,
        "commits": commits
    }))
}

fn combined_status_dto(value: &Value) -> Result<Value, String> {
    let statuses = value
        .get("statuses")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(status_context_dto)
                .take(MAX_PAGE_SIZE as usize)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(json!({
        "state": limited_string(value.get("state")),
        "sha": limited_string(value.get("sha")),
        "total_count": value.get("total_count").and_then(Value::as_i64),
        "statuses": statuses
    }))
}

fn object_list_dto(
    value: &Value,
    key: &str,
    per_page: u64,
    mapper: fn(&Value) -> Option<Value>,
) -> Result<Value, String> {
    let items = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| "GitHub 响应格式不正确".to_string())?
        .iter()
        .filter_map(mapper)
        .take(per_page as usize)
        .collect::<Vec<_>>();
    let count = items.len();
    let mut object = serde_json::Map::new();
    object.insert(key.to_string(), Value::Array(items));
    object.insert("count".to_string(), json!(count));
    Ok(Value::Object(object))
}

fn list_dto(
    value: &Value,
    per_page: u64,
    mapper: fn(&Value) -> Option<Value>,
) -> Result<Value, String> {
    let items = value
        .as_array()
        .ok_or_else(|| "GitHub 响应格式不正确".to_string())?
        .iter()
        .filter_map(mapper)
        .take(per_page as usize)
        .collect::<Vec<_>>();
    let count = items.len();
    Ok(json!({"items": items, "count": count}))
}

fn file_dto(value: &Value) -> Result<Value, String> {
    if value.get("type").and_then(Value::as_str) == Some("dir") || value.get("content").is_none() {
        return Err("GitHub 路径不是可读取的单个文件".into());
    }
    let encoded = value
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.replace('\n', "").as_bytes())
        .map_err(|_| "文件内容不是有效 Base64".to_string())?;
    let is_binary = std::str::from_utf8(&decoded).is_err() || decoded.contains(&0);
    let content = if is_binary {
        None
    } else {
        Some(truncate(
            std::str::from_utf8(&decoded).unwrap_or_default(),
            MAX_CONTENT_BYTES,
        ))
    };
    serde_json::to_value(GithubFileDto {
        path: limited_string(value.get("path")),
        sha: limited_string(value.get("sha")),
        size: value.get("size").and_then(Value::as_u64),
        content,
        is_binary,
        truncated: decoded.len() > MAX_CONTENT_BYTES,
    })
    .map_err(|e| e.to_string())
}

fn limited_string(value: Option<&Value>) -> Option<String> {
    limited_string_with_cap(value, MAX_DESCRIPTION_BYTES)
}

fn limited_string_with_cap(value: Option<&Value>, cap: usize) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(|value| truncate(value, cap))
}

fn truncate(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let suffix_bytes = ELLIPSIS.len();
    let mut end = max_bytes.saturating_sub(suffix_bytes).min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &value[..end], ELLIPSIS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;

    fn find_tool(name: &str) -> Value {
        api_tool_definitions()
            .into_iter()
            .find(|definition| definition["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing"))
    }

    #[test]
    fn generate_notes_is_read_only_post() {
        let def = find_tool("github_release_generate_notes");
        assert_eq!(def["readOnly"], true);
        assert_eq!(def["risk"], "low");
    }

    #[test]
    fn failed_jobs_without_steps_mark_quota() {
        let jobs = json!({"jobs":[{"conclusion":"failure","steps":[]}]});
        let dto = workflow_jobs_dto(&jobs).unwrap();
        assert_eq!(dto["quota_exhausted_suspect"], true);
        let with_step = workflow_jobs_dto(&json!({
            "jobs": [{"conclusion": "failure", "steps": [{"name": "build", "conclusion": "failure"}]}]
        }))
        .unwrap();
        assert_ne!(with_step["quota_exhausted_suspect"], true);
        let mixed = workflow_jobs_dto(&json!({
            "jobs": [
                {"conclusion": "failure", "steps": []},
                {"conclusion": "success", "steps": []}
            ]
        }))
        .unwrap();
        assert_ne!(mixed["quota_exhausted_suspect"], true);
    }

    #[test]
    fn asset_file_names_reject_traversal() {
        assert!(asset_file_name("../evil").is_err());
        assert_eq!(asset_file_name("app.zip").unwrap(), "app.zip");
    }

    #[test]
    fn variable_confirm_fields_omit_value() {
        let fields = variable_confirm_fields("octocat/hello-world", "DEPLOY_HOST", "super-secret-host");
        let rendered = fields
            .iter()
            .map(|(label, value)| format!("{label}={value}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("DEPLOY_HOST"));
        assert!(rendered.contains("octocat/hello-world"));
        assert!(!rendered.contains("super-secret-host"));
    }

    #[test]
    fn release_and_actions_writes_hidden_until_api_write() {
        let hidden = tool_names(&GithubMcpPolicy {
            enabled: true,
            api_write_enabled: false,
            ..Default::default()
        });
        for name in [
            "github_release_publish",
            "github_release_delete",
            "github_release_asset_upload",
            "github_workflow_dispatch",
            "github_repository_dispatch",
            "github_run_rerun",
            "github_rerun_failed_jobs",
            "github_run_cancel",
            "github_repo_variable_set",
            "github_repo_variable_delete",
        ] {
            assert!(!hidden.iter().any(|item| item == name), "{name} leaked");
        }
        for name in [
            "github_release_generate_notes",
            "github_run_artifacts",
            "github_repo_variable_list",
        ] {
            assert!(hidden.iter().any(|item| item == name), "{name} missing");
        }
    }

    #[test]
    fn repo_search_requires_q_and_is_low_risk() {
        let def = api_tool_definitions()
            .into_iter()
            .find(|t| t["name"] == "github_repo_search")
            .unwrap();
        assert_eq!(def["readOnly"], true);
        assert_eq!(def["risk"], "low");
        let error = validate_tool_arguments(&def["inputSchema"], &json!({})).unwrap_err();
        assert!(error.contains("q"));
    }

    #[test]
    fn billing_rejects_month_without_year() {
        let error = billing_query(&json!({"month": 9})).unwrap_err();
        assert!(error.contains("year"));
    }

    #[test]
    fn billing_rejects_year_without_month_and_accepts_both() {
        let error = billing_query(&json!({"year": 2026})).unwrap_err();
        assert!(error.contains("year"), "{error}");
        let params = billing_query(&json!({"year": 2026, "month": 9})).unwrap();
        assert!(params.iter().any(|(key, value)| key == "year" && value == "2026"));
        assert!(params.iter().any(|(key, value)| key == "month" && value == "9"));
    }

    #[test]
    fn ref_get_strips_refs_prefix() {
        assert_eq!(normalize_git_ref("refs/heads/main").unwrap(), "heads/main");
        assert!(normalize_git_ref("heads/../main").is_err());
    }

    #[test]
    fn file_put_requires_sha_when_updating() {
        let error = file_put_body(&json!({"path":"README.md","content":"hi","sha":""})).unwrap_err();
        assert!(error.contains("sha"));
    }

    #[test]
    fn ref_create_rejects_short_sha() {
        assert!(normalize_full_sha("abc").is_err());
        assert_eq!(normalize_full_sha(&"a".repeat(40)).unwrap().len(), 40);
    }

    #[test]
    fn file_put_body_encodes_content_and_omits_missing_sha() {
        let body = file_put_body(&json!({"path":"README.md","content":"hi","message":"add readme"})).unwrap();
        assert_eq!(body["content"], "aGk=");
        assert!(body.get("sha").is_none());
        let sha = "a".repeat(40);
        let updating = file_put_body(&json!({
            "path": "README.md",
            "content": "hi",
            "message": "update readme",
            "sha": sha
        }))
        .unwrap();
        assert_eq!(updating["sha"], sha);
        let huge = "x".repeat(48 * 1024 + 1);
        let error = file_put_body(&json!({"path":"README.md","content":huge,"message":"too big"})).unwrap_err();
        assert!(error.contains("content") || error.contains("48") || error.contains("字节"), "{error}");
    }

    #[test]
    fn file_and_ref_writes_hidden_until_api_write() {
        let hidden = tool_names(&GithubMcpPolicy {
            enabled: true,
            api_write_enabled: false,
            ..Default::default()
        });
        for name in [
            "github_file_put",
            "github_file_delete",
            "github_ref_create",
            "github_ref_delete",
        ] {
            assert!(!hidden.iter().any(|item| item == name), "{name} leaked");
        }
        let visible = tool_names(&GithubMcpPolicy {
            enabled: true,
            api_write_enabled: true,
            ..Default::default()
        });
        for name in [
            "github_file_put",
            "github_file_delete",
            "github_ref_create",
            "github_ref_delete",
        ] {
            assert!(visible.iter().any(|item| item == name), "{name} missing");
        }
    }

    #[test]
    fn new_read_tools_stay_visible_without_api_write() {
        let definitions = tool_definitions_for_policy(&GithubMcpPolicy {
            enabled: true,
            api_write_enabled: false,
            ..Default::default()
        });
        for name in [
            "github_repo_search",
            "github_commits_list",
            "github_branches_list",
            "github_ref_get",
            "github_billing_actions",
        ] {
            let definition = definitions
                .iter()
                .find(|definition| definition["name"] == name)
                .unwrap_or_else(|| panic!("{name} missing"));
            assert_eq!(definition["readOnly"], true);
            assert_eq!(definition["risk"], "low");
        }
    }

    #[test]
    fn repo_create_refuses_public() {
        let error = repo_create_body(&json!({"name":"box","private":false})).unwrap_err();
        assert!(error.contains("私有"));
    }

    #[test]
    fn repo_create_body_forces_private_and_omits_description() {
        let body = repo_create_body(&json!({"name":"box"})).unwrap();
        assert_eq!(body, json!({"name":"box","private":true}));
        let explicit = repo_create_body(&json!({"name":"box","private":true,"description":"notes"})).unwrap();
        assert_eq!(explicit["private"], true);
        assert_eq!(explicit["name"], "box");
        assert_eq!(explicit["description"], "notes");
    }

    #[test]
    fn repo_update_rejects_public_and_empty() {
        let public = repo_update_body(&json!({"private":false})).unwrap_err();
        assert!(public.contains("私有") || public.contains("公开"), "{public}");
        assert!(repo_update_body(&json!({})).is_err());
    }

    #[test]
    fn issue_update_rejects_bad_state_and_empty_patch() {
        let state = issue_update_body(&json!({"state":"done"})).unwrap_err();
        assert!(state.contains("state") || state.contains("取值"), "{state}");
        assert!(issue_update_body(&json!({})).is_err());
        let body = issue_update_body(&json!({"title":"fix","state":"closed"})).unwrap();
        assert_eq!(body, json!({"title":"fix","state":"closed"}));
    }

    #[test]
    fn issue_update_hidden_until_api_write() {
        let names = tool_names(&GithubMcpPolicy {
            enabled: true,
            api_write_enabled: false,
            ..Default::default()
        });
        assert!(!names.iter().any(|name| name == "github_issue_update"));
        let names = tool_names(&GithubMcpPolicy {
            enabled: true,
            api_write_enabled: true,
            ..Default::default()
        });
        assert!(names.iter().any(|name| name == "github_issue_update"));
        assert!(names.iter().any(|name| name == "github_pr_merge"));
        assert!(names.iter().any(|name| name == "github_repo_create"));
        assert!(names.iter().any(|name| name == "github_repo_update"));
    }

    fn tool_names(policy: &GithubMcpPolicy) -> Vec<String> {
        tool_definitions_for_policy(policy)
            .into_iter()
            .filter_map(|definition| {
                definition
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect()
    }

    #[test]
    fn alias_collapses_to_canonical_name() {
        assert_eq!(canonical_tool_name("github_list_repositories"), "github_repo_list");
        assert_eq!(canonical_tool_name("github_repo_list"), "github_repo_list");
        assert_eq!(canonical_tool_name("github_create_issue"), "github_issue_create");
        assert_eq!(canonical_tool_name("github_get_file"), "github_file_get");
        assert_eq!(canonical_tool_name("github_git_status"), "github_git_status");
    }

    #[test]
    fn default_policy_is_disabled() {
        let policy = GithubMcpPolicy::default();
        assert!(!policy.enabled);
        assert!(!policy.api_write_enabled);
    }

    #[test]
    fn legacy_policy_fields_migrate_to_disabled() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        vault
            .set_secret_setting(
                &dek,
                "github_mcp_policy",
                r#"{"enabled":true,"scopes":["user"],"allowed_repositories":["octocat/repo"]}"#,
            )
            .unwrap();
        assert!(!load_policy(&vault, &dek).enabled);
    }

    #[test]
    fn repository_and_path_reject_traversal() {
        assert!(normalize_repository("octocat/hello-world/extra").is_err());
        assert!(normalize_repository("octocat/%2e%2e").is_err());
        assert!(path_arg(&json!({"path":"src/../secret"}), "path").is_err());
        assert!(path_arg(&json!({"path":"src/%2e%2e/secret"}), "path").is_err());
        assert_eq!(
            path_arg(&json!({"path":"docs/my file@2.txt"}), "path").unwrap(),
            "docs/my%20file%402.txt"
        );
        assert!(optional_ref(&json!({"ref":"refs/../main"})).is_err());
    }

    #[test]
    fn readonly_paths_reject_bad_refs_and_encode_compare() {
        assert!(positive_id(&json!({"id": 0}), "id").is_err());
        assert_eq!(positive_id(&json!({"run_id": 42}), "run_id").unwrap(), 42);
        assert!(compare_ref_arg(&json!({"base": "refs/../main"}), "base").is_err());
        assert!(compare_ref_arg(&json!({"head": "feature%2Fx"}), "head").is_err());
        assert_eq!(
            compare_endpoint("octocat/hello-world", "main", "feature%2Fui").unwrap(),
            "/repos/octocat/hello-world/compare/main...feature%2Fui"
        );
        assert!(compare_endpoint("octocat/hello-world", "a...b", "main").is_err());
        let missing = pull_status_selector(&json!({"repo": "octocat/hello-world"})).unwrap_err();
        assert!(missing.contains("number"), "{missing}");
        assert_eq!(
            pull_status_selector(&json!({"repo": "octocat/hello-world", "ref": "abc123"})).unwrap(),
            PullStatusSelector::Ref("abc123".into())
        );
    }

    #[test]
    fn release_tool_is_high_risk_and_closed() {
        let definition = api_tool_definitions()
            .into_iter()
            .find(|definition| definition["name"] == "github_create_release")
            .expect("release tool must be registered");
        assert_eq!(definition["readOnly"], false);
        assert_eq!(definition["risk"], "high");
        assert_eq!(definition["annotations"]["readOnlyHint"], false);
        assert_eq!(definition["annotations"]["destructiveHint"], true);
        assert_eq!(definition["inputSchema"]["additionalProperties"], false);
        assert!(definition["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "tag_name"));
    }

    #[test]
    fn write_tools_require_the_separate_policy_switch() {
        let read_only = tool_definitions_for_policy(&GithubMcpPolicy {
            enabled: true,
            api_write_enabled: false,
            ..Default::default()
        });
        assert!(!read_only
            .iter()
            .any(|definition| definition["name"] == "github_create_release"));
        let with_write = tool_definitions_for_policy(&GithubMcpPolicy {
            enabled: true,
            api_write_enabled: true,
            ..Default::default()
        });
        assert!(with_write
            .iter()
            .any(|definition| definition["name"] == "github_create_release"));
        assert!(with_write
            .iter()
            .any(|definition| definition["name"] == "github_create_pull_request"));
        assert!(with_write
            .iter()
            .any(|definition| definition["name"] == "github_create_issue"));
    }

    #[test]
    fn read_only_tools_have_closed_schemas() {
        let expected = [
            "github_list_credentials",
            "github_get_authenticated_user",
            "github_list_repositories",
            "github_get_repository",
            "github_get_file",
            "github_list_issues",
            "github_list_pull_requests",
            "github_get_pull_request",
            "github_list_workflow_runs",
            "github_list_pull_request_files",
            "github_list_pull_request_commits",
            "github_list_pull_request_reviews",
            "github_list_pull_request_comments",
            "github_get_pull_request_status",
            "github_list_releases",
            "github_get_release",
            "github_list_release_assets",
            "github_list_tags",
            "github_compare_commits",
            "github_list_workflows",
            "github_get_workflow_run",
            "github_list_workflow_jobs",
        ];
        let definitions = tool_definitions();
        for name in expected {
            let definition = definitions
                .iter()
                .find(|definition| definition["name"] == name)
                .expect("tool must be registered");
            assert_eq!(definition["readOnly"], true);
            assert_eq!(definition["risk"], "low");
            assert_eq!(definition["annotations"]["readOnlyHint"], true);
            assert_eq!(definition["annotations"]["destructiveHint"], false);
            assert_eq!(definition["inputSchema"]["additionalProperties"], false);
            assert!(is_github_api_tool(name));
            assert!(is_github_tool(name));
        }
        assert!(is_github_tool("github_git_status"));
        assert!(!is_github_api_tool("github_git_status"));
    }

    #[test]
    fn all_github_tools_reject_when_policy_is_disabled() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let cases = [
            ("github_list_credentials", json!({})),
            (
                "github_get_authenticated_user",
                json!({"credential_id":"id"}),
            ),
            ("github_list_repositories", json!({"credential_id":"id"})),
            (
                "github_get_repository",
                json!({"credential_id":"id","owner":"octocat","repo":"hello-world"}),
            ),
            (
                "github_get_file",
                json!({"credential_id":"id","owner":"octocat","repo":"hello-world","path":"README.md"}),
            ),
            (
                "github_list_issues",
                json!({"credential_id":"id","owner":"octocat","repo":"hello-world"}),
            ),
            (
                "github_list_pull_requests",
                json!({"credential_id":"id","owner":"octocat","repo":"hello-world"}),
            ),
            (
                "github_list_pull_request_files",
                json!({"repo":"octocat/hello-world","number":1}),
            ),
            (
                "github_get_pull_request_status",
                json!({"repo":"octocat/hello-world","number":1}),
            ),
            (
                "github_list_releases",
                json!({"repo":"octocat/hello-world"}),
            ),
            (
                "github_get_release",
                json!({"repo":"octocat/hello-world","tag_name":"v1.0.0"}),
            ),
            (
                "github_compare_commits",
                json!({"repo":"octocat/hello-world","base":"main","head":"feature"}),
            ),
            (
                "github_get_workflow_run",
                json!({"repo":"octocat/hello-world","run_id":1}),
            ),
            (
                "github_list_workflow_jobs",
                json!({"repo":"octocat/hello-world","run_id":1}),
            ),
        ];
        for (name, args) in cases {
            let error = call_tool(&mut session, name, args).unwrap_err();
            assert!(error.contains("未启用"), "{name}: {error}");
        }
        let release_error = call_tool(
            &mut session,
            "github_create_release",
            json!({
                "credential_id":"id",
                "owner":"octocat",
                "repo":"hello-world",
                "tag_name":"v1.0.0"
            }),
        )
        .unwrap_err();
        assert!(release_error.contains("未启用"), "{release_error}");
        let git_error = call_tool(
            &mut session,
            "github_git_status",
            json!({"path":"E:\\\\repo"}),
        )
        .unwrap_err();
        assert!(git_error.contains("未启用"), "{git_error}");
    }

    #[test]
    fn new_readonly_tools_stay_visible_without_api_write() {
        let definitions = tool_definitions_for_policy(&GithubMcpPolicy {
            enabled: true,
            api_write_enabled: false,
            ..Default::default()
        });
        for name in [
            "github_list_pull_request_files",
            "github_get_pull_request_status",
            "github_list_releases",
            "github_get_release",
            "github_list_release_assets",
            "github_compare_commits",
            "github_list_workflow_jobs",
        ] {
            assert!(
                definitions
                    .iter()
                    .any(|definition| definition["name"] == name),
                "{name} missing"
            );
        }
    }

    #[test]
    fn tool_schemas_are_closed() {
        for definition in api_tool_definitions() {
            assert_eq!(definition["inputSchema"]["additionalProperties"], false);
        }
        let read_only = api_tool_definitions()
            .into_iter()
            .filter(|definition| definition["readOnly"] == true)
            .count();
        // 22 original read-only tools, 8 new read tools, plus 13 read-only aliases.
        assert_eq!(read_only, 43);
    }

    #[test]
    fn user_info_alias_shares_schema_with_legacy_name() {
        let definitions = api_tool_definitions();
        let legacy = definitions
            .iter()
            .find(|definition| definition["name"] == "github_get_authenticated_user")
            .expect("legacy user tool");
        let canonical = definitions
            .iter()
            .find(|definition| definition["name"] == "github_user_info")
            .expect("canonical user tool");
        assert_eq!(legacy["readOnly"], canonical["readOnly"]);
        assert_eq!(legacy["risk"], canonical["risk"]);
        assert_eq!(legacy["description"], canonical["description"]);
        assert_eq!(legacy["inputSchema"], canonical["inputSchema"]);
        assert!(is_github_api_tool("github_get_authenticated_user"));
        assert!(is_github_api_tool("github_user_info"));
    }

    #[test]
    fn release_arguments_reject_unsafe_values_and_wrong_boolean_types() {
        assert!(release_tag_arg(&json!({"tag_name":"refs/../main"})).is_err());
        assert!(release_tag_arg(&json!({"tag_name":"release%2F1"})).is_err());
        assert!(optional_release_string(&json!({"name": 1}), "name", 200).is_err());
        assert!(optional_release_body(&json!({"body": "bad\u{000b}"})).is_err());
        assert!(bool_arg(&json!({"draft":"true"}), "draft", true).is_err());
        assert_eq!(bool_arg(&json!({}), "draft", true).unwrap(), true);
    }

    #[test]
    fn policy_disables_api_writes_without_disabling_git() {
        let policy = normalize_policy(GithubMcpPolicy {
            enabled: false,
            api_write_enabled: true,
            ..Default::default()
        })
        .unwrap();
        assert!(!policy.enabled);
        assert!(!policy.api_write_enabled);
    }

    #[test]
    fn workflow_run_dto_keeps_hex_head_sha_only() {
        let dto = workflow_run_dto(&json!({
            "id": 1,
            "name": "release",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "master",
            "head_sha": "abcdef1234567890",
            "html_url": "https://github.com/a/b/actions/runs/1"
        }))
        .unwrap();
        assert_eq!(dto["head_sha"], "abcdef1234567890");
        let rejected = workflow_run_dto(&json!({"head_sha": "not a sha/../x"})).unwrap();
        assert!(rejected.get("head_sha").unwrap().is_null());
    }

    #[test]
    fn file_dto_filters_and_marks_binary_content() {
        let value = json!({
            "type":"file",
            "path":"README.md",
            "sha":"abc",
            "size":3,
            "content":base64::engine::general_purpose::STANDARD.encode("abc")
        });
        let dto = file_dto(&value).unwrap();
        assert_eq!(dto["content"], "abc");
        assert_eq!(dto["is_binary"], false);
        assert_eq!(dto["truncated"], false);
        assert!(dto.get("token").is_none());
        assert!(file_dto(&json!({"type":"dir"})).is_err());
        let leaked = serde_json::to_string(&json!({"body": "ghp_test_token_value"})).unwrap();
        let redacted = redact_text(&leaked, &["ghp_test_token_value"]);
        assert!(!redacted.contains("ghp_test_token_value"));
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn readonly_dtos_drop_patches_logs_and_download_urls() {
        let file = pull_file_dto(&json!({
            "filename": "src/main.rs",
            "status": "modified",
            "additions": 3,
            "deletions": 1,
            "changes": 4,
            "sha": "abc",
            "patch": "@@ secret patch",
            "contents_url": "https://api.github.com/repos/a/b/contents/src/main.rs"
        }))
        .unwrap();
        assert_eq!(file["filename"], "src/main.rs");
        assert_eq!(file["additions"], 3);
        assert!(file.get("patch").is_none());
        assert!(file.get("contents_url").is_none());

        let asset = release_asset_dto(&json!({
            "id": 9,
            "name": "Sealbox_setup.exe",
            "size": 100,
            "content_type": "application/octet-stream",
            "download_count": 2,
            "browser_download_url": "https://github.com/a/b/releases/download/v1/Sealbox_setup.exe",
            "url": "https://api.github.com/repos/a/b/releases/assets/9"
        }))
        .unwrap();
        assert_eq!(asset["name"], "Sealbox_setup.exe");
        assert!(asset.get("browser_download_url").is_none());
        assert!(asset.get("url").is_none());

        let job = workflow_job_dto(&json!({
            "id": 7,
            "name": "build",
            "status": "completed",
            "conclusion": "success",
            "html_url": "https://github.com/a/b/actions/runs/1/job/7",
            "logs_url": "https://api.github.com/repos/a/b/actions/jobs/7/logs",
            "steps": [
                {"name": "checkout", "status": "completed", "conclusion": "success", "number": 1},
                {"name": "secret-step", "status": "completed", "conclusion": "failure", "number": 2}
            ]
        }))
        .unwrap();
        assert_eq!(job["name"], "build");
        assert!(job.get("logs_url").is_none());
        assert_eq!(job["steps"][1]["conclusion"], "failure");
        assert!(job["steps"][0].get("log").is_none());

        let compare = compare_dto(&json!({
            "status": "ahead",
            "ahead_by": 1,
            "behind_by": 0,
            "total_commits": 1,
            "files": [{"filename": "README.md", "status": "modified", "additions": 1, "deletions": 0, "patch": "leak"}],
            "commits": [{"sha": "deadbeef", "commit": {"message": "docs"}}]
        }))
        .unwrap();
        assert_eq!(compare["ahead_by"], 1);
        assert_eq!(compare["files"][0]["filename"], "README.md");
        assert!(compare["files"][0].get("patch").is_none());
        assert_eq!(compare["commits"].as_array().unwrap().len(), 1);
    }

    fn token_entry(service: &str) -> (Vault, [u8; 32], String) {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let entry = vault
            .upsert_entry(
                &dek,
                crate::vault::UpsertEntry {
                    id: None,
                    kind: crate::vault::EntryKind::ApiToken,
                    title: service.into(),
                    account: Some("octocat".into()),
                    url: None,
                    folder_id: None,
                    tags: Vec::new(),
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::ApiToken {
                        service: service.into(),
                        account: Some("octocat".into()),
                        token: "ghp_test_token_value".into(),
                    },
                },
            )
            .unwrap();
        (vault, dek, entry.id)
    }

    #[test]
    fn enabled_policy_requires_no_preselected_token() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        save_policy(
            &vault,
            &dek,
            &GithubMcpPolicy {
                enabled: true,
                api_write_enabled: false,
                ..Default::default()
            },
        )
        .unwrap();
        let policy = load_policy(&vault, &dek);
        assert!(policy.enabled);
        assert!(!policy.api_write_enabled);
    }

    #[test]
    fn active_token_is_selected_by_tool_argument() {
        let (vault, dek, id) = token_entry("github");
        save_policy(
            &vault,
            &dek,
            &GithubMcpPolicy {
                enabled: true,
                api_write_enabled: false,
                ..Default::default()
            },
        )
        .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let (token, _) = prepare(
            &session,
            "github_get_repository",
            &json!({"credential_id":id,"owner":"octocat","repo":"other"}),
        )
        .unwrap();
        assert_eq!(token, "ghp_test_token_value");
    }

    #[test]
    fn credential_can_be_matched_by_title_or_omitted_when_unique() {
        let (vault, dek, _) = token_entry("github");
        save_policy(
            &vault,
            &dek,
            &GithubMcpPolicy {
                enabled: true,
                api_write_enabled: false,
                ..Default::default()
            },
        )
        .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let by_title = prepare(
            &session,
            "github_get_authenticated_user",
            &json!({"credential":"github"}),
        )
        .unwrap();
        assert_eq!(by_title.0, "ghp_test_token_value");
        let implicit = prepare(&session, "github_get_authenticated_user", &json!({})).unwrap();
        assert_eq!(implicit.0, "ghp_test_token_value");
    }

    #[test]
    fn repository_accepts_owner_slash_repo() {
        assert_eq!(
            repository_args(&json!({"repo":"hahaha-taotao/sealbox"})).unwrap(),
            "hahaha-taotao/sealbox"
        );
        assert_eq!(
            repository_args(&json!({"repo":"https://github.com/octocat/hello-world.git"})).unwrap(),
            "octocat/hello-world"
        );
        assert_eq!(
            repository_args(&json!({"owner":"octocat","repo":"hello-world"})).unwrap(),
            "octocat/hello-world"
        );
    }

    #[test]
    fn credential_discovery_returns_metadata_without_token() {
        let (vault, dek, _) = token_entry("github");
        save_policy(
            &vault,
            &dek,
            &GithubMcpPolicy {
                enabled: true,
                api_write_enabled: false,
                ..Default::default()
            },
        )
        .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let text = call_tool(&mut session, "github_list_credentials", json!({})).unwrap();
        assert!(text.contains("github"));
        assert!(text.contains("is_default"));
        assert!(!text.contains("ghp_test_token_value"));
    }

    #[test]
    fn write_is_denied_when_desktop_confirm_rejects() {
        let (vault, dek, id) = token_entry("github");
        save_policy(
            &vault,
            &dek,
            &GithubMcpPolicy {
                enabled: true,
                api_write_enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let error = crate::confirm::with_auto(Some(false), || {
            call_tool(
                &mut session,
                "github_create_issue",
                json!({
                    "credential_id": id,
                    "repo": "octocat/hello-world",
                    "title": "bug"
                }),
            )
        })
        .unwrap_err();
        assert!(error.contains("拒绝"), "{error}");
    }
}
