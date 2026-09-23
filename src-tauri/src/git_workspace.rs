//! 本地仓库上的 `github_git_*` 工具。
//!
//! 与 `github_mcp` 共用 `GithubMcpPolicy.enabled`。可先注册工作区短名，
//! 之后用 workspace="sealbox" 代替绝对路径；push / pull / clone 用一次性
//! askpass 注入金库 Token，不改 remote URL。

use crate::github_mcp::{self, GithubMcpPolicy, GithubWorkspace};
use crate::redact::redact_text;
use crate::session::Session;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_LOG: u64 = 100;
const DEFAULT_LOG: u64 = 20;
const MAX_PATH: u64 = 500;
const ELLIPSIS: &str = "…";

fn workspace_prop() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 64,
        "description": "已登记的工作区短名，例如 sealbox。登记后不必再传绝对路径。"
    })
}

fn path_prop() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_PATH,
        "description": "本机绝对路径。已登记工作区时改传 workspace。"
    })
}

fn credential_prop() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 100,
        "description": "GitHub Token 的标题、账号或 ID。可省略：使用工作区默认凭据、MCP 页默认 Token，或金库里唯一的 GitHub Token。"
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

fn location_props() -> Vec<(&'static str, Value)> {
    vec![("workspace", workspace_prop()), ("path", path_prop())]
}

pub fn tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "github_git_workspace_list",
            "列出已登记的本地 git 工作区短名和绝对路径。之后可用 workspace=\"sealbox\" 代替每次传绝对路径。",
            schema(&[], &[]),
            true,
        ),
        tool(
            "github_git_workspace_register",
            "把本机 git 仓库登记成短名。用户说「把这个仓库登记为 sealbox」或后续不想再传绝对路径时调用。每次弹出桌面确认。",
            schema(
                &[
                    ("name", json!({"type":"string","minLength":1,"maxLength":64,"description":"短名，例如 sealbox"})),
                    ("path", path_prop()),
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                ],
                &["name", "path"],
            ),
            false,
        ),
        tool(
            "github_git_status",
            "查看本地仓库当前分支和 porcelain 状态。开始改代码前、提交前确认工作区是否干净时调用。传 workspace 或 path。",
            schema(&location_props(), &[]),
            true,
        ),
        tool(
            "github_git_diff",
            "查看本地 diff。默认返回 --stat 摘要；需要看具体改动时设 stat_only=false。staged=true 看暂存区。提交说明或 code review 前调用。",
            schema(
                &[
                    ("workspace", workspace_prop()),
                    ("path", path_prop()),
                    ("staged", json!({"type":"boolean","default":false})),
                    ("stat_only", json!({"type":"boolean","default":true})),
                    ("file", string_schema(1, 500)),
                ],
                &[],
            ),
            true,
        ),
        tool(
            "github_git_log",
            "查看最近提交。默认 20 条，最多 100。写 Release notes、确认 HEAD 或对比远端前调用。",
            schema(
                &[
                    ("workspace", workspace_prop()),
                    ("path", path_prop()),
                    ("limit", json!({"type":"integer","minimum":1,"maximum":100,"default":20})),
                ],
                &[],
            ),
            true,
        ),
        tool(
            "github_git_branches",
            "列出本地分支，当前分支带标记。准备 push、开 PR 或确认是否在正确分支时调用。",
            schema(&location_props(), &[]),
            true,
        ),
        tool(
            "github_git_stage",
            "把仓库内相对路径加入暂存区。all=true 才等价 git add -A。准备提交时调用。每次弹出桌面确认。",
            schema(
                &[
                    ("workspace", workspace_prop()),
                    ("path", path_prop()),
                    ("file", string_schema(1, 500)),
                    ("all", json!({"type":"boolean","default":false})),
                ],
                &[],
            ),
            false,
        ),
        tool(
            "github_git_commit",
            "提交已暂存改动。message 必填。不改正文作者、不做 amend。每次弹出桌面确认。",
            schema(
                &[
                    ("workspace", workspace_prop()),
                    ("path", path_prop()),
                    ("message", string_schema(1, 2000)),
                ],
                &["message"],
            ),
            false,
        ),
        tool(
            "github_git_push",
            "推送到 GitHub 远程。默认 remote=origin。可指定 branch、tag（只推该标签）、tags=true（连同所有标签）、force_with_lease=true（先 ls-remote 再 --force-with-lease）。发布、同步远端时调用。返回 pushed / up_to_date。每次弹出桌面确认。",
            schema(
                &[
                    ("workspace", workspace_prop()),
                    ("path", path_prop()),
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("remote", json!({"type":"string","minLength":1,"maxLength":64,"description":"远程名，默认 origin。必须是 https://github.com"})),
                    ("branch", string_schema(1, 200)),
                    ("tag", json!({"type":"string","minLength":1,"maxLength":200,"description":"只推这个标签，例如 v0.1.7。与 branch / tags=true 互斥"})),
                    ("tags", json!({"type":"boolean","default":false,"description":"同时推送全部标签"})),
                    ("force_with_lease", json!({"type":"boolean","default":false})),
                ],
                &[],
            ),
            false,
        ),
        tool(
            "github_git_pull",
            "从 GitHub 远程快进拉取。默认 remote=origin、当前分支。工作区有未提交改动时拒绝。无 rebase、无 force。同步远端更新时调用。每次弹出桌面确认。",
            schema(
                &[
                    ("workspace", workspace_prop()),
                    ("path", path_prop()),
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("remote", json!({"type":"string","minLength":1,"maxLength":64,"description":"远程名，默认 origin。必须是 https://github.com"})),
                    ("branch", string_schema(1, 200)),
                ],
                &[],
            ),
            false,
        ),
        tool(
            "github_git_clone",
            "把 github.com/{owner}/{repo} 克隆到已存在的绝对父目录。可选 name 作为目录名，并可同时登记为工作区短名。每次弹出桌面确认。",
            schema(
                &[
                    ("path", path_prop()),
                    ("credential", credential_prop()),
                    ("credential_id", credential_id_prop()),
                    ("repo", json!({"type":"string","minLength":1,"maxLength":201,"description":"owner/repo，例如 hahaha-taotao/sealbox"})),
                    ("owner", string_schema(1, 100)),
                    ("name", string_schema(1, 100)),
                    ("workspace", json!({"type":"string","minLength":1,"maxLength":64,"description":"克隆成功后登记的短名"})),
                ],
                &["path", "repo"],
            ),
            false,
        ),
    ]
}

pub fn is_git_tool(name: &str) -> bool {
    name.starts_with("github_git_")
}

pub fn call_tool_text(session: &mut Session, name: &str, args: Value) -> Result<String, String> {
    let definition = tool_definitions()
        .into_iter()
        .find(|definition| definition.get("name").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| "未知 GitHub git 工具".to_string())?;
    crate::github_mcp::validate_tool_arguments(&definition["inputSchema"], &args)?;
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    if !crate::github_mcp::load_policy(vault, dek).enabled {
        return Err("GitHub MCP 能力未启用".into());
    }
    let secrets = git_secrets(session, &args);
    let result = match name {
        "github_git_workspace_list" => list_workspaces(session),
        "github_git_workspace_register" => register_workspace(session, &args),
        "github_git_status" => status(session, &args),
        "github_git_diff" => diff(session, &args),
        "github_git_log" => log(session, &args),
        "github_git_branches" => branches(session, &args),
        "github_git_stage" => stage(session, &args),
        "github_git_commit" => commit(session, &args),
        "github_git_push" => push(session, &args),
        "github_git_pull" => pull(session, &args),
        "github_git_clone" => clone_repo(session, &args),
        _ => Err("未知 GitHub git 工具".into()),
    }?;
    session.touch();
    Ok(redact_text(
        &result,
        &secrets.iter().map(String::as_str).collect::<Vec<_>>(),
    ))
}

fn git_secrets(session: &Session, args: &Value) -> Vec<String> {
    github_mcp::resolve_github_credential(session, args)
        .map(|resolved| vec![resolved.token])
        .unwrap_or_default()
}

fn confirm_git_write(title: &str, prompt: &str, fields: &[(&str, String)]) -> Result<(), String> {
    if crate::confirm::ask(title, prompt, fields) {
        Ok(())
    } else {
        Err("用户拒绝了这次 git 写操作".into())
    }
}

fn display_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        return rest.to_string();
    }
    if let Some(rest) = raw.strip_prefix("//?/UNC/") {
        return format!(r"\\{}", rest.replace('/', "\\"));
    }
    if let Some(rest) = raw.strip_prefix("//?/") {
        return rest.replace('/', "\\");
    }
    raw.into_owned()
}

fn list_workspaces(session: &Session) -> Result<String, String> {
    let policy = current_policy(session)?;
    let items: Vec<Value> = policy
        .workspaces
        .iter()
        .map(|workspace| {
            json!({
                "name": workspace.name,
                "path": display_path(Path::new(&workspace.path)),
                "has_default_credential": workspace.default_credential_id.is_some(),
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "workspaces": items,
        "count": items.len(),
    }))
    .map_err(|e| e.to_string())
}

fn register_workspace(session: &Session, args: &Value) -> Result<String, String> {
    let name = github_mcp::normalize_workspace_name(
        args.get("name")
            .and_then(Value::as_str)
            .ok_or("缺少参数 name")?,
    )?;
    let path = absolute_path(args)?;
    let root = repo_root_from_path(&path)?;
    let credential_id = if args.get("credential").is_some() || args.get("credential_id").is_some() {
        Some(github_mcp::resolve_github_credential(session, args)?.id)
    } else {
        None
    };
    confirm_git_write(
        "登记 git 工作区",
        "允许把这个本地仓库登记为短名？之后可用短名代替绝对路径。",
        &[("短名", name.clone()), ("路径", display_path(&root))],
    )?;
    let mut policy = current_policy(session)?;
    if let Some(existing) = policy
        .workspaces
        .iter_mut()
        .find(|workspace| workspace.name == name)
    {
        existing.path = display_path(&root);
        if credential_id.is_some() {
            existing.default_credential_id = credential_id.clone();
        }
    } else {
        policy.workspaces.push(GithubWorkspace {
            name: name.clone(),
            path: display_path(&root),
            default_credential_id: credential_id,
        });
    }
    save_current_policy(session, &policy)?;
    Ok(format!("已登记工作区 {name} -> {}", display_path(&root)))
}

fn status(session: &Session, args: &Value) -> Result<String, String> {
    let root = repo_root(session, args)?;
    let raw = git_output(&root, &["status", "--porcelain=v1", "-b"], None)?;
    Ok(json_text(parse_status(&raw)))
}

fn diff(session: &Session, args: &Value) -> Result<String, String> {
    let root = repo_root(session, args)?;
    let staged = args.get("staged").and_then(Value::as_bool).unwrap_or(false);
    let stat_only = args.get("stat_only").and_then(Value::as_bool).unwrap_or(true);
    let mut cmd = vec!["diff"];
    if staged {
        cmd.push("--cached");
    }
    if stat_only {
        cmd.push("--stat");
    }
    let file = optional_rel_path(args, "file")?;
    if let Some(rel) = file.as_deref() {
        cmd.push("--");
        cmd.push(rel);
    }
    let raw = git_output(&root, &cmd, None)?;
    Ok(json_text(json!({
        "staged": staged,
        "stat_only": stat_only,
        "file": file,
        "output": raw,
    })))
}

fn log(session: &Session, args: &Value) -> Result<String, String> {
    let root = repo_root(session, args)?;
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_LOG)
        .clamp(1, MAX_LOG);
    let n = format!("-{limit}");
    let raw = git_output(
        &root,
        &[
            "log",
            "--pretty=format:%h%x09%ad%x09%an%x09%s",
            "--date=short",
            &n,
        ],
        None,
    )?;
    let commits = parse_log(&raw);
    Ok(json_text(json!({
        "count": commits.len(),
        "commits": commits,
    })))
}

fn branches(session: &Session, args: &Value) -> Result<String, String> {
    let root = repo_root(session, args)?;
    let raw = git_output(&root, &["branch", "-vv"], None)?;
    Ok(json_text(parse_branches(&raw)))
}

fn stage(session: &Session, args: &Value) -> Result<String, String> {
    let root = repo_root(session, args)?;
    let all = args.get("all").and_then(Value::as_bool).unwrap_or(false);
    let file = optional_rel_path(args, "file")?;
    confirm_git_write(
        "暂存本地改动",
        "允许这次本地 git 写操作？",
        &[
            ("仓库", display_path(&root)),
            (
                "操作",
                if all {
                    "git add -A".into()
                } else {
                    format!("git add {}", file.as_deref().unwrap_or("?"))
                },
            ),
        ],
    )?;
    if all {
        return git_output(&root, &["add", "-A"], None);
    }
    let file = file.ok_or_else(|| "请提供 file，或设 all=true".to_string())?;
    git_output(&root, &["add", "--", &file], None)
}

fn commit(session: &Session, args: &Value) -> Result<String, String> {
    let root = repo_root(session, args)?;
    let message = args
        .get("message")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "缺少提交说明".to_string())?;
    confirm_git_write(
        "创建 git 提交",
        "允许这次本地 git 写操作？",
        &[
            ("仓库", display_path(&root)),
            ("说明", message.to_string()),
        ],
    )?;
    git_output(&root, &["commit", "-m", message], None)
}

fn push(session: &Session, args: &Value) -> Result<String, String> {
    let root = repo_root(session, args)?;
    let remote = remote_name(args)?;
    require_github_https_remote(&root, &remote)?;
    let tag = requested_tag(args)?;
    let tags = args.get("tags").and_then(Value::as_bool).unwrap_or(false);
    if tag.is_some() && (tags || args.get("branch").is_some()) {
        return Err("tag 与 branch / tags=true 不能同时使用。只推某个标签时只传 tag。".into());
    }
    let force_with_lease = args
        .get("force_with_lease")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if force_with_lease && tag.is_some() {
        return Err("只推标签时不能使用 force_with_lease".into());
    }
    let token = github_token(session, args)?;
    let mut cmd = vec!["push".to_string(), remote.clone()];
    let branch;
    let target_label;
    if let Some(tag_name) = tag.as_ref() {
        branch = None;
        target_label = format!("refs/tags/{tag_name}");
        cmd.push(format!("refs/tags/{tag_name}"));
    } else {
        let name = match requested_branch(args)? {
            Some(name) => name,
            None => current_branch(&root)?,
        };
        target_label = format!("{remote}/{name}");
        cmd.push("-u".into());
        cmd.push(name.clone());
        if tags {
            cmd.push("--tags".into());
        }
        if force_with_lease {
            let before = ls_remote_sha(&root, &token, &remote, &name)?;
            if before.is_empty() {
                cmd.push(format!("--force-with-lease=refs/heads/{name}:"));
            } else {
                cmd.push(format!("--force-with-lease=refs/heads/{name}:{before}"));
            }
        }
        branch = Some(name);
    }
    confirm_git_write(
        "推送到 GitHub",
        "允许这次本地 git 写操作？",
        &[
            ("仓库", display_path(&root)),
            (
                "目标",
                format!("{target_label}{}", if tags { " + tags" } else { "" }),
            ),
            (
                "方式",
                if force_with_lease {
                    "force-with-lease".into()
                } else {
                    "普通 push".into()
                },
            ),
        ],
    )?;
    let args_ref: Vec<&str> = cmd.iter().map(String::as_str).collect();
    let output = git_with_token(&root, &args_ref, &token)?;
    Ok(classify_push_output(
        &output,
        &remote,
        branch.as_deref(),
        tag.as_deref(),
    ))
}

fn pull(session: &Session, args: &Value) -> Result<String, String> {
    let root = repo_root(session, args)?;
    let remote = remote_name(args)?;
    require_github_https_remote(&root, &remote)?;
    if working_tree_dirty(&root)? {
        return Err("工作区有未提交改动，已拒绝 pull".into());
    }
    let branch = requested_branch(args)?;
    let token = github_token(session, args)?;
    confirm_git_write(
        "从 GitHub 拉取",
        "允许这次本地 git 写操作？",
        &[
            ("仓库", display_path(&root)),
            (
                "目标",
                branch
                    .as_deref()
                    .map(|value| format!("{remote}/{value}"))
                    .unwrap_or_else(|| format!("{remote} 当前分支")),
            ),
        ],
    )?;
    let mut cmd = vec!["pull".to_string(), "--ff-only".into(), remote];
    if let Some(branch) = branch {
        cmd.push(branch);
    }
    let args_ref: Vec<&str> = cmd.iter().map(String::as_str).collect();
    git_with_token(&root, &args_ref, &token)
}

fn clone_repo(session: &Session, args: &Value) -> Result<String, String> {
    let parent = existing_dir(args)?;
    let repository = github_mcp::normalize_repository(&clone_repo_name(args)?)?;
    let mut parts = repository.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(repo);
    let dir_name = clone_dir_name(name)?;
    let dest = parent.join(&dir_name);
    if dest.exists() {
        return Err(format!("目标目录已存在：{}", display_path(&dest)));
    }
    let token = github_token(session, args)?;
    confirm_git_write(
        "克隆 GitHub 仓库",
        "允许这次本地 git 写操作？",
        &[
            ("来源", format!("https://github.com/{repository}.git")),
            ("目标", display_path(&dest)),
        ],
    )?;
    let url = format!("https://github.com/{owner}/{repo}.git");
    git_with_token(&parent, &["clone", &url, &dir_name], &token)?;
    if let Some(workspace) = args.get("workspace").and_then(Value::as_str) {
        let name = github_mcp::normalize_workspace_name(workspace)?;
        let mut policy = current_policy(session)?;
        policy.workspaces.retain(|item| item.name != name);
        policy.workspaces.push(GithubWorkspace {
            name,
            path: display_path(&dest),
            default_credential_id: Some(
                github_mcp::resolve_github_credential(session, args)?.id,
            ),
        });
        save_current_policy(session, &policy)?;
    }
    Ok(format!("已克隆到 {}", display_path(&dest)))
}

fn clone_repo_name(args: &Value) -> Result<String, String> {
    if let Some(repo) = args.get("repo").and_then(Value::as_str) {
        if repo.contains('/') || args.get("owner").is_none() {
            return Ok(repo.to_string());
        }
        if let Some(owner) = args.get("owner").and_then(Value::as_str) {
            return Ok(format!("{owner}/{repo}"));
        }
    }
    Err("缺少仓库。请传 repo=\"owner/repo\"".into())
}

fn repo_root(session: &Session, args: &Value) -> Result<PathBuf, String> {
    if let Some(name) = args.get("workspace").and_then(Value::as_str) {
        let name = github_mcp::normalize_workspace_name(name)?;
        let policy = current_policy(session)?;
        let workspace = policy
            .workspaces
            .iter()
            .find(|item| item.name == name)
            .ok_or_else(|| {
                format!("未登记工作区「{name}」。先调 github_git_workspace_register，或传 path 绝对路径。")
            })?;
        return repo_root_from_path(&PathBuf::from(&workspace.path));
    }
    if args.get("path").and_then(Value::as_str).is_none() {
        return Err("请传 workspace 短名，或 path 绝对路径".into());
    }
    let path = absolute_path(args)?;
    repo_root_from_path(&path)
}

fn repo_root_from_path(path: &Path) -> Result<PathBuf, String> {
    if !path.exists() {
        return Err(format!("路径不存在：{}", display_path(path)));
    }
    let output = git_output(path, &["rev-parse", "--show-toplevel"], None)?;
    let toplevel = PathBuf::from(output.trim());
    let canonical = toplevel
        .canonicalize()
        .map_err(|_| format!("仓库路径无效：{}", display_path(&toplevel)))?;
    if !canonical.join(".git").exists() && !canonical.join(".git").is_file() {
        return Err("该目录不是 git 仓库".into());
    }
    Ok(canonical)
}

fn current_policy(session: &Session) -> Result<GithubMcpPolicy, String> {
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    Ok(github_mcp::load_policy(vault, dek))
}

fn save_current_policy(session: &Session, policy: &GithubMcpPolicy) -> Result<(), String> {
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    github_mcp::save_policy(vault, dek, policy)
}

fn requested_branch(args: &Value) -> Result<Option<String>, String> {
    let Some(raw) = args.get("branch").and_then(Value::as_str) else {
        return Ok(None);
    };
    Ok(Some(validate_branch(raw)?))
}

fn current_branch(root: &Path) -> Result<String, String> {
    let text = git_output(root, &["rev-parse", "--abbrev-ref", "HEAD"], None)?;
    validate_branch(text.trim())
}

fn validate_branch(raw: &str) -> Result<String, String> {
    validate_ref_name(raw, "branch")
}

fn ls_remote_sha(root: &Path, token: &str, remote: &str, branch: &str) -> Result<String, String> {
    let spec = format!("refs/heads/{branch}");
    let output = git_with_token(root, &["ls-remote", remote, &spec], token)?;
    let sha = output
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let sha = parts.next()?;
            let name = parts.next().unwrap_or("");
            if name.ends_with(&spec) || spec == "HEAD" {
                Some(sha.to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();
    Ok(sha)
}

fn classify_push_output(output: &str, remote: &str, branch: Option<&str>, tag: Option<&str>) -> String {
    let lower = output.to_ascii_lowercase();
    let up_to_date = lower.contains("everything up-to-date")
        || lower.contains("already up to date")
        || lower.contains("already up-to-date");
    let pushed = !up_to_date
        && (lower.contains(" -> ")
            || lower.contains("* [new")
            || lower.contains("[new branch]")
            || lower.contains("[new tag]")
            || lower.contains("forced update"));
    json_text(json!({
        "ok": true,
        "remote": remote,
        "branch": branch,
        "tag": tag,
        "up_to_date": up_to_date,
        "pushed": pushed || (!up_to_date && !output.trim().is_empty()),
        "output": output,
    }))
}

fn existing_dir(args: &Value) -> Result<PathBuf, String> {
    let path = absolute_path(args)?;
    let canonical = path
        .canonicalize()
        .map_err(|_| format!("路径无效：{}", display_path(&path)))?;
    if !canonical.is_dir() {
        return Err("path 必须是已存在的文件夹".into());
    }
    Ok(canonical)
}

fn absolute_path(args: &Value) -> Result<PathBuf, String> {
    let raw = args
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "缺少参数 path".to_string())?;
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err("path 必须是绝对路径".into());
    }
    Ok(path)
}

fn optional_rel_path(args: &Value, key: &str) -> Result<Option<String>, String> {
    let Some(raw) = args.get(key).and_then(Value::as_str) else {
        return Ok(None);
    };
    Ok(Some(rel_path(raw)?))
}

fn rel_path(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().replace('\\', "/");
    if trimmed.is_empty() {
        return Err("路径不能为空".into());
    }
    if trimmed.starts_with('/') || Path::new(&trimmed).is_absolute() {
        return Err("只允许仓库内相对路径".into());
    }
    if Path::new(&trimmed)
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("路径不能包含 .. 或绝对前缀".into());
    }
    Ok(trimmed)
}

fn clone_dir_name(raw: &str) -> Result<String, String> {
    if !raw
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        || raw.contains("..")
        || raw.contains('/')
        || raw.contains('\\')
    {
        return Err("clone 目录名只能是单层字母数字、点、下划线或连字符".into());
    }
    Ok(raw.to_string())
}

fn working_tree_dirty(root: &Path) -> Result<bool, String> {
    let text = git_output(root, &["status", "--porcelain=v1"], None)?;
    Ok(!text.trim().is_empty())
}

fn require_github_https_origin(root: &Path) -> Result<(), String> {
    require_github_https_remote(root, "origin")
}

fn require_github_https_remote(root: &Path, remote: &str) -> Result<(), String> {
    let url = git_output(root, &["remote", "get-url", remote], None)?;
    let url = url.trim();
    if url.starts_with("git@") || url.starts_with("ssh://") {
        return Err("只允许 https://github.com 远程，已拒绝 SSH".into());
    }
    let parsed = crate::http_guard::parse_http_url(url, true)?;
    if parsed.scheme != "https" || parsed.host != "github.com" || parsed.port != 443 {
        return Err("只允许 https://github.com 远程".into());
    }
    Ok(())
}

fn remote_name(args: &Value) -> Result<String, String> {
    let Some(raw) = args.get("remote").and_then(Value::as_str) else {
        return Ok("origin".into());
    };
    let name = raw.trim();
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        || name.contains("..")
    {
        return Err("remote 只能是字母、数字、点、下划线或连字符，默认 origin".into());
    }
    Ok(name.to_string())
}

fn requested_tag(args: &Value) -> Result<Option<String>, String> {
    let Some(raw) = args.get("tag").and_then(Value::as_str) else {
        return Ok(None);
    };
    Ok(Some(validate_ref_name(raw, "tag")?))
}

fn validate_ref_name(raw: &str, label: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty()
        || value == "HEAD"
        || value.starts_with("refs/")
        || value.chars().count() > 200
        || value.contains("..")
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(format!("{label} 格式不合法"));
    }
    Ok(value.to_string())
}

fn json_text(value: Value) -> String {
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
}

fn parse_status(raw: &str) -> Value {
    let mut branch = None;
    let mut ahead: Option<u64> = None;
    let mut behind: Option<u64> = None;
    let mut files = Vec::new();
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            let (head, extra) = rest.split_once(" [").unwrap_or((rest, ""));
            if let Some((local, upstream)) = head.split_once("...") {
                branch = Some(local.trim().to_string());
                let _ = upstream;
            } else {
                branch = Some(head.trim().to_string());
            }
            if extra.contains("ahead ") {
                ahead = extra
                    .split("ahead ")
                    .nth(1)
                    .and_then(|part| part.chars().take_while(|ch| ch.is_ascii_digit()).collect::<String>().parse().ok());
            }
            if extra.contains("behind ") {
                behind = extra
                    .split("behind ")
                    .nth(1)
                    .and_then(|part| part.chars().take_while(|ch| ch.is_ascii_digit()).collect::<String>().parse().ok());
            }
            continue;
        }
        if line.len() < 3 {
            continue;
        }
        let index = line.chars().next().unwrap_or(' ');
        let worktree = line.chars().nth(1).unwrap_or(' ');
        let path = line[3..].to_string();
        files.push(json!({
            "index": index.to_string(),
            "worktree": worktree.to_string(),
            "path": path,
        }));
    }
    json!({
        "branch": branch,
        "ahead": ahead,
        "behind": behind,
        "dirty": !files.is_empty(),
        "files": files,
        "output": raw,
    })
}

fn parse_log(raw: &str) -> Vec<Value> {
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let mut parts = line.splitn(4, '\t');
            Some(json!({
                "sha": parts.next()?,
                "date": parts.next().unwrap_or(""),
                "author": parts.next().unwrap_or(""),
                "subject": parts.next().unwrap_or(""),
            }))
        })
        .collect()
}

fn parse_branches(raw: &str) -> Value {
    let items: Vec<Value> = raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let current = line.starts_with('*');
            json!({
                "current": current,
                "line": line.trim(),
            })
        })
        .collect();
    json!({
        "count": items.len(),
        "branches": items,
        "output": raw,
    })
}

fn github_token(session: &Session, args: &Value) -> Result<Zeroizing<String>, String> {
    let mut lookup = args.clone();
    if lookup.get("credential").is_none() && lookup.get("credential_id").is_none() {
        if let Some(name) = args.get("workspace").and_then(Value::as_str) {
            if let Ok(name) = github_mcp::normalize_workspace_name(name) {
                if let Ok(policy) = current_policy(session) {
                    if let Some(id) = policy
                        .workspaces
                        .iter()
                        .find(|item| item.name == name)
                        .and_then(|item| item.default_credential_id.clone())
                    {
                        if let Some(object) = lookup.as_object_mut() {
                            object.insert("credential_id".into(), Value::String(id));
                        }
                    }
                }
            }
        }
    }
    let resolved = github_mcp::resolve_github_credential(session, &lookup)?;
    Ok(Zeroizing::new(resolved.token))
}

fn git_output(root: &Path, args: &[&str], token: Option<&str>) -> Result<String, String> {
    let output = git_command(root, args, token)?;
    finish_git(output, token.unwrap_or(""))
}

fn git_with_token(root: &Path, args: &[&str], token: &str) -> Result<String, String> {
    git_output(root, args, Some(token))
}

fn git_command(root: &Path, args: &[&str], token: Option<&str>) -> Result<Output, String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root);
    if token.is_some() {
        command.args(["-c", "credential.helper="]);
    }
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GCM_INTERACTIVE", "never");
    let helper_dir;
    if let Some(token) = token {
        helper_dir = write_askpass(token)?;
        command.env("GIT_ASKPASS", helper_dir.join(askpass_name()));
        command.env("SEALBOX_GIT_ASKPASS_TOKEN", token);
        command.env("GIT_USERNAME", "x-access-token");
    } else {
        helper_dir = PathBuf::new();
    }
    let output = command
        .output()
        .map_err(|error| format!("无法执行 git：{error}。请确认本机已安装 Git 并在 PATH 中。"))?;
    if token.is_some() {
        let _ = fs::remove_dir_all(&helper_dir);
    }
    Ok(output)
}

fn finish_git(output: Output, token: &str) -> Result<String, String> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut text = stdout.trim_end().to_string();
    if !stderr.trim().is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(stderr.trim_end());
    }
    let redacted = redact_text(&truncate(&text), &[token]);
    if output.status.success() {
        Ok(if redacted.is_empty() {
            "ok".into()
        } else {
            redacted
        })
    } else {
        Err(if redacted.is_empty() {
            format!("git 失败 ({})", output.status)
        } else {
            redacted
        })
    }
}

fn write_askpass(token: &str) -> Result<PathBuf, String> {
    let _ = token;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("sealbox-git-{}-{}", std::process::id(), nanos));
    fs::create_dir_all(&dir).map_err(|error| format!("无法创建 askpass 目录：{error}"))?;
    let path = dir.join(askpass_name());
    fs::write(&path, askpass_script()).map_err(|error| format!("无法写入 askpass：{error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&path)
            .map_err(|error| format!("无法读取 askpass 权限：{error}"))?
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions)
            .map_err(|error| format!("无法设置 askpass 权限：{error}"))?;
    }
    Ok(dir)
}

fn askpass_name() -> &'static str {
    if cfg!(windows) {
        "askpass.cmd"
    } else {
        "askpass.sh"
    }
}

fn askpass_script() -> String {
    if cfg!(windows) {
        "@echo off\r\necho(%1)| findstr /I \"Username\" >nul\r\nif %errorlevel%==0 (\r\n  echo x-access-token\r\n  goto :eof\r\n)\r\necho %SEALBOX_GIT_ASKPASS_TOKEN%\r\n".into()
    } else {
        "#!/bin/sh\ncase \"$1\" in\n  [Uu]sername*) echo x-access-token ;;\n  *) echo \"$SEALBOX_GIT_ASKPASS_TOKEN\" ;;\nesac\n".into()
    }
}

fn truncate(value: &str) -> String {
    if value.len() <= MAX_OUTPUT_BYTES {
        return value.to_string();
    }
    let mut end = MAX_OUTPUT_BYTES.saturating_sub(ELLIPSIS.len()).min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{ELLIPSIS}", &value[..end])
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

fn tool(name: &str, description: &str, input_schema: Value, read_only: bool) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "readOnly": read_only,
        "risk": if read_only { "low" } else { "high" },
        "annotations": github_mcp::annotations(read_only, !read_only)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_mcp::GithubMcpPolicy;
    use crate::session::Session;
    use crate::vault::{EntryKind, SecretPayload, UpsertEntry, Vault};

    fn temp_git_repo() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sealbox-git-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let init = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["init"])
            .status()
            .unwrap();
        assert!(init.success());
        let _ = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["checkout", "-b", "master"])
            .status();
        for args in [
            vec!["config", "user.email", "sealbox@example.com"],
            vec!["config", "user.name", "Sealbox"],
        ] {
            let status = Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(&args)
                .status()
                .unwrap();
            assert!(status.success());
        }
        fs::write(dir.join("README.md"), "hi\n").unwrap();
        let status = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["add", "README.md"])
            .status()
            .unwrap();
        assert!(status.success());
        let status = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(["commit", "-m", "init"])
            .status()
            .unwrap();
        assert!(status.success());
        dir.canonicalize().unwrap()
    }

    fn enabled_session() -> Session {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let _ = vault
            .upsert_entry(
                &dek,
                UpsertEntry {
                    id: None,
                    kind: EntryKind::ApiToken,
                    title: "github".into(),
                    account: Some("octocat".into()),
                    url: None,
                    folder_id: None,
                    tags: Vec::new(),
                    pinned: false,
                    expires_at: None,
                    notes: None,
                    secret: SecretPayload::ApiToken {
                        service: "github".into(),
                        account: Some("octocat".into()),
                        token: "ghp_test_token_value".into(),
                    },
                },
            )
            .unwrap();
        crate::github_mcp::save_policy(
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
        session
    }

    #[test]
    fn rel_path_rejects_escape() {
        assert!(rel_path("../secret").is_err());
        assert!(rel_path("/etc/passwd").is_err());
        assert_eq!(rel_path("src/lib.rs").unwrap(), "src/lib.rs");
    }

    #[test]
    fn clone_dir_name_is_single_segment() {
        assert!(clone_dir_name("..").is_err());
        assert!(clone_dir_name("a/b").is_err());
        assert_eq!(clone_dir_name("sealbox").unwrap(), "sealbox");
    }

    #[test]
    fn relative_path_is_rejected() {
        let mut session = enabled_session();
        let err = call_tool_text(
            &mut session,
            "github_git_status",
            json!({"path":"relative/repo"}),
        )
        .unwrap_err();
        assert!(err.contains("绝对路径"), "{err}");
    }

    #[test]
    fn ssh_origin_is_rejected() {
        let repo = temp_git_repo();
        Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["remote", "add", "origin", "git@github.com:octocat/hello.git"])
            .status()
            .unwrap();
        let err = require_github_https_origin(&repo).unwrap_err();
        assert!(err.contains("SSH"), "{err}");
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn status_and_log_work_on_local_repo() {
        let repo = temp_git_repo();
        let mut session = enabled_session();
        let path = repo.to_string_lossy().into_owned();
        let status = call_tool_text(
            &mut session,
            "github_git_status",
            json!({ "path": path }),
        )
        .unwrap();
        let status_json: Value = serde_json::from_str(&status).unwrap();
        let branch = status_json["branch"].as_str().unwrap_or_default();
        assert!(
            branch.contains("master") || branch.contains("main") || status.contains("master"),
            "{status}"
        );
        let log = call_tool_text(
            &mut session,
            "github_git_log",
            json!({ "path": path, "limit": 5 }),
        )
        .unwrap();
        let log_json: Value = serde_json::from_str(&log).unwrap();
        assert!(
            log.contains("init") || log_json["commits"][0]["subject"] == "init",
            "{log}"
        );
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn dirty_tree_rejects_pull() {
        let repo = temp_git_repo();
        fs::write(repo.join("README.md"), "dirty\n").unwrap();
        let mut session = enabled_session();
        Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["remote", "add", "origin", "https://github.com/octocat/hello.git"])
            .status()
            .unwrap();
        let creds = crate::github_mcp::list_credentials(&session).unwrap();
        let err = call_tool_text(
            &mut session,
            "github_git_pull",
            json!({
                "path": repo.to_string_lossy(),
                "credential_id": creds[0].id
            }),
        )
        .unwrap_err();
        assert!(err.contains("未提交"), "{err}");
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn write_tools_are_high_risk() {
        for name in [
            "github_git_stage",
            "github_git_commit",
            "github_git_push",
            "github_git_pull",
            "github_git_clone",
        ] {
            let definition = tool_definitions()
                .into_iter()
                .find(|tool| tool["name"] == name)
                .unwrap();
            assert_eq!(definition["readOnly"], false);
            assert_eq!(definition["risk"], "high");
            assert_eq!(definition["annotations"]["readOnlyHint"], false);
            assert_eq!(definition["annotations"]["destructiveHint"], true);
        }
        assert!(!tool_definitions()
            .iter()
            .any(|tool| tool["name"] == "github_git_list"));
        assert!(tool_definitions()
            .iter()
            .any(|tool| tool["name"] == "github_git_workspace_register"));
    }

    #[test]
    fn workspace_short_name_resolves_path() {
        let repo = temp_git_repo();
        let mut session = enabled_session();
        let path = repo.to_string_lossy().into_owned();
        let registered = call_tool_text(
            &mut session,
            "github_git_workspace_register",
            json!({ "name": "sealbox", "path": path }),
        )
        .unwrap();
        assert!(registered.contains("sealbox"), "{registered}");
        assert!(!registered.contains(r#"\\?\"#), "{registered}");
        let status = call_tool_text(
            &mut session,
            "github_git_status",
            json!({ "workspace": "sealbox" }),
        )
        .unwrap();
        let status_json: Value = serde_json::from_str(&status).unwrap();
        let branch = status_json["branch"].as_str().unwrap_or_default();
        assert!(
            branch.contains("master") || branch.contains("main") || status.contains("master"),
            "{status}"
        );
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn display_path_strips_verbatim_prefix() {
        assert_eq!(
            display_path(Path::new(r"\\?\E:\project\密码管理器")),
            r"E:\project\密码管理器"
        );
        assert_eq!(
            display_path(Path::new(r"\\?\UNC\server\share\repo")),
            r"\\server\share\repo"
        );
        assert_eq!(display_path(Path::new(r"E:\project\sealbox")), r"E:\project\sealbox");
        assert_eq!(
            display_path(Path::new("//?/E:/project/sealbox")),
            r"E:\project\sealbox"
        );
    }

    #[test]
    fn classify_push_distinguishes_up_to_date() {
        let up_to_date = classify_push_output("Everything up-to-date", "origin", Some("main"), None);
        assert!(up_to_date.contains("\"up_to_date\": true"), "{up_to_date}");
        let pushed = classify_push_output(
            "   abc1234..def5678  HEAD -> main",
            "origin",
            Some("main"),
            None,
        );
        assert!(pushed.contains("\"pushed\": true"), "{pushed}");
        let tag_only = classify_push_output(
            " * [new tag]         v0.1.7 -> v0.1.7",
            "origin",
            None,
            Some("v0.1.7"),
        );
        assert!(tag_only.contains("\"tag\": \"v0.1.7\""), "{tag_only}");
        assert!(tag_only.contains("\"pushed\": true"), "{tag_only}");
    }

    #[test]
    fn push_rejects_tag_combined_with_branch() {
        let repo = temp_git_repo();
        let mut session = enabled_session();
        Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["remote", "add", "origin", "https://github.com/octocat/hello.git"])
            .status()
            .unwrap();
        let err = call_tool_text(
            &mut session,
            "github_git_push",
            json!({
                "path": repo.to_string_lossy(),
                "tag": "v0.1.7",
                "branch": "master"
            }),
        )
        .unwrap_err();
        assert!(err.contains("互斥") || err.contains("不能同时"), "{err}");
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn git_write_is_denied_when_confirm_rejects() {
        let repo = temp_git_repo();
        let mut session = enabled_session();
        let path = repo.to_string_lossy().into_owned();
        let error = crate::confirm::with_auto(Some(false), || {
            call_tool_text(
                &mut session,
                "github_git_commit",
                json!({ "path": path, "message": "nope" }),
            )
        })
        .unwrap_err();
        assert!(error.contains("拒绝"), "{error}");
        let _ = fs::remove_dir_all(&repo);
    }
}
