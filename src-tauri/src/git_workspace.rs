//! 本地仓库上的 `github_git_*` 工具。
//!
//! 是否可用看 MCP 页的总开关。仓库一律传本机绝对路径。
//! push / pull / clone 用一次性 askpass 注入金库 Token，不改 remote URL。

use crate::github_mcp;
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

fn path_prop() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_PATH,
        "description": "本机 git 仓库的绝对路径。"
    })
}

fn credential_prop() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 100,
        "description": "GitHub Token 的标题、账号或 ID。金库里只有一个 GitHub Token 时可省略。"
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

const GIT_ACTIONS: &[&str] = &[
    "status",
    "diff",
    "log",
    "branches",
    "fetch",
    "pull",
    "commit",
    "push",
    "clone",
];

fn action_prop() -> Value {
    json!({
        "type": "string",
        "enum": GIT_ACTIONS,
        "description": "status/diff/log/branches 只读；fetch 只更新远端跟踪；pull 快进当前分支；commit 可带 files 或 all，暂存和提交一次确认；push 推分支或标签；clone 把 owner/repo 克隆到 path 指定的已存在父目录。"
    })
}

pub fn tool_definitions() -> Vec<Value> {
    vec![tool(
        "github_git",
        "本机仓库的常用 git。action 取 status、diff、log、branches、fetch、pull、commit、push、clone。除 clone 外 path 是仓库绝对路径；clone 的 path 是已存在的父目录。写动作每次弹出一次桌面确认。",
        schema(
            &[
                ("action", action_prop()),
                ("path", path_prop()),
                ("credential", credential_prop()),
                ("credential_id", credential_id_prop()),
                ("staged", json!({"type":"boolean","default":false,"description":"仅 diff：看暂存区"})),
                ("stat_only", json!({"type":"boolean","default":true,"description":"仅 diff：只返回 --stat。false 才返回 patch"})),
                ("file", string_schema(1, 500)),
                (
                    "files",
                    json!({
                        "type": "array",
                        "maxItems": 100,
                        "items": string_schema(1, 500),
                        "description": "仅 commit：提交前先暂存这些仓库内相对路径。与 all 互斥。"
                    }),
                ),
                ("all", json!({"type":"boolean","default":false,"description":"仅 commit：先 git add -A 再提交。与 file/files 互斥。"})),
                ("message", string_schema(1, 2000)),
                ("limit", json!({"type":"integer","minimum":1,"maximum":100,"default":20,"description":"仅 log"})),
                ("remote", json!({"type":"string","minLength":1,"maxLength":64,"description":"fetch/pull/push 的远程名，默认 origin。必须是 https://github.com"})),
                ("branch", string_schema(1, 200)),
                ("tag", json!({"type":"string","minLength":1,"maxLength":200,"description":"仅 push：只推这个标签。与 branch / tags 互斥"})),
                ("tags", json!({"type":"boolean","default":false,"description":"仅 push：推送分支时带上全部标签"})),
                ("force_with_lease", json!({"type":"boolean","default":false,"description":"仅 push：先 ls-remote 再 --force-with-lease。不推标签时不能用"})),
                ("repo", json!({"type":"string","minLength":1,"maxLength":201,"description":"仅 clone：owner/repo"})),
                ("owner", string_schema(1, 100)),
                ("name", string_schema(1, 100)),
            ],
            &["action", "path"],
        ),
        false,
    )]
}

/// 旧的细工具名映射到 github_git 的 action。未知名原样返回。
fn legacy_git_action(name: &str) -> Option<&'static str> {
    Some(match name {
        "github_git_status" => "status",
        "github_git_diff" => "diff",
        "github_git_log" => "log",
        "github_git_branches" => "branches",
        "github_git_pull" => "pull",
        "github_git_commit" | "github_git_stage" => "commit",
        "github_git_push" => "push",
        "github_git_clone" => "clone",
        _ => return None,
    })
}

fn definition_named<'a>(definitions: &'a [Value], name: &str) -> Result<&'a Value, String> {
    definitions
        .iter()
        .find(|definition| definition.get("name").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| "未知 GitHub git 工具".to_string())
}

pub fn is_git_tool(name: &str) -> bool {
    name == "github_git" || name.starts_with("github_git_")
}

pub fn call_tool_text(session: &mut Session, name: &str, args: Value) -> Result<String, String> {
    match prepare_tool(session, name, args)? {
        PreparedGitOp::Immediate(text) => Ok(text),
        PreparedGitOp::Pending {
            payload,
            deny,
            exec,
        } => {
            if crate::confirm::ask_payload(&payload) {
                exec(session)
            } else {
                Err(deny)
            }
        }
    }
}

pub enum PreparedGitOp {
    Immediate(String),
    Pending {
        payload: crate::confirm::ConfirmPayload,
        deny: String,
        exec: Box<dyn FnOnce(&mut Session) -> Result<String, String> + Send>,
    },
}

pub fn prepare_tool(
    session: &mut Session,
    name: &str,
    args: Value,
) -> Result<PreparedGitOp, String> {
    let definitions = tool_definitions();
    let definition = definition_named(&definitions, "github_git")?;
    let (action, args) = if name == "github_git" {
        crate::github_mcp::validate_tool_arguments(&definition["inputSchema"], &args)?;
        let action = args
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        (action, args)
    } else {
        let action = legacy_git_action(name).ok_or_else(|| "未知 GitHub git 工具".to_string())?;
        (action.to_string(), args)
    };
    let vault = session.vault().map_err(|e| e.to_string())?;
    let dek = session.dek().map_err(|e| e.to_string())?;
    if !crate::zoomkey::mcp_enabled(vault, dek) {
        return Err("MCP 未启用。请先在 Sealbox 的 MCP 页面打开。".into());
    }
    let secrets = git_secrets(session, &args);
    let prepared = match action.as_str() {
        "status" => PreparedGitOp::Immediate(status(session, &args)?),
        "diff" => PreparedGitOp::Immediate(diff(session, &args)?),
        "log" => PreparedGitOp::Immediate(log(session, &args)?),
        "branches" => PreparedGitOp::Immediate(branches(session, &args)?),
        "fetch" => prepare_fetch(session, &args)?,
        "commit" => prepare_commit(session, &args)?,
        "push" => prepare_push(session, &args)?,
        "pull" => prepare_pull(session, &args)?,
        "clone" => prepare_clone(session, &args)?,
        _ => return Err("未知的 github_git action".into()),
    };
    session.touch();
    Ok(redact_prepared(prepared, secrets))
}

fn redact_prepared(prepared: PreparedGitOp, secrets: Vec<String>) -> PreparedGitOp {
    match prepared {
        PreparedGitOp::Immediate(text) => PreparedGitOp::Immediate(redact_text(
            &text,
            &secrets.iter().map(String::as_str).collect::<Vec<_>>(),
        )),
        PreparedGitOp::Pending {
            payload,
            deny,
            exec,
        } => PreparedGitOp::Pending {
            payload,
            deny,
            exec: Box::new(move |session| {
                let text = exec(session)?;
                Ok(redact_text(
                    &text,
                    &secrets.iter().map(String::as_str).collect::<Vec<_>>(),
                ))
            }),
        },
    }
}

fn git_secrets(session: &Session, args: &Value) -> Vec<String> {
    github_mcp::resolve_github_credential(session, args)
        .map(|resolved| vec![resolved.token])
        .unwrap_or_default()
}

fn git_confirm_payload(
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

fn status(session: &Session, args: &Value) -> Result<String, String> {
    let root = repo_root(session, args)?;
    let raw = git_output(&root, &["status", "--porcelain=v1", "-b"], None)?;
    Ok(json_text(parse_status(&raw)))
}

fn diff(session: &Session, args: &Value) -> Result<String, String> {
    let root = repo_root(session, args)?;
    let staged = args.get("staged").and_then(Value::as_bool).unwrap_or(false);
    let stat_only = args
        .get("stat_only")
        .and_then(Value::as_bool)
        .unwrap_or(true);
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

fn stage_paths(args: &Value) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    if let Some(file) = optional_rel_path(args, "file")? {
        files.push(file);
    }
    if let Some(list) = args.get("files") {
        let list = list
            .as_array()
            .ok_or_else(|| "files 必须是路径数组".to_string())?;
        if list.len() > 100 {
            return Err("一次最多暂存 100 个路径".into());
        }
        for item in list {
            let raw = item
                .as_str()
                .ok_or_else(|| "files 里的每一项都必须是路径字符串".to_string())?;
            files.push(rel_path(raw)?);
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn prepare_commit(session: &Session, args: &Value) -> Result<PreparedGitOp, String> {
    let root = repo_root(session, args)?;
    let message = args
        .get("message")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "缺少提交说明".to_string())?
        .to_string();
    let all = args.get("all").and_then(Value::as_bool).unwrap_or(false);
    let files = stage_paths(args)?;
    if all && !files.is_empty() {
        return Err("all=true 时不要再传 file 或 files".into());
    }
    let stage = if all {
        "git add -A".to_string()
    } else if files.is_empty() {
        "使用已暂存内容".to_string()
    } else {
        format!("git add -- {}", files.join(" "))
    };
    let payload = git_confirm_payload(
        "创建 git 提交",
        "允许这次本地 git 写操作？",
        &[
            ("仓库", display_path(&root)),
            ("暂存", stage),
            ("说明", message.clone()),
        ],
    );
    Ok(PreparedGitOp::Pending {
        payload,
        deny: "用户拒绝了这次 git 写操作".into(),
        exec: Box::new(move |_session| {
            if all {
                git_output(&root, &["add", "-A"], None)?;
            } else if !files.is_empty() {
                let mut cmd = vec!["add".to_string(), "--".to_string()];
                cmd.extend(files);
                let add_args = cmd.iter().map(String::as_str).collect::<Vec<_>>();
                git_output(&root, &add_args, None)?;
            }
            git_output(&root, &["commit", "-m", &message], None)
        }),
    })
}

fn prepare_fetch(session: &Session, args: &Value) -> Result<PreparedGitOp, String> {
    let root = repo_root(session, args)?;
    let remote = remote_name(args)?;
    require_github_https_remote(&root, &remote)?;
    let token = github_token(session, args)?;
    let payload = git_confirm_payload(
        "抓取 GitHub 远端",
        "允许这次本地 git 写操作？",
        &[
            ("仓库", display_path(&root)),
            ("远程", remote.clone()),
            ("说明", "只更新远端跟踪，不改工作区".into()),
        ],
    );
    Ok(PreparedGitOp::Pending {
        payload,
        deny: "用户拒绝了这次 git 写操作".into(),
        exec: Box::new(move |_session| git_with_token(&root, &["fetch", &remote], &token)),
    })
}

fn prepare_push(session: &Session, args: &Value) -> Result<PreparedGitOp, String> {
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
    let payload = git_confirm_payload(
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
    );
    Ok(PreparedGitOp::Pending {
        payload,
        deny: "用户拒绝了这次 git 写操作".into(),
        exec: Box::new(move |_session| {
            let args_ref: Vec<&str> = cmd.iter().map(String::as_str).collect();
            let output = git_with_token(&root, &args_ref, &token)?;
            Ok(classify_push_output(
                &output,
                &remote,
                branch.as_deref(),
                tag.as_deref(),
            ))
        }),
    })
}

fn prepare_pull(session: &Session, args: &Value) -> Result<PreparedGitOp, String> {
    let root = repo_root(session, args)?;
    let remote = remote_name(args)?;
    require_github_https_remote(&root, &remote)?;
    if working_tree_dirty(&root)? {
        return Err("工作区有未提交改动，已拒绝 pull".into());
    }
    let branch = requested_branch(args)?;
    let token = github_token(session, args)?;
    let payload = git_confirm_payload(
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
    );
    Ok(PreparedGitOp::Pending {
        payload,
        deny: "用户拒绝了这次 git 写操作".into(),
        exec: Box::new(move |_session| {
            let mut cmd = vec!["pull".to_string(), "--ff-only".into(), remote];
            if let Some(branch) = branch {
                cmd.push(branch);
            }
            let args_ref: Vec<&str> = cmd.iter().map(String::as_str).collect();
            git_with_token(&root, &args_ref, &token)
        }),
    })
}

fn prepare_clone(session: &Session, args: &Value) -> Result<PreparedGitOp, String> {
    let parent = existing_dir(args)?;
    let repository = github_mcp::normalize_repository(&clone_repo_name(args)?)?;
    let mut parts = repository.split('/');
    let owner = parts.next().unwrap_or_default().to_string();
    let repo = parts.next().unwrap_or_default().to_string();
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(repo.as_str())
        .to_string();
    let dir_name = clone_dir_name(&name)?;
    let dest = parent.join(&dir_name);
    if dest.exists() {
        return Err(format!("目标目录已存在：{}", display_path(&dest)));
    }
    let token = github_token(session, args)?;
    let payload = git_confirm_payload(
        "克隆 GitHub 仓库",
        "允许这次本地 git 写操作？",
        &[
            ("来源", format!("https://github.com/{repository}.git")),
            ("目标", display_path(&dest)),
        ],
    );
    Ok(PreparedGitOp::Pending {
        payload,
        deny: "用户拒绝了这次 git 写操作".into(),
        exec: Box::new(move |_session| {
            let url = format!("https://github.com/{owner}/{repo}.git");
            git_with_token(&parent, &["clone", &url, &dir_name], &token)?;
            Ok(format!("已克隆到 {}", display_path(&dest)))
        }),
    })
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

fn repo_root(_session: &Session, args: &Value) -> Result<PathBuf, String> {
    if args.get("path").and_then(Value::as_str).is_none() {
        return Err("请传 path 绝对路径".into());
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

fn classify_push_output(
    output: &str,
    remote: &str,
    branch: Option<&str>,
    tag: Option<&str>,
) -> String {
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

#[cfg(test)]
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
                ahead = extra.split("ahead ").nth(1).and_then(|part| {
                    part.chars()
                        .take_while(|ch| ch.is_ascii_digit())
                        .collect::<String>()
                        .parse()
                        .ok()
                });
            }
            if extra.contains("behind ") {
                behind = extra.split("behind ").nth(1).and_then(|part| {
                    part.chars()
                        .take_while(|ch| ch.is_ascii_digit())
                        .collect::<String>()
                        .parse()
                        .ok()
                });
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
    let resolved = github_mcp::resolve_github_credential(session, args)?;
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
    let mut end = MAX_OUTPUT_BYTES
        .saturating_sub(ELLIPSIS.len())
        .min(value.len());
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
        crate::zoomkey::save_policy(
            &vault,
            &dek,
            &crate::zoomkey::ZoomkeyMcpPolicy {
                enabled: true,
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
            "github_git",
            json!({"action":"status","path":"relative/repo"}),
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
            .args([
                "remote",
                "add",
                "origin",
                "git@github.com:octocat/hello.git",
            ])
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
        let status =
            call_tool_text(
                &mut session,
                "github_git",
                json!({ "action": "status", "path": path }),
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
            "github_git",
            json!({ "action": "log", "path": path, "limit": 5 }),
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
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/octocat/hello.git",
            ])
            .status()
            .unwrap();
        let creds = crate::github_mcp::list_credentials(&session).unwrap();
        let err = call_tool_text(
            &mut session,
            "github_git",
            json!({
                "action": "pull",
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
        let definitions = tool_definitions();
        assert_eq!(definitions.len(), 1);
        let definition = &definitions[0];
        assert_eq!(definition["name"], "github_git");
        assert_eq!(definition["readOnly"], false);
        assert_eq!(definition["risk"], "high");
        assert_eq!(definition["annotations"]["readOnlyHint"], false);
        assert_eq!(definition["annotations"]["destructiveHint"], true);
        let actions = definition["inputSchema"]["properties"]["action"]["enum"]
            .as_array()
            .unwrap();
        for action in ["status", "diff", "log", "branches", "fetch", "pull", "commit", "push", "clone"] {
            assert!(actions.iter().any(|item| item == action), "missing {action}");
        }
        assert!(!definitions.iter().any(|tool| tool["name"] == "github_git_list"));
        assert!(!definitions
            .iter()
            .any(|tool| tool["name"] == "github_git_workspace_register"));
    }

    #[test]
    fn status_requires_absolute_path() {
        let repo = temp_git_repo();
        let mut session = enabled_session();
        let status = call_tool_text(
            &mut session,
            "github_git",
            json!({ "action": "status", "path": repo.to_string_lossy() }),
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
        assert_eq!(
            display_path(Path::new(r"E:\project\sealbox")),
            r"E:\project\sealbox"
        );
        assert_eq!(
            display_path(Path::new("//?/E:/project/sealbox")),
            r"E:\project\sealbox"
        );
    }

    #[test]
    fn classify_push_distinguishes_up_to_date() {
        let up_to_date =
            classify_push_output("Everything up-to-date", "origin", Some("main"), None);
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
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/octocat/hello.git",
            ])
            .status()
            .unwrap();
        let err = call_tool_text(
            &mut session,
            "github_git",
            json!({
                "action": "push",
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
                "github_git",
                json!({ "action": "commit", "path": path, "message": "nope" }),
            )
        })
        .unwrap_err();
        assert!(error.contains("拒绝"), "{error}");
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn stage_files_confirms_once_and_stages_all() {
        let repo = temp_git_repo();
        fs::write(repo.join("a.txt"), "a\n").unwrap();
        fs::write(repo.join("b.txt"), "b\n").unwrap();
        let mut session = enabled_session();
        let path = repo.to_string_lossy().into_owned();
        let prepared = prepare_tool(
            &mut session,
            "github_git",
            json!({
                "action": "commit",
                "path": path,
                "message": "add both",
                "files": ["b.txt", "a.txt", "a.txt"]
            }),
        )
        .unwrap();
        let PreparedGitOp::Pending { payload, exec, .. } = prepared else {
            panic!("commit must wait for one confirmation");
        };
        let staged = payload
            .fields
            .iter()
            .find(|field| field.label == "暂存")
            .map(|field| field.value.as_str())
            .unwrap_or_default();
        assert_eq!(staged, "git add -- a.txt b.txt");
        exec(&mut session).unwrap();
        let committed = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["show", "--name-only", "--pretty=format:", "HEAD"])
            .output()
            .unwrap();
        let names = String::from_utf8_lossy(&committed.stdout);
        assert!(committed.status.success());
        assert!(names.contains("a.txt"), "{names}");
        assert!(names.contains("b.txt"), "{names}");
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn denied_stage_files_leaves_worktree_unstaged() {
        let repo = temp_git_repo();
        fs::write(repo.join("a.txt"), "a\n").unwrap();
        fs::write(repo.join("b.txt"), "b\n").unwrap();
        let mut session = enabled_session();
        let path = repo.to_string_lossy().into_owned();
        let prepared = prepare_tool(
            &mut session,
            "github_git",
            json!({
                "action": "commit",
                "path": path,
                "message": "add both",
                "files": ["a.txt", "b.txt"]
            }),
        )
        .unwrap();
        let PreparedGitOp::Pending {
            payload,
            deny,
            exec: _,
        } = prepared
        else {
            panic!("stage must wait for confirmation before touching the index");
        };
        assert!(payload
            .fields
            .iter()
            .any(|field| field.value.contains("a.txt")));
        assert!(payload
            .fields
            .iter()
            .any(|field| field.value.contains("b.txt")));
        assert!(deny.contains("拒绝"));
        let staged = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["diff", "--cached", "--name-only"])
            .output()
            .unwrap();
        assert!(staged.status.success());
        assert!(String::from_utf8_lossy(&staged.stdout).trim().is_empty());
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn stage_files_rejects_parent_path_before_confirm() {
        let repo = temp_git_repo();
        let mut session = enabled_session();
        let path = repo.to_string_lossy().into_owned();
        let error = match prepare_tool(
            &mut session,
            "github_git",
            json!({
                "action": "commit",
                "path": path,
                "message": "nope",
                "files": ["ok.txt", "../secret"]
            }),
        ) {
            Err(error) => error,
            Ok(_) => panic!("parent path must be rejected before confirmation"),
        };
        assert!(error.contains(".."), "{error}");
        let _ = fs::remove_dir_all(&repo);
    }
}
