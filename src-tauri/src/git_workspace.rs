//! 本地仓库上的 `github_git_*` 工具。
//!
//! 与 `github_mcp` 共用 `GithubMcpPolicy.enabled`。Agent 传入本机绝对路径；
//! push / pull / clone 用一次性 askpass 注入金库 Token，不改 remote URL。

use crate::redact::redact_text;
use crate::session::Session;
use crate::vault::SecretPayload;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_LOG: u64 = 50;
const DEFAULT_LOG: u64 = 20;
const MAX_PATH: u64 = 500;
const ELLIPSIS: &str = "…";

pub fn tool_definitions() -> Vec<Value> {
    vec![
        tool(
            "github_git_status",
            "查看本地 git 仓库的当前分支与 porcelain 状态。path 为仓库绝对路径。",
            schema(&[("path", string_schema(1, MAX_PATH))], &["path"]),
            true,
        ),
        tool(
            "github_git_diff",
            "查看本地 git 仓库的 diff。默认只返回 stat 摘要；staged=true 看暂存区。path 为仓库绝对路径。",
            schema(
                &[
                    ("path", string_schema(1, MAX_PATH)),
                    ("staged", json!({"type":"boolean","default":false})),
                    ("stat_only", json!({"type":"boolean","default":true})),
                    ("file", string_schema(1, 500)),
                ],
                &["path"],
            ),
            true,
        ),
        tool(
            "github_git_log",
            "查看本地 git 仓库的最近提交（oneline）。默认 20 条，最多 50 条。path 为仓库绝对路径。",
            schema(
                &[
                    ("path", string_schema(1, MAX_PATH)),
                    ("limit", json!({"type":"integer","minimum":1,"maximum":50,"default":20})),
                ],
                &["path"],
            ),
            true,
        ),
        tool(
            "github_git_branches",
            "列出本地 git 仓库的分支，当前分支带标记。path 为仓库绝对路径。",
            schema(&[("path", string_schema(1, MAX_PATH))], &["path"]),
            true,
        ),
        tool(
            "github_git_stage",
            "把仓库内相对路径加入暂存区。all=true 才等价 git add -A。path 为仓库绝对路径。",
            schema(
                &[
                    ("path", string_schema(1, MAX_PATH)),
                    ("file", string_schema(1, 500)),
                    ("all", json!({"type":"boolean","default":false})),
                ],
                &["path"],
            ),
            false,
        ),
        tool(
            "github_git_commit",
            "提交已暂存改动。message 必填。不改正文作者、不做 amend。path 为仓库绝对路径。",
            schema(
                &[
                    ("path", string_schema(1, MAX_PATH)),
                    ("message", string_schema(1, 2000)),
                ],
                &["path", "message"],
            ),
            false,
        ),
        tool(
            "github_git_push",
            "把当前分支推到 origin。只用金库 GitHub Token 经 askpass 注入，不改 remote URL。",
            schema(
                &[
                    ("path", string_schema(1, MAX_PATH)),
                    ("credential_id", string_schema(1, 100)),
                ],
                &["path", "credential_id"],
            ),
            false,
        ),
        tool(
            "github_git_pull",
            "从 origin 拉取并合并当前分支。工作区有未提交改动时拒绝。无 rebase、无 force。",
            schema(
                &[
                    ("path", string_schema(1, MAX_PATH)),
                    ("credential_id", string_schema(1, 100)),
                ],
                &["path", "credential_id"],
            ),
            false,
        ),
        tool(
            "github_git_clone",
            "把 github.com/{owner}/{repo} 克隆到 path 目录下。path 为已存在的绝对父目录。",
            schema(
                &[
                    ("path", string_schema(1, MAX_PATH)),
                    ("credential_id", string_schema(1, 100)),
                    ("owner", string_schema(1, 100)),
                    ("repo", string_schema(1, 100)),
                    ("name", string_schema(1, 100)),
                ],
                &["path", "credential_id", "owner", "repo"],
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
        "github_git_status" => status(&args),
        "github_git_diff" => diff(&args),
        "github_git_log" => log(&args),
        "github_git_branches" => branches(&args),
        "github_git_stage" => stage(&args),
        "github_git_commit" => commit(&args),
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
    let Some(id) = args.get("credential_id").and_then(Value::as_str) else {
        return Vec::new();
    };
    let Ok(vault) = session.vault() else {
        return Vec::new();
    };
    let Ok(dek) = session.dek() else {
        return Vec::new();
    };
    match vault.get_active_secret(dek, id) {
        Ok(SecretPayload::ApiToken { token, .. }) if !token.is_empty() => vec![token],
        _ => Vec::new(),
    }
}

fn status(args: &Value) -> Result<String, String> {
    let root = repo_root(args)?;
    git_output(&root, &["status", "--porcelain=v1", "-b"], None)
}

fn diff(args: &Value) -> Result<String, String> {
    let root = repo_root(args)?;
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
    let owned;
    if let Some(rel) = file {
        owned = rel;
        cmd.push("--");
        cmd.push(&owned);
    }
    git_output(&root, &cmd, None)
}

fn log(args: &Value) -> Result<String, String> {
    let root = repo_root(args)?;
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_LOG)
        .clamp(1, MAX_LOG);
    let n = format!("-{limit}");
    git_output(&root, &["log", "--oneline", &n], None)
}

fn branches(args: &Value) -> Result<String, String> {
    let root = repo_root(args)?;
    git_output(&root, &["branch", "--list"], None)
}

fn stage(args: &Value) -> Result<String, String> {
    let root = repo_root(args)?;
    let all = args.get("all").and_then(Value::as_bool).unwrap_or(false);
    if all {
        return git_output(&root, &["add", "-A"], None);
    }
    let file = optional_rel_path(args, "file")?
        .ok_or_else(|| "请提供 file，或设 all=true".to_string())?;
    git_output(&root, &["add", "--", &file], None)
}

fn commit(args: &Value) -> Result<String, String> {
    let root = repo_root(args)?;
    let message = args
        .get("message")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "缺少提交说明".to_string())?;
    git_output(&root, &["commit", "-m", message], None)
}

fn push(session: &Session, args: &Value) -> Result<String, String> {
    let root = repo_root(args)?;
    require_github_https_origin(&root)?;
    let token = github_token(session, args)?;
    git_with_token(&root, &["push", "-u", "origin", "HEAD"], &token)
}

fn pull(session: &Session, args: &Value) -> Result<String, String> {
    let root = repo_root(args)?;
    require_github_https_origin(&root)?;
    if working_tree_dirty(&root)? {
        return Err("工作区有未提交改动，已拒绝 pull".into());
    }
    let token = github_token(session, args)?;
    git_with_token(&root, &["pull", "--ff-only", "origin"], &token)
}

fn clone_repo(session: &Session, args: &Value) -> Result<String, String> {
    let parent = existing_dir(args)?;
    let owner = slug(args, "owner")?;
    let repo = slug(args, "repo")?;
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(repo.as_str());
    let dir_name = clone_dir_name(name)?;
    let dest = parent.join(&dir_name);
    if dest.exists() {
        return Err(format!("目标目录已存在：{}", dest.display()));
    }
    let token = github_token(session, args)?;
    let url = format!("https://github.com/{owner}/{repo}.git");
    git_with_token(&parent, &["clone", &url, &dir_name], &token)?;
    Ok(format!("已克隆到 {}", dest.display()))
}

fn repo_root(args: &Value) -> Result<PathBuf, String> {
    let path = absolute_path(args)?;
    if !path.exists() {
        return Err(format!("路径不存在：{}", path.display()));
    }
    let output = git_output(&path, &["rev-parse", "--show-toplevel"], None)?;
    let toplevel = PathBuf::from(output.trim());
    let canonical = toplevel
        .canonicalize()
        .map_err(|_| format!("仓库路径无效：{}", toplevel.display()))?;
    if !canonical.join(".git").exists() {
        return Err("该目录不是 git 仓库".into());
    }
    Ok(canonical)
}

fn existing_dir(args: &Value) -> Result<PathBuf, String> {
    let path = absolute_path(args)?;
    let canonical = path
        .canonicalize()
        .map_err(|_| format!("路径无效：{}", path.display()))?;
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

fn slug(args: &Value, key: &str) -> Result<String, String> {
    let raw = args
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("缺少参数 {key}"))?;
    if !raw
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(format!("{key} 含有非法字符"));
    }
    if raw.contains("..") {
        return Err(format!("{key} 不能包含 .."));
    }
    Ok(raw.to_string())
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
    let url = git_output(root, &["remote", "get-url", "origin"], None)?;
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

fn github_token(session: &Session, args: &Value) -> Result<Zeroizing<String>, String> {
    let credential_id = args
        .get("credential_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "缺少参数 credential_id".to_string())?;
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
        return Err("凭据缺少 Token".into());
    }
    Ok(Zeroizing::new(token))
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
        "risk": if read_only { "low" } else { "high" }
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
        crate::github_mcp::save_policy(&vault, &dek, &GithubMcpPolicy { enabled: true }).unwrap();
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
        assert!(
            status.contains("master") || status.contains("main") || status.contains("##"),
            "{status}"
        );
        let log = call_tool_text(
            &mut session,
            "github_git_log",
            json!({ "path": path, "limit": 5 }),
        )
        .unwrap();
        assert!(log.contains("init"), "{log}");
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
        }
        assert!(!tool_definitions()
            .iter()
            .any(|tool| tool["name"] == "github_git_list"));
    }
}
