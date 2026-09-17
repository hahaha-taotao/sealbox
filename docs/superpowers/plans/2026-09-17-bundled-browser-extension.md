# Bundled Browser Extension Install Wizard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用户在 Sealbox「插件」页把随包扩展导出到本机固定目录，并打开 Chrome / Edge 扩展页；不必再去仓库找 `extension/`。

**Architecture:** 新增 `src-tauri/src/extension_install.rs` 处理白名单复制、版本/哈希比对、浏览器探测和打开命令。`commands.rs` 只把 Tauri `AppHandle` 路径转进去。前端「插件」页上半是安装向导，下半保持现有配对。不改填表协议、配对码、Token。

**Tech Stack:** Tauri 2、Rust、Vue 3、现有 `sha2` / `hex` / `serde_json`；Windows 下用 `winreg` 读 App Paths。

**Spec:** `docs/superpowers/specs/2026-09-17-bundled-browser-extension-design.md`

---

## File map

| File | Responsibility |
|---|---|
| Create `src-tauri/src/extension_install.rs` | 白名单、复制、指纹、status、浏览器探测、explorer/chrome/edge 命令 |
| Modify `src-tauri/src/lib.rs` | `pub mod extension_install`；注册 4 个 command |
| Modify `src-tauri/src/commands.rs` | 4 个薄 `#[tauri::command]`，不要求解锁 |
| Modify `src-tauri/Cargo.toml` | Windows `winreg` |
| Modify `src-tauri/tauri.conf.json` | `bundle.resources` 按文件映射到 `extension/` |
| Modify `src/lib/tauri.ts` | 类型 + 4 个 invoke |
| Modify `src/App.vue` | 插件页安装段 |
| Modify `src/styles.css` | 目录路径 / 步骤列表 |
| Modify `README.md` | 安装步骤改为从客户端导出 |

不要改 `extension/*.js` 填表逻辑，不要把 `fill-logic.test.js` 打进安装包。

---

### Task 1: 白名单复制、指纹、过期检测

**Files:**
- Create: `src-tauri/src/extension_install.rs`
- Modify: `src-tauri/src/lib.rs`（只加 `pub mod extension_install;`）

- [ ] **Step 1: 加模块声明，先写会失败的测试**

在 `src-tauri/src/lib.rs` 的 `pub mod fill;` 后插入：

```rust
pub mod extension_install;
```

创建 `src-tauri/src/extension_install.rs`，先只放测试（实现函数先不要写全，让编译失败也算红灯）：

```rust
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub const FILES: &[&str] = &[
    "manifest.json",
    "background.js",
    "content.js",
    "fill-logic.cjs",
    "overlay-inject.js",
    "overlay.html",
    "overlay.js",
    "page-fill.js",
    "popup.css",
    "popup.html",
    "popup.js",
];

const MISSING_BUNDLE: &str = "找不到内置扩展，请重新安装 Sealbox。";
const WRITE_FAILED: &str = "无法写入扩展目录，请检查磁盘权限。";

#[derive(Debug, Clone, Serialize)]
pub struct BrowserAvailability {
    pub available: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtensionInstallStatus {
    pub dest_path: String,
    pub bundled_version: String,
    pub installed: bool,
    pub installed_version: Option<String>,
    pub outdated: bool,
    pub chrome: BrowserAvailability,
    pub edge: BrowserAvailability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserKind {
    Chrome,
    Edge,
}

pub fn dest_dir(local_data_dir: &Path) -> PathBuf {
    local_data_dir.join("extension")
}

pub fn require_bundled(bundled: &Path) -> Result<(), String> {
    if bundled.join("manifest.json").is_file() {
        Ok(())
    } else {
        Err(MISSING_BUNDLE.into())
    }
}

pub fn manifest_version(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join("manifest.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("version")?.as_str().map(|s| s.to_string())
}

pub fn fingerprint(dir: &Path) -> String {
    let mut names: Vec<&str> = FILES.to_vec();
    names.sort_unstable();
    let mut hasher = Sha256::new();
    for name in names {
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
        let bytes = std::fs::read(dir.join(name)).unwrap_or_default();
        hasher.update(&bytes);
    }
    hex::encode(hasher.finalize())
}

pub fn copy_extension(src: &Path, dest: &Path) -> Result<(), String> {
    require_bundled(src)?;
    std::fs::create_dir_all(dest).map_err(|_| WRITE_FAILED.to_string())?;
    for name in FILES {
        let from = src.join(name);
        if !from.is_file() {
            return Err(MISSING_BUNDLE.into());
        }
        std::fs::copy(&from, dest.join(name)).map_err(|_| WRITE_FAILED.to_string())?;
    }
    let allowed: HashSet<&str> = FILES.iter().copied().collect();
    let entries = std::fs::read_dir(dest).map_err(|_| WRITE_FAILED.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|_| WRITE_FAILED.to_string())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if allowed.contains(name.as_ref()) {
            continue;
        }
        let path = entry.path();
        let res = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        res.map_err(|_| WRITE_FAILED.to_string())?;
    }
    Ok(())
}

pub fn status_at(
    bundled: &Path,
    dest: &Path,
    chrome: bool,
    edge: bool,
) -> Result<ExtensionInstallStatus, String> {
    require_bundled(bundled)?;
    let bundled_version = manifest_version(bundled).ok_or_else(|| MISSING_BUNDLE.to_string())?;
    let installed = dest.join("manifest.json").is_file();
    let installed_version = if installed {
        manifest_version(dest)
    } else {
        None
    };
    let outdated = installed && fingerprint(bundled) != fingerprint(dest);
    Ok(ExtensionInstallStatus {
        dest_path: dest.to_string_lossy().into_owned(),
        bundled_version,
        installed,
        installed_version,
        outdated,
        chrome: BrowserAvailability { available: chrome },
        edge: BrowserAvailability { available: edge },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sealbox-ext-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_bundle(dir: &Path, version: &str, background: &str) {
        fs::create_dir_all(dir).unwrap();
        for name in FILES {
            let body = if *name == "manifest.json" {
                format!(r#"{{"manifest_version":3,"version":"{version}","name":"Sealbox"}}"#)
            } else if *name == "background.js" {
                background.to_string()
            } else {
                format!("// {name}\n")
            };
            fs::write(dir.join(name), body).unwrap();
        }
        fs::write(dir.join("fill-logic.test.js"), "should not copy").unwrap();
    }

    #[test]
    fn dest_dir_stays_under_local_data() {
        let root = temp_dir();
        let dest = dest_dir(&root);
        assert_eq!(dest, root.join("extension"));
        assert!(dest.starts_with(&root));
    }

    #[test]
    fn copy_writes_whitelist_only_and_strips_extras() {
        let src = temp_dir().join("src");
        let dest = temp_dir().join("dest");
        write_bundle(&src, "0.1.0", "v1");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("evil.js"), "nope").unwrap();
        copy_extension(&src, &dest).unwrap();
        for name in FILES {
            assert!(dest.join(name).is_file(), "{name}");
        }
        assert!(!dest.join("fill-logic.test.js").exists());
        assert!(!dest.join("evil.js").exists());
        assert_eq!(fs::read_to_string(dest.join("background.js")).unwrap(), "v1");
    }

    #[test]
    fn missing_bundle_fails() {
        let src = temp_dir().join("empty");
        fs::create_dir_all(&src).unwrap();
        let dest = temp_dir().join("dest");
        let err = copy_extension(&src, &dest).unwrap_err();
        assert_eq!(err, "找不到内置扩展，请重新安装 Sealbox。");
    }

    #[test]
    fn outdated_when_version_or_bytes_differ() {
        let bundled = temp_dir().join("bundled");
        let dest = temp_dir().join("dest");
        write_bundle(&bundled, "0.1.1", "new");
        write_bundle(&dest, "0.1.0", "new");
        let st = status_at(&bundled, &dest, false, false).unwrap();
        assert!(st.installed);
        assert_eq!(st.installed_version.as_deref(), Some("0.1.0"));
        assert_eq!(st.bundled_version, "0.1.1");
        assert!(st.outdated);

        write_bundle(&dest, "0.1.1", "old");
        let st = status_at(&bundled, &dest, false, false).unwrap();
        assert_eq!(st.installed_version.as_deref(), Some("0.1.1"));
        assert!(st.outdated);

        write_bundle(&dest, "0.1.1", "new");
        let st = status_at(&bundled, &dest, true, false).unwrap();
        assert!(!st.outdated);
        assert!(st.chrome.available);
        assert!(!st.edge.available);
    }

    #[test]
    fn not_installed_is_not_outdated() {
        let bundled = temp_dir().join("bundled");
        write_bundle(&bundled, "0.1.0", "x");
        let dest = temp_dir().join("missing");
        let st = status_at(&bundled, &dest, false, false).unwrap();
        assert!(!st.installed);
        assert!(st.installed_version.is_none());
        assert!(!st.outdated);
    }
}
```

这一步把实现和测试一起放进文件，是为了一次编译通过。真正的 TDD 顺序是：先保存测试 + 空函数，跑红，再填函数。若你严格先红后绿：先注释掉函数体、让测试编译失败，再恢复。

- [ ] **Step 2: 跑测试**

```bash
cargo test --manifest-path src-tauri/Cargo.toml extension_install -- --nocapture
```

Expected: 全部 PASS（`dest_dir_stays_under_local_data`、`copy_writes_whitelist_only_and_strips_extras`、`missing_bundle_fails`、`outdated_when_version_or_bytes_differ`、`not_installed_is_not_outdated`）。

若 `lib.rs` 未加 `pub mod extension_install;`，会编译失败。

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/extension_install.rs src-tauri/src/lib.rs
git commit -m "feat: copy bundled fill extension into a stable local folder"
```

---

### Task 2: 浏览器探测与打开命令（不 spawn 真浏览器）

**Files:**
- Modify: `src-tauri/src/extension_install.rs`
- Modify: `src-tauri/Cargo.toml`

- [ ] **Step 1: 在 `Cargo.toml` 的 Windows 依赖里加 winreg**

`src-tauri/Cargo.toml` 现有：

```toml
[target.'cfg(windows)'.dependencies]
windows = { version = "0.58", features = [
  "Security_Credentials_UI",
  "Foundation",
] }
```

改成：

```toml
[target.'cfg(windows)'.dependencies]
winreg = "0.52"
windows = { version = "0.58", features = [
  "Security_Credentials_UI",
  "Foundation",
] }
```

- [ ] **Step 2: 追加探测 / 打开命令和测试**

在 `src-tauri/src/extension_install.rs` 顶部 `use` 增加：

```rust
use std::process::Command;
```

在 `status_at` 之后、`#[cfg(test)]` 之前追加：

```rust
pub fn parse_browser(name: &str) -> Result<BrowserKind, String> {
    match name {
        "chrome" => Ok(BrowserKind::Chrome),
        "edge" => Ok(BrowserKind::Edge),
        _ => Err("未检测到该浏览器。".into()),
    }
}

pub fn resolve_browser(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|p| p.is_file()).cloned()
}

pub fn chrome_install_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(pf) = std::env::var("ProgramFiles") {
        out.push(PathBuf::from(pf).join(r"Google\Chrome\Application\chrome.exe"));
    }
    if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
        out.push(PathBuf::from(pf86).join(r"Google\Chrome\Application\chrome.exe"));
    }
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        out.push(PathBuf::from(local).join(r"Google\Chrome\Application\chrome.exe"));
    }
    out
}

pub fn edge_install_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
        out.push(PathBuf::from(pf86).join(r"Microsoft\Edge\Application\msedge.exe"));
    }
    if let Ok(pf) = std::env::var("ProgramFiles") {
        out.push(PathBuf::from(pf).join(r"Microsoft\Edge\Application\msedge.exe"));
    }
    out
}

#[cfg(windows)]
fn app_path_from_registry(exe_name: &str) -> Option<PathBuf> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;
    let sub = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}");
    for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        let hk = RegKey::predef(hive);
        let Ok(key) = hk.open_subkey(&sub) else { continue };
        let Ok(val) = key.get_value::<String, _>("") else { continue };
        let path = PathBuf::from(val);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

#[cfg(not(windows))]
fn app_path_from_registry(_exe_name: &str) -> Option<PathBuf> {
    None
}

pub fn detect_chrome() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(p) = app_path_from_registry("chrome.exe") {
        candidates.push(p);
    }
    candidates.extend(chrome_install_candidates());
    resolve_browser(&candidates)
}

pub fn detect_edge() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(p) = app_path_from_registry("msedge.exe") {
        candidates.push(p);
    }
    candidates.extend(edge_install_candidates());
    resolve_browser(&candidates)
}

pub fn explorer_open_command(dir: &Path) -> Command {
    let mut cmd = Command::new("explorer.exe");
    cmd.arg(dir);
    cmd
}

pub fn browser_open_command(exe: &Path, kind: BrowserKind) -> Command {
    let mut cmd = Command::new(exe);
    cmd.arg(match kind {
        BrowserKind::Chrome => "chrome://extensions",
        BrowserKind::Edge => "edge://extensions",
    });
    cmd
}

pub fn spawn_logged(mut cmd: Command, fail: &str) -> Result<(), String> {
    cmd.spawn().map(|_| ()).map_err(|_| fail.to_string())
}
```

在 `mod tests` 里追加（保留 Task 1 的测试）：

```rust
    #[test]
    fn resolve_browser_picks_first_existing_file() {
        let dir = temp_dir();
        let missing = dir.join("missing.exe");
        let present = dir.join("present.exe");
        fs::write(&present, b"x").unwrap();
        assert_eq!(
            resolve_browser(&[missing.clone(), present.clone()]),
            Some(present)
        );
        assert_eq!(resolve_browser(&[missing]), None);
    }

    #[test]
    fn open_commands_use_fixed_targets() {
        let folder = temp_dir();
        let explorer = explorer_open_command(&folder);
        assert_eq!(explorer.get_program(), "explorer.exe");
        let args: Vec<_> = explorer
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, [folder.to_string_lossy().into_owned()]);

        let chrome = browser_open_command(Path::new(r"C:\Chrome\chrome.exe"), BrowserKind::Chrome);
        assert_eq!(chrome.get_program(), Path::new(r"C:\Chrome\chrome.exe"));
        let args: Vec<_> = chrome
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["chrome://extensions"]);

        let edge = browser_open_command(Path::new(r"C:\Edge\msedge.exe"), BrowserKind::Edge);
        let args: Vec<_> = edge
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["edge://extensions"]);
    }

    #[test]
    fn parse_browser_only_allows_chrome_and_edge() {
        assert_eq!(parse_browser("chrome").unwrap(), BrowserKind::Chrome);
        assert_eq!(parse_browser("edge").unwrap(), BrowserKind::Edge);
        assert!(parse_browser("firefox").is_err());
        assert!(parse_browser("chrome.exe").is_err());
    }
```

- [ ] **Step 3: 跑测试**

```bash
cargo test --manifest-path src-tauri/Cargo.toml extension_install -- --nocapture
```

Expected: Task 1 + Task 2 测试全 PASS。不要对真实 Chrome 调 `spawn`。

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/extension_install.rs src-tauri/Cargo.toml src-tauri/Cargo.lock
git commit -m "feat: detect Chrome and Edge for the extension install wizard"
```

---

### Task 3: Tauri 命令 + 把扩展打进安装包

**Files:**
- Modify: `src-tauri/src/extension_install.rs`（AppHandle 封装）
- Modify: `src-tauri/src/commands.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/tauri.conf.json`

- [ ] **Step 1: 在 `extension_install.rs` 加 AppHandle 封装**

文件顶部增加：

```rust
use tauri::{AppHandle, Manager};
```

在 `spawn_logged` 之后追加：

```rust
fn bundled_dir(app: &AppHandle) -> Result<PathBuf, String> {
    if let Ok(dir) = app.path().resource_dir() {
        let bundled = dir.join("extension");
        if bundled.join("manifest.json").is_file() {
            return Ok(bundled);
        }
    }
    let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../extension");
    if dev.join("manifest.json").is_file() {
        return Ok(dev);
    }
    Err(MISSING_BUNDLE.into())
}

fn local_dest(app: &AppHandle) -> Result<PathBuf, String> {
    let root = app
        .path()
        .app_local_data_dir()
        .map_err(|_| WRITE_FAILED.to_string())?;
    Ok(dest_dir(&root))
}

pub fn status_for_app(app: &AppHandle) -> Result<ExtensionInstallStatus, String> {
    status_at(
        &bundled_dir(app)?,
        &local_dest(app)?,
        detect_chrome().is_some(),
        detect_edge().is_some(),
    )
}

pub fn install_for_app(app: &AppHandle) -> Result<ExtensionInstallStatus, String> {
    let src = bundled_dir(app)?;
    let dest = local_dest(app)?;
    copy_extension(&src, &dest)?;
    let _ = spawn_logged(
        explorer_open_command(&dest),
        "无法打开扩展目录，请手动打开上面的路径。",
    );
    status_at(&src, &dest, detect_chrome().is_some(), detect_edge().is_some())
}

pub fn open_folder_for_app(app: &AppHandle) -> Result<(), String> {
    let dest = local_dest(app)?;
    if !dest.join("manifest.json").is_file() {
        return Err("请先安装到本机。".into());
    }
    spawn_logged(explorer_open_command(&dest), "无法打开扩展目录，请手动打开上面的路径。")
}

pub fn open_browser_for_app(app: &AppHandle, browser: &str) -> Result<(), String> {
    let _ = app;
    let kind = parse_browser(browser)?;
    let (exe, missing, fail) = match kind {
        BrowserKind::Chrome => (
            detect_chrome(),
            "未检测到 Google Chrome",
            "无法打开扩展页，请手动访问 chrome://extensions 或 edge://extensions。",
        ),
        BrowserKind::Edge => (
            detect_edge(),
            "未检测到 Microsoft Edge",
            "无法打开扩展页，请手动访问 chrome://extensions 或 edge://extensions。",
        ),
    };
    let exe = exe.ok_or_else(|| missing.to_string())?;
    spawn_logged(browser_open_command(&exe, kind), fail)
}
```

`open_browser_for_app` 里的 `let _ = app;` 是为了签名稳定，以后若要写审计不必改 command。探测不依赖 `app`。

- [ ] **Step 2: 在 `commands.rs` 加四个不解锁的 command**

放在 `window_control` 附近即可。`commands.rs` 增加：

```rust
#[tauri::command]
pub fn extension_install_status(
    app: AppHandle,
) -> Result<crate::extension_install::ExtensionInstallStatus, String> {
    crate::extension_install::status_for_app(&app)
}

#[tauri::command]
pub fn extension_install(
    app: AppHandle,
) -> Result<crate::extension_install::ExtensionInstallStatus, String> {
    crate::extension_install::install_for_app(&app)
}

#[tauri::command]
pub fn extension_open_folder(app: AppHandle) -> Result<(), String> {
    crate::extension_install::open_folder_for_app(&app)
}

#[tauri::command]
pub fn extension_open_browser(app: AppHandle, browser: String) -> Result<(), String> {
    crate::extension_install::open_browser_for_app(&app, &browser)
}
```

这些命令不要调用 `session` / `require_existing_vault`。金库锁定时安装仍可用。

- [ ] **Step 3: 注册 invoke handler**

`src-tauri/src/lib.rs` 的 `generate_handler!` 里，在 `commands::window_control,` 前加入：

```rust
            commands::extension_install_status,
            commands::extension_install,
            commands::extension_open_folder,
            commands::extension_open_browser,
```

- [ ] **Step 4: `tauri.conf.json` 按文件打包**

`bundle` 段现为：

```json
  "bundle": {
    "active": true,
    "targets": "all",
    "icon": [
```

改成：

```json
  "bundle": {
    "active": true,
    "targets": "all",
    "resources": {
      "../extension/manifest.json": "extension/manifest.json",
      "../extension/background.js": "extension/background.js",
      "../extension/content.js": "extension/content.js",
      "../extension/fill-logic.cjs": "extension/fill-logic.cjs",
      "../extension/overlay-inject.js": "extension/overlay-inject.js",
      "../extension/overlay.html": "extension/overlay.html",
      "../extension/overlay.js": "extension/overlay.js",
      "../extension/page-fill.js": "extension/page-fill.js",
      "../extension/popup.css": "extension/popup.css",
      "../extension/popup.html": "extension/popup.html",
      "../extension/popup.js": "extension/popup.js"
    },
    "icon": [
```

不要加 `fill-logic.test.js`。不要用 `../extension/**/*`。

- [ ] **Step 5: 编译测试**

```bash
cargo test --manifest-path src-tauri/Cargo.toml extension_install
```

Expected: PASS。若 `winreg` 未进 lockfile，先 `cargo test` 让它更新 `Cargo.lock`。

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/extension_install.rs src-tauri/src/commands.rs src-tauri/src/lib.rs src-tauri/tauri.conf.json src-tauri/Cargo.lock
git commit -m "feat: expose bundled extension install commands"
```

---

### Task 4: 「插件」页安装向导

**Files:**
- Modify: `src/lib/tauri.ts`
- Modify: `src/App.vue`
- Modify: `src/styles.css`

- [ ] **Step 1: 前端 API**

在 `src/lib/tauri.ts` 的 `api` 对象里、`fillPairingStatus` 之后加入：

```ts
export interface ExtensionInstallStatus {
  dest_path: string;
  bundled_version: string;
  installed: boolean;
  installed_version: string | null;
  outdated: boolean;
  chrome: { available: boolean };
  edge: { available: boolean };
}
```

把类型加进 `App.vue` 的 import 列表（见 Step 2）。`api` 内：

```ts
  extensionInstallStatus: () => invoke<ExtensionInstallStatus>("extension_install_status"),
  extensionInstall: () => invoke<ExtensionInstallStatus>("extension_install"),
  extensionOpenFolder: () => invoke("extension_open_folder"),
  extensionOpenBrowser: (browser: "chrome" | "edge") =>
    invoke("extension_open_browser", { browser }),
```

- [ ] **Step 2: `App.vue` 状态与动作**

`import { api, type ... }` 增加 `type ExtensionInstallStatus`。

在 `pairingBusy` 旁增加：

```ts
const extStatus = ref<ExtensionInstallStatus | null>(null);
const extError = ref("");
const extBusy = ref(false);

function extStatusText(s: ExtensionInstallStatus | null) {
  if (!s) return "尚未检查本机扩展。";
  if (!s.installed) return "尚未安装到本机";
  if (!s.outdated) return `已安装 · v${s.installed_version || s.bundled_version}`;
  if (s.installed_version && s.installed_version !== s.bundled_version) {
    return `已安装 · v${s.installed_version}，内置 v${s.bundled_version}，请更新后再到浏览器点刷新`;
  }
  return `已安装 · v${s.installed_version || s.bundled_version}，内置文件已更新，请重新安装后再到浏览器点刷新`;
}

async function refreshExtensionInstall() {
  try {
    extStatus.value = await api.extensionInstallStatus();
    extError.value = "";
  } catch (e) {
    extStatus.value = null;
    extError.value = String(e);
  }
}

async function installExtension() {
  if (extBusy.value) return;
  extBusy.value = true;
  extError.value = "";
  try {
    extStatus.value = await api.extensionInstall();
    showToast("已安装到本机并打开目录");
  } catch (e) {
    extError.value = String(e);
    showToast(extError.value);
  } finally {
    extBusy.value = false;
  }
}

async function openExtensionFolder() {
  extError.value = "";
  try {
    await api.extensionOpenFolder();
  } catch (e) {
    extError.value = String(e);
    showToast(extError.value);
  }
}

async function openExtensionBrowser(browser: "chrome" | "edge") {
  extError.value = "";
  try {
    await api.extensionOpenBrowser(browser);
  } catch (e) {
    extError.value = String(e);
    showToast(extError.value);
  }
}

async function copyExtensionPath() {
  if (!extStatus.value?.dest_path) return;
  await navigator.clipboard.writeText(extStatus.value.dest_path);
  showToast("扩展目录已复制");
}
```

把 `openPlugin` 改成：

```ts
async function openPlugin() {
  goPage("plugin");
  await refreshMcp();
  await refreshPairing();
  await refreshExtensionInstall();
}
```

- [ ] **Step 3: 替换插件页卡片**

把 `page === 'plugin'` 里 `mcp-head` crumb 和整张 `mcp-card` 换成：

```vue
          <div class="mcp-head">
            <div>
              <h2>插件</h2>
              <p class="crumb">Chrome / Edge 扩展随客户端分发。先安装到本机再加载，然后配对。配对码一次性有效；填表 Token 与 MCP Token 分开。</p>
            </div>
          </div>
          <div class="mcp-card" style="max-width:640px">
            <h3>安装扩展</h3>
            <p class="crumb">{{ extStatusText(extStatus) }}</p>
            <div class="field" v-if="extStatus?.dest_path">
              <label>本机目录</label>
              <div class="secret-row">
                <input class="plugin-path" :value="extStatus.dest_path" readonly />
                <button class="btn" type="button" @click="copyExtensionPath">复制</button>
              </div>
            </div>
            <p class="error" v-if="extError">{{ extError }}</p>
            <div class="mcp-actions">
              <button class="btn primary" type="button" :disabled="extBusy" @click="installExtension">
                {{ extBusy ? "正在安装…" : (extStatus && extStatus.installed && !extStatus.outdated ? "重新安装并打开目录" : "安装到本机并打开目录") }}
              </button>
              <button class="btn" type="button" :disabled="!extStatus?.installed" @click="openExtensionFolder">打开目录</button>
              <button class="btn" type="button" :disabled="!extStatus?.chrome.available" @click="openExtensionBrowser('chrome')">打开 Chrome 扩展页</button>
              <button class="btn" type="button" :disabled="!extStatus?.edge.available" @click="openExtensionBrowser('edge')">打开 Edge 扩展页</button>
            </div>
            <p class="crumb" v-if="extStatus && !extStatus.chrome.available">未检测到 Google Chrome</p>
            <p class="crumb" v-if="extStatus && !extStatus.edge.available">未检测到 Microsoft Edge</p>
            <ol class="plugin-steps">
              <li>打开开发者模式</li>
              <li>加载已解压的扩展</li>
              <li>选择上面这个文件夹</li>
            </ol>
            <p class="crumb">升级 Sealbox 后若提示更新，先点安装覆盖文件，再回扩展页点刷新。路径不要改。</p>

            <h3>配对</h3>
            <p class="crumb">扩展加载成功后，点配对，60 秒内把一次性配对码填进扩展。</p>
            <div class="mcp-actions">
              <button class="btn primary" type="button" :disabled="pairingBusy" @click="openFillPairing">{{ pairingBusy ? "正在打开…" : "配对" }}</button>
              <button class="btn" type="button" @click="rotateFill">轮换填表 Token</button>
            </div>
            <p class="error" v-if="pairingError">{{ pairingError }}</p>
            <div id="pairing-code-box" class="pairing-box" v-if="pairing?.active && pairing.code">
              <div class="pairing-meta">
                <span>一次性配对码</span>
                <span>{{ pairing.expires_in_secs }} 秒后失效</span>
              </div>
              <div class="pairing-code-row">
                <div class="pairing-code" aria-label="配对码">{{ pairingLabel(pairing.code) }}</div>
                <button class="icon-btn" type="button" title="复制配对码" aria-label="复制配对码" @click="copyPairingCode">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <rect x="9" y="9" width="13" height="13" rx="2" />
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                  </svg>
                </button>
              </div>
              <p class="crumb" style="margin:8px 0 0;text-align:center">用过即作废。过期后会自动消失。</p>
            </div>
            <p class="crumb" v-else>当前没有开放的配对窗口。</p>
            <div class="field">
              <label>填表 Token</label>
              <div class="secret-row">
                <input :value="revealedFillToken || '••••••••'" readonly />
                <button class="btn" type="button" :disabled="!mcp?.has_fill_token" @click="toggleFillToken">{{ revealedFillToken ? "隐藏" : "显示" }}</button>
                <button class="btn" type="button" :disabled="!mcp?.has_fill_token" @click="copyFillToken">复制</button>
              </div>
            </div>
            <p class="crumb">{{ mcp?.fill_url || "http://127.0.0.1:17891/fill" }} · 只接受 Host 为 127.0.0.1 的本机请求</p>
          </div>
```

`pairingError` 只服务配对段。安装失败走 `extError`。

- [ ] **Step 4: 样式**

`src/styles.css` 在 `.mcp-actions` 后加：

```css
.plugin-path {
  font-family: ui-monospace, Consolas, monospace;
  font-size: 12px;
}
.plugin-steps {
  margin: 0 0 12px;
  padding-left: 1.2em;
  color: var(--text);
  font-size: 13px;
  line-height: 1.7;
}
.plugin-steps li { margin: 0; }
```

- [ ] **Step 5: 手工点一次（dev）**

```bash
npm run tauri dev
```

解锁后打开「插件」：应看到本机目录（`%LOCALAPPDATA%\com.sealbox.app\extension`）、安装按钮、三步说明。点安装后目录被打开，内含白名单文件、没有 `fill-logic.test.js`。未装的浏览器按钮禁用。配对段与以前相同。

- [ ] **Step 6: Commit**

```bash
git add src/lib/tauri.ts src/App.vue src/styles.css
git commit -m "feat: add extension install wizard to the plugin page"
```

---

### Task 5: README 与规格状态

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-09-17-bundled-browser-extension-design.md`

- [ ] **Step 1: 改 README「插件 Plugin」安装步骤**

把：

```
扩展在仓库 `extension/` 目录。应用启动后会在 `127.0.0.1:17891` 提供填表接口。配对在侧栏 **插件** 页，不和 MCP 混在一起。

The unpacked extension lives in `extension/`. After the app starts, fill APIs listen on `127.0.0.1:17891`. Pairing is on the **Plugin** page, not MCP.

1. 运行并解锁 Sealbox / Run and unlock Sealbox.
2. 打开 `chrome://extensions`（Edge：`edge://extensions`），打开「开发者模式」，加载已解压的扩展，选择 `extension` 文件夹 / Enable Developer mode and load the unpacked `extension` folder.
3. 在 Sealbox 的 **插件** 页点 **配对**，60 秒内把一次性配对码填进扩展 / On the Plugin page click **Pair**, then enter the one-time code in the extension within 60 seconds.
```

换成：

```
应用启动后会在 `127.0.0.1:17891` 提供填表接口。配对和扩展安装都在侧栏 **插件** 页，不和 MCP 混在一起。开发调试仍可直接加载仓库里的 `extension/`。

After the app starts, fill APIs listen on `127.0.0.1:17891`. Install and pairing are on the **Plugin** page, not MCP. Developers can still load the repo `extension/` folder unpacked.

1. 运行 Sealbox（安装扩展不要求解锁）/ Run Sealbox. Installing the extension does not require an unlocked vault.
2. 打开侧栏 **插件**，点 **安装到本机并打开目录**。扩展写到 `%LOCALAPPDATA%\com.sealbox.app\extension\`。再打开 `chrome://extensions` 或 `edge://extensions`，打开开发者模式，加载已解压的扩展，选刚打开的文件夹 / On **Plugin**, click install. The files go to `%LOCALAPPDATA%\com.sealbox.app\extension\`. Load that unpacked folder in Chrome or Edge.
3. 解锁后点 **配对**，60 秒内把一次性配对码填进扩展 / Unlock, click **Pair**, then enter the one-time code in the extension within 60 seconds.
```

功能列表里「插件 Plugin」那行改成「Chrome / Edge 从客户端安装后按当前网址填充或一键登记」。

- [ ] **Step 2: 规格状态**

`docs/superpowers/specs/2026-09-17-bundled-browser-extension-design.md` 开头：

```
状态：待确认
```

改成：

```
状态：已确认
```

- [ ] **Step 3: 回归测试**

```bash
cargo test --manifest-path src-tauri/Cargo.toml
node --test extension/fill-logic.test.js
```

Expected: 现有测试 + `extension_install` 全过；fill-logic 测试不过扩展脚本。

- [ ] **Step 4: Commit**

```bash
git add README.md docs/superpowers/specs/2026-09-17-bundled-browser-extension-design.md
git commit -m "docs: install the fill extension from the Sealbox plugin page"
```

---

## Spec coverage

| Spec | Task |
|---|---|
| 随包白名单、不含测试 | 1, 3 |
| `%LOCALAPPDATA%\com.sealbox.app\extension\` | 1, 3 |
| 覆盖复制、删白名单外文件、不先删目录 | 1 |
| version + SHA-256 过期 | 1 |
| 打开页只检查不自动覆盖 | 4 |
| Chrome / Edge App Paths + 常见路径 | 2 |
| explorer / chrome://extensions / edge://extensions | 2, 3 |
| 四个 invoke、不要求解锁 | 3 |
| 安装成功自动打开目录、不自动开浏览器 | 3 |
| 插件页两段文案与按钮态 | 4 |
| 失败中文、目录可复制 | 1, 4 |
| 不写注册表强制安装、不发 crx、不改填表 | 全程不做 |
| README | 5 |

## 不做

Firefox / 商店 / `.crx` / 注册表强装 / 改 `extension/*.js` 填表行为 / 自动弹配对。
)
