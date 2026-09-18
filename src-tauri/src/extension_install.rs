use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use tauri::{AppHandle, Manager};

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

pub fn parse_browser(name: &str) -> Result<BrowserKind, String> {
    match name {
        "chrome" => Ok(BrowserKind::Chrome),
        "edge" => Ok(BrowserKind::Edge),
        _ => Err("未检测到该浏览器。".into()),
    }
}

pub fn extensions_page_url(kind: BrowserKind) -> &'static str {
    match kind {
        BrowserKind::Chrome => "chrome://extensions",
        BrowserKind::Edge => "edge://extensions",
    }
}

pub fn exe_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
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

pub fn browser_open_command(exe: &Path) -> Command {
    Command::new(exe)
}

pub fn spawn_logged(mut cmd: Command, fail: &str) -> Result<(), String> {
    cmd.spawn().map(|_| ()).map_err(|_| fail.to_string())
}

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

pub fn open_browser_for_app(app: &AppHandle, browser: &str) -> Result<String, String> {
    let _ = app;
    let kind = parse_browser(browser)?;
    let (exe, missing, fail) = match kind {
        BrowserKind::Chrome => (
            detect_chrome(),
            "未检测到 Google Chrome",
            "无法打开扩展页，请手动访问 chrome://extensions。",
        ),
        BrowserKind::Edge => (
            detect_edge(),
            "未检测到 Microsoft Edge",
            "无法打开扩展页，请手动访问 edge://extensions。",
        ),
    };
    let exe = exe.ok_or_else(|| missing.to_string())?;
    let url = extensions_page_url(kind);
    let already_open = browser_window_open(&exe);
    if !already_open {
        spawn_logged(browser_open_command(&exe), fail)?;
    }
    if let Err(detail) = navigate_omnibox(&exe, url) {
        return Err(format!("{fail}（{detail}）"));
    }
    Ok(url.to_string())
}

fn browser_window_open(exe: &Path) -> bool {
    #[cfg(windows)]
    {
        windows_omnibox::has_window(exe)
    }
    #[cfg(not(windows))]
    {
        let _ = exe;
        false
    }
}

fn navigate_omnibox(exe: &Path, url: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows_omnibox::navigate(exe, url)
    }
    #[cfg(not(windows))]
    {
        let _ = (exe, url);
        Err("仅支持 Windows".into())
    }
}

#[cfg(windows)]
mod windows_omnibox {
    use super::exe_stem;
    use std::mem::size_of;
    use std::path::Path;
    use std::time::{Duration, Instant};
    use windows::core::{BSTR, VARIANT};
    use windows::Win32::Foundation::{CloseHandle, BOOL, HWND, LPARAM, MAX_PATH, WPARAM};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::System::Threading::{
        AttachThreadInput, GetCurrentThreadId, OpenProcess, QueryFullProcessImageNameW,
        PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::UI::Accessibility::{
        CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationValuePattern,
        TreeScope_Descendants, UIA_ClassNamePropertyId, UIA_ValuePatternId,
    };
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, VIRTUAL_KEY,
        VK_RETURN,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        AllowSetForegroundWindow, EnumWindows, GetClassNameW, GetForegroundWindow, GetWindowTextW,
        GetWindowThreadProcessId, IsIconic, IsWindowVisible, PostMessageW, SetForegroundWindow,
        ShowWindow, SW_RESTORE, WM_KEYDOWN, WM_KEYUP,
    };

    const OMNIBOX_CLASS: &str = "OmniboxViewViews";
    const BROWSER_WINDOW_CLASS: &str = "Chrome_WidgetWin_1";

    struct FoundWindows {
        hwnds: Vec<HWND>,
        wanted: String,
    }

    pub fn has_window(exe: &Path) -> bool {
        find_windows(exe).map(|hwnds| !hwnds.is_empty()).unwrap_or(false)
    }

    pub fn navigate(exe: &Path, url: &str) -> Result<(), String> {
        let exe = exe.to_path_buf();
        let url = url.to_string();
        std::thread::spawn(move || navigate_sta(&exe, &url))
            .join()
            .unwrap_or_else(|_| Err("无法打开扩展页".into()))
    }

    fn navigate_sta(exe: &Path, url: &str) -> Result<(), String> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut last = "未找到浏览器窗口".to_string();
        while Instant::now() < deadline {
            match find_windows(exe) {
                Ok(hwnds) => {
                    for hwnd in hwnds {
                        if navigate_window(hwnd, url).is_ok() {
                            return Ok(());
                        }
                    }
                    last = "无法写入浏览器地址栏".into();
                }
                Err(e) => last = e,
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        Err(last)
    }

    fn navigate_window(hwnd: HWND, url: &str) -> Result<(), String> {
        let _ = focus_window(hwnd);
        let native = set_omnibox(hwnd, url)?;
        std::thread::sleep(Duration::from_millis(80));
        send_enter(native.unwrap_or(hwnd));
        Ok(())
    }

    fn find_windows(exe: &Path) -> Result<Vec<HWND>, String> {
        let mut found = FoundWindows {
            hwnds: Vec::new(),
            wanted: exe_stem(exe),
        };
        unsafe {
            let _ = EnumWindows(
                Some(enum_windows_proc),
                LPARAM(&mut found as *mut FoundWindows as isize),
            );
        }
        if found.hwnds.is_empty() {
            return Err(format!("未找到 {} 窗口", found.wanted));
        }
        Ok(found.hwnds)
    }

    unsafe extern "system" fn enum_windows_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let found = &mut *(lparam.0 as *mut FoundWindows);
        if !IsWindowVisible(hwnd).as_bool() {
            return BOOL(1);
        }
        let mut class_buf = [0u16; 256];
        let class_len = GetClassNameW(hwnd, &mut class_buf);
        if class_len <= 0 {
            return BOOL(1);
        }
        let class_name = String::from_utf16_lossy(&class_buf[..class_len as usize]);
        if class_name != BROWSER_WINDOW_CLASS {
            return BOOL(1);
        }
        let mut title_buf = [0u16; 512];
        if GetWindowTextW(hwnd, &mut title_buf) <= 0 {
            return BOOL(1);
        }
        if window_matches_exe(hwnd, &found.wanted) {
            found.hwnds.push(hwnd);
        }
        BOOL(1)
    }

    fn window_matches_exe(hwnd: HWND, wanted_stem: &str) -> bool {
        let mut pid = 0u32;
        unsafe {
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
        }
        if pid == 0 {
            return false;
        }
        process_stem(pid).map(|stem| stem == wanted_stem).unwrap_or(false)
    }

    fn process_stem(pid: u32) -> Option<String> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut buf = [0u16; MAX_PATH as usize];
            let mut size = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut size,
            )
            .is_ok();
            let _ = CloseHandle(handle);
            if !ok {
                return None;
            }
            let path = String::from_utf16_lossy(&buf[..size as usize]);
            Some(exe_stem(Path::new(&path)))
        }
    }

    fn focus_window(hwnd: HWND) -> Result<(), String> {
        unsafe {
            if IsIconic(hwnd).as_bool() {
                let _ = ShowWindow(hwnd, SW_RESTORE);
            }
            let mut pid = 0u32;
            let target_thread = GetWindowThreadProcessId(hwnd, Some(&mut pid));
            let _ = AllowSetForegroundWindow(pid);
            let current = GetCurrentThreadId();
            let attached = if target_thread != 0 && target_thread != current {
                AttachThreadInput(current, target_thread, true).as_bool()
            } else {
                false
            };
            let ok = SetForegroundWindow(hwnd).as_bool() || GetForegroundWindow() == hwnd;
            if attached {
                let _ = AttachThreadInput(current, target_thread, false);
            }
            if ok {
                return Ok(());
            }
        }
        Err("无法激活浏览器窗口".into())
    }

    fn set_omnibox(hwnd: HWND, url: &str) -> Result<Option<HWND>, String> {
        unsafe {
            let automation: IUIAutomation =
                CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER)
                    .map_err(|_| "无法访问浏览器地址栏".to_string())?;
            let root = automation
                .ElementFromHandle(hwnd)
                .map_err(|_| "无法访问浏览器地址栏".to_string())?;
            let condition = automation
                .CreatePropertyCondition(UIA_ClassNamePropertyId, &VARIANT::from(OMNIBOX_CLASS))
                .map_err(|_| "无法访问浏览器地址栏".to_string())?;
            let omnibox: IUIAutomationElement = root
                .FindFirst(TreeScope_Descendants, &condition)
                .map_err(|_| "无法访问浏览器地址栏".to_string())?;
            let _ = omnibox.SetFocus();
            let pattern: IUIAutomationValuePattern = omnibox
                .GetCurrentPatternAs(UIA_ValuePatternId)
                .map_err(|_| "无法写入浏览器地址栏".to_string())?;
            pattern
                .SetValue(&BSTR::from(url))
                .map_err(|_| "无法写入浏览器地址栏".to_string())?;
            let native = omnibox.CurrentNativeWindowHandle().ok().filter(|h| !h.is_invalid());
            Ok(native)
        }
    }

    fn send_enter(hwnd: HWND) {
        unsafe {
            let _ = PostMessageW(hwnd, WM_KEYDOWN, WPARAM(VK_RETURN.0 as usize), LPARAM(0));
            let _ = PostMessageW(
                hwnd,
                WM_KEYUP,
                WPARAM(VK_RETURN.0 as usize),
                LPARAM(1 << 30 | 1 << 31),
            );
            let down = key(VK_RETURN, false);
            let up = key(VK_RETURN, true);
            SendInput(&[down, up], size_of::<INPUT>() as i32);
        }
    }

    fn key(vk: VIRTUAL_KEY, up: bool) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: if up { KEYEVENTF_KEYUP } else { Default::default() },
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn missing_exe_has_no_window() {
            let err = find_windows(Path::new(r"C:\missing\chrome.exe")).unwrap_err();
            assert!(err.contains("未找到"), "{err}");
        }

        #[test]
        #[ignore]
        fn navigates_running_edge_if_present() {
            let Some(exe) = super::super::detect_edge() else {
                return;
            };
            navigate(&exe, "edge://extensions").unwrap();
        }
    }
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
    fn exe_stem_matches_chrome_and_edge_paths() {
        assert_eq!(
            exe_stem(Path::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe")),
            "chrome"
        );
        assert_eq!(
            exe_stem(Path::new(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")),
            "msedge"
        );
        assert_ne!(exe_stem(Path::new(r"C:\Windows\explorer.exe")), "chrome");
    }

    #[test]
    fn extensions_page_url_is_browser_specific() {
        assert_eq!(extensions_page_url(BrowserKind::Chrome), "chrome://extensions");
        assert_eq!(extensions_page_url(BrowserKind::Edge), "edge://extensions");
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

        let chrome = browser_open_command(Path::new(r"C:\Chrome\chrome.exe"));
        assert_eq!(chrome.get_program(), Path::new(r"C:\Chrome\chrome.exe"));
        let args: Vec<_> = chrome
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.is_empty(), "{args:?}");

        let edge = browser_open_command(Path::new(r"C:\Edge\msedge.exe"));
        let args: Vec<_> = edge
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.is_empty(), "{args:?}");
        assert!(!args.iter().any(|a| a.contains("chrome://") || a.contains("edge://")));
    }

    #[test]
    fn parse_browser_only_allows_chrome_and_edge() {
        assert_eq!(parse_browser("chrome").unwrap(), BrowserKind::Chrome);
        assert_eq!(parse_browser("edge").unwrap(), BrowserKind::Edge);
        assert!(parse_browser("firefox").is_err());
        assert!(parse_browser("chrome.exe").is_err());
    }
}
