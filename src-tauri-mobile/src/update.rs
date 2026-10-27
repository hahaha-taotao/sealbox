use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

const RELEASES_URL: &str = "https://api.github.com/repos/hahaha-taotao/sealbox/releases?per_page=30";
const USER_AGENT: &str = "sealbox-mobile";
const APK_NAME: &str = "sealbox-mobile-update.apk";

#[derive(Serialize, Clone)]
pub struct MobileRelease {
    pub current_version: String,
    pub latest_version: String,
    pub published_at: Option<String>,
    pub notes: Option<String>,
    pub release_url: String,
    pub download_url: String,
    pub asset_name: String,
    pub asset_size: u64,
    pub update_available: bool,
}

#[derive(Deserialize, Clone)]
struct GithubAsset {
    name: String,
    size: u64,
    browser_download_url: String,
}

#[derive(Deserialize, Clone)]
struct GithubRelease {
    tag_name: String,
    #[allow(dead_code)]
    name: Option<String>,
    body: Option<String>,
    html_url: String,
    published_at: Option<String>,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

pub fn current_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub fn check() -> Result<MobileRelease, String> {
    let current = current_version();
    let releases = fetch_releases()?;
    release_response(releases, &current)
}

fn select_release(releases: Vec<GithubRelease>) -> Option<PickedRelease> {
    releases
        .into_iter()
        .filter_map(mobile_release)
        .max_by_key(|release| (release.version_key, release.unified_tag))
}

fn release_response(releases: Vec<GithubRelease>, current: &str) -> Result<MobileRelease, String> {
    let release = select_release(releases).ok_or("没有找到 Android 发布")?;
    let update_available = version_newer(&release.version, current);
    Ok(MobileRelease {
        current_version: current.to_string(),
        latest_version: release.version,
        published_at: release.published_at,
        notes: release.notes,
        release_url: release.html_url,
        download_url: release.download_url,
        asset_name: release.asset_name,
        asset_size: release.asset_size,
        update_available,
    })
}

struct PickedRelease {
    version: String,
    version_key: [u64; 3],
    unified_tag: bool,
    published_at: Option<String>,
    notes: Option<String>,
    html_url: String,
    download_url: String,
    asset_name: String,
    asset_size: u64,
}

fn release_version(tag: &str) -> Option<(&str, [u64; 3], bool)> {
    let unified = tag.starts_with(['v', 'V']);
    let version = tag
        .strip_prefix('v')
        .or_else(|| tag.strip_prefix('V'))
        .or_else(|| tag.strip_prefix("mobile-v"))
        .or_else(|| tag.strip_prefix("mobile-V"))?;
    let mut parts = version.split('.');
    let mut key = [0; 3];
    for value in &mut key {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *value = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some((version, key, unified))
}

fn mobile_release(release: GithubRelease) -> Option<PickedRelease> {
    if release.draft || release.prerelease {
        return None;
    }
    let (version, version_key, unified_tag) = release_version(&release.tag_name)?;
    let asset = release.assets.into_iter().find(|asset| {
        let name = asset.name.to_ascii_lowercase();
        name.ends_with(".apk") && trusted_download_url(&asset.browser_download_url)
    })?;
    let notes = release
        .body
        .map(|body| body.trim().to_string())
        .filter(|body| !body.is_empty());
    Some(PickedRelease {
        version: version.to_string(),
        version_key,
        unified_tag,
        published_at: release.published_at,
        notes,
        html_url: release.html_url,
        download_url: asset.browser_download_url,
        asset_name: asset.name,
        asset_size: asset.size,
    })
}

fn fetch_releases() -> Result<Vec<GithubRelease>, String> {
    let response = ureq::get(RELEASES_URL)
        .timeout(Duration::from_secs(20))
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|error| format!("检查更新失败：{error}"))?;
    let body = response
        .into_string()
        .map_err(|error| format!("发布信息无法读取：{error}"))?;
    serde_json::from_str(&body).map_err(|error| format!("发布信息无法解析：{error}"))
}

pub fn download(url: &str, cache_dir: &Path, on_progress: impl Fn(u64, Option<u64>)) -> Result<PathBuf, String> {
    if !trusted_download_url(url) {
        return Err("更新地址不在 GitHub 发布页".into());
    }
    std::fs::create_dir_all(cache_dir).map_err(|error| error.to_string())?;
    let path = cache_dir.join(APK_NAME);
    let partial = cache_dir.join(format!("{APK_NAME}.partial"));
    let response = fetch_apk(url)?;
    let total = response
        .header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0);
    let mut reader = response.into_reader();
    let mut file = std::fs::File::create(&partial).map_err(|error| error.to_string())?;
    let mut downloaded = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    on_progress(0, total);
    loop {
        let read = reader.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        std::io::Write::write_all(&mut file, &buffer[..read]).map_err(|error| error.to_string())?;
        downloaded += read as u64;
        on_progress(downloaded, total);
    }
    drop(file);
    if downloaded < 1024 {
        let _ = std::fs::remove_file(&partial);
        return Err("下载到的文件不是安装包".into());
    }
    if let Some(total) = total {
        if downloaded != total {
            let _ = std::fs::remove_file(&partial);
            return Err("安装包下载不完整".into());
        }
    }
    if !apk_header_ok(&partial)? {
        let _ = std::fs::remove_file(&partial);
        return Err("下载到的文件不是 APK".into());
    }
    if path.exists() {
        std::fs::remove_file(&path).map_err(|error| error.to_string())?;
    }
    std::fs::rename(&partial, &path).map_err(|error| error.to_string())?;
    Ok(path)
}

pub fn install_apk(path: &Path) -> Result<(), String> {
    let path = path
        .canonicalize()
        .map_err(|error| format!("找不到安装包：{error}"))?;
    install::install_apk(&path)
}

#[cfg(not(target_os = "android"))]
mod install {
    use std::path::Path;

    pub fn install_apk(_path: &Path) -> Result<(), String> {
        Err("安装更新只在 Android 上可用".into())
    }
}

#[cfg(target_os = "android")]
mod install {
    use jni::objects::{JObject, JValue};
    use jni::JNIEnv;
    use std::path::Path;

    fn with_env<T>(f: impl FnOnce(&mut JNIEnv) -> Result<T, String>) -> Result<T, String> {
        if !crate::mobile_context::is_ready() {
            return Err("Android 上下文未就绪，无法打开安装器".into());
        }
        let context = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(context.vm() as *mut _) }.map_err(|error| error.to_string())?;
        let mut env = vm.attach_current_thread().map_err(|error| error.to_string())?;
        f(&mut env)
    }

    fn check(env: &mut JNIEnv) -> Result<(), String> {
        if env.exception_check().map_err(|error| error.to_string())? {
            env.exception_describe().ok();
            env.exception_clear().ok();
            return Err("系统拒绝打开安装界面".into());
        }
        Ok(())
    }

    pub fn install_apk(path: &Path) -> Result<(), String> {
        let path_text = path.to_str().ok_or("安装包路径无效")?;
        with_env(|env| {
            let context = unsafe { JObject::from_raw(ndk_context::android_context().context() as _) };
            let package = env
                .call_method(&context, "getPackageName", "()Ljava/lang/String;", &[])
                .map_err(|error| error.to_string())?
                .l()
                .map_err(|error| error.to_string())?;
            let value = jni::objects::JString::from(package);
            let package_name = {
                let text = env.get_string(&value).map_err(|error| error.to_string())?;
                String::from(text.to_str().unwrap_or_default())
            };
            let authority = env
                .new_string(format!("{package_name}.fileprovider"))
                .map_err(|error| error.to_string())?;
            let file_class = env
                .find_class("java/io/File")
                .map_err(|error| error.to_string())?;
            let file_path = env.new_string(path_text).map_err(|error| error.to_string())?;
            let file = env
                .new_object(file_class, "(Ljava/lang/String;)V", &[(&file_path).into()])
                .map_err(|error| error.to_string())?;
            let uri = env
                .call_static_method(
                    "androidx/core/content/FileProvider",
                    "getUriForFile",
                    "(Landroid/content/Context;Ljava/lang/String;Ljava/io/File;)Landroid/net/Uri;",
                    &[(&context).into(), (&authority).into(), (&file).into()],
                )
                .map_err(|error| error.to_string())?
                .l()
                .map_err(|error| error.to_string())?;
            check(env)?;
            let action = env
                .new_string("android.intent.action.VIEW")
                .map_err(|error| error.to_string())?;
            let intent = env
                .new_object(
                    "android/content/Intent",
                    "(Ljava/lang/String;)V",
                    &[(&action).into()],
                )
                .map_err(|error| error.to_string())?;
            let mime = env
                .new_string("application/vnd.android.package-archive")
                .map_err(|error| error.to_string())?;
            env.call_method(
                &intent,
                "setDataAndType",
                "(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;",
                &[(&uri).into(), (&mime).into()],
            )
            .map_err(|error| error.to_string())?;
            env.call_method(
                &intent,
                "addFlags",
                "(I)Landroid/content/Intent;",
                &[JValue::Int(0x00000001)],
            )
            .map_err(|error| error.to_string())?;
            env.call_method(
                &intent,
                "addFlags",
                "(I)Landroid/content/Intent;",
                &[JValue::Int(0x10000000)],
            )
            .map_err(|error| error.to_string())?;
            check(env)?;
            env.call_method(
                &context,
                "startActivity",
                "(Landroid/content/Intent;)V",
                &[(&intent).into()],
            )
            .map_err(|error| error.to_string())?;
            check(env)?;
            Ok(())
        })
    }
}

fn trusted_download_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let github_release = host == "github.com"
        && parsed
            .path()
            .starts_with("/hahaha-taotao/sealbox/releases/download/");
    let github_asset = host == "objects.githubusercontent.com"
        || host == "release-assets.githubusercontent.com"
        || host == "github-releases.githubusercontent.com";
    github_release || github_asset
}

fn fetch_apk(url: &str) -> Result<ureq::Response, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(120))
        .redirects(5)
        .build();
    let response = agent
        .get(url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/octet-stream")
        .call()
        .map_err(|error| format!("下载更新失败：{error}"))?;
    let final_url = response.get_url();
    if !trusted_download_url(final_url) {
        return Err("更新地址跳到了 GitHub 之外".into());
    }
    Ok(response)
}

fn apk_header_ok(path: &Path) -> Result<bool, String> {
    let mut file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut header = [0u8; 2];
    std::io::Read::read_exact(&mut file, &mut header).map_err(|error| error.to_string())?;
    Ok(header == [0x50, 0x4b])
}

pub fn version_newer(latest: &str, current: &str) -> bool {
    let left = version_parts(latest);
    let right = version_parts(current);
    let len = left.len().max(right.len());
    for index in 0..len {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        if a != b {
            return a > b;
        }
    }
    false
}

fn version_parts(version: &str) -> Vec<u64> {
    version
        .trim()
        .trim_start_matches(['v', 'V'])
        .split(['.', '-', '+'])
        .map(|part| part.chars().take_while(|ch| ch.is_ascii_digit()).collect::<String>())
        .map(|part| part.parse::<u64>().unwrap_or(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str) -> GithubRelease {
        GithubRelease {
            tag_name: tag.into(),
            name: None,
            body: Some("  Release notes  ".into()),
            html_url: format!("https://github.com/hahaha-taotao/sealbox/releases/tag/{tag}"),
            published_at: Some("2026-10-01T00:00:00Z".into()),
            draft: false,
            prerelease: false,
            assets: vec![GithubAsset {
                name: "Sealbox-arm64.APK".into(),
                size: 12345,
                browser_download_url: format!(
                    "https://github.com/hahaha-taotao/sealbox/releases/download/{tag}/Sealbox-arm64.apk"
                ),
            }],
        }
    }

    #[test]
    fn unified_release_builds_update_response_for_093() {
        let source = release("v0.9.4");
        let result = release_response(vec![source.clone()], "0.9.3").unwrap();
        assert!(result.update_available);
        assert_eq!(result.current_version, "0.9.3");
        assert_eq!(result.latest_version, "0.9.4");
        assert_eq!(result.notes.as_deref(), Some("Release notes"));
        assert_eq!(result.published_at, source.published_at);
        assert_eq!(result.release_url, source.html_url);
        assert_eq!(result.download_url, source.assets[0].browser_download_url);
        assert_eq!(result.asset_name, source.assets[0].name);
        assert_eq!(result.asset_size, 12345);
        for current in ["0.9.4", "0.9.5"] {
            assert!(!release_response(vec![source.clone()], current).unwrap().update_available);
        }
    }

    #[test]
    fn accepts_unified_and_legacy_tag_case() {
        for tag in ["v0.9.4", "V0.9.4", "mobile-v0.9.4", "mobile-V0.9.4"] {
            let result = release_response(vec![release(tag)], "0.9.3").unwrap();
            assert_eq!(result.latest_version, "0.9.4", "{tag}");
            assert!(result.update_available, "{tag}");
        }
    }

    #[test]
    fn selects_numeric_latest_independent_of_publication_order() {
        let mut newest = release("v0.9.10");
        newest.published_at = Some("2020-01-01T00:00:00Z".into());
        let releases = vec![release("v0.9.9"), newest, release("mobile-v0.9.4")];
        for releases in [releases.clone(), releases.into_iter().rev().collect()] {
            let result = release_response(releases, "0.9.9").unwrap();
            assert_eq!(result.latest_version, "0.9.10");
            assert!(result.update_available);
        }
    }

    #[test]
    fn same_version_prefers_unified_tag_in_both_orders() {
        for tags in [["v0.9.4", "mobile-v0.9.4"], ["mobile-v0.9.4", "v0.9.4"]] {
            let result = release_response(tags.into_iter().map(release).collect(), "0.9.3").unwrap();
            assert!(result.release_url.ends_with("/v0.9.4"));
            assert!(result.download_url.contains("/v0.9.4/"));
        }
    }

    #[test]
    fn rejects_non_stable_or_malformed_releases() {
        let mut invalid = Vec::new();
        for tag in [
            "0.9.5", "v", "v0.9", "v0.9.5.1", "v0..5", "v0.9.x",
            "v0.9.5-beta", "v0.9.5+build", "v+0.9.5", "v0.9. 5",
            " v0.9.5", "v0.9.5 ", "mobile-vv0.9.5", "mobile-VV0.9.5",
            "v0.9.５", "v18446744073709551616.0.0",
        ] {
            invalid.push(release(tag));
        }
        let mut draft = release("v9.0.0");
        draft.draft = true;
        invalid.push(draft);
        let mut prerelease = release("v9.0.0");
        prerelease.prerelease = true;
        invalid.push(prerelease);
        assert_eq!(release_response(invalid.clone(), "0.9.3").err().as_deref(), Some("没有找到 Android 发布"));
        invalid.push(release("v0.9.4"));
        assert_eq!(release_response(invalid, "0.9.3").unwrap().latest_version, "0.9.4");
    }

    #[test]
    fn skips_newer_releases_without_trusted_apk() {
        let mut no_apk = release("v1.0.0");
        no_apk.assets.clear();
        let mut desktop = release("v2.0.0");
        desktop.assets[0].name = "Sealbox.exe".into();
        let result = release_response(vec![no_apk, desktop, release("v0.9.4")], "0.9.3").unwrap();
        assert_eq!(result.latest_version, "0.9.4");
        assert!(release_response(vec![], "0.9.3").is_err());
    }

    #[test]
    fn selection_uses_existing_download_trust_boundary() {
        for url in [
            "http://github.com/hahaha-taotao/sealbox/releases/download/v1/a.apk",
            "https://evil.example/a.apk",
            "https://github.com.evil.example/hahaha-taotao/sealbox/releases/download/v1/a.apk",
            "https://github.com@evil.example/hahaha-taotao/sealbox/releases/download/v1/a.apk",
            "https://github.com/other/repo/releases/download/v1/a.apk",
            "https://github.com/hahaha-taotao/sealbox/releases/tag/v1/a.apk",
            "not a URL",
        ] {
            let mut invalid = release("v1.0.0");
            invalid.assets[0].browser_download_url = url.into();
            assert!(release_response(vec![invalid], "0.9.3").is_err(), "{url}");
        }
        for host in ["objects.githubusercontent.com", "release-assets.githubusercontent.com", "github-releases.githubusercontent.com"] {
            let mut valid = release("v0.9.4");
            valid.assets[0].browser_download_url = format!("https://{host}/a.apk");
            assert!(release_response(vec![valid], "0.9.3").unwrap().update_available);
        }
        let mut mixed = release("v0.9.4");
        let mut bad = mixed.assets[0].clone();
        bad.browser_download_url = "https://evil.example/a.apk".into();
        mixed.assets.insert(0, bad);
        assert!(release_response(vec![mixed], "0.9.3").unwrap().download_url.starts_with("https://github.com/"));
    }

    #[test]
    #[ignore = "requires public GitHub API network access"]
    fn live_github_094_updates_093() {
        let releases = fetch_releases().expect("fetch real public GitHub releases");
        let target = releases.iter().find(|release| release.tag_name == "v0.9.4")
            .expect("v0.9.4 in real GitHub release metadata").clone();
        let result = release_response(vec![target], "0.9.3").unwrap();
        assert_eq!(result.latest_version, "0.9.4");
        assert!(result.update_available);
        assert!(trusted_download_url(&result.download_url));
        println!("real GitHub v0.9.4: {} -> {}, update_available={}, APK={}",
            result.current_version, result.latest_version, result.update_available, result.download_url);
        let latest = release_response(releases, "0.9.3").unwrap();
        assert!(latest.update_available);
        println!("real release list selected {} ({})", latest.latest_version, latest.download_url);
    }
}

