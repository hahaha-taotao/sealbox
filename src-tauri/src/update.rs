use crate::http_guard::{assert_public_target, parse_http_url, PublicResolver};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::io::Read;
use std::time::Duration;
use tauri::command;

const RELEASES_API: &str = "https://api.github.com/repos/hahaha-taotao/sealbox/releases/latest";
const RELEASE_PAGE_URL: &str = "https://github.com/hahaha-taotao/sealbox/releases/latest";
const RELEASE_URL_PREFIX: &str = "https://github.com/hahaha-taotao/sealbox/releases/";
const DOWNLOAD_URL_PREFIX: &str = "https://github.com/hahaha-taotao/sealbox/releases/download/";
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_NOTES_CHARS: usize = 8_000;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InstallerAsset {
    pub name: String,
    pub url: String,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    UpdateAvailable,
    UpToDate,
    Ahead,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UpdateCheck {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub version_status: VersionStatus,
    pub release_url: String,
    pub published_at: Option<String>,
    pub notes: Option<String>,
    pub installer: Option<InstallerAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: Option<String>,
    browser_download_url: Option<String>,
    size: Option<u64>,
}

fn normalize_version(raw: &str) -> Result<Vec<u64>, String> {
    let value = raw.trim().trim_start_matches(['v', 'V']);
    if value.is_empty() || value.contains(['-', '+']) {
        return Err(format!("版本号不合法：{raw}"));
    }
    let core = value;
    if core.is_empty() {
        return Err("版本号为空".into());
    }
    let mut parts = Vec::new();
    for segment in core.split('.') {
        if segment.is_empty() {
            return Err(format!("版本号不合法：{raw}"));
        }
        parts.push(
            segment
                .parse::<u64>()
                .map_err(|_| format!("版本号不合法：{raw}"))?,
        );
    }
    Ok(parts)
}

fn compare_versions(current: &str, latest: &str) -> Result<Ordering, String> {
    let current = normalize_version(current)?;
    let latest = normalize_version(latest)?;
    let width = current.len().max(latest.len());
    for index in 0..width {
        let current_part = current.get(index).copied().unwrap_or(0);
        let latest_part = latest.get(index).copied().unwrap_or(0);
        match latest_part.cmp(&current_part) {
            Ordering::Equal => {}
            ordering => return Ok(ordering),
        }
    }
    Ok(Ordering::Equal)
}

fn validate_release_url(url: &str) -> Result<String, String> {
    if !url.starts_with(RELEASE_URL_PREFIX) {
        return Err("GitHub Release 地址不合法".into());
    }
    let target = parse_http_url(url, true)?;
    if target.scheme != "https" || target.host != "github.com" || target.port != 443 {
        return Err("GitHub Release 地址不合法".into());
    }
    assert_public_target(&target)?;
    Ok(url.to_string())
}

fn validate_download_url(url: &str) -> Result<String, String> {
    if !url.starts_with(DOWNLOAD_URL_PREFIX) {
        return Err("安装包下载地址不合法".into());
    }
    let target = parse_http_url(url, true)?;
    if target.scheme != "https" || target.host != "github.com" || target.port != 443 {
        return Err("安装包下载地址不合法".into());
    }
    assert_public_target(&target)?;
    Ok(url.to_string())
}

fn choose_installer(assets: &[ReleaseAsset]) -> Result<Option<InstallerAsset>, String> {
    let mut candidates = Vec::new();
    for asset in assets {
        let Some(name) = asset
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let Some(url) = asset
            .browser_download_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let lower_name = name.to_ascii_lowercase();
        if !lower_name.ends_with("setup.exe")
            || !(lower_name.contains("x64") || lower_name.contains("amd64"))
        {
            continue;
        }
        candidates.push((name.to_string(), url.to_string(), asset.size));
    }
    let Some((name, url, size)) = candidates.into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(InstallerAsset {
        name,
        url: validate_download_url(&url)?,
        size,
    }))
}

fn truncate_notes(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    let mut notes = value.chars().take(MAX_NOTES_CHARS).collect::<String>();
    if value.chars().count() > MAX_NOTES_CHARS {
        notes.push('…');
    }
    Some(notes)
}

fn parse_release(value: &Value, current_version: &str) -> Result<UpdateCheck, String> {
    let tag_name = value
        .get("tag_name")
        .and_then(Value::as_str)
        .ok_or_else(|| "GitHub Release 缺少版本号".to_string())?;
    let latest_version = tag_name.trim().trim_start_matches(['v', 'V']).to_string();
    let comparison = compare_versions(current_version, &latest_version)?;
    let version_status = match comparison {
        Ordering::Greater => VersionStatus::UpdateAvailable,
        Ordering::Equal => VersionStatus::UpToDate,
        Ordering::Less => VersionStatus::Ahead,
    };
    let update_available = matches!(version_status, VersionStatus::UpdateAvailable);
    let release_url = match value.get("html_url").and_then(Value::as_str) {
        Some(url) => validate_release_url(url)?,
        None => RELEASE_PAGE_URL.to_string(),
    };
    let published_at = value
        .get("published_at")
        .and_then(Value::as_str)
        .map(str::to_string);
    let notes = truncate_notes(value.get("body").and_then(Value::as_str));
    let assets = value
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(|| "GitHub Release 缺少安装包列表".to_string())?
        .iter()
        .map(|asset| {
            serde_json::from_value::<ReleaseAsset>(asset.clone())
                .map_err(|_| "GitHub Release 安装包信息无效".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let installer = if update_available {
        choose_installer(&assets)?
    } else {
        None
    };
    Ok(UpdateCheck {
        current_version: current_version.to_string(),
        latest_version,
        update_available,
        version_status,
        release_url,
        published_at,
        notes,
        installer,
    })
}

fn read_response(response: ureq::Response) -> Result<Vec<u8>, String> {
    let mut reader = response.into_reader();
    let mut body = Vec::new();
    let mut buffer = [0u8; 8 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| "GitHub 更新信息读取失败".to_string())?;
        if count == 0 {
            break;
        }
        if body.len().saturating_add(count) > MAX_RESPONSE_BYTES {
            return Err("GitHub 更新信息超过安全大小限制".into());
        }
        body.extend_from_slice(&buffer[..count]);
    }
    Ok(body)
}

fn fetch_latest(current_version: &str) -> Result<UpdateCheck, String> {
    let target = parse_http_url(RELEASES_API, true)?;
    if target.scheme != "https" || target.host != "api.github.com" || target.port != 443 {
        return Err("更新服务地址不合法".into());
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
        .get(RELEASES_API)
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .call();
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(status, _)) => {
            return Err(format!("GitHub 更新检查失败（HTTP {status}）"));
        }
        Err(_) => return Err("GitHub 更新检查失败，请检查网络连接".into()),
    };
    let body = read_response(response)?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| "GitHub 更新响应不是有效 JSON".to_string())?;
    if value.get("draft").and_then(Value::as_bool).unwrap_or(false)
        || value
            .get("prerelease")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err("GitHub 最新 Release 不是稳定版本".into());
    }
    parse_release(&value, current_version)
}

#[command]
pub async fn check_for_updates() -> Result<UpdateCheck, String> {
    tauri::async_runtime::spawn_blocking(|| fetch_latest(env!("CARGO_PKG_VERSION")))
        .await
        .map_err(|_| "更新检查任务异常终止".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compares_versions_with_optional_v_prefix_and_padding() {
        assert_eq!(
            compare_versions("0.1.1", "v0.1.2").unwrap(),
            Ordering::Greater
        );
        assert_eq!(compare_versions("v1.2", "1.2.0").unwrap(), Ordering::Equal);
        assert_eq!(compare_versions("1.3.0", "1.2.99").unwrap(), Ordering::Less);
    }

    #[test]
    fn rejects_invalid_versions() {
        assert!(compare_versions("0.1", "latest").is_err());
        assert!(compare_versions("", "1.0.0").is_err());
    }

    #[test]
    fn chooses_x64_setup_asset_and_validates_download_url() {
        let assets = vec![
            ReleaseAsset {
                name: Some("Sealbox_0.1.2_arm64-setup.exe".into()),
                browser_download_url: Some(
                    "https://github.com/hahaha-taotao/sealbox/releases/download/v0.1.2/arm64.exe"
                        .into(),
                ),
                size: Some(1),
            },
            ReleaseAsset {
                name: Some("Sealbox_0.1.2_x64-setup.exe".into()),
                browser_download_url: Some(
                    "https://github.com/hahaha-taotao/sealbox/releases/download/v0.1.2/x64.exe"
                        .into(),
                ),
                size: Some(2),
            },
        ];
        let installer = choose_installer(&assets).unwrap().unwrap();
        assert_eq!(installer.name, "Sealbox_0.1.2_x64-setup.exe");
        assert_eq!(installer.size, Some(2));
    }

    #[test]
    fn ignores_non_installer_assets_and_rejects_external_downloads() {
        let assets = vec![
            ReleaseAsset {
                name: Some("checksums.txt".into()),
                browser_download_url: Some("https://github.com/hahaha-taotao/sealbox/releases/download/v0.1.2/checksums.txt".into()),
                size: Some(1),
            },
            ReleaseAsset {
                name: Some("Sealbox_0.1.2_x64-setup.exe".into()),
                browser_download_url: Some("https://example.com/installer.exe".into()),
                size: Some(2),
            },
        ];
        assert!(choose_installer(&assets).is_err());
    }

    #[test]
    fn does_not_choose_arm64_or_unknown_architecture_assets() {
        let assets = vec![
            ReleaseAsset {
                name: Some("Sealbox_0.1.2_arm64-setup.exe".into()),
                browser_download_url: Some(
                    "https://github.com/hahaha-taotao/sealbox/releases/download/v0.1.2/arm64.exe"
                        .into(),
                ),
                size: Some(1),
            },
            ReleaseAsset {
                name: Some("Sealbox_0.1.2-setup.exe".into()),
                browser_download_url: Some(
                    "https://github.com/hahaha-taotao/sealbox/releases/download/v0.1.2/setup.exe"
                        .into(),
                ),
                size: Some(2),
            },
        ];
        assert!(choose_installer(&assets).unwrap().is_none());
    }

    #[test]
    fn parses_release_metadata_and_limits_notes() {
        let value = json!({
            "tag_name": "v0.1.2",
            "html_url": "https://github.com/hahaha-taotao/sealbox/releases/tag/v0.1.2",
            "published_at": "2026-09-20T12:00:00Z",
            "body": "修复与改进",
            "draft": false,
            "prerelease": false,
            "assets": []
        });
        let result = parse_release(&value, "0.1.1").unwrap();
        assert!(result.update_available);
        assert_eq!(result.version_status, VersionStatus::UpdateAvailable);
        assert_eq!(result.latest_version, "0.1.2");
        assert_eq!(
            result.release_url,
            "https://github.com/hahaha-taotao/sealbox/releases/tag/v0.1.2"
        );
        assert_eq!(result.notes.as_deref(), Some("修复与改进"));
    }

    #[test]
    fn reports_up_to_date_without_an_installer() {
        let value = json!({
            "tag_name": "v0.1.2",
            "html_url": "https://github.com/hahaha-taotao/sealbox/releases/tag/v0.1.2",
            "assets": [{
                "name": "Sealbox_0.1.2_x64-setup.exe",
                "browser_download_url": "https://github.com/hahaha-taotao/sealbox/releases/download/v0.1.2/x64.exe",
                "size": 2
            }]
        });
        let result = parse_release(&value, "0.1.2").unwrap();
        assert_eq!(result.version_status, VersionStatus::UpToDate);
        assert!(!result.update_available);
        assert!(result.installer.is_none());
    }

    #[test]
    fn reports_ahead_without_an_installer() {
        let value = json!({
            "tag_name": "v0.1.2",
            "html_url": "https://github.com/hahaha-taotao/sealbox/releases/tag/v0.1.2",
            "assets": []
        });
        let result = parse_release(&value, "0.1.3").unwrap();
        assert_eq!(result.version_status, VersionStatus::Ahead);
        assert!(!result.update_available);
        assert!(result.installer.is_none());
    }

    #[test]
    fn rejects_release_url_outside_repository() {
        let value = json!({
            "tag_name": "v0.1.2",
            "html_url": "https://example.com/release",
            "assets": []
        });
        assert!(parse_release(&value, "0.1.1").is_err());
    }
}
