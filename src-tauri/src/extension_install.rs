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
