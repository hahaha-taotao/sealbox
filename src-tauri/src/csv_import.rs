//! Desktop path adapter; parsing, validation, preview and import live in core.
pub use sealbox_core::csv::*;
use crate::vault::Vault;
use std::{fs, path::Path};

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let path = Path::new(path);
    if !path.is_absolute() || path.components().any(|part| matches!(part, std::path::Component::ParentDir)) {
        return Err("CSV 路径必须是绝对路径且不能包含 ..".into());
    }
    if fs::metadata(path).map_err(|e| e.to_string())?.len() > 5 * 1024 * 1024 {
        return Err("CSV 文件不能超过 5 MiB".into());
    }
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if bytes.len() > 5 * 1024 * 1024 { return Err("CSV 文件不能超过 5 MiB".into()); }
    Ok(bytes)
}

pub fn preview_file(vault: &Vault, dek: &[u8; 32], path: &str) -> Result<CsvImportPreview, String> {
    preview_bytes(vault, dek, &read_file(path)?)
}

pub fn commit_file(vault: &Vault, dek: &[u8; 32], path: &str, overwrite: bool) -> Result<CsvImportResult, String> {
    // Re-read and re-parse actual bytes; never commit rows supplied by the frontend.
    commit_rows(vault, dek, &read_file(path)?, overwrite).map_err(|e| e.to_string())
}
