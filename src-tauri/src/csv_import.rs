use crate::vault::{EntryKind, ListFilter, SecretPayload, SortBy, UpsertEntry, Vault, VaultError};
use serde::Serialize;
use std::fs;
use std::path::Path;

const MAX_BYTES: usize = 5 * 1024 * 1024;
const MAX_ROWS: usize = 5000;
const MAX_TITLE: usize = 200;
const MAX_URL: usize = 2000;
const MAX_USERNAME: usize = 300;
const MAX_PASSWORD: usize = 4096;
const MAX_TOTP: usize = 512;
const MAX_NOTES: usize = 8000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsvFormat {
    Chrome,
    Bitwarden,
    OnePassword,
    Sealbox,
}

impl CsvFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Bitwarden => "bitwarden",
            Self::OnePassword => "onepassword",
            Self::Sealbox => "sealbox",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CsvImportSample {
    pub title: String,
    pub url: String,
    pub username: String,
    pub has_password: bool,
    pub has_totp: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CsvImportPreview {
    pub format: String,
    pub total: usize,
    pub importable: usize,
    pub skipped_existing: usize,
    pub skipped_invalid: usize,
    pub sample: Vec<CsvImportSample>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CsvImportResult {
    pub format: String,
    pub inserted: usize,
    pub updated: usize,
    pub skipped_existing: usize,
    pub skipped_invalid: usize,
}

#[derive(Clone, Debug)]
struct CsvRow {
    title: String,
    url: String,
    username: String,
    password: String,
    totp: Option<String>,
    totp_column_present: bool,
    notes: Option<String>,
    tags: Vec<String>,
}

#[derive(Debug)]
struct ParsedCsv {
    format: CsvFormat,
    rows: Vec<Result<CsvRow, ()>>,
}

pub fn detect_format(header_line: &str) -> Result<CsvFormat, String> {
    let header = header_line.trim_start_matches('\u{feff}');
    let mut records = parse_csv(header)?;
    let header = records.drain(..).next().unwrap_or_default();
    detect_header(&header)
}

fn detect_header(header: &[String]) -> Result<CsvFormat, String> {
    let original: Vec<String> = header.iter().map(|name| name.trim().to_string()).collect();
    let names: Vec<String> = original
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let has = |columns: &[String], name: &str| columns.iter().any(|column| column == name);
    if has(&names, "login_uri") && has(&names, "login_username") && has(&names, "login_password") {
        return Ok(CsvFormat::Bitwarden);
    }
    let has_onepassword_columns = has(&names, "title")
        && has(&names, "url")
        && has(&names, "username")
        && has(&names, "password");
    if has_onepassword_columns
        && (has(&names, "otpauth")
            || original
                .iter()
                .any(|name| matches!(name.as_str(), "Title" | "Url" | "Username" | "Password")))
    {
        return Ok(CsvFormat::OnePassword);
    }
    if has(&names, "name")
        && has(&names, "url")
        && has(&names, "username")
        && has(&names, "password")
    {
        return Ok(CsvFormat::Chrome);
    }
    if has(&names, "title")
        && has(&names, "url")
        && has(&names, "username")
        && has(&names, "password")
    {
        return Ok(CsvFormat::Sealbox);
    }
    Err("无法识别的 CSV 表头".into())
}

/// Parse RFC4180-style records, including quoted delimiters/newlines and doubled quotes.
fn parse_csv(input: &str) -> Result<Vec<Vec<String>>, String> {
    let bytes = input.as_bytes();
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut index = 0;
    let mut quoted = false;
    let mut closed_quote = false;

    while index < bytes.len() {
        let ch = input[index..].chars().next().expect("valid UTF-8 boundary");
        let width = ch.len_utf8();
        if quoted {
            if ch == '"' {
                if bytes.get(index + 1) == Some(&b'"') {
                    field.push('"');
                    index += 2;
                    continue;
                }
                quoted = false;
                closed_quote = true;
            } else {
                field.push(ch);
            }
            index += width;
            continue;
        }
        if closed_quote && ch != ',' && ch != '\r' && ch != '\n' && !ch.is_whitespace() {
            return Err("CSV 引号格式不正确".into());
        }
        match ch {
            '"' if field.is_empty() && !closed_quote => {
                quoted = true;
                index += width;
            }
            '"' => return Err("CSV 引号格式不正确".into()),
            ',' => {
                record.push(std::mem::take(&mut field));
                closed_quote = false;
                index += width;
            }
            '\r' | '\n' => {
                record.push(std::mem::take(&mut field));
                if record.iter().any(|value| !value.is_empty()) {
                    records.push(std::mem::take(&mut record));
                } else {
                    record.clear();
                }
                closed_quote = false;
                if ch == '\r' && bytes.get(index + 1) == Some(&b'\n') {
                    index += 2;
                } else {
                    index += width;
                }
            }
            _ => {
                field.push(ch);
                index += width;
            }
        }
    }
    if quoted {
        return Err("CSV 引号未闭合".into());
    }
    if !field.is_empty() || !record.is_empty() || closed_quote {
        record.push(field);
        if record.iter().any(|value| !value.is_empty()) {
            records.push(record);
        }
    }
    Ok(records)
}

fn parse_bytes(bytes: &[u8]) -> Result<ParsedCsv, String> {
    if bytes.len() > MAX_BYTES {
        return Err("CSV 文件不能超过 5 MiB".into());
    }
    let content = std::str::from_utf8(bytes).map_err(|_| "请将文件另存为 UTF-8".to_string())?;
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut records = parse_csv(content)?;
    if records.is_empty() {
        return Err("无法识别的 CSV 表头".into());
    }
    let header = records.remove(0);
    let headers: Vec<String> = header
        .iter()
        .map(|field| field.trim().to_ascii_lowercase())
        .collect();
    let format = detect_header(&header)?;
    if records.len() > MAX_ROWS {
        return Err("CSV 文件不能超过 5000 行".into());
    }
    let rows = records
        .into_iter()
        .map(|fields| map_row(format, &headers, &fields))
        .collect();
    Ok(ParsedCsv { format, rows })
}

fn map_row(format: CsvFormat, headers: &[String], fields: &[String]) -> Result<CsvRow, ()> {
    let get = |name: &str| -> Option<&str> {
        headers
            .iter()
            .position(|header| header == name)
            .and_then(|index| fields.get(index))
            .map(String::as_str)
    };
    if format == CsvFormat::Bitwarden
        && get("type")
            .map(|kind| !kind.trim().eq_ignore_ascii_case("login"))
            .unwrap_or(false)
    {
        return Err(());
    }
    let (title, url, username, password, totp, notes, tags) = match format {
        CsvFormat::Chrome => (
            get("name"),
            get("url"),
            get("username"),
            get("password"),
            None,
            None,
            None,
        ),
        CsvFormat::Bitwarden => (
            get("name"),
            get("login_uri"),
            get("login_username"),
            get("login_password"),
            get("login_totp"),
            get("notes"),
            None,
        ),
        CsvFormat::OnePassword => (
            get("title"),
            get("url"),
            get("username"),
            get("password"),
            get("otpauth"),
            get("notes"),
            get("tags"),
        ),
        CsvFormat::Sealbox => (
            get("title"),
            get("url"),
            get("username"),
            get("password"),
            get("totp"),
            get("notes"),
            get("tags"),
        ),
    };
    let title = title.unwrap_or_default().trim().to_string();
    let url = url.unwrap_or_default().trim().to_string();
    let username = username.unwrap_or_default().trim().to_string();
    let password = password.unwrap_or_default().to_string();
    let totp_raw = totp.unwrap_or_default().trim();
    let notes_value = notes.map(|value| value.to_string());
    let tags = tags
        .unwrap_or_default()
        .split([';', ','])
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
        .collect();

    let normalized_totp = if totp_raw.is_empty() {
        None
    } else {
        Some(crate::totp::normalize_totp_secret(totp_raw).map_err(|_| ())?)
    };
    if title.chars().count() > MAX_TITLE
        || url.chars().count() > MAX_URL
        || username.chars().count() > MAX_USERNAME
        || password.chars().count() > MAX_PASSWORD
        || totp_raw.chars().count() > MAX_TOTP
        || notes_value
            .as_ref()
            .map(|value| value.chars().count() > MAX_NOTES)
            .unwrap_or(false)
        || !valid_login_url(&url)
        || (password.trim().is_empty() && totp_raw.is_empty())
    {
        return Err(());
    }
    Ok(CsvRow {
        title,
        url,
        username,
        password,
        totp: normalized_totp,
        totp_column_present: match format {
            CsvFormat::Chrome => false,
            CsvFormat::Bitwarden => headers.iter().any(|header| header == "login_totp"),
            CsvFormat::OnePassword => headers.iter().any(|header| header == "otpauth"),
            CsvFormat::Sealbox => headers.iter().any(|header| header == "totp"),
        },
        notes: notes_value,
        tags,
    })
}

fn valid_login_url(url: &str) -> bool {
    if url.is_empty() || !url.contains('.') {
        return false;
    }
    origin_of(url).is_some()
}

fn origin_of(url: &str) -> Option<(String, String, u16)> {
    let url = url.trim();
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else if url.contains("://") {
        return None;
    } else {
        ("https", url)
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()?
        .split('@')
        .next_back()?
        .trim();
    if authority.is_empty() {
        return None;
    }
    let default_port = if scheme == "http" { 80 } else { 443 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            (host, port.parse().ok()?)
        }
        _ => (authority, default_port),
    };
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_start_matches("www.")
        .to_ascii_lowercase();
    if host.is_empty() || host == "localhost" || !host.contains('.') {
        return None;
    }
    Some((scheme.into(), host, port))
}

fn parse_valid_rows(parsed: &ParsedCsv) -> (Vec<CsvRow>, usize) {
    let mut valid = Vec::new();
    let mut invalid = 0;
    for row in &parsed.rows {
        match row {
            Ok(row) => valid.push(row.clone()),
            Err(()) => invalid += 1,
        }
    }
    (valid, invalid)
}

pub fn parse_preview(bytes: &[u8]) -> Result<CsvImportPreview, String> {
    let parsed = parse_bytes(bytes)?;
    let (rows, skipped_invalid) = parse_valid_rows(&parsed);
    Ok(CsvImportPreview {
        format: parsed.format.as_str().into(),
        total: parsed.rows.len(),
        importable: rows.len(),
        skipped_existing: 0,
        skipped_invalid,
        sample: rows
            .iter()
            .take(20)
            .map(|row| CsvImportSample {
                title: if row.title.is_empty() {
                    host_of(&row.url).unwrap_or_else(|| "website".into())
                } else {
                    row.title.clone()
                },
                url: row.url.clone(),
                username: row.username.clone(),
                has_password: !row.password.trim().is_empty(),
                has_totp: row.totp.is_some(),
            })
            .collect(),
    })
}

fn host_of(url: &str) -> Option<String> {
    origin_of(url).map(|(_, host, _)| host)
}

pub fn preview_file(
    vault: &Vault,
    _dek: &[u8; 32],
    path: &str,
) -> Result<CsvImportPreview, String> {
    let bytes = read_file(path)?;
    let mut preview = parse_preview(&bytes)?;
    let parsed = parse_bytes(&bytes)?;
    let (rows, _) = parse_valid_rows(&parsed);
    let existing = website_entries(vault).map_err(|error| error.to_string())?;
    preview.skipped_existing = rows
        .iter()
        .filter(|row| find_duplicate(&existing, row).is_some())
        .count();
    Ok(preview)
}

pub fn commit_file(
    vault: &Vault,
    dek: &[u8; 32],
    path: &str,
    overwrite: bool,
) -> Result<CsvImportResult, String> {
    let bytes = read_file(path)?;
    commit_rows(vault, dek, &bytes, overwrite).map_err(|error| error.to_string())
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let path = Path::new(path);
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("CSV 路径必须是绝对路径且不能包含 ..".into());
    }
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() > MAX_BYTES as u64 {
        return Err("CSV 文件不能超过 5 MiB".into());
    }
    fs::read(path).map_err(|error| error.to_string())
}

fn website_entries(vault: &Vault) -> Result<Vec<crate::vault::EntryDto>, VaultError> {
    vault.list_entries(&ListFilter {
        kind: Some(EntryKind::Website),
        kinds: vec![EntryKind::Website],
        sort: SortBy::Title,
        ..Default::default()
    })
}

fn find_duplicate<'a>(
    entries: &'a [crate::vault::EntryDto],
    row: &CsvRow,
) -> Option<&'a crate::vault::EntryDto> {
    let source = origin_of(&row.url)?;
    entries.iter().find(|entry| {
        let Some(existing_origin) = entry.url.as_deref().and_then(origin_of) else {
            return false;
        };
        existing_origin == source && entry.account.as_deref().unwrap_or("") == row.username
    })
}

pub fn commit_rows(
    vault: &Vault,
    dek: &[u8; 32],
    bytes: &[u8],
    overwrite: bool,
) -> Result<CsvImportResult, VaultError> {
    let parsed = parse_bytes(bytes).map_err(|_| VaultError::CorruptBackup)?;
    let (rows, skipped_invalid) = parse_valid_rows(&parsed);
    let mut existing = website_entries(vault)?;
    let mut inserted = 0;
    let mut updated = 0;
    let mut skipped_existing = 0;
    for row in rows {
        let duplicate = find_duplicate(&existing, &row).cloned();
        if duplicate.is_some() && !overwrite {
            skipped_existing += 1;
            continue;
        }
        let notes = match (&row.notes, &duplicate) {
            (Some(notes), _) => Some(notes.clone()),
            (None, Some(entry)) => vault.get_notes(dek, &entry.id)?,
            (None, None) => None,
        };
        let old_secret = duplicate
            .as_ref()
            .map(|entry| vault.get_secret(dek, &entry.id))
            .transpose()?;
        let (folder_id, pinned, expires_at, totp) = match old_secret {
            Some(SecretPayload::Website { totp_secret, .. }) if !row.totp_column_present => (
                duplicate.as_ref().and_then(|entry| entry.folder_id.clone()),
                duplicate
                    .as_ref()
                    .map(|entry| entry.pinned)
                    .unwrap_or(false),
                duplicate
                    .as_ref()
                    .and_then(|entry| entry.expires_at.clone()),
                totp_secret,
            ),
            _ => (
                duplicate.as_ref().and_then(|entry| entry.folder_id.clone()),
                duplicate
                    .as_ref()
                    .map(|entry| entry.pinned)
                    .unwrap_or(false),
                duplicate
                    .as_ref()
                    .and_then(|entry| entry.expires_at.clone()),
                row.totp.clone(),
            ),
        };
        let id = duplicate.as_ref().map(|entry| entry.id.clone());
        let title = if row.title.is_empty() {
            host_of(&row.url).unwrap_or_else(|| "website".into())
        } else {
            row.title.clone()
        };
        let result = vault.upsert_entry(
            dek,
            UpsertEntry {
                id,
                kind: EntryKind::Website,
                title,
                account: Some(row.username.clone()),
                url: Some(row.url.clone()),
                folder_id,
                tags: duplicate
                    .as_ref()
                    .map(|entry| entry.tags.clone())
                    .unwrap_or_else(|| row.tags.clone()),
                pinned,
                expires_at,
                notes,
                secret: SecretPayload::Website {
                    url: Some(row.url.clone()),
                    username: Some(row.username),
                    password: row.password,
                    totp_secret: totp,
                },
            },
        )?;
        if let Some(index) = existing.iter().position(|entry| entry.id == result.id) {
            existing[index] = result;
            updated += 1;
        } else {
            existing.push(result);
            inserted += 1;
        }
    }
    Ok(CsvImportResult {
        format: parsed.format.as_str().into(),
        inserted,
        updated,
        skipped_existing,
        skipped_invalid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_supported_headers_case_insensitive_and_bom() {
        assert_eq!(
            detect_format("name,url,username,password").unwrap(),
            CsvFormat::Chrome
        );
        assert_eq!(
            detect_format("\u{feff}LOGIN_URI,Login_Username,login_password,login_totp").unwrap(),
            CsvFormat::Bitwarden
        );
        assert_eq!(
            detect_format("Title,Url,Username,Password,OTPAuth").unwrap(),
            CsvFormat::OnePassword
        );
        assert_eq!(detect_format("foo,bar").unwrap_err(), "无法识别的 CSV 表头");
    }

    #[test]
    fn parses_quoted_commas_newlines_and_doubled_quotes() {
        let preview = parse_preview(b"title,url,username,password,notes\r\n\"A, \"\"Site\"\"\",https://example.com,a,pw,\"line one\r\nline two, and \"\"quoted\"\"\"\r\n").unwrap();
        assert_eq!(preview.sample[0].title, "A, \"Site\"");
        assert_eq!(preview.importable, 1);
    }

    #[test]
    fn preview_is_metadata_only_and_enforces_utf8_and_size() {
        let csv = "name,url,username,password\nGitHub,https://github.com,octocat,s3cret\n";
        let preview = parse_preview(csv.as_bytes()).unwrap();
        assert_eq!(preview.format, "chrome");
        assert_eq!(preview.importable, 1);
        assert!(preview.sample[0].has_password);
        assert!(!serde_json::to_string(&preview).unwrap().contains("s3cret"));
        assert!(parse_preview(&[0xff]).unwrap_err().contains("UTF-8"));
        assert!(parse_preview(&vec![b'x'; MAX_BYTES + 1]).is_err());
    }

    #[test]
    fn rejects_more_than_5000_data_rows_and_malformed_quotes() {
        let mut csv = String::from("title,url,username,password\n");
        for _ in 0..=MAX_ROWS {
            csv.push_str("site,https://example.com,u,p\n");
        }
        assert!(parse_preview(csv.as_bytes()).is_err());
        assert!(parse_preview(b"title,url,username,password\n\"unterminated").is_err());
    }

    #[test]
    fn skips_non_login_empty_secret_and_oversized_fields() {
        let csv = "type,name,login_uri,login_username,login_password,login_totp,notes\n";
        let csv = format!("{csv}note,Other,https://example.com,u,p,,\nlogin,Empty,https://example.com,u,,,\nlogin,Valid,https://example.com,u,p,,{}\n", "x".repeat(MAX_NOTES + 1));
        let preview = parse_preview(csv.as_bytes()).unwrap();
        assert_eq!(preview.total, 3);
        assert_eq!(preview.importable, 0);
        assert_eq!(preview.skipped_invalid, 3);
    }

    #[test]
    fn commit_inserts_then_deduplicates_by_origin_and_username_and_overwrites() {
        let csv = b"title,url,username,password,totp\nGitHub,https://github.com,octocat,new,JBSWY3DPEHPK3PXP\n";
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let created = commit_rows(&vault, &dek, csv, false).unwrap();
        assert_eq!(created.inserted, 1);
        let skipped = commit_rows(&vault, &dek, csv, false).unwrap();
        assert_eq!(skipped.skipped_existing, 1);
        let updated = commit_rows(&vault, &dek, csv, true).unwrap();
        assert_eq!(updated.updated, 1);
        let entries = website_entries(&vault).unwrap();
        match vault.get_secret(&dek, &entries[0].id).unwrap() {
            SecretPayload::Website {
                password,
                totp_secret,
                ..
            } => {
                assert_eq!(password, "new");
                assert_eq!(
                    totp_secret.as_deref(),
                    Some("JBSWY3DPEHPK3PXP")
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn invalid_totp_rows_are_skipped_without_partial_commit() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let csv = b"title,url,username,password,totp\nGood,https://good.example,user,pw,JBSWY3DPEHPK3PXPJBSWY3DP\nBad,https://bad.example,user,pw,NOT-BASE0\n";
        let result = commit_rows(&vault, &dek, csv, false).unwrap();
        assert_eq!(result.inserted, 1);
        assert_eq!(result.skipped_invalid, 1);
        assert_eq!(website_entries(&vault).unwrap().len(), 1);
    }

    #[test]
    fn overwrite_preserves_notes_and_totp_if_the_csv_columns_are_absent() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let original = vault
            .upsert_entry(
                &dek,
                UpsertEntry {
                    id: None,
                    kind: EntryKind::Website,
                    title: "Old".into(),
                    account: Some("user".into()),
                    url: Some("https://example.com".into()),
                    folder_id: None,
                    tags: vec![],
                    pinned: false,
                    expires_at: None,
                    notes: Some("keep me".into()),
                    secret: SecretPayload::Website {
                        url: Some("https://example.com".into()),
                        username: Some("user".into()),
                        password: "old".into(),
                        totp_secret: Some("OLDSECRET".into()),
                    },
                },
            )
            .unwrap();
        commit_rows(
            &vault,
            &dek,
            b"title,url,username,password\nNew,https://www.example.com,user,new\n",
            true,
        )
        .unwrap();
        assert_eq!(
            vault.get_notes(&dek, &original.id).unwrap().as_deref(),
            Some("keep me")
        );
        match vault.get_secret(&dek, &original.id).unwrap() {
            SecretPayload::Website {
                password,
                totp_secret,
                ..
            } => {
                assert_eq!(password, "new");
                assert_eq!(totp_secret.as_deref(), Some("OLDSECRET"));
            }
            other => panic!("{other:?}"),
        }
    }
}
