use chrono::{Duration, Utc};
use sealbox_lib::db;
use sealbox_lib::vault::{
    EntryKind, ListFilter, SecretPayload, SortBy, UpsertEntry, Vault, VaultError,
};
use std::path::PathBuf;

fn sample_website(title: &str, notes: Option<&str>) -> UpsertEntry {
    UpsertEntry {
        id: None,
        kind: EntryKind::Website,
        title: title.into(),
        account: Some("alice".into()),
        url: Some("https://jira.example.com".into()),
        folder_id: None,
        tags: vec!["work".into()],
        pinned: false,
        expires_at: None,
        notes: notes.map(|s| s.into()),
        secret: SecretPayload::Website {
            url: Some("https://jira.example.com".into()),
            username: Some("alice".into()),
            password: "s3cret-pass".into(),
            totp_secret: None,
        },
    }
}

fn temp_db_path() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sealbox-open-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("vault.db")
}

#[test]
fn create_and_unlock() {
    let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
    let dek2 = vault.unlock("correct horse battery staple extra").unwrap();
    assert_eq!(dek, dek2);
    assert!(vault.unlock("wrong password extra").is_err());
}

#[test]
fn open_missing_file_returns_not_initialized_without_creating() {
    let path = temp_db_path();
    assert!(!path.exists());
    match Vault::open(path.to_str().unwrap()) {
        Err(VaultError::NotInitialized) => {}
        Ok(_) => panic!("expected NotInitialized, open succeeded"),
        Err(e) => panic!("expected NotInitialized, got {e}"),
    }
    assert!(
        db::open_existing(path.to_str().unwrap()).is_err(),
        "open_existing must not create a database"
    );
    assert!(
        !path.exists(),
        "unlock/open must not create an empty vault.db"
    );
    assert!(!Vault::is_initialized(path.to_str().unwrap()));
}

#[test]
fn empty_sqlite_leftover_is_not_initialized_and_can_be_replaced() {
    let path = temp_db_path();
    db::open(path.to_str().unwrap()).unwrap();
    assert!(path.exists());
    assert!(
        !Vault::is_initialized(path.to_str().unwrap()),
        "schema-only leftover must not count as an initialized vault"
    );

    let dek = Vault::create(path.to_str().unwrap(), "correct horse battery staple extra")
        .expect("setup must be able to replace an uninitialized leftover");
    let vault = Vault::open(path.to_str().unwrap()).unwrap();
    assert_eq!(
        vault.unlock("correct horse battery staple extra").unwrap(),
        dek
    );
    assert!(Vault::is_initialized(path.to_str().unwrap()));
}

#[test]
fn list_dto_has_no_password_and_search_skips_notes() {
    let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
    vault
        .upsert_entry(
            &dek,
            sample_website("jira", Some("recovery-code-SHOULD-NOT-MATCH")),
        )
        .unwrap();
    let listed = vault.list_entries(&ListFilter::default()).unwrap();
    assert_eq!(listed.len(), 1);
    let json = serde_json::to_string(&listed[0]).unwrap();
    assert!(!json.contains("s3cret-pass"));
    assert!(!json.contains("recovery-code"));

    let by_title = vault
        .list_entries(&ListFilter {
            query: Some("jira".into()),
            kind: None,
            folder_id: None,
            uncategorized: false,
            tag: None,
            trash: false,
            sort: SortBy::Title,
        })
        .unwrap();
    assert_eq!(by_title.len(), 1);

    let by_notes = vault
        .list_entries(&ListFilter {
            query: Some("recovery-code".into()),
            ..ListFilter {
                sort: SortBy::Title,
                ..ListFilter::default()
            }
        })
        .unwrap();
    assert!(by_notes.is_empty());
}

#[test]
fn three_kinds_roundtrip_and_trash() {
    let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
    let web = vault
        .upsert_entry(&dek, sample_website("jira", None))
        .unwrap();
    let token = vault
        .upsert_entry(
            &dek,
            UpsertEntry {
                id: None,
                kind: EntryKind::ApiToken,
                title: "github".into(),
                account: Some("octocat".into()),
                url: None,
                folder_id: None,
                tags: vec![],
                pinned: false,
                expires_at: None,
                notes: None,
                secret: SecretPayload::ApiToken {
                    service: "github".into(),
                    account: Some("octocat".into()),
                    token: "ghp_testtoken".into(),
                },
            },
        )
        .unwrap();
    let mail = vault
        .upsert_entry(
            &dek,
            UpsertEntry {
                id: None,
                kind: EntryKind::Mailbox,
                title: "work-mail".into(),
                account: None,
                url: None,
                folder_id: None,
                tags: vec![],
                pinned: false,
                expires_at: None,
                notes: None,
                secret: SecretPayload::Mailbox {
                    email: "me@example.com".into(),
                    password: "mail-pass".into(),
                    imap_host: Some("imap.example.com".into()),
                    imap_port: Some(993),
                    smtp_host: Some("smtp.example.com".into()),
                    smtp_port: Some(465),
                },
            },
        )
        .unwrap();
    let custom = vault
        .upsert_entry(
            &dek,
            UpsertEntry {
                id: None,
                kind: EntryKind::ApiToken,
                title: "internal-api".into(),
                account: Some("bot".into()),
                url: Some("https://api.example.com".into()),
                folder_id: None,
                tags: vec![],
                pinned: false,
                expires_at: None,
                notes: None,
                secret: SecretPayload::ApiToken {
                    service: "custom".into(),
                    account: Some("bot".into()),
                    token: "custom-token-value".into(),
                },
            },
        )
        .unwrap();
    assert_eq!(custom.url.as_deref(), Some("https://api.example.com"));
    vault
        .upsert_entry(
            &dek,
            UpsertEntry {
                id: None,
                kind: EntryKind::MailAuth,
                title: "qq-auth".into(),
                account: None,
                url: None,
                folder_id: None,
                tags: vec![],
                pinned: false,
                expires_at: None,
                notes: None,
                secret: SecretPayload::MailAuth {
                    email: "me@qq.com".into(),
                    provider: "qq".into(),
                    auth_code: "auth-code-xyz".into(),
                },
            },
        )
        .unwrap();
    vault
        .upsert_entry(
            &dek,
            UpsertEntry {
                id: None,
                kind: EntryKind::Server,
                title: "prod-box".into(),
                account: None,
                url: None,
                folder_id: None,
                tags: vec![],
                pinned: false,
                expires_at: None,
                notes: None,
                secret: SecretPayload::Server {
                    host: "10.0.0.8".into(),
                    port: Some(22),
                    protocol: "ssh".into(),
                    username: "root".into(),
                    password: "server-pass".into(),
                },
            },
        )
        .unwrap();
    vault
        .upsert_entry(
            &dek,
            UpsertEntry {
                id: None,
                kind: EntryKind::Database,
                title: "prod-mysql".into(),
                account: None,
                url: None,
                folder_id: None,
                tags: vec![],
                pinned: false,
                expires_at: None,
                notes: None,
                secret: SecretPayload::Database {
                    engine: "mysql".into(),
                    host: "10.0.0.9".into(),
                    port: Some(3306),
                    database: "app".into(),
                    username: "app".into(),
                    password: "db-pass-secret".into(),
                },
            },
        )
        .unwrap();
    let ssh = vault
        .upsert_entry(
            &dek,
            UpsertEntry {
                id: None,
                kind: EntryKind::Ssh,
                title: "prod".into(),
                account: Some("deploy".into()),
                url: None,
                folder_id: None,
                tags: vec![],
                pinned: false,
                expires_at: None,
                notes: None,
                secret: SecretPayload::Ssh {
                    key_type: "ed25519".into(),
                    private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
                        .into(),
                    passphrase: None,
                    public_fingerprint: Some("SHA256:abcd".into()),
                },
            },
        )
        .unwrap();

    match vault.get_secret(&dek, &token.id).unwrap() {
        SecretPayload::ApiToken { token: t, .. } => assert_eq!(t, "ghp_testtoken"),
        _ => panic!("wrong kind"),
    }
    match vault.get_secret(&dek, &ssh.id).unwrap() {
        SecretPayload::Ssh {
            public_fingerprint, ..
        } => {
            assert_eq!(public_fingerprint.as_deref(), Some("SHA256:abcd"));
        }
        _ => panic!("wrong kind"),
    }
    match vault.get_secret(&dek, &mail.id).unwrap() {
        SecretPayload::Mailbox {
            email, password, ..
        } => {
            assert_eq!(email, "me@example.com");
            assert_eq!(password, "mail-pass");
        }
        _ => panic!("wrong kind"),
    }
    let listed = vault.list_entries(&ListFilter::default()).unwrap();
    let json = serde_json::to_string(&listed).unwrap();
    assert!(!json.contains("mail-pass"));
    assert!(!json.contains("auth-code-xyz"));
    assert!(!json.contains("server-pass"));
    assert!(!json.contains("db-pass-secret"));
    assert_eq!(listed.len(), 8);

    vault.soft_delete(&[web.id.clone()]).unwrap();
    let active = vault.list_entries(&ListFilter::default()).unwrap();
    assert_eq!(active.len(), 7);
    let trash = vault
        .list_entries(&ListFilter {
            trash: true,
            ..ListFilter::default()
        })
        .unwrap();
    assert_eq!(trash.len(), 1);
    vault.restore(&[web.id.clone()]).unwrap();
    assert_eq!(vault.list_entries(&ListFilter::default()).unwrap().len(), 8);
    vault.set_pinned(&web.id, true).unwrap();
    assert!(vault.list_entries(&ListFilter::default()).unwrap()[0].pinned);
    vault.soft_delete(&[web.id.clone()]).unwrap();
    vault.empty_trash().unwrap();
    assert_eq!(
        vault
            .list_entries(&ListFilter {
                trash: true,
                ..ListFilter::default()
            })
            .unwrap()
            .len(),
        0
    );

    vault.soft_delete(&[token.id.clone()]).unwrap();
    let old = Utc::now() - Duration::days(40);
    vault.purge_expired_trash(old, 30).unwrap();
}

#[test]
fn recent_and_expiring() {
    let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
    let mut soon = sample_website("expires-soon", None);
    soon.expires_at = Some((Utc::now() + Duration::days(3)).to_rfc3339());
    let row = vault.upsert_entry(&dek, soon).unwrap();
    vault.bump_use(&row.id).unwrap();
    assert_eq!(vault.recent_entries(5).unwrap().len(), 1);
    assert_eq!(vault.expiring_entries(30).unwrap().len(), 1);
    assert!(vault.expiring_entries(1).unwrap().is_empty());
}

#[test]
fn list_filter_accepts_partial_json_from_quick_search() {
    let filter: ListFilter =
        serde_json::from_str(r#"{"query":"","trash":false,"sort":"use_count"}"#)
            .expect("quick search payload should deserialize");
    assert_eq!(filter.query.as_deref(), Some(""));
    assert!(!filter.trash);
    assert!(!filter.uncategorized);
    assert!(filter.kind.is_none());
    assert!(filter.folder_id.is_none());
    assert!(filter.tag.is_none());
    assert!(matches!(filter.sort, SortBy::UseCount));

    let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
    vault
        .upsert_entry(&dek, sample_website("跳板机", None))
        .unwrap();
    let listed = vault.list_entries(&filter).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].title, "跳板机");
}

#[test]
fn change_master_password() {
    let (vault, dek) = Vault::create_in_memory("old password long enough").unwrap();
    vault
        .change_master_password(&dek, "old password long enough", "new password long enough")
        .unwrap();
    assert!(vault.unlock("old password long enough").is_err());
    let dek2 = vault.unlock("new password long enough").unwrap();
    assert_eq!(dek, dek2);
}

#[test]
fn secret_settings_encrypt_and_migrate_plaintext() {
    let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
    vault.set_setting("mcp_token", "sbx_plain_legacy").unwrap();
    let got = vault
        .get_secret_setting(&dek, "mcp_token")
        .unwrap()
        .unwrap();
    assert_eq!(got, "sbx_plain_legacy");
    assert!(vault.get_setting("mcp_token").unwrap().is_none());
    let enc = vault.get_setting("mcp_token_enc").unwrap().unwrap();
    assert!(!enc.contains("sbx_plain_legacy"));
    vault
        .set_secret_setting(&dek, "fill_token", "fill_0123456789abcdef0123456789abcdef")
        .unwrap();
    assert_eq!(
        vault
            .get_secret_setting(&dek, "fill_token")
            .unwrap()
            .as_deref(),
        Some("fill_0123456789abcdef0123456789abcdef")
    );
    let wrong = [0u8; 32];
    assert!(vault
        .get_secret_setting(&wrong, "fill_token")
        .unwrap()
        .is_none());
}
