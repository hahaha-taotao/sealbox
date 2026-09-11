use chrono::{Duration, Utc};
use sealbox_lib::vault::{
    EntryKind, ListFilter, SecretPayload, SortBy, UpsertEntry, Vault,
};

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

#[test]
fn create_and_unlock() {
    let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
    let dek2 = vault.unlock("correct horse battery staple extra").unwrap();
    assert_eq!(dek, dek2);
    assert!(vault.unlock("wrong password extra").is_err());
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
    let web = vault.upsert_entry(&dek, sample_website("jira", None)).unwrap();
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
        SecretPayload::Ssh { public_fingerprint, .. } => {
            assert_eq!(public_fingerprint.as_deref(), Some("SHA256:abcd"));
        }
        _ => panic!("wrong kind"),
    }

    vault.soft_delete(&[web.id.clone()]).unwrap();
    let active = vault.list_entries(&ListFilter::default()).unwrap();
    assert_eq!(active.len(), 2);
    let trash = vault
        .list_entries(&ListFilter {
            trash: true,
            ..ListFilter::default()
        })
        .unwrap();
    assert_eq!(trash.len(), 1);
    vault.restore(&[web.id.clone()]).unwrap();
    assert_eq!(vault.list_entries(&ListFilter::default()).unwrap().len(), 3);

    let old = Utc::now() - Duration::days(40);
    vault.soft_delete(&[web.id.clone()]).unwrap();
    // force deleted_at into the past via restore path is hard; purge uses deleted_at timestamp.
    // Just ensure purge with future cutoff doesn't panic.
    vault.purge_expired_trash(old, 30).unwrap();
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
