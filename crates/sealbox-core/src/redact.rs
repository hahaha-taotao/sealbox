use crate::vault::SecretPayload;
use regex::Regex;
use std::sync::OnceLock;

fn pem_block() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)-----BEGIN (?:[A-Z ]*PRIVATE KEY|CERTIFICATE)-----.*?-----END (?:[A-Z ]*PRIVATE KEY|CERTIFICATE)-----")
            .unwrap()
    })
}

fn token_like() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)(",
            // GitHub
            r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gho_[A-Za-z0-9]{20,}|",
            // OpenAI / Stripe (sk- uses a hyphen, sk_live_ uses underscores)
            r"sk-[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{10,}|rk_live_[A-Za-z0-9]{10,}|",
            // AWS access key id
            r"AKIA[0-9A-Z]{16}|",
            // Sealbox's own tokens
            r"fill_[A-Fa-f0-9]{32}|sbx_[A-Fa-f0-9]{32}|",
            // GitLab personal/project access tokens
            r"glpat-[A-Za-z0-9_-]{20,}|",
            // Slack
            r"xox[baprs]-[A-Za-z0-9-]{10,}|",
            // Google API key
            r"AIza[0-9A-Za-z_-]{35}|",
            // HashiCorp Atlas
            r"atlasv1\.[A-Za-z0-9_=.-]{20,}|",
            // Any JWT-shaped bearer value
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|",
            // An inline PEM header
            r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|CERTIFICATE)-----",
            r")"
        ))
        .unwrap()
    })
}

pub fn redact_text(input: &str, secrets: &[&str]) -> String {
    let mut out = input.to_string();
    let mut extras: Vec<String> = Vec::new();
    for s in secrets {
        if s.len() >= 6 {
            extras.push((*s).to_string());
        }
    }
    extras.sort_by_key(|s| std::cmp::Reverse(s.len()));
    extras.dedup();
    for s in extras {
        if out.contains(&s) {
            out = out.replace(&s, "[REDACTED]");
        }
    }
    let out = pem_block().replace_all(&out, "[REDACTED]");
    token_like().replace_all(&out, "[REDACTED]").into_owned()
}

pub fn secrets_from_payload(payload: &SecretPayload) -> Vec<String> {
    match payload {
        SecretPayload::Website {
            password,
            totp_secret,
            username,
            ..
        } => {
            let mut v = vec![password.clone()];
            if let Some(t) = totp_secret {
                v.push(t.clone());
            }
            if let Some(u) = username {
                if u.len() >= 8 {
                    v.push(u.clone());
                }
            }
            v
        }
        SecretPayload::ApiToken { token, .. } => vec![token.clone()],
        SecretPayload::Ssh {
            private_key,
            passphrase,
            ..
        } => {
            let mut v = vec![private_key.clone()];
            if let Some(p) = passphrase {
                v.push(p.clone());
            }
            v
        }
        SecretPayload::Mailbox { password, .. } => vec![password.clone()],
        SecretPayload::MailAuth { auth_code, .. } => vec![auth_code.clone()],
        SecretPayload::Server { password, .. } => vec![password.clone()],
        SecretPayload::Database { password, .. } => vec![password.clone()],
        SecretPayload::ClientCert {
            key_pem,
            passphrase,
            ..
        } => {
            let mut v = vec![key_pem.clone()];
            if let Some(p) = passphrase {
                v.push(p.clone());
            }
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_explicit_and_github_token() {
        let text = "token=ghp_abcdefghijklmnopqrstuvwxyz012345 and also secret-value-xyz";
        let out = redact_text(text, &["secret-value-xyz"]);
        assert!(!out.contains("ghp_"));
        assert!(!out.contains("secret-value-xyz"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_fill_and_mcp_tokens() {
        let fill = "fill_0123456789abcdef0123456789abcdef";
        let mcp = "sbx_0123456789abcdef0123456789abcdef";
        let out = redact_text(&format!("got {fill} and {mcp}"), &[]);
        assert!(!out.contains(fill));
        assert!(!out.contains(mcp));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_third_party_token_shapes() {
        // Shapes that are not Sealbox's own and were previously passed through.
        // The GitLab/Stripe fixtures are spliced at runtime so no verbatim
        // vendor token literal lands in the repo: GitHub push protection
        // matches these shapes and rejects the push even for dummies.
        let splice = |prefix: &str, body: &str| format!("{prefix}{body}");
        for token in [
            splice("glpat-", "AbCdEf0123456789GhIj"),
            splice("sk_", "live_4eC39HqLyjWDarjtT1zdp7dc"),
            splice("rk_", "live_4eC39HqLyjWDarjtT1zdp7dc"),
            String::from("xoxb-123456789012-abcdefghijkl"),
            String::from("AIzaSyD-1234567890abcdefghijklmnopqrstu"),
            String::from("atlasv1.abcdefghijklmnopqrstuvwxyz0123"),
            String::from("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
        ] {
            let token = token.as_str();
            let out = redact_text(&format!("header {token} footer"), &[]);
            assert!(!out.contains(token), "{token} must be redacted, got {out}");
            assert!(out.contains("[REDACTED]"), "{token} must leave a marker");
        }
        // A plain sentence must survive untouched.
        let clean = "the quick brown fox jumps over the lazy dog";
        assert_eq!(redact_text(clean, &[]), clean);
    }

    #[test]
    fn redacts_complete_certificate_and_private_key_blocks() {
        let input = "-----BEGIN CERTIFICATE-----\npublic-body\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nprivate-body\n-----END PRIVATE KEY-----";
        let out = redact_text(input, &[]);
        assert!(!out.contains("public-body"));
        assert!(!out.contains("private-body"));
        assert_eq!(out.matches("[REDACTED]").count(), 2);
    }
}
