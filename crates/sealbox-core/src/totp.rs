use rand::Rng;
use totp_rs::{Algorithm, Secret, TOTP};

const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "!@#$%^&*_-+=?";
const FALLBACK: &str = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub fn generate_password(
    length: usize,
    upper: bool,
    lower: bool,
    digits: bool,
    symbols: bool,
) -> String {
    generate_password_with_options(length, upper, lower, digits, symbols, false)
}

pub fn generate_password_with_options(
    length: usize,
    upper: bool,
    lower: bool,
    digits: bool,
    symbols: bool,
    ensure_each: bool,
) -> String {
    let mut classes = Vec::new();
    if lower {
        classes.push(LOWER);
    }
    if upper {
        classes.push(UPPER);
    }
    if digits {
        classes.push(DIGITS);
    }
    if symbols {
        classes.push(SYMBOLS);
    }

    let alphabet = if classes.is_empty() {
        FALLBACK.to_string()
    } else {
        classes.join("")
    };
    let chars: Vec<char> = alphabet.chars().collect();
    let n = length.clamp(8, 128);
    let mut rng = rand::thread_rng();
    let mut result = Vec::with_capacity(n);

    if ensure_each {
        for class in &classes {
            let chars: Vec<char> = class.chars().collect();
            if result.len() == n {
                break;
            }
            result.push(chars[rng.gen_range(0..chars.len())]);
        }
    }
    while result.len() < n {
        result.push(chars[rng.gen_range(0..chars.len())]);
    }
    for i in (1..result.len()).rev() {
        let j = rng.gen_range(0..=i);
        result.swap(i, j);
    }
    result.into_iter().collect()
}

pub fn generate_passphrase(words: usize, separator: &str) -> String {
    let count = if words == 0 { 4 } else { words.clamp(3, 8) };
    let separator = if separator.is_empty() { "-" } else { separator };
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| {
            crate::passphrase_words::WORDS[rng.gen_range(0..crate::passphrase_words::WORDS.len())]
        })
        .collect::<Vec<_>>()
        .join(separator)
}

pub fn normalize_totp_secret(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("TOTP 密钥不能为空".into());
    }
    let secret = if let Some(rest) = trimmed.strip_prefix("otpauth://") {
        parse_otpauth(rest)?
    } else {
        compact_base32(trimmed)?
    };
    Secret::Encoded(secret.clone())
        .to_bytes()
        .map_err(|_| "TOTP 密钥不是有效 Base32".to_string())?;
    Ok(secret)
}

fn parse_otpauth(rest: &str) -> Result<String, String> {
    let (kind, query) = rest.split_once('?').ok_or("otpauth URI 缺少参数")?;
    if !kind.to_ascii_lowercase().starts_with("totp/") {
        return Err("只支持 otpauth://totp".into());
    }
    let mut secret = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key)?.to_ascii_lowercase();
        let value = percent_decode(value)?;
        match key.as_str() {
            "secret" => secret = Some(compact_base32(&value)?),
            "digits" if value != "6" => return Err("只支持 6 位 TOTP".into()),
            "period" if value != "30" => return Err("只支持 30 秒周期".into()),
            "algorithm" if !value.eq_ignore_ascii_case("sha1") => {
                return Err("只支持 SHA1 TOTP".into())
            }
            _ => {}
        }
    }
    secret.ok_or_else(|| "otpauth URI 缺少 secret".into())
}

fn compact_base32(raw: &str) -> Result<String, String> {
    let compact: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if compact.len() < 8 || compact.len() > 128 {
        return Err("TOTP 密钥长度不合法".into());
    }
    if !compact
        .chars()
        .all(|c| matches!(c, 'A'..='Z' | '2'..='7' | '='))
    {
        return Err("TOTP 密钥不是有效 Base32".into());
    }
    Ok(compact)
}

fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("otpauth URI 编码无效".into());
            }
            let hex =
                std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|_| "otpauth URI 编码无效")?;
            decoded.push(u8::from_str_radix(hex, 16).map_err(|_| "otpauth URI 编码无效")?);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| "otpauth URI 编码无效".into())
}

pub fn totp_now(secret: &str) -> Result<String, String> {
    let secret = normalize_totp_secret(secret)?;
    let secret = Secret::Encoded(secret)
        .to_bytes()
        .map_err(|e| e.to_string())?;
    let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret, None, "Sealbox".into());
    totp.generate_current().map_err(|e| e.to_string())
}

pub fn ssh_fingerprint(private_key: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    if private_key.trim().is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(private_key.as_bytes());
    let digest = hasher.finalize();
    Some(format!(
        "SHA256:{}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, digest,)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_clamps_length() {
        assert_eq!(
            generate_password(1, true, true, true, true).chars().count(),
            8
        );
        assert_eq!(
            generate_password(999, true, true, true, true)
                .chars()
                .count(),
            128
        );
    }

    #[test]
    fn password_respects_enabled_classes() {
        let value = generate_password(32, false, false, true, false);
        assert!(value.chars().all(|c| DIGITS.contains(c)));
    }

    #[test]
    fn password_can_guarantee_each_enabled_class() {
        let value = generate_password_with_options(8, true, true, true, true, true);
        assert!(value.chars().any(|c| LOWER.contains(c)));
        assert!(value.chars().any(|c| UPPER.contains(c)));
        assert!(value.chars().any(|c| DIGITS.contains(c)));
        assert!(value.chars().any(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn password_falls_back_when_no_class_is_selected() {
        let value = generate_password_with_options(32, false, false, false, false, true);
        assert!(value.chars().all(|c| FALLBACK.contains(c)));
    }

    #[test]
    fn passphrase_uses_requested_word_count_and_separator() {
        let value = generate_passphrase(5, "::");
        let words: Vec<&str> = value.split("::").collect();
        assert_eq!(words.len(), 5);
        assert!(words
            .iter()
            .all(|word| crate::passphrase_words::WORDS.contains(word)));
    }

    #[test]
    fn passphrase_clamps_and_defaults() {
        assert_eq!(generate_passphrase(1, "").split('-').count(), 3);
        assert_eq!(generate_passphrase(0, "").split('-').count(), 4);
        assert_eq!(generate_passphrase(99, "-").split('-').count(), 8);
    }

    #[test]
    fn normalize_accepts_otpauth_and_spaces() {
        let secret = super::normalize_totp_secret(
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        )
        .unwrap();
        assert_eq!(secret, "JBSWY3DPEHPK3PXP");
        assert!(super::normalize_totp_secret("jbsw y3dp ehpk 3pxp").is_ok());
        assert!(super::normalize_totp_secret("").is_err());
        assert!(
            super::normalize_totp_secret("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8")
                .is_err()
        );
        assert!(super::normalize_totp_secret("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(
            super::normalize_totp_secret("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP%ZZ").is_err()
        );
    }

    #[test]
    fn totp_now_accepts_normalized_secret() {
        let secret = super::normalize_totp_secret("JBSWY3DPEHPK3PXP").unwrap();
        let code = super::totp_now(&secret).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}
