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

pub fn totp_now(secret: &str) -> Result<String, String> {
    let secret = Secret::Encoded(secret.to_string())
        .to_bytes()
        .or_else(|_| Secret::Raw(secret.as_bytes().to_vec()).to_bytes())
        .map_err(|e| e.to_string())?;
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret, None, "Sealbox".into())
        .map_err(|e| e.to_string())?;
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
}
