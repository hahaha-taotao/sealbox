use rand::Rng;
use totp_rs::{Algorithm, Secret, TOTP};

pub fn generate_password(length: usize, upper: bool, lower: bool, digits: bool, symbols: bool) -> String {
    let mut alphabet = String::new();
    if lower {
        alphabet.push_str("abcdefghijkmnopqrstuvwxyz");
    }
    if upper {
        alphabet.push_str("ABCDEFGHJKLMNPQRSTUVWXYZ");
    }
    if digits {
        alphabet.push_str("23456789");
    }
    if symbols {
        alphabet.push_str("!@#$%^&*_-+=?");
    }
    if alphabet.is_empty() {
        alphabet.push_str("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789");
    }
    let chars: Vec<char> = alphabet.chars().collect();
    let mut rng = rand::thread_rng();
    let n = length.clamp(8, 128);
    (0..n).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
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
    Some(format!("SHA256:{}", base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        digest,
    )))
}
