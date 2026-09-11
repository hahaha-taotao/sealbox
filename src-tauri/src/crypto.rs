use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const ARGON_M_COST: u32 = 19_456;
pub const ARGON_T_COST: u32 = 2;
pub const ARGON_P_COST: u32 = 1;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("key derivation failed")]
    Kdf,
    #[error("wrapped key has invalid length")]
    BadKeyLength,
    #[error("ciphertext too short")]
    Truncated,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Encrypted {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Encrypted {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NONCE_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < NONCE_LEN + 16 {
            return Err(CryptoError::Truncated);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[..NONCE_LEN]);
        Ok(Self {
            nonce,
            ciphertext: bytes[NONCE_LEN..].to_vec(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArgonParams {
    pub salt: [u8; 16],
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for ArgonParams {
    fn default() -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            salt,
            m_cost: ARGON_M_COST,
            t_cost: ARGON_T_COST,
            p_cost: ARGON_P_COST,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(pub Vec<u8>);

pub fn random_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn derive_kek(password: &str, params: &ArgonParams) -> Result<[u8; KEY_LEN], CryptoError> {
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| CryptoError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), &params.salt, &mut out)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Encrypted, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Encrypt)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(Encrypted {
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn decrypt(key: &[u8; KEY_LEN], enc: &Encrypted) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Decrypt)?;
    let nonce = Nonce::from_slice(&enc.nonce);
    cipher
        .decrypt(nonce, enc.ciphertext.as_ref())
        .map_err(|_| CryptoError::Decrypt)
}

pub fn wrap_key(kek: &[u8; KEY_LEN], dek: &[u8; KEY_LEN]) -> Result<Encrypted, CryptoError> {
    encrypt(kek, dek)
}

pub fn unwrap_key(kek: &[u8; KEY_LEN], enc: &Encrypted) -> Result<[u8; KEY_LEN], CryptoError> {
    let bytes = decrypt(kek, enc)?;
    if bytes.len() != KEY_LEN {
        return Err(CryptoError::BadKeyLength);
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}
