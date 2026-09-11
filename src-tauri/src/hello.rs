use crate::crypto::random_key;
use crate::vault::Vault;
use keyring::Entry;

const SERVICE: &str = "com.sealbox.app";
const USER: &str = "hello_key";

pub fn store_hello_key(key: &[u8; 32]) -> Result<(), String> {
    let entry = Entry::new(SERVICE, USER).map_err(|e| e.to_string())?;
    entry
        .set_password(&hex::encode(key))
        .map_err(|e| e.to_string())
}

pub fn load_hello_key() -> Result<[u8; 32], String> {
    let entry = Entry::new(SERVICE, USER).map_err(|e| e.to_string())?;
    let s = entry.get_password().map_err(|e| e.to_string())?;
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err("hello key length".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn delete_hello_key() -> Result<(), String> {
    let entry = Entry::new(SERVICE, USER).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn enable_hello(vault: &Vault, dek: &[u8; 32]) -> Result<(), String> {
    let key = random_key();
    vault.set_hello(dek, Some(&key)).map_err(|e| e.to_string())?;
    store_hello_key(&key)
}

pub fn disable_hello(vault: &Vault, dek: &[u8; 32]) -> Result<(), String> {
    vault.set_hello(dek, None).map_err(|e| e.to_string())?;
    delete_hello_key()
}

#[cfg(windows)]
pub fn prompt_hello() -> Result<bool, String> {
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    let availability = UserConsentVerifier::CheckAvailabilityAsync()
        .map_err(|e| e.to_string())?
        .get()
        .map_err(|e| e.to_string())?;
    if availability != UserConsentVerifierAvailability::Available
        && availability != UserConsentVerifierAvailability::DeviceBusy
    {
        return Ok(false);
    }
    let result = UserConsentVerifier::RequestVerificationAsync(&windows::core::HSTRING::from(
        "解锁 Sealbox 印盒",
    ))
    .map_err(|e| e.to_string())?
    .get()
    .map_err(|e| e.to_string())?;
    Ok(result == UserConsentVerificationResult::Verified)
}

#[cfg(not(windows))]
pub fn prompt_hello() -> Result<bool, String> {
    Err("Windows Hello 仅支持 Windows".into())
}

pub fn hello_available() -> bool {
    #[cfg(windows)]
    {
        use windows::Security::Credentials::UI::{
            UserConsentVerifier, UserConsentVerifierAvailability,
        };
        UserConsentVerifier::CheckAvailabilityAsync()
            .ok()
            .and_then(|op| op.get().ok())
            .map(|a| {
                a == UserConsentVerifierAvailability::Available
                    || a == UserConsentVerifierAvailability::DeviceBusy
            })
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        false
    }
}
