use crate::vault::{Vault, VaultError};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

pub struct Session {
    pub vault: Option<Vault>,
    dek: Option<[u8; 32]>,
    last_active: Instant,
    pub idle_secs: u64,
    pub clipboard_secs: u64,
    clipboard_deadline: Option<Instant>,
    clipboard_hash: Option<[u8; 32]>,
    failed_unlocks: u32,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            vault: None,
            dek: None,
            last_active: Instant::now(),
            idle_secs: 15 * 60,
            clipboard_secs: 20,
            clipboard_deadline: None,
            clipboard_hash: None,
            failed_unlocks: 0,
        }
    }
}

impl Session {
    pub fn is_unlocked(&self) -> bool {
        self.dek.is_some()
    }

    pub fn touch(&mut self) {
        self.last_active = Instant::now();
    }

    pub fn maybe_idle_lock(&mut self) -> bool {
        if self.dek.is_some() && self.last_active.elapsed() > Duration::from_secs(self.idle_secs) {
            self.lock();
            return true;
        }
        false
    }

    pub fn lock(&mut self) {
        if let Some(mut k) = self.dek.take() {
            k.zeroize();
        }
        self.failed_unlocks = 0;
    }

    pub fn unlock_delay_ms(&self) -> u64 {
        let n = self.failed_unlocks.min(10);
        (50u64 * 2u64.saturating_pow(n)).min(2000)
    }

    pub fn set_unlocked(&mut self, vault: Vault, dek: [u8; 32]) {
        self.vault = Some(vault);
        self.dek = Some(dek);
        self.failed_unlocks = 0;
        self.touch();
    }

    pub fn note_failed_unlock(&mut self) {
        self.failed_unlocks = self.failed_unlocks.saturating_add(1);
    }

    pub fn dek(&self) -> Result<&[u8; 32], VaultError> {
        self.dek.as_ref().ok_or(VaultError::NotInitialized)
    }

    pub fn vault(&self) -> Result<&Vault, VaultError> {
        self.vault.as_ref().ok_or(VaultError::NotInitialized)
    }

    pub fn remember_clipboard(&mut self, secret: &str) {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        self.clipboard_hash = Some(hash);
        self.clipboard_deadline = Some(Instant::now() + Duration::from_secs(self.clipboard_secs));
    }

    pub fn clipboard_should_clear(&self, current: &str) -> bool {
        let Some(deadline) = self.clipboard_deadline else {
            return false;
        };
        if Instant::now() < deadline {
            return false;
        }
        let Some(expected) = self.clipboard_hash else {
            return false;
        };
        let mut hasher = Sha256::new();
        hasher.update(current.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        hash == expected
    }

    pub fn clear_clipboard_mark(&mut self) {
        self.clipboard_deadline = None;
        self.clipboard_hash = None;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_drops_dek() {
        let mut s = Session::default();
        s.dek = Some([1u8; 32]);
        s.lock();
        assert!(s.dek().is_err());
    }

    #[test]
    fn clipboard_hash_matches_only_same_payload() {
        let mut s = Session::default();
        s.clipboard_secs = 0;
        s.remember_clipboard("alpha");
        std::thread::sleep(Duration::from_millis(5));
        assert!(s.clipboard_should_clear("alpha"));
        assert!(!s.clipboard_should_clear("beta"));
    }
}
