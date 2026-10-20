use sealbox_core::vault::{SecretPayload, Vault, VaultError};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

pub struct Session {
    vault: Option<Vault>,
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
            idle_secs: 60,
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

    pub fn maybe_idle_lock(&mut self) -> bool {
        if self.dek.is_some() && self.last_active.elapsed() > Duration::from_secs(self.idle_secs) {
            self.lock();
            return true;
        }
        false
    }

    pub fn lock(&mut self) {
        self.clear_owned_clipboard();
        if let Some(mut key) = self.dek.take() {
            key.zeroize();
        }
        self.vault = None;
        self.failed_unlocks = 0;
    }

    pub fn unlock_delay_ms(&self) -> u64 {
        let n = self.failed_unlocks.min(8);
        (80u64 * 2u64.saturating_pow(n)).min(3000)
    }

    pub fn set_unlocked(&mut self, vault: Vault, dek: [u8; 32]) {
        if self.dek.is_some() {
            self.lock();
        }
        self.vault = Some(vault);
        self.dek = Some(dek);
        self.failed_unlocks = 0;
        self.last_active = Instant::now();
    }

    pub fn note_failed_unlock(&mut self) {
        self.failed_unlocks = self.failed_unlocks.saturating_add(1);
    }

    pub fn dek(&self) -> Result<&[u8; 32], VaultError> {
        self.dek.as_ref().ok_or(VaultError::Locked)
    }

    pub fn vault(&self) -> Result<&Vault, VaultError> {
        if self.dek.is_none() {
            return Err(VaultError::Locked);
        }
        self.vault.as_ref().ok_or(VaultError::Locked)
    }

    pub fn require_unlocked(&mut self) -> Result<(), VaultError> {
        self.maybe_idle_lock();
        self.dek()?;
        self.last_active = Instant::now();
        Ok(())
    }

    pub fn remember_clipboard(&mut self, secret: &str) {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        self.clipboard_hash = Some(hasher.finalize().into());
        self.clipboard_deadline = Some(Instant::now() + Duration::from_secs(self.clipboard_secs));
    }

    pub fn clipboard_should_clear(&self, current: &str) -> bool {
        let Some(deadline) = self.clipboard_deadline else {
            return false;
        };
        if Instant::now() < deadline {
            return false;
        }
        self.clipboard_owned(current)
    }

    fn clipboard_owned(&self, current: &str) -> bool {
        let Some(expected) = self.clipboard_hash else {
            return false;
        };
        let mut hasher = Sha256::new();
        hasher.update(current.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        hash == expected
    }

    pub fn clipboard_deadline_due(&self) -> bool {
        self.clipboard_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    pub fn clear_clipboard_mark(&mut self) {
        self.clipboard_deadline = None;
        self.clipboard_hash = None;
    }

    fn clear_owned_clipboard(&mut self) {
        if self.clipboard_hash.is_none() {
            return;
        }
        let current = crate::clipboard::read_text().unwrap_or_default();
        if self.clipboard_owned(&current) {
            let _ = crate::clipboard::clear();
        }
        self.clear_clipboard_mark();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.lock();
    }
}
