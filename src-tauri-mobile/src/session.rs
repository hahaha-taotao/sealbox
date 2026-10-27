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
    /// Set only when a live DEK is discarded. Callers clear transfer and the
    /// sync runtime after releasing this mutex. A lock with no DEK — the
    /// uninitialized restore screen — must not look like one.
    lock_event: bool,
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
            lock_event: false,
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

    /// Returns whether a DEK was actually discarded.
    pub fn lock(&mut self) -> bool {
        self.clear_owned_clipboard();
        let had_dek = self.dek.is_some();
        if let Some(mut key) = self.dek.take() {
            key.zeroize();
            self.lock_event = true;
        }
        self.vault = None;
        self.failed_unlocks = 0;
        had_dek
    }

    pub fn take_lock_event(&mut self) -> bool {
        let happened = self.lock_event;
        self.lock_event = false;
        happened
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_without_dek_does_not_signal_wipe() {
        let mut session = Session::default();
        assert!(!session.lock());
        assert!(!session.take_lock_event());
    }
}
