use crate::vault::{Vault, VaultError};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

pub struct Session {
    vault: Option<Vault>,
    dek: Option<[u8; 32]>,
    last_active: Instant,
    pub idle_secs: u64,
    pub clipboard_secs: u64,
    pub hotkey: String,
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
            hotkey: "Ctrl+Shift+Space".into(),
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

    #[cfg(test)]
    pub fn age_last_active(&mut self, by: Duration) {
        if let Some(t) = self.last_active.checked_sub(by) {
            self.last_active = t;
        }
    }

    pub fn maybe_idle_lock(&mut self) -> bool {
        if self.dek.is_some() && self.last_active.elapsed() > Duration::from_secs(self.idle_secs) {
            self.lock();
            return true;
        }
        false
    }

    pub fn lock(&mut self) {
        if self.clipboard_hash.is_some() {
            let current = crate::clipboard::read_text().unwrap_or_default();
            if self.clipboard_owned(&current) {
                let _ = crate::clipboard::clear();
            }
        }
        if let Some(mut k) = self.dek.take() {
            k.zeroize();
        }
        self.vault = None;
        self.clear_clipboard_mark();
        self.failed_unlocks = 0;
        crate::lock::on_session_locked();
    }

    pub fn unlock_delay_ms(&self) -> u64 {
        let n = self.failed_unlocks.min(10);
        (50u64 * 2u64.saturating_pow(n)).min(2000)
    }

    pub fn set_unlocked(&mut self, vault: Vault, dek: [u8; 32]) {
        if self.dek.is_some() || self.vault.is_some() {
            self.lock();
        }
        self.vault = Some(vault);
        self.dek = Some(dek);
        self.failed_unlocks = 0;
        self.touch();
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

    pub fn attach_vault_if_unlocked(&mut self, vault: Vault) {
        if self.dek.is_some() && self.vault.is_none() {
            self.vault = Some(vault);
        }
    }

    #[cfg(test)]
    pub fn drop_vault_handle(&mut self) {
        self.vault = None;
    }

    pub fn require_unlocked(&mut self) -> Result<(), VaultError> {
        self.maybe_idle_lock();
        self.dek()?;
        self.touch();
        Ok(())
    }

    pub fn remember_clipboard(&mut self, secret: &str) {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        self.clipboard_hash = Some(hash);
        self.clipboard_deadline = Some(Instant::now() + Duration::from_secs(self.clipboard_secs));
    }

    pub fn clipboard_owned(&self, current: &str) -> bool {
        let Some(expected) = self.clipboard_hash else {
            return false;
        };
        let mut hasher = Sha256::new();
        hasher.update(current.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        hash == expected
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
    fn lock_drops_vault_handle() {
        let (vault, dek) =
            crate::vault::Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut s = Session::default();
        s.set_unlocked(vault, dek);
        assert!(s.vault().is_ok());
        s.lock();
        assert!(!s.is_unlocked());
        assert!(matches!(s.dek(), Err(VaultError::Locked)));
        assert!(matches!(s.vault(), Err(VaultError::Locked)));
    }

    #[test]
    fn vault_accessor_requires_dek() {
        let (vault, _dek) =
            crate::vault::Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut s = Session::default();
        s.attach_vault_if_unlocked(vault);
        assert!(!s.is_unlocked());
        assert!(s.vault().is_err());
    }

    #[test]
    fn require_unlocked_rejects_locked_session() {
        let mut s = Session::default();
        assert!(s.require_unlocked().is_err());
        let (vault, dek) =
            crate::vault::Vault::create_in_memory("correct horse battery staple extra").unwrap();
        s.set_unlocked(vault, dek);
        assert!(s.require_unlocked().is_ok());
        s.lock();
        assert!(matches!(s.require_unlocked(), Err(VaultError::Locked)));
    }

    #[test]
    fn attach_vault_while_locked_is_ignored() {
        let (vault, dek) =
            crate::vault::Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let (extra, _) =
            crate::vault::Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut s = Session::default();
        s.set_unlocked(vault, dek);
        s.lock();
        s.attach_vault_if_unlocked(extra);
        assert!(s.vault().is_err());
        assert!(!s.is_unlocked());
    }

    #[test]
    fn idle_lock_drops_vault_handle() {
        let (vault, dek) =
            crate::vault::Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut s = Session::default();
        s.set_unlocked(vault, dek);
        s.idle_secs = 2;
        s.age_last_active(Duration::from_secs(3));
        assert!(s.maybe_idle_lock());
        assert!(matches!(s.vault(), Err(VaultError::Locked)));
        assert!(!s.is_unlocked());
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

    #[test]
    fn clipboard_owned_ignores_deadline() {
        let mut s = Session::default();
        s.clipboard_secs = 120;
        s.remember_clipboard("alpha");
        assert!(s.clipboard_owned("alpha"));
        assert!(!s.clipboard_owned("beta"));
        assert!(!s.clipboard_should_clear("alpha"));
    }

    #[test]
    fn lock_clears_clipboard_mark() {
        let mut s = Session::default();
        s.clipboard_secs = 120;
        s.remember_clipboard("alpha");
        s.lock();
        assert!(!s.clipboard_owned("alpha"));
        assert!(!s.clipboard_should_clear("alpha"));
    }

    #[test]
    fn lock_clears_owned_os_clipboard_before_deadline() {
        let secret = format!("sealbox-lock-clipboard-test-{}", std::process::id());
        match crate::clipboard::write_text(&secret) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("skip: clipboard write failed: {e}");
                return;
            }
        }
        let got = crate::clipboard::read_text().unwrap_or_default();
        if got != secret {
            eprintln!("skip: clipboard roundtrip failed, got {got:?}");
            return;
        }
        let mut s = Session::default();
        s.clipboard_secs = 120;
        s.remember_clipboard(&secret);
        assert!(s.clipboard_owned(&secret));
        assert!(
            !s.clipboard_should_clear(&secret),
            "deadline has not passed; timed clear must not fire yet"
        );
        s.lock();
        let after = crate::clipboard::read_text().unwrap_or_default();
        assert_ne!(
            after, secret,
            "lock must wipe the copied secret immediately"
        );
        assert!(!s.clipboard_owned(&secret));
        assert!(!s.clipboard_should_clear(&secret));
    }

    #[test]
    fn lock_does_not_clear_unrelated_clipboard() {
        let ours = "sealbox-owned-secret";
        let theirs = "user-copied-other-text";
        match crate::clipboard::write_text(theirs) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("skip: clipboard write failed: {e}");
                return;
            }
        }
        if crate::clipboard::read_text().unwrap_or_default() != theirs {
            eprintln!("skip: clipboard roundtrip failed");
            return;
        }
        let mut s = Session::default();
        s.clipboard_secs = 120;
        s.remember_clipboard(ours);
        s.lock();
        assert_eq!(crate::clipboard::read_text().unwrap_or_default(), theirs);
        assert!(!s.clipboard_owned(ours));
    }

    #[test]
    fn idle_lock_fires_without_touch() {
        let mut s = Session::default();
        s.dek = Some([1u8; 32]);
        s.idle_secs = 2;
        s.age_last_active(Duration::from_secs(3));
        assert!(s.maybe_idle_lock());
        assert!(s.dek().is_err());
    }

    #[test]
    fn touch_resets_idle_timer() {
        let mut s = Session::default();
        s.dek = Some([1u8; 32]);
        s.idle_secs = 2;
        s.age_last_active(Duration::from_secs(1));
        s.touch();
        s.age_last_active(Duration::from_millis(1500));
        assert!(!s.maybe_idle_lock());
        assert!(s.dek().is_ok());
    }
}
