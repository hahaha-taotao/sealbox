//! One-shot native cache. Backup and CSV bytes never return to the webview.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sealbox_core::crypto::random_key;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const TTL: Duration = Duration::from_secs(10 * 60);
const INVALID: &str = "预览已失效，请重新预览";

enum TransferKind {
    Backup {
        bytes: Zeroizing<Vec<u8>>,
        password: Zeroizing<String>,
    },
    Csv {
        bytes: Zeroizing<Vec<u8>>,
    },
}

struct TransferEntry {
    token: String,
    created: Instant,
    hash: [u8; 32],
    /// Set by `backup_restore_new` before it copies the bytes out. `clear`
    /// keeps this entry so lock/idle cannot drop the token being restored
    /// into an uninitialized vault.
    pinned: bool,
    kind: TransferKind,
}

#[derive(Default)]
pub struct TransferCache {
    entry: Option<TransferEntry>,
}

impl TransferCache {
    pub fn clear(&mut self) {
        if self.entry.as_ref().is_some_and(|entry| entry.pinned) {
            return;
        }
        self.entry = None;
    }

    pub fn put_backup(&mut self, bytes: Vec<u8>, password: String) -> Result<String, String> {
        self.put(TransferKind::Backup {
            bytes: Zeroizing::new(bytes),
            password: Zeroizing::new(password),
        })
    }

    pub fn put_csv(&mut self, bytes: Vec<u8>) -> Result<String, String> {
        self.put(TransferKind::Csv {
            bytes: Zeroizing::new(bytes),
        })
    }

    pub fn pin_backup(&mut self, token: &str) -> Result<(), String> {
        self.expire();
        let Some(entry) = self.entry.as_mut() else {
            return Err(INVALID.into());
        };
        if entry.token != token || !matches!(entry.kind, TransferKind::Backup { .. }) || !intact(entry)
        {
            return Err(INVALID.into());
        }
        entry.pinned = true;
        Ok(())
    }

    pub fn take_backup(&mut self, token: &str) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<String>), String> {
        let entry = self.take_entry(token)?;
        match entry.kind {
            TransferKind::Backup { bytes, password } => Ok((bytes, password)),
            TransferKind::Csv { .. } => {
                self.entry = Some(entry);
                Err(INVALID.into())
            }
        }
    }

    pub fn take_csv(&mut self, token: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let entry = self.take_entry(token)?;
        match entry.kind {
            TransferKind::Csv { bytes } => Ok(bytes),
            TransferKind::Backup { .. } => {
                self.entry = Some(entry);
                Err(INVALID.into())
            }
        }
    }

    fn put(&mut self, kind: TransferKind) -> Result<String, String> {
        if self.entry.as_ref().is_some_and(|entry| entry.pinned) {
            return Err("正在从备份创建金库，请稍后再试".into());
        }
        let hash = digest(bytes_of(&kind));
        let token = URL_SAFE_NO_PAD.encode(random_key());
        self.entry = Some(TransferEntry {
            token: token.clone(),
            created: Instant::now(),
            hash,
            pinned: false,
            kind,
        });
        Ok(token)
    }

    fn take_entry(&mut self, token: &str) -> Result<TransferEntry, String> {
        self.expire();
        let entry = self.entry.take().ok_or(INVALID)?;
        if entry.token != token {
            if intact(&entry) && entry.created.elapsed() < TTL {
                self.entry = Some(entry);
            }
            return Err(INVALID.into());
        }
        if entry.created.elapsed() >= TTL || !intact(&entry) {
            return Err(INVALID.into());
        }
        Ok(entry)
    }

    fn expire(&mut self) {
        if self
            .entry
            .as_ref()
            .is_some_and(|entry| !entry.pinned && entry.created.elapsed() >= TTL)
        {
            self.entry = None;
        }
    }
}

fn bytes_of(kind: &TransferKind) -> &[u8] {
    match kind {
        TransferKind::Backup { bytes, .. } | TransferKind::Csv { bytes } => bytes.as_slice(),
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn intact(entry: &TransferEntry) -> bool {
    digest(bytes_of(&entry.kind)) == entry.hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transfer_token_is_one_time_and_kind_bound() {
        let mut cache = TransferCache::default();
        let token = cache.put_csv(vec![1, 2, 3]).unwrap();
        assert_eq!(&*cache.take_csv(&token).unwrap(), &[1, 2, 3]);
        assert_eq!(cache.take_csv(&token).unwrap_err(), INVALID);
    }

    #[test]
    fn replacing_a_transfer_discards_the_previous_secret() {
        let mut cache = TransferCache::default();
        let old = cache.put_backup(vec![1], "old".into()).unwrap();
        let new = cache.put_backup(vec![2], "new".into()).unwrap();
        assert_eq!(cache.take_backup(&old).unwrap_err(), INVALID);
        let (bytes, password) = cache.take_backup(&new).unwrap();
        assert_eq!(&*bytes, &[2]);
        assert_eq!(&*password, "new");
    }

    #[test]
    fn clear_keeps_only_the_pinned_backup_token() {
        let mut cache = TransferCache::default();
        let token = cache.put_backup(b"backup".to_vec(), "secret".into()).unwrap();
        cache.pin_backup(&token).unwrap();
        assert!(cache.put_csv(vec![1]).is_err());
        cache.clear();
        let (bytes, password) = cache.take_backup(&token).unwrap();
        assert_eq!(&*bytes, b"backup");
        assert_eq!(&*password, "secret");
        cache.clear();
        assert!(cache.take_backup(&token).is_err());
    }

    #[test]
    fn tamper_and_expiry_fail_closed() {
        let mut cache = TransferCache::default();
        let token = cache.put_csv(b"original".to_vec()).unwrap();
        cache.entry.as_mut().unwrap().created = Instant::now() - TTL;
        assert!(cache.take_csv(&token).is_err());

        let token = cache.put_csv(b"original".to_vec()).unwrap();
        match &mut cache.entry.as_mut().unwrap().kind {
            TransferKind::Csv { bytes } => bytes[0] ^= 1,
            TransferKind::Backup { .. } => unreachable!(),
        }
        assert!(cache.take_csv(&token).is_err());
    }
}
