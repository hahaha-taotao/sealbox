//! OS-backed storage for the optional automatic-unlock DEK.
//!
//! The master password never reaches this module.  On Windows the DEK is kept
//! in the current user's Credential Manager as a generic credential.  Other
//! desktop targets keep the safe, fail-closed behavior (no persisted key) until
//! a native keychain backend is provided.

const TARGET: &str = "Sealbox/auto-unlock-dek/v1";

/// Read the persisted DEK, if this platform has a supported secure store.
pub fn load_dek() -> Result<Option<[u8; 32]>, String> {
    #[cfg(windows)]
    {
        return windows_store::load();
    }

    #[cfg(not(windows))]
    {
        Ok(None)
    }
}

/// Persist only the DEK.  Unsupported targets deliberately degrade to a
/// session-only unlock rather than writing a plaintext fallback.
pub fn save_dek(dek: &[u8; 32]) -> Result<(), String> {
    #[cfg(windows)]
    {
        return windows_store::save(dek);
    }

    #[cfg(not(windows))]
    {
        let _ = dek;
        Ok(())
    }
}

/// Remove any persisted DEK.  Missing credentials are treated as success.
pub fn clear_dek() -> Result<(), String> {
    #[cfg(windows)]
    {
        return windows_store::clear();
    }

    #[cfg(not(windows))]
    {
        Ok(())
    }
}

#[cfg(windows)]
mod windows_store {
    use super::TARGET;
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use std::slice;
    use windows::core::PCWSTR;
    use windows::Win32::Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS,
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(super) fn load() -> Result<Option<[u8; 32]>, String> {
        let target = wide(TARGET);
        let mut raw = null_mut();
        // SAFETY: CredReadW initializes `raw` to an owned CREDENTIALW pointer;
        // it is released with CredFree on every successful read.
        let found = unsafe {
            CredReadW(
                PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                0,
                &mut raw,
            )
        };
        if found.is_err() {
            return Ok(None);
        }
        if raw.is_null() {
            return Ok(None);
        }
        let result = unsafe {
            let credential = &*raw;
            let size = credential.CredentialBlobSize as usize;
            if credential.CredentialBlob.is_null() || size != 32 {
                None
            } else {
                let bytes = slice::from_raw_parts(credential.CredentialBlob, size);
                let mut dek = [0u8; 32];
                dek.copy_from_slice(bytes);
                Some(dek)
            }
        };
        // SAFETY: `raw` was allocated by CredReadW.
        unsafe { CredFree(raw as *const c_void) };
        if result.is_none() {
            // A malformed credential must not remain available for a future
            // restore attempt; the next launch should ask for the password.
            let _ = clear();
        }
        Ok(result)
    }

    pub(super) fn save(dek: &[u8; 32]) -> Result<(), String> {
        let target = wide(TARGET);
        let mut credential = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: windows::core::PWSTR(target.as_ptr() as *mut u16),
            Comment: windows::core::PWSTR(null_mut()),
            LastWritten: Default::default(),
            CredentialBlobSize: dek.len() as u32,
            CredentialBlob: dek.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: null_mut(),
            TargetAlias: windows::core::PWSTR(null_mut()),
            UserName: windows::core::PWSTR(null_mut()),
        };
        // SAFETY: all pointers reference data valid for the duration of the
        // synchronous CredWriteW call; the credential blob is exactly 32 bytes.
        unsafe { CredWriteW(&mut credential, 0).map_err(|e| e.to_string()) }
    }

    pub(super) fn clear() -> Result<(), String> {
        let target = wide(TARGET);
        // SAFETY: target is a NUL-terminated UTF-16 string valid for this call.
        let result = unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, 0) };
        if result.is_err() {
            // Credential Manager reports ERROR_NOT_FOUND when already absent;
            // clearing is idempotent and should not block a password unlock.
            return Ok(());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_platform_never_persists_a_plaintext_key() {
        #[cfg(not(windows))]
        {
            let dek = [7u8; 32];
            save_dek(&dek).unwrap();
            assert_eq!(load_dek().unwrap(), None);
            clear_dek().unwrap();
        }
    }
}
