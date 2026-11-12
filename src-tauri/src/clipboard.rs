use arboard::Clipboard;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

fn clipboard_mutex() -> &'static Mutex<()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
}

fn with_clipboard<T>(mut f: impl FnMut(&mut Clipboard) -> Result<T, String>) -> Result<T, String> {
    let _guard = clipboard_mutex().lock().unwrap_or_else(|e| e.into_inner());
    retrying(f, 8)
}

/// Open the clipboard and run `f` while holding the process-wide clipboard
/// lock. Retries because another process can hold the clipboard open for a
/// few tens of milliseconds at a time.
fn retrying<T>(mut f: impl FnMut(&mut Clipboard) -> Result<T, String>, attempts: u32) -> Result<T, String> {
    let mut last = String::from("clipboard error");
    for attempt in 0..attempts {
        match Clipboard::new() {
            Ok(mut cb) => match f(&mut cb) {
                Ok(value) => return Ok(value),
                Err(e) => last = e,
            },
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(Duration::from_millis(20 * u64::from(attempt + 1)));
    }
    Err(last)
}

/// Write `text` to the clipboard while telling Windows not to archive it.
///
/// `arboard` writes plain text with no format opt-out, so a copied password
/// stays readable in clipboard history (Win+V) and in the user's Microsoft
/// account long after the 20-second sweep empties the live clipboard. Windows
/// exposes this as two registered clipboard formats carrying a DWORD; setting
/// `1` marks the write as private.
///
/// All formats must go into the *same* clipboard session: `SetClipboardData`
/// empties the clipboard on every call, so writing the text first and then
/// adding the exclusion formats would delete the text. Returns `false` when
/// this platform cannot do it, so the caller falls back to `arboard`.
#[cfg(windows)]
fn write_text_private(text: &str) -> bool {
    use std::ffi::c_void;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    /// Formats documented for clipboard history exclusion.
    const PRIVATE_FORMATS: [&str; 2] = [
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
    ];

    /// Copy `bytes` into a moveable global block the clipboard can own.
    unsafe fn owned_block(bytes: &[u8]) -> Option<HGLOBAL> {
        let handle = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1)).ok()?;
        let dest = GlobalLock(handle) as *mut u8;
        if dest.is_null() {
            let _ = GlobalFree(handle);
            return None;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dest, bytes.len());
        let _ = GlobalUnlock(handle);
        Some(handle)
    }

    let utf16: Vec<u16> = text.encode_utf16().collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    let names: Vec<Vec<u16>> = PRIVATE_FORMATS
        .iter()
        .map(|name| name.encode_utf16().chain(std::iter::once(0)).collect())
        .collect();

    unsafe {
        if OpenClipboard(HWND(std::ptr::null_mut::<c_void>())).is_err() {
            return false;
        }
        let mut ok = false;
        if EmptyClipboard().is_ok() {
            if let Some(handle) = owned_block(&bytes) {
                if SetClipboardData(u32::from(CF_UNICODETEXT.0), HANDLE(handle.0)).is_ok() {
                    ok = true;
                } else {
                    let _ = GlobalFree(handle);
                }
            }
            // A failure here only costs history protection, not the copy.
            if ok {
                for name in &names {
                    let format = RegisterClipboardFormatW(PCWSTR(name.as_ptr()));
                    if format == 0 {
                        continue;
                    }
                    if let Some(handle) = owned_block(&1u32.to_le_bytes()) {
                        if SetClipboardData(format, HANDLE(handle.0)).is_err() {
                            let _ = GlobalFree(handle);
                        }
                    }
                }
            }
        }
        let _ = CloseClipboard();
        ok
    }
}

#[cfg(not(windows))]
fn write_text_private(_text: &str) -> bool {
    false
}

/// Write `text` and read it back before reporting success.
///
/// `arboard::set_text` can return `Ok` while the content never reaches the
/// clipboard: on Windows another process holding the clipboard open makes the
/// write silently a no-op. The UI would then say "已复制" while the user pastes
/// a stale value — possibly a different secret. Verifying the read-back is the
/// only way to know the copy actually happened, so a mismatch is an error.
pub fn write_text(text: &str) -> Result<(), String> {
    let _guard = clipboard_mutex().lock().unwrap_or_else(|e| e.into_inner());
    let written = retrying(
        |cb| {
            // Windows writes every format in one clipboard session so the
            // history opt-out cannot erase the text it accompanies.
            if !write_text_private(text) {
                cb.set_text(text.to_string()).map_err(|e| e.to_string())?;
            }
            match cb.get_text() {
                Ok(read_back) if read_back == text => Ok(()),
                Ok(_) => Err("剪贴板内容与写入的不一致".to_string()),
                Err(e) => Err(format!("剪贴板回读失败：{e}")),
            }
        },
        6,
    );
    written.map_err(|e| format!("{e}（剪贴板可能正被其他程序占用，请稍后重试）"))
}

pub fn read_text() -> Result<String, String> {
    with_clipboard(|cb| cb.get_text().map_err(|e| e.to_string()))
}

/// Clearing is best-effort: a clipboard held open by another process must not
/// turn the security sweep into a hard error.
pub fn clear() -> Result<(), String> {
    with_clipboard(|cb| {
        cb.set_text(String::new()).map_err(|e| e.to_string())?;
        Ok(())
    })
}

/// 测试里会真实读写系统剪贴板，必须串行执行，否则并行测试互相覆盖剪贴板内容会随机失败。
#[cfg(test)]
pub(crate) fn test_clipboard_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clipboard_available() -> bool {
        with_clipboard(|cb| cb.get_text().map_err(|e| e.to_string())).is_ok()
    }

    #[test]
    fn write_text_verifies_the_read_back() {
        let _guard = test_clipboard_lock();
        if !clipboard_available() {
            return;
        }
        let marker = format!("sealbox-clipboard-test-{}", std::process::id());
        write_text(&marker).expect("write should pass the read-back check");
        assert_eq!(read_text().unwrap(), marker);
        let _ = clear();
    }

    #[test]
    fn clear_empties_the_clipboard() {
        let _guard = test_clipboard_lock();
        if !clipboard_available() {
            return;
        }
        write_text("sealbox-clear-test").unwrap();
        clear().unwrap();
        assert_eq!(read_text().unwrap_or_default(), "");
    }
}
