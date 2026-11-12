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

/// Ask Windows not to record the next clipboard write in clipboard history
/// (Win+V) or sync it to the user's Microsoft account.
///
/// `arboard` writes plain text with no format opt-out, so a copied password
/// stays readable in the history list and in the cloud long after the 20-second
/// sweep empties the live clipboard. Windows exposes this as two registered
/// clipboard formats carrying a DWORD; setting `1` marks the write as private.
#[cfg(windows)]
fn exclude_from_history() {
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HANDLE, HWND};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    // Formats documented for clipboard history exclusion.
    const FORMATS: [&str; 2] = [
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
    ];
    let wide: Vec<Vec<u16>> = FORMATS
        .iter()
        .map(|name| name.encode_utf16().chain(std::iter::once(0)).collect())
        .collect();
    unsafe {
        if OpenClipboard(std::ptr::null_mut::<c_void>() as HWND).is_err() {
            return;
        }
        for slot in &wide {
            let Ok(format) = RegisterClipboardFormatW(PCWSTR(slot.as_ptr())) else {
                continue;
            };
            if format == 0 {
                continue;
            }
            // Private memory block owned by the clipboard after SetClipboardData.
            let Ok(ptr) = GlobalAlloc(GMEM_MOVEABLE, std::mem::size_of::<u32>()) else {
                continue;
            };
            let locked = GlobalLock(ptr) as *mut u32;
            if locked.is_null() {
                let _ = windows::Win32::Foundation::GlobalFree(ptr);
                continue;
            }
            *locked = 1;
            let _ = GlobalUnlock(ptr);
            if SetClipboardData(format, HANDLE(ptr.0)).is_err() {
                let _ = windows::Win32::Foundation::GlobalFree(ptr);
            }
        }
        let _ = CloseClipboard();
    }
}

#[cfg(not(windows))]
fn exclude_from_history() {}

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
            cb.set_text(text.to_string()).map_err(|e| e.to_string())?;
            // Mark right after the write: history exclusion applies to the
            // content currently on the clipboard.
            exclude_from_history();
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
