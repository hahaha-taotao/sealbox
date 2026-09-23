//! 写操作的本机桌面确认。MCP 工作线程会阻塞直到用户点「是」或「否」。
//!
//! 测试默认自动放行，避免弹窗；可用 [`with_auto`] 覆盖。

use std::cell::Cell;

thread_local! {
    static AUTO: Cell<i8> = const { Cell::new(if cfg!(test) { 1 } else { 0 }) };
}

/// `None` 走系统对话框；`Some(true)` 放行；`Some(false)` 拒绝。
pub fn with_auto<T>(allow: Option<bool>, f: impl FnOnce() -> T) -> T {
    AUTO.with(|slot| {
        let previous = slot.get();
        slot.set(match allow {
            None => 0,
            Some(true) => 1,
            Some(false) => -1,
        });
        let result = f();
        slot.set(previous);
        result
    })
}

pub fn ask(title: &str, message: &str) -> bool {
    match AUTO.with(Cell::get) {
        1 => return true,
        n if n < 0 => return false,
        _ => {}
    }
    native_ask(title, message)
}

#[cfg(windows)]
fn native_ask(title: &str, message: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_ICONWARNING, MB_SETFOREGROUND, MB_TASKMODAL, MB_TOPMOST, MB_YESNO,
    };

    let title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let message: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    let result = unsafe {
        MessageBoxW(
            HWND(std::ptr::null_mut()),
            PCWSTR(message.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_YESNO | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND | MB_TASKMODAL,
        )
    };
    result == IDYES
}

#[cfg(not(windows))]
fn native_ask(_title: &str, _message: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_allow_and_deny() {
        assert!(with_auto(Some(true), || ask("t", "m")));
        assert!(!with_auto(Some(false), || ask("t", "m")));
    }
}
