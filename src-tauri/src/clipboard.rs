use arboard::Clipboard;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

fn clipboard_mutex() -> &'static Mutex<()> {
    static M: OnceLock<Mutex<()>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(()))
}

fn with_clipboard<T>(mut f: impl FnMut(&mut Clipboard) -> Result<T, String>) -> Result<T, String> {
    let _guard = clipboard_mutex().lock().unwrap_or_else(|e| e.into_inner());
    let mut last = String::from("clipboard error");
    for attempt in 0..8u32 {
        match Clipboard::new() {
            Ok(mut cb) => match f(&mut cb) {
                Ok(value) => return Ok(value),
                Err(e) => last = e,
            },
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(Duration::from_millis(15 * u64::from(attempt + 1)));
    }
    Err(last)
}

pub fn write_text(text: &str) -> Result<(), String> {
    with_clipboard(|cb| cb.set_text(text.to_string()).map_err(|e| e.to_string()))
}

pub fn read_text() -> Result<String, String> {
    with_clipboard(|cb| cb.get_text().map_err(|e| e.to_string()))
}

pub fn clear() -> Result<(), String> {
    write_text("")
}
