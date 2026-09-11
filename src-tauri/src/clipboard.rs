use arboard::Clipboard;

pub fn write_text(text: &str) -> Result<(), String> {
    let mut cb = Clipboard::new().map_err(|e| e.to_string())?;
    cb.set_text(text.to_string()).map_err(|e| e.to_string())
}

pub fn read_text() -> Result<String, String> {
    let mut cb = Clipboard::new().map_err(|e| e.to_string())?;
    cb.get_text().map_err(|e| e.to_string())
}

pub fn clear() -> Result<(), String> {
    write_text("")
}
