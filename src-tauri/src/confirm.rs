//! 写操作的本机桌面确认。MCP 工作线程会阻塞直到用户点「允许」或「拒绝」。
//!
//! 测试默认自动放行，避免弹窗；可用 [`with_auto`] 覆盖。

use serde::Serialize;
use std::sync::{mpsc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

thread_local! {
    static AUTO: std::cell::Cell<i8> = const { std::cell::Cell::new(if cfg!(test) { 1 } else { 0 }) };
}

static APP: OnceLock<AppHandle> = OnceLock::new();
static ASK_GATE: Mutex<()> = Mutex::new(());
static PENDING: Mutex<Option<PendingConfirm>> = Mutex::new(None);

const WINDOW: &str = "confirm";
const ASK_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Clone, Serialize)]
pub struct ConfirmField {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Serialize)]
pub struct ConfirmPayload {
    pub title: String,
    pub prompt: String,
    pub fields: Vec<ConfirmField>,
}

struct PendingConfirm {
    payload: ConfirmPayload,
    tx: mpsc::Sender<bool>,
}

/// `None` 走桌面确认窗；`Some(true)` 放行；`Some(false)` 拒绝。
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

pub fn set_app(app: AppHandle) {
    let _ = APP.set(app);
}

pub fn ask(title: &str, prompt: &str, fields: &[(&str, String)]) -> bool {
    match AUTO.with(std::cell::Cell::get) {
        1 => return true,
        n if n < 0 => return false,
        _ => {}
    }
    native_ask(title, prompt, fields)
}

pub fn payload() -> Option<ConfirmPayload> {
    pending().as_ref().map(|item| item.payload.clone())
}

pub fn respond(app: &AppHandle, allow: bool) -> Result<(), String> {
    let Some(item) = pending().take() else {
        hide_window(app);
        return Err("没有待审批的操作".into());
    };
    let _ = item.tx.send(allow);
    hide_window(app);
    Ok(())
}

pub fn on_window_closed() {
    if let Some(item) = pending().take() {
        let _ = item.tx.send(false);
    }
}

pub fn deny_pending() {
    if let Some(item) = pending().take() {
        let _ = item.tx.send(false);
    }
    if let Some(app) = APP.get() {
        hide_window(app);
    }
}

fn native_ask(title: &str, prompt: &str, fields: &[(&str, String)]) -> bool {
    let Some(app) = APP.get() else {
        return false;
    };
    if app.get_webview_window(WINDOW).is_none() {
        return false;
    }
    let _gate = ASK_GATE.lock().unwrap_or_else(|e| e.into_inner());
    let (tx, rx) = mpsc::channel();
    *pending() = Some(PendingConfirm {
        payload: ConfirmPayload {
            title: title.to_string(),
            prompt: prompt.to_string(),
            fields: fields
                .iter()
                .map(|(label, value)| ConfirmField {
                    label: (*label).to_string(),
                    value: value.clone(),
                })
                .collect(),
        },
        tx,
    });
    show_window(app);
    let allowed = rx.recv_timeout(ASK_TIMEOUT).unwrap_or(false);
    pending().take();
    hide_window(app);
    allowed
}

fn show_window(app: &AppHandle) {
    let payload = pending().as_ref().map(|item| item.payload.clone());
    if let Some(payload) = payload {
        let _ = app.emit_to(WINDOW, "confirm-open", payload);
    }
    if let Some(win) = app.get_webview_window(WINDOW) {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_always_on_top(true);
        let _ = win.set_focus();
    }
}

fn hide_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window(WINDOW) {
        let _ = win.hide();
    }
}

fn pending() -> MutexGuard<'static, Option<PendingConfirm>> {
    PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_allow_and_deny() {
        assert!(with_auto(Some(true), || ask("t", "m", &[])));
        assert!(!with_auto(Some(false), || ask("t", "m", &[])));
    }
}
