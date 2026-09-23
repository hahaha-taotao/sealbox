//! 写操作的本机桌面确认。MCP 工作线程会阻塞直到用户点「允许」或「拒绝」。
//!
//! 测试默认自动放行，避免弹窗；可用 [`with_auto`] 覆盖。
//! 窗口的显示/隐藏由 [`set_hooks`] 注入，避免测试二进制链上 Tauri GUI。

use serde::Serialize;
use std::sync::{mpsc, Mutex, MutexGuard};
use std::time::Duration;

thread_local! {
    static AUTO: std::cell::Cell<i8> = const { std::cell::Cell::new(if cfg!(test) { 1 } else { 0 }) };
}

static ASK_GATE: Mutex<()> = Mutex::new(());
static PENDING: Mutex<Option<PendingConfirm>> = Mutex::new(None);
static HOOKS: Mutex<Option<ConfirmHooks>> = Mutex::new(None);

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

struct ConfirmHooks {
    show: Box<dyn Fn(&ConfirmPayload) + Send + Sync>,
    hide: Box<dyn Fn() + Send + Sync>,
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

pub fn set_hooks(
    show: impl Fn(&ConfirmPayload) + Send + Sync + 'static,
    hide: impl Fn() + Send + Sync + 'static,
) {
    *hooks() = Some(ConfirmHooks {
        show: Box::new(show),
        hide: Box::new(hide),
    });
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

pub fn respond(allow: bool) -> Result<(), String> {
    let Some(item) = pending().take() else {
        hide();
        return Err("没有待审批的操作".into());
    };
    let _ = item.tx.send(allow);
    hide();
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
    hide();
}

fn native_ask(title: &str, prompt: &str, fields: &[(&str, String)]) -> bool {
    if hooks().is_none() {
        return false;
    }
    let _gate = ASK_GATE.lock().unwrap_or_else(|e| e.into_inner());
    let (tx, rx) = mpsc::channel();
    let payload = ConfirmPayload {
        title: title.to_string(),
        prompt: prompt.to_string(),
        fields: fields
            .iter()
            .map(|(label, value)| ConfirmField {
                label: (*label).to_string(),
                value: value.clone(),
            })
            .collect(),
    };
    *pending() = Some(PendingConfirm {
        payload: payload.clone(),
        tx,
    });
    show_payload(&payload);
    let allowed = rx.recv_timeout(ASK_TIMEOUT).unwrap_or(false);
    pending().take();
    hide();
    allowed
}

fn show_payload(payload: &ConfirmPayload) {
    if let Some(hooks) = hooks().as_ref() {
        (hooks.show)(payload);
    }
}

fn hide() {
    if let Some(hooks) = hooks().as_ref() {
        (hooks.hide)();
    }
}

fn pending() -> MutexGuard<'static, Option<PendingConfirm>> {
    PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

fn hooks() -> MutexGuard<'static, Option<ConfirmHooks>> {
    HOOKS.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_allow_and_deny() {
        assert!(with_auto(Some(true), || ask("t", "m", &[])));
        assert!(!with_auto(Some(false), || ask("t", "m", &[])));
    }

    #[test]
    fn deny_pending_without_window_hooks() {
        deny_pending();
        assert!(payload().is_none());
    }
}
