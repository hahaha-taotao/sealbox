//! 写操作的本机桌面确认。默认放行；只有标记为 `dangerous` 的破坏性写操作才弹窗，
//! MCP 工作线程会阻塞直到用户点「允许」或「拒绝」。
//!
//! 测试默认自动放行，避免弹窗；可用 [`with_auto`] 覆盖。
//! 窗口的显示/隐藏由 [`set_hooks`] 注入，避免测试二进制链上 Tauri GUI。

use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex, MutexGuard};
use std::time::Duration;

thread_local! {
    static AUTO: std::cell::Cell<i8> = const { std::cell::Cell::new(if cfg!(test) { 1 } else { 0 }) };
}

static ASK_GATE: Mutex<()> = Mutex::new(());
static PENDING: Mutex<Option<PendingConfirm>> = Mutex::new(None);
static HOOKS: Mutex<Option<ConfirmHooks>> = Mutex::new(None);

/// True while the main window is hidden to the tray, minimised, or not focused.
/// A confirmation prompt is easy to miss in that state, so its wait window is
/// extended instead of expiring while the user is away from the app.
static MAIN_WINDOW_HIDDEN: AtomicBool = AtomicBool::new(false);

const ASK_TIMEOUT: Duration = Duration::from_secs(600);
const ASK_TIMEOUT_WHILE_HIDDEN: Duration = Duration::from_secs(1800);

/// How long a prompt waits for an answer. Exposed for tests.
pub fn ask_timeout(main_window_hidden: bool) -> Duration {
    if main_window_hidden {
        ASK_TIMEOUT_WHILE_HIDDEN
    } else {
        ASK_TIMEOUT
    }
}

/// Set by the window event handler whenever the main window's visibility or
/// focus changes. Cheap and lock-free: the confirmation thread reads it once
/// per prompt, not per tick.
pub fn set_main_window_hidden(hidden: bool) {
    MAIN_WINDOW_HIDDEN.store(hidden, Ordering::SeqCst);
}

pub fn main_window_hidden() -> bool {
    MAIN_WINDOW_HIDDEN.load(Ordering::SeqCst)
}

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
    /// 破坏性写操作才弹窗确认；普通写操作默认放行。
    #[serde(default)]
    pub dangerous: bool,
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
    ask_payload(&ConfirmPayload {
        title: title.to_string(),
        prompt: prompt.to_string(),
        fields: fields
            .iter()
            .map(|(label, value)| ConfirmField {
                label: (*label).to_string(),
                value: value.clone(),
            })
            .collect(),
        dangerous: false,
    })
}

/// Run `prepare` while the session mutex is held, then wait for desktop
/// confirmation after that mutex has been released.
pub fn after_prepare<T, E: From<String>>(
    prepare: impl FnOnce() -> Result<(T, ConfirmPayload), E>,
) -> Result<T, E> {
    let (value, payload) = prepare()?;
    if ask_payload(&payload) {
        Ok(value)
    } else {
        Err(E::from("用户拒绝了这次写操作".into()))
    }
}

pub fn ask_payload(payload: &ConfirmPayload) -> bool {
    match AUTO.with(std::cell::Cell::get) {
        1 => return true,
        n if n < 0 => return false,
        _ => {}
    }
    if !payload.dangerous {
        return true;
    }
    native_ask_payload(payload.clone())
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

fn native_ask_payload(payload: ConfirmPayload) -> bool {
    if hooks().is_none() {
        return false;
    }
    let _gate = ASK_GATE.lock().unwrap_or_else(|e| e.into_inner());
    let (tx, rx) = mpsc::channel();
    *pending() = Some(PendingConfirm {
        payload: payload.clone(),
        tx,
    });
    show_payload(&payload);
    // Read the visibility at prompt time: the user may have opened the app to
    // answer, and a prompt raised while hidden must not expire early.
    let allowed = rx
        .recv_timeout(ask_timeout(main_window_hidden()))
        .unwrap_or(false);
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

    #[test]
    fn after_prepare_denies_without_running_work() {
        let result: Result<i32, String> = with_auto(Some(false), || {
            after_prepare(|| {
                Ok((
                    42,
                    ConfirmPayload {
                        title: "t".into(),
                        prompt: "m".into(),
                        fields: Vec::new(),
                        dangerous: false,
                    },
                ))
            })
        });
        assert_eq!(result, Err("用户拒绝了这次写操作".to_string()));
    }

    #[test]
    fn hidden_main_window_gets_a_longer_prompt_window() {
        assert_eq!(ask_timeout(false), Duration::from_secs(600));
        assert_eq!(ask_timeout(true), Duration::from_secs(1800));
        assert!(ask_timeout(true) > ask_timeout(false));
    }

    #[test]
    fn main_window_visibility_is_tracked() {
        // Restore the process-wide flag so a failure here cannot leak into
        // other tests that run in the same binary.
        let previous = main_window_hidden();
        set_main_window_hidden(true);
        assert!(main_window_hidden());
        set_main_window_hidden(false);
        assert!(!main_window_hidden());
        set_main_window_hidden(previous);
    }
}
