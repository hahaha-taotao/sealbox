use crate::mcp::McpState;
use crate::session::Session;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

static ACTIVE_SESSION: OnceLock<Mutex<Weak<Mutex<Session>>>> = OnceLock::new();
static ACTIVE_MCP: OnceLock<Mutex<Option<McpState>>> = OnceLock::new();

fn active_slot() -> &'static Mutex<Weak<Mutex<Session>>> {
    ACTIVE_SESSION.get_or_init(|| Mutex::new(Weak::new()))
}

fn active_mcp_slot() -> &'static Mutex<Option<McpState>> {
    ACTIVE_MCP.get_or_init(|| Mutex::new(None))
}

pub fn register_active_session(session: &Arc<Mutex<Session>>) {
    *recover_lock(active_slot()) = Arc::downgrade(session);
}

pub fn register_active_mcp(mcp: &McpState) {
    *recover_lock(active_mcp_slot()) = Some(mcp.clone());
}

fn sweep_mcp(mcp: &McpState) {
    mcp.close_pairing();
    crate::zoomkey::tls::clear_cache();
    crate::zoomkey::crm::clear_cache();
}

/// Pairing window and HTTP response cache belong with the DEK: any session
/// lock (idle, tray, command, Drop) must drop them even if the caller only
/// has the session mutex.
pub fn on_session_locked() {
    crate::confirm::deny_pending();
    if let Some(mcp) = recover_lock(active_mcp_slot()).as_ref() {
        sweep_mcp(mcp);
    }
}

/// Zeroize DEK, clear an owned clipboard secret, close pairing, wipe HTTP logs.
pub fn lock_everything(session: &Mutex<Session>, mcp: &McpState) {
    crate::confirm::deny_pending();
    lock_session(session).lock();
    sweep_mcp(mcp);
}

/// Idle timeout uses the same cleanup as an explicit lock.
pub fn idle_lock_if_needed(session: &mut Session, mcp: &McpState) -> bool {
    if session.maybe_idle_lock() {
        sweep_mcp(mcp);
        true
    } else {
        false
    }
}

/// Last-resort cleanup if a panic would otherwise skip `Drop` / idle lock.
/// Zeroizes the DEK (if the session Arc is still alive) and clears the
/// clipboard. Uses `try_lock` so a panic that already holds the session
/// mutex cannot deadlock the hook; poison recovery still zeroizes.
pub fn emergency_lock() {
    let weak = recover_lock(active_slot()).clone();
    if let Some(session) = weak.upgrade() {
        match session.try_lock() {
            Ok(mut g) => g.lock(),
            Err(std::sync::TryLockError::Poisoned(p)) => {
                let mut g = p.into_inner();
                g.lock();
            }
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
    }
    let _ = crate::clipboard::clear();
}

/// Recover a poisoned mutex instead of panicking. Non-secret state can keep
/// serving after a sibling thread aborted a critical section.
pub fn recover_lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Like [`recover_lock`], but a poisoned session means a thread panicked while
/// holding the DEK. Zeroize it and force a re-unlock rather than handing the
/// key to the next caller.
pub fn lock_session(m: &Mutex<Session>) -> MutexGuard<'_, Session> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => {
            let mut g = p.into_inner();
            g.lock();
            g
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;

    #[test]
    fn recovers_poisoned_mutex() {
        let m = Mutex::new(7u32);
        let _ = std::panic::catch_unwind(|| {
            let _g = m.lock().unwrap();
            panic!("boom");
        });
        assert_eq!(*recover_lock(&m), 7);
    }

    #[test]
    fn poisoned_session_zeroizes_dek() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let m = Mutex::new(session);
        let _ = std::panic::catch_unwind(|| {
            let _g = m.lock().unwrap();
            panic!("boom");
        });
        assert!(!lock_session(&m).is_unlocked());
    }

    #[test]
    fn emergency_lock_zeroizes_registered_session() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let m = Arc::new(Mutex::new(session));
        register_active_session(&m);
        assert!(lock_session(&m).is_unlocked());
        emergency_lock();
        assert!(!lock_session(&m).is_unlocked());
    }

    #[test]
    fn emergency_lock_does_not_deadlock_when_session_is_held() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        let m = Arc::new(Mutex::new(session));
        register_active_session(&m);
        let _held = lock_session(&m);
        emergency_lock();
        assert!(_held.is_unlocked());
    }

    #[test]
    fn lock_everything_locks_session_and_closes_pairing() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        session.clipboard_secs = 120;
        session.remember_clipboard("alpha");
        let m = Mutex::new(session);
        let mcp = crate::mcp::McpState::default();
        mcp.open_pairing();
        assert!(mcp.pairing_status().active);
        lock_everything(&m, &mcp);
        assert!(!lock_session(&m).is_unlocked());
        assert!(!lock_session(&m).clipboard_owned("alpha"));
        assert!(!mcp.pairing_status().active);
    }

    #[test]
    fn idle_lock_if_needed_cleans_mcp() {
        let (vault, dek) = Vault::create_in_memory("correct horse battery staple extra").unwrap();
        let mut session = Session::default();
        session.set_unlocked(vault, dek);
        session.idle_secs = 1;
        session.age_last_active(std::time::Duration::from_secs(2));
        let mcp = crate::mcp::McpState::default();
        mcp.open_pairing();
        assert!(idle_lock_if_needed(&mut session, &mcp));
        assert!(!session.is_unlocked());
        assert!(!mcp.pairing_status().active);
    }
}
