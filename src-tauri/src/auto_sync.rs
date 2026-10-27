use crate::commands::{self, AppState};
use crate::lock::lock_session;
use crate::session::Session;
use crate::sync;
use crate::vault::Vault;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};

/// Per-device schedule for the background sync. The settings are cached here so
/// the one-second tick never touches the database; only `last_run` and `running`
/// are purely in memory.
#[derive(Default)]
pub struct AutoSync {
    enabled: bool,
    secs: u64,
    last_run: Option<Instant>,
    running: bool,
}

pub fn state_of(state: &AppState) -> MutexGuard<'_, AutoSync> {
    crate::lock::recover_lock(&state.auto)
}

pub fn apply(state: &AppState, enabled: bool, secs: u64) {
    let mut auto = state_of(state);
    auto.enabled = enabled;
    auto.secs = secs.max(1);
}

pub fn refresh_from_vault(state: &AppState, vault: &Vault) {
    if let Ok(auto) = sync::auto_settings(vault) {
        apply(state, auto.enabled, auto.secs);
    }
}

/// Startup runs before anything is unlocked, and the settings live in plain
/// text, so the schedule can be known without a session.
pub fn refresh_from_disk(app: &AppHandle, state: &AppState) {
    let Ok(path) = commands::vault_path_for(app) else {
        return;
    };
    if let Ok(vault) = Vault::open(path.to_str().unwrap_or_default()) {
        refresh_from_vault(state, &vault);
    }
}

/// A run is due once the interval has passed; the first unlock runs at once.
fn is_due(last_run: Option<Instant>, now: Instant, secs: u64) -> bool {
    match last_run {
        None => true,
        Some(last) => now.saturating_duration_since(last) >= Duration::from_secs(secs.max(1)),
    }
}

/// Runs once a second from the security tick. The network round trip happens on
/// its own thread, so idle lock and clipboard cleanup keep their cadence.
pub fn tick(app: &AppHandle, state: &AppState) {
    {
        let auto = state_of(state);
        if !auto.enabled || auto.running {
            return;
        }
        if !is_due(auto.last_run, Instant::now(), auto.secs) {
            return;
        }
    }

    let session = state.session.clone();
    let dek = {
        let guard = lock_session(&session);
        if !guard.is_unlocked() {
            return;
        }
        let Ok(dek) = guard.dek() else {
            return;
        };
        *dek
    };
    let Ok(path) = commands::vault_path_for(app) else {
        return;
    };

    {
        let mut auto = state_of(state);
        if auto.running {
            return;
        }
        auto.running = true;
    }

    let handle = app.clone();
    std::thread::spawn(move || {
        // A panic here must not leave `running` stuck, or auto sync dies for the
        // rest of the session.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let state = handle
                .try_state::<AppState>()
                .ok_or_else(|| "应用状态不可用".to_string())?;
            run_once(&session, &path, &dek, &state.sync_runtime)
        }))
        .unwrap_or_else(|_| Err("自动同步异常中止".into()));

        if let Some(state) = handle.try_state::<AppState>() {
            let mut auto = state_of(&state);
            auto.running = false;
            auto.last_run = Some(Instant::now());
        }
        let payload = match &result {
            Ok(report) => serde_json::json!({ "ok": true, "error": null, "report": report }),
            Err(error) => serde_json::json!({ "ok": false, "error": error, "report": null }),
        };
        let _ = handle.emit("sync-finished", payload);
    });
}

fn run_once(
    session: &Arc<Mutex<Session>>,
    path: &PathBuf,
    dek: &[u8; 32],
    runtime: &Mutex<sync::SyncRuntime>,
) -> Result<sync::SyncReport, String> {
    if !lock_session(session).is_unlocked() {
        return Err(sync::SYNC_ABORTED.into());
    }
    let vault = Vault::open(path.to_str().unwrap_or_default()).map_err(|e| e.to_string())?;
    let still_unlocked = || lock_session(session).is_unlocked();
    // DEK was copied before this lock. Do not hold the session mutex here.
    let result = {
        let mut runtime = crate::lock::recover_lock(runtime);
        sync::sync_now_with_runtime(&mut runtime, &vault, dek, &still_unlocked)
    };
    if let Err(error) = &result {
        if error != sync::SYNC_ABORTED {
            let _ = vault.set_setting("sync_last_result", &format!("自动同步失败：{error}"));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_run_after_unlock_is_due() {
        assert!(is_due(None, Instant::now(), 60));
    }

    #[test]
    fn waits_for_the_configured_interval() {
        let now = Instant::now();
        assert!(!is_due(Some(now - Duration::from_secs(59)), now, 60));
        assert!(is_due(Some(now - Duration::from_secs(60)), now, 60));
    }

    #[test]
    fn zero_interval_cannot_spin_every_tick() {
        let now = Instant::now();
        assert!(!is_due(Some(now), now, 0));
        assert!(is_due(Some(now), now + Duration::from_secs(1), 0));
    }
}
