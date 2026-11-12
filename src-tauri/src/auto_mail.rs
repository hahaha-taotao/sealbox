//! Background mail polling.
//!
//! Mirrors [`crate::auto_sync`]: a one-second tick decides whether a run is due, and the actual
//! network work happens on its own thread so the lock/clipboard tick keeps its cadence.
//!
//! Two deliberate choices, both copied from how real mail clients behave:
//!
//! * The default interval is five minutes. QQ and 163 rate-limit logins, so a shorter one risks
//!   the account being refused rather than refreshing faster.
//! * A failing account only writes a log line. A notification for "your token expired" every
//!   five minutes is worse than a silent gap the user notices when they open the mailbox.

use crate::commands::{self, AppState};
use crate::lock::lock_session;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};

pub const DEFAULT_SECS: u64 = 300;
/// The shortest interval the settings page offers, and the floor this module enforces.
pub const MIN_SECS: u64 = 60;

#[derive(Default)]
pub struct AutoMail {
    enabled: bool,
    secs: u64,
    last_run: Option<Instant>,
    running: bool,
    /// Invalidates a completion from a run that started before the schedule changed.
    epoch: u64,
}

pub fn state_of(state: &AppState) -> std::sync::MutexGuard<'_, AutoMail> {
    crate::lock::recover_lock(&state.auto_mail)
}

/// Applies a new schedule. Disabling keeps the previous `last_run` so re-enabling does not
/// immediately fire.
pub fn apply(state: &AppState, enabled: bool, secs: u64) {
    let mut auto = state_of(state);
    let changed = auto.enabled != enabled || auto.secs != secs;
    auto.enabled = enabled;
    auto.secs = secs.max(MIN_SECS);
    if changed {
        auto.last_run = None;
        auto.epoch = auto.epoch.wrapping_add(1);
    }
}

/// The schedule lives in the vault settings, so it is read on unlock and after the settings page
/// saves.
pub fn refresh_from_vault(state: &AppState, vault: &crate::vault::Vault) {
    let secs = vault
        .get_setting("mail_auto_sync_secs")
        .ok()
        .flatten()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    apply(state, secs >= MIN_SECS, secs);
}

fn is_due(last_run: Option<Instant>, now: Instant, secs: u64) -> bool {
    match last_run {
        None => true,
        Some(last) => now.saturating_duration_since(last) >= Duration::from_secs(secs.max(MIN_SECS)),
    }
}

fn should_run(auto: &AutoMail, now: Instant) -> bool {
    auto.enabled && !auto.running && is_due(auto.last_run, now, auto.secs)
}

/// Called once a second from the existing security tick.
pub fn tick(app: &AppHandle, state: &AppState) {
    {
        let auto = state_of(state);
        if !should_run(&auto, Instant::now()) {
            return;
        }
    }
    {
        let session = lock_session(&state.session);
        // Nothing to poll while the vault is locked, and no credential to read either.
        if !session.is_unlocked() {
            return;
        }
    }

    let run_epoch = {
        let mut auto = state_of(state);
        if !should_run(&auto, Instant::now()) {
            return;
        }
        auto.running = true;
        auto.epoch
    };

    let handle = app.clone();
    std::thread::spawn(move || {
        // A panic must not leave `running` set, or polling dies for the rest of the session.
        let result: Result<commands::MailSyncReport, String> =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let state = handle.try_state::<AppState>().ok_or_else(|| "应用状态不可用".to_string())?;
                commands::mail_sync_blocking(&state)
            })) {
                Ok(Ok(report)) => Ok(report),
                Ok(Err(error)) => Err(error),
                Err(_) => Err("mail polling aborted".into()),
            };
        let report = match result {
            Ok(report) => Some(report),
            Err(error) => {
                log_line(&error);
                None
            }
        };

        if let Some(state) = handle.try_state::<AppState>() {
            let mut auto = state_of(&state);
            auto.running = false;
            if auto.epoch == run_epoch {
                auto.last_run = Some(Instant::now());
            }
        }

        if let Some(report) = report {
            notify(&handle, &report);
            let _ = handle.emit("mail-synced", &report);
        }
    });
}

fn log_line(message: &str) {
    // Never the credential and never the server's own reply: `mail_sync_blocking` already
    // reduces failures to fixed sentences.
    eprintln!("mail auto sync: {message}");
}

/// Shows one notification for the whole run rather than one per account.
///
/// While the vault is locked the text deliberately omits sender and subject: a lock screen is
/// exactly when someone else may be looking at the display.
fn notify(app: &AppHandle, report: &commands::MailSyncReport) {
    let new_total: usize = report.accounts.iter().map(|account| account.new_count).sum();
    if new_total == 0 {
        return;
    }
    let locked = !lock_session(&app.state::<AppState>().session).is_unlocked();
    let (title, body) = if locked {
        (format!("📬 印盒 · {new_total} 封新邮件"), "解锁后查看".to_string())
    } else if new_total == 1 {
        let sample = report
            .accounts
            .iter()
            .flat_map(|account| account.samples.iter())
            .next()
            .cloned()
            .unwrap_or_default();
        ("📬 印盒 · 新邮件".to_string(), sample)
    } else {
        let samples: Vec<String> = report
            .accounts
            .iter()
            .flat_map(|account| account.samples.iter())
            .take(2)
            .cloned()
            .collect();
        let mut body = samples.join("\n");
        if new_total > samples.len() {
            body.push_str(&format!("\n…等 {new_total} 封"));
        }
        (format!("📬 印盒 · {new_total} 封新邮件"), body)
    };
    use tauri_plugin_notification::NotificationExt;
    let _ = app.notification().builder().title(title).body(body).show();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_run_fires_and_then_the_interval_governs() {
        let now = Instant::now();
        assert!(is_due(None, now, DEFAULT_SECS));
        assert!(!is_due(Some(now), now, DEFAULT_SECS));
        // A clock that jumped backwards must not fire repeatedly.
        assert!(!is_due(Some(now + Duration::from_secs(60)), now, DEFAULT_SECS));
    }

    #[test]
    fn intervals_below_the_floor_are_clamped() {
        let mut auto = AutoMail { enabled: true, secs: 0, ..AutoMail::default() };
        auto.secs = MIN_SECS;
        auto.last_run = None;
        assert!(should_run(&auto, Instant::now()));
        let now = Instant::now();
        auto.last_run = Some(now - Duration::from_secs(MIN_SECS as u64 - 1));
        assert!(!should_run(&auto, now));
        auto.last_run = Some(now - Duration::from_secs(MIN_SECS as u64));
        assert!(should_run(&auto, now));
    }

    #[test]
    fn a_disabled_schedule_never_runs_and_a_running_one_is_not_restarted() {
        let auto = AutoMail { enabled: false, secs: MIN_SECS, last_run: None, running: false, epoch: 0 };
        assert!(!should_run(&auto, Instant::now()));
        let running = AutoMail { enabled: true, secs: MIN_SECS, last_run: None, running: true, epoch: 0 };
        assert!(!should_run(&running, Instant::now()));
    }
}
