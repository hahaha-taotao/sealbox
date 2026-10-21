mod clipboard;
mod commands;
mod session;
mod update;

#[cfg(test)]
mod tests {
    #[test]
    fn newer_version_compares_numeric_parts() {
        assert!(crate::update::version_newer("0.1.2", "0.1.1"));
        assert!(crate::update::version_newer("0.2.0", "0.1.9"));
        assert!(!crate::update::version_newer("0.1.1", "0.1.1"));
        assert!(!crate::update::version_newer("0.1.0", "0.1.1"));
        assert!(crate::update::version_newer("1.0", "0.9.9"));
    }
}

use tauri::{Emitter, Manager};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_biometry::init())
        .plugin(tauri_plugin_opener::init())
        .manage(commands::AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::setup_vault,
            commands::unlock_vault,
            commands::unlock_with_dek,
            commands::export_dek,
            commands::set_biometry_enabled,
            commands::lock_vault,
            commands::tick_idle,
            commands::list_entries,
            commands::list_counts,
            commands::list_folders,
            commands::create_folder,
            commands::rename_folder,
            commands::delete_folder,
            commands::list_tags,
            commands::create_entry,
            commands::delete_entries,
            commands::restore_entries,
            commands::empty_trash,
            commands::pin_entry,
            commands::copy_secret,
            commands::reveal_secret,
            commands::get_notes,
            commands::settings_get,
            commands::settings_set,
            commands::sync_status,
            commands::sync_save,
            commands::sync_clear,
            commands::sync_now,
            commands::app_version,
            commands::check_mobile_update,
            commands::download_mobile_update,
            commands::install_mobile_update,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let locked = {
                    let Some(state) = handle.try_state::<commands::AppState>() else {
                        continue;
                    };
                    commands::tick_idle(state).unwrap_or(false)
                };
                if locked {
                    let _ = handle.emit("lock-now", ());
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Sealbox mobile");
}
