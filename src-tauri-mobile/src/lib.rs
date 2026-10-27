mod auto_sync;
mod clipboard;
mod commands;
mod session;
mod saf;
mod transfer;
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
        .plugin(saf::init())
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
            commands::merge_folders,
            commands::delete_folder,
            commands::list_tags,
            commands::rename_tag,
            commands::delete_tag,
            commands::merge_tags,
            commands::create_entry,
            commands::delete_entries,
            commands::restore_entries,
            commands::empty_trash,
            commands::pin_entry,
            commands::copy_secret,
            commands::reveal_secret,
            commands::get_notes,
            commands::entry_profile,
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
            commands::document_open,
            commands::document_save,
            commands::backup_inspect,
            commands::backup_restore,
            commands::backup_restore_new,
            commands::backup_export,
            commands::csv_preview,
            commands::csv_commit,
            commands::csv_export,
            commands::change_master,
            commands::import_client_cert,
            commands::sync_preview,
            commands::sync_commit,
            commands::sync_verify_conditional,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            if let Some(state) = handle.try_state::<commands::AppState>() {
                auto_sync::refresh_from_disk(&handle, &state);
            }
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let locked = {
                    let Some(state) = handle.try_state::<commands::AppState>() else {
                        continue;
                    };
                    auto_sync::tick(&handle, &state);
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
