pub mod backup;
pub mod clipboard;
pub mod commands;
pub mod crypto;
pub mod db;
pub mod fill;
pub mod hello;
pub mod http_guard;
pub mod lock;
pub mod mcp;
pub mod passphrase_words;
pub mod redact;
pub mod session;
pub mod totp;
pub mod vault;

use commands::AppState;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(lock::emergency_lock));
        default_hook(info);
    }));
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::home_overview,
            commands::setup_vault,
            commands::unlock_vault,
            commands::unlock_hello,
            commands::lock_vault,
            commands::list_entries,
            commands::create_entry,
            commands::update_entry,
            commands::delete_entries,
            commands::restore_entries,
            commands::empty_trash,
            commands::pin_entry,
            commands::list_folders,
            commands::create_folder,
            commands::list_tags,
            commands::list_audit,
            commands::copy_secret,
            commands::reveal_secret,
            commands::get_notes,
            commands::tick_idle,
            commands::gen_password,
            commands::export_backup,
            commands::import_backup,
            commands::settings_get,
            commands::settings_set,
            commands::set_hello_enabled,
            commands::change_master,
            commands::mcp_status,
            commands::mcp_start,
            commands::mcp_stop,
            commands::mcp_rotate_token,
            commands::fill_rotate_token,
            commands::reveal_mcp_token,
            commands::reveal_fill_token,
            commands::copy_mcp_token,
            commands::copy_fill_token,
            commands::copy_mcp_snippet,
            commands::fill_open_pairing,
            commands::fill_pairing_status,
            commands::mcp_http_logs,
            commands::mcp_tools,
            commands::window_control,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let _ = handle.emit("tick", ());
            });
            let show = MenuItem::with_id(app, "show", "打开", true, None::<&str>)?;
            let lock = MenuItem::with_id(app, "lock", "锁定", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &lock, &quit])?;
            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().cloned().unwrap())
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "lock" => {
                        if let Some(state) = app.try_state::<AppState>() {
                            lock::lock_everything(&state.session, &state.mcp);
                        }
                        let _ = app.emit("lock-now", ());
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;
            let _ = commands::register_hotkey(app.handle(), "Ctrl+Shift+Space");
            if let Some(state) = app.try_state::<AppState>() {
                let _ = mcp::start(&state.mcp, state.session.clone());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
            if window.label() == "quick" {
                if let tauri::WindowEvent::Focused(false) = event {
                    let win = window.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_millis(160));
                        if !win.is_focused().unwrap_or(true) {
                            let _ = win.hide();
                        }
                    });
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
