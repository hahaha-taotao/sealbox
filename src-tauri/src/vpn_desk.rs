use crate::commands::{map_err, AppState};
use crate::lock::lock_session;
use crate::vault::{EntryKind, ListFilter};
use sealbox_core::vpn::{
    launch_plan, probe_clients, session_may_open, ConnectSession, KnownAccount, VpnWorkbench,
};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tauri::State;

const SETTING_KEY: &str = "vpn_workbench";
static CONNECT_ID: AtomicU64 = AtomicU64::new(0);
static CONNECT_CANCELLED: AtomicBool = AtomicBool::new(false);

#[derive(Serialize)]
pub struct VpnAccountRef {
    pub id: String,
    pub title: String,
    pub account: Option<String>,
    pub url: Option<String>,
    pub alive: bool,
}

#[derive(Serialize)]
pub struct VpnDeskView {
    pub workbench: VpnWorkbench,
    pub accounts: Vec<VpnAccountRef>,
    pub clients: Vec<sealbox_core::vpn::ClientStatus>,
    pub windows: bool,
    pub fill_mode: &'static str,
    pub fill_note: &'static str,
}

fn windows() -> bool {
    cfg!(windows)
}

fn load_workbench(vault: &crate::vault::Vault) -> VpnWorkbench {
    vault
        .get_setting(SETTING_KEY)
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

#[tauri::command]
pub fn vpn_workbench_get(state: State<AppState>) -> Result<VpnDeskView, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let workbench = load_workbench(vault);
    let entries = vault
        .list_entries(&ListFilter {
            kind: Some(EntryKind::Vpn),
            ..Default::default()
        })
        .map_err(map_err)?;
    let accounts = entries
        .into_iter()
        .map(|entry| VpnAccountRef {
            id: entry.id,
            title: entry.title,
            account: entry.account,
            url: entry.url,
            alive: true,
        })
        .collect();
    let clients = if windows() {
        probe_clients(|path| std::path::Path::new(path).is_file())
    } else {
        probe_clients(|_| false)
    };
    Ok(VpnDeskView {
        workbench,
        accounts,
        clients,
        windows: windows(),
        fill_mode: "manual",
        fill_note: "现有浏览器扩展不能把一次性授权限定到所选账号、精确标签页和 HTTPS origin，因此不自动填充或提交。请在官方登录页手动登录。",
    })
}

#[tauri::command]
pub fn vpn_workbench_save(state: State<AppState>, workbench: VpnWorkbench) -> Result<VpnWorkbench, String> {
    let raw = serde_json::to_string(&workbench).map_err(|e| e.to_string())?;
    if raw.to_ascii_lowercase().contains("password") || raw.contains("cookie") {
        return Err("入口设置不能包含密码或 Cookie".into());
    }
    let mut cleaned = VpnWorkbench {
        connections: workbench.connections,
        portals: Vec::new(),
    };
    for connection in &mut cleaned.connections {
        connection.id = connection.id.trim().to_string();
        connection.label = connection.label.trim().to_string();
        connection.gateway = connection.gateway.trim().to_string();
        if connection.id.is_empty() || connection.label.is_empty() {
            return Err("连接需要名称".into());
        }
    }
    for portal in workbench.portals {
        cleaned
            .portals
            .push(sealbox_core::vpn::normalize_portal(portal, &cleaned.connections).map_err(|err| format!("{err:?}"))?);
    }
    let stored = serde_json::to_string(&cleaned).map_err(|e| e.to_string())?;
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    session
        .vault()
        .map_err(map_err)?
        .set_setting(SETTING_KEY, &stored)
        .map_err(map_err)?;
    Ok(cleaned)
}

#[derive(Serialize)]
pub struct VpnConnectResult {
    pub session_id: u64,
    pub started: bool,
    pub message: String,
}

#[tauri::command]
pub fn vpn_connect(state: State<AppState>, connection_id: String) -> Result<VpnConnectResult, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let workbench = load_workbench(session.vault().map_err(map_err)?);
    drop(session);
    let connection = workbench
        .connections
        .into_iter()
        .find(|item| item.id == connection_id)
        .ok_or("找不到 VPN 连接")?;
    let installed = probe_clients(|path| std::path::Path::new(path).is_file())
        .into_iter()
        .find(|item| item.client == connection.client)
        .and_then(|item| item.path);
    let id = CONNECT_ID.fetch_add(1, Ordering::SeqCst) + 1;
    CONNECT_CANCELLED.store(false, Ordering::SeqCst);
    match launch_plan(&connection.client, installed.as_deref(), windows()) {
        sealbox_core::vpn::LaunchPlan::Unavailable { reason } => Ok(VpnConnectResult {
            session_id: id,
            started: false,
            message: reason,
        }),
        sealbox_core::vpn::LaunchPlan::Spawn { program } => {
            match std::process::Command::new(&program).spawn() {
                Ok(_) => Ok(VpnConnectResult {
                    session_id: id,
                    started: true,
                    message: format!("已唤起 {}。请在官方客户端完成登录，不要在此窗口输入密码。", connection.client.label()),
                }),
                Err(err) => Ok(VpnConnectResult {
                    session_id: id,
                    started: false,
                    message: format!("无法启动客户端：{err}"),
                }),
            }
        }
    }
}

#[tauri::command]
pub fn vpn_cancel(session_id: u64) -> Result<(), String> {
    if CONNECT_ID.load(Ordering::SeqCst) == session_id {
        CONNECT_CANCELLED.store(true, Ordering::SeqCst);
    }
    Ok(())
}

#[tauri::command]
pub fn vpn_finish_open(session_id: u64) -> Result<(), String> {
    let current = ConnectSession {
        id: CONNECT_ID.load(Ordering::SeqCst),
        cancelled: CONNECT_CANCELLED.load(Ordering::SeqCst),
    };
    session_may_open(session_id, &current, false).map_err(|err| err.to_string())
}

#[tauri::command]
pub fn vpn_plan(
    state: State<AppState>,
    portal_id: String,
    reachable: bool,
    explicit_switch: bool,
) -> Result<String, String> {
    let mut session = lock_session(&state.session);
    session.require_unlocked().map_err(map_err)?;
    let vault = session.vault().map_err(map_err)?;
    let workbench = load_workbench(vault);
    let portal = workbench
        .portals
        .iter()
        .find(|item| item.id == portal_id)
        .ok_or("找不到入口")?;
    let entries = vault
        .list_entries(&ListFilter {
            kind: Some(EntryKind::Vpn),
            ..Default::default()
        })
        .map_err(map_err)?;
    let accounts: Vec<KnownAccount> = portal
        .account_ids
        .iter()
        .map(|id| KnownAccount {
            id: id.clone(),
            alive: entries.iter().any(|entry| &entry.id == id),
        })
        .collect();
    let plan = sealbox_core::vpn::plan_access(portal, &accounts, reachable, explicit_switch);
    Ok(format!("{plan:?}"))
}
