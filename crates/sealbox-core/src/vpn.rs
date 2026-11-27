//! VPN 入口编排。只保存连接引用和账号 ID，不保存密码。

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnClient {
    Atrust,
    EasyConnect,
    OpenVpnConnect,
    Clash,
    Tailscale,
}

impl VpnClient {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Atrust => "aTrust",
            Self::EasyConnect => "EasyConnect",
            Self::OpenVpnConnect => "OpenVPN Connect",
            Self::Clash => "Clash",
            Self::Tailscale => "Tailscale",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnConnection {
    pub id: String,
    pub client: VpnClient,
    pub label: String,
    /// 网关或已导入配置名。不是口令。
    pub gateway: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VpnTargetKind {
    Url,
    App,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnPortal {
    pub id: String,
    pub name: String,
    pub target_kind: VpnTargetKind,
    pub target: String,
    pub connection_id: String,
    pub account_ids: Vec<String>,
    pub default_account_id: Option<String>,
    pub ask_each_time: bool,
    /// 首版不执行自动提交。字段保留，保存时强制为 false。
    pub auto_submit: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnWorkbench {
    pub connections: Vec<VpnConnection>,
    pub portals: Vec<VpnPortal>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownAccount {
    pub id: String,
    pub alive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortalError {
    EmptyName,
    BadTarget,
    MissingConnection,
    DefaultNotBound,
    DuplicateAccount,
}

pub fn normalize_portal(
    mut portal: VpnPortal,
    connections: &[VpnConnection],
) -> Result<VpnPortal, PortalError> {
    portal.name = portal.name.trim().to_string();
    portal.target = portal.target.trim().to_string();
    if portal.name.is_empty() {
        return Err(PortalError::EmptyName);
    }
    if portal.target.is_empty() || portal.target.chars().any(|c| c.is_control()) {
        return Err(PortalError::BadTarget);
    }
    if matches!(portal.target_kind, VpnTargetKind::Url) {
        let ok = portal.target.starts_with("https://") && !portal.target.contains(' ');
        if !ok {
            return Err(PortalError::BadTarget);
        }
    }
    if !connections.iter().any(|item| item.id == portal.connection_id) {
        return Err(PortalError::MissingConnection);
    }
    let mut seen = Vec::new();
    for id in portal.account_ids.drain(..) {
        let id = id.trim().to_string();
        if id.is_empty() || seen.contains(&id) {
            return Err(PortalError::DuplicateAccount);
        }
        seen.push(id);
    }
    portal.account_ids = seen;
    if let Some(default_id) = portal.default_account_id.as_deref() {
        if !portal.account_ids.iter().any(|id| id == default_id) {
            return Err(PortalError::DefaultNotBound);
        }
    }
    portal.auto_submit = false;
    Ok(portal)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessPlan {
    /// 目标已可达，且用户没有要求切换账号。
    OpenDirect,
    UseAccount(String),
    Ask,
    /// 默认账号已删除或失效，不自动改用列表中的其他账号。
    DefaultUnavailable,
    NoAccount,
}

pub fn plan_access(
    portal: &VpnPortal,
    accounts: &[KnownAccount],
    reachable: bool,
    explicit_switch: bool,
) -> AccessPlan {
    let alive: Vec<&str> = portal
        .account_ids
        .iter()
        .filter(|id| accounts.iter().any(|item| item.alive && &item.id == *id))
        .map(String::as_str)
        .collect();
    if explicit_switch {
        return if alive.is_empty() {
            AccessPlan::NoAccount
        } else {
            AccessPlan::Ask
        };
    }
    if reachable {
        return AccessPlan::OpenDirect;
    }
    if !portal.ask_each_time {
        if let Some(id) = portal.default_account_id.as_deref() {
            if portal.account_ids.iter().any(|item| item == id) && !alive.contains(&id) {
                return AccessPlan::DefaultUnavailable;
            }
        }
    }
    match alive.as_slice() {
        [] => AccessPlan::NoAccount,
        [only] => AccessPlan::UseAccount((*only).to_string()),
        _ if portal.ask_each_time => AccessPlan::Ask,
        _ => match portal.default_account_id.as_deref() {
            Some(id) if alive.contains(&id) => AccessPlan::UseAccount(id.to_string()),
            Some(_) => AccessPlan::DefaultUnavailable,
            None => AccessPlan::Ask,
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillRequest {
    pub account_id: String,
    pub account_alive: bool,
    pub account_is_vpn: bool,
    pub origin: String,
    pub expected_origin: String,
    pub tab_id: String,
    pub expected_tab_id: String,
    pub vault_unlocked: bool,
    pub grant_expired: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FillDecision {
    Deny(String),
    /// 现有扩展桥不能把一次性授权绑定到精确标签页，因此拒绝自动填充。
    ManualLogin,
}

pub fn decide_fill(request: &FillRequest) -> FillDecision {
    if !request.vault_unlocked {
        return FillDecision::Deny("密码库已锁定".into());
    }
    if request.grant_expired {
        return FillDecision::Deny("授权已过期".into());
    }
    if !request.account_is_vpn || !request.account_alive {
        return FillDecision::Deny("不是可用的 VPN 账号".into());
    }
    if request.origin != request.expected_origin || request.tab_id != request.expected_tab_id {
        return FillDecision::Deny("页面或标签页不匹配".into());
    }
    FillDecision::ManualLogin
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClientStatus {
    pub client: VpnClient,
    pub installed: bool,
    pub path: Option<String>,
}

pub fn candidate_paths(client: &VpnClient) -> &'static [&'static str] {
    match client {
        VpnClient::Atrust => &["C:\\Program Files\\aTrust\\aTrust.exe", "C:\\Program Files (x86)\\aTrust\\aTrust.exe"],
        VpnClient::EasyConnect => &[
            "C:\\Program Files\\Sangfor\\SSL\\EasyConnect\\EasyConnect.exe",
            "C:\\Program Files (x86)\\Sangfor\\SSL\\EasyConnect\\EasyConnect.exe",
        ],
        VpnClient::OpenVpnConnect => &[
            "C:\\Program Files\\OpenVPN Connect\\OpenVPNConnect.exe",
            "C:\\Program Files\\OpenVPN Technologies\\OpenVPN Client\\ovpnconnector.exe",
        ],
        VpnClient::Clash => &[
            "C:\\Program Files\\Clash for Windows\\Clash for Windows.exe",
            "C:\\Program Files\\Clash Verge\\clash-verge.exe",
        ],
        VpnClient::Tailscale => &["C:\\Program Files\\Tailscale\\tailscale-ipn.exe"],
    }
}

pub fn probe_clients(exists: impl Fn(&str) -> bool) -> Vec<ClientStatus> {
    [
        VpnClient::Atrust,
        VpnClient::EasyConnect,
        VpnClient::OpenVpnConnect,
        VpnClient::Clash,
        VpnClient::Tailscale,
    ]
    .into_iter()
    .map(|client| {
        let path = candidate_paths(&client)
            .iter()
            .copied()
            .find(|path| exists(path))
            .map(str::to_string);
        ClientStatus {
            installed: path.is_some(),
            path,
            client,
        }
    })
    .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchPlan {
    Spawn { program: String },
    Unavailable { reason: String },
}

pub fn launch_plan(client: &VpnClient, installed_path: Option<&str>, platform_windows: bool) -> LaunchPlan {
    if !platform_windows {
        return LaunchPlan::Unavailable {
            reason: "当前平台只保存 VPN 条目，不启动客户端".into(),
        };
    }
    if matches!(client, VpnClient::Tailscale) {
        return LaunchPlan::Unavailable {
            reason: "Tailscale 首版不发起连接，只保留以后接入".into(),
        };
    }
    match installed_path.map(str::trim).filter(|path| !path.is_empty()) {
        Some(program) => LaunchPlan::Spawn {
            program: program.to_string(),
        },
        None => LaunchPlan::Unavailable {
            reason: format!("未找到已安装的 {}", client.label()),
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectSession {
    pub id: u64,
    pub cancelled: bool,
}

pub fn session_may_open(current: u64, session: &ConnectSession, timed_out: bool) -> Result<(), &'static str> {
    if session.cancelled || session.id != current {
        return Err("已取消，不再打开目标");
    }
    if timed_out {
        return Err("等待超时，可在登录完成后手动打开");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn portal(accounts: &[&str], default: Option<&str>, ask: bool) -> VpnPortal {
        VpnPortal {
            id: "p".into(),
            name: "内网".into(),
            target_kind: VpnTargetKind::Url,
            target: "https://intranet.example".into(),
            connection_id: "c".into(),
            account_ids: accounts.iter().map(|s| (*s).to_string()).collect(),
            default_account_id: default.map(str::to_string),
            ask_each_time: ask,
            auto_submit: true,
        }
    }

    fn conn() -> VpnConnection {
        VpnConnection {
            id: "c".into(),
            client: VpnClient::Atrust,
            label: "办公".into(),
            gateway: "vpn.example".into(),
        }
    }

    #[test]
    fn portal_keeps_refs_and_drops_auto_submit() {
        let saved = normalize_portal(portal(&["a", "b"], Some("a"), false), &[conn()]).unwrap();
        assert!(!saved.auto_submit);
        assert!(normalize_portal(portal(&["a"], Some("b"), false), &[conn()]).is_err());
    }

    #[test]
    fn deleted_default_is_not_replaced() {
        let item = portal(&["gone", "other"], Some("gone"), false);
        let accounts = vec![
            KnownAccount { id: "gone".into(), alive: false },
            KnownAccount { id: "other".into(), alive: true },
        ];
        assert_eq!(
            plan_access(&item, &accounts, false, false),
            AccessPlan::DefaultUnavailable
        );
        assert_eq!(
            plan_access(&item, &accounts, true, false),
            AccessPlan::OpenDirect
        );
        assert_eq!(plan_access(&item, &accounts, true, true), AccessPlan::Ask);
    }

    #[test]
    fn fill_never_auto_submits_without_tab_binding() {
        let request = FillRequest {
            account_id: "a".into(),
            account_alive: true,
            account_is_vpn: true,
            origin: "https://vpn.example".into(),
            expected_origin: "https://vpn.example".into(),
            tab_id: "1".into(),
            expected_tab_id: "1".into(),
            vault_unlocked: true,
            grant_expired: false,
        };
        assert_eq!(decide_fill(&request), FillDecision::ManualLogin);
        let mut wrong = request.clone();
        wrong.origin = "https://vpn.example:8443".into();
        assert!(matches!(decide_fill(&wrong), FillDecision::Deny(_)));
        wrong = request.clone();
        wrong.account_is_vpn = false;
        assert!(matches!(decide_fill(&wrong), FillDecision::Deny(_)));
        wrong = request;
        wrong.vault_unlocked = false;
        assert!(matches!(decide_fill(&wrong), FillDecision::Deny(_)));
    }

    #[test]
    fn launch_uses_fixed_program_only() {
        assert!(matches!(
            launch_plan(&VpnClient::Atrust, Some("C:\\aTrust.exe"), true),
            LaunchPlan::Spawn { program } if program == "C:\\aTrust.exe"
        ));
        assert!(matches!(
            launch_plan(&VpnClient::Tailscale, Some("C:\\tailscale.exe"), true),
            LaunchPlan::Unavailable { .. }
        ));
        assert!(matches!(
            launch_plan(&VpnClient::Clash, None, false),
            LaunchPlan::Unavailable { .. }
        ));
        let found = probe_clients(|path| path.ends_with("aTrust.exe"));
        assert!(found.iter().any(|item| item.client == VpnClient::Atrust && item.installed));
        assert!(found.iter().any(|item| item.client == VpnClient::Clash && !item.installed));
    }

    #[test]
    fn cancelled_session_does_not_open() {
        let session = ConnectSession { id: 1, cancelled: true };
        assert!(session_may_open(1, &session, false).is_err());
        let next = ConnectSession { id: 2, cancelled: false };
        assert!(session_may_open(3, &next, false).is_err());
        assert!(session_may_open(2, &next, true).is_err());
        assert!(session_may_open(2, &next, false).is_ok());
    }
}
