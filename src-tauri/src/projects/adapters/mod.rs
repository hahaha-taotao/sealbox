//! Structured ERP / Jira read adapters for the desktop project workbench.
//!
//! These modules map ZoomKey JSON records into project DTOs. They call the
//! low-level `run_query_inner` / `retrieve_inner` / Jira GET helpers — **never**
//! scrape `ToolOutcome.text`. Desktop auth uses
//! [`crate::zoomkey::build_runtime_for_desktop`] /
//! [`crate::zoomkey::build_profile_runtime_for_desktop`] so MCP can stay off.
//!
//! ## Pointing a SourceBinding at a real profile
//!
//! 1. Create/select a vault API-Token credential with a ZoomKey CRM or Jira
//!    CredentialProfile (`adapter = zoomkey_crm` / `zoomkey_jira`, origin, mTLS
//!    or Basic + client cert + CA).
//! 2. Upsert a `SourceBinding` whose `credential_entry_id` is that vault entry
//!    id, `site` matches the profile origin, and `status = Active`.
//! 3. Do **not** use the `fixture:` credential prefix or `fixture.sealbox.local`
//!    site — those always select the offline PROJ3733 snapshot.
//! 4. Unlock the vault; project search/detail use the live adapter for real
//!    bindings. Live failures return empty/error with a warning — they do not
//!    silently fall back to the fixture.

pub mod crm;
pub mod jira;

use sealbox_core::projects::{PlatformKind, SourceBinding};

use crate::session::Session;
use crate::zoomkey::{self, EndpointRuntime, ToolFailure};

/// True for the offline PROJ3733 placeholder bindings seeded by the service.
pub(crate) fn is_fixture_binding(binding: &SourceBinding) -> bool {
    binding.credential_entry_id.starts_with("fixture:")
        || binding.site.contains("fixture.sealbox.local")
}

/// Build a desktop EndpointRuntime for a SourceBinding without requiring MCP.
///
/// Preference order:
/// 1. CredentialProfile on the binding's vault entry (desktop path, MCP-independent)
/// 2. Legacy ZoomKey policy endpoint when the binding credential matches
pub(crate) fn open_desktop_runtime(
    session: &Session,
    binding: &SourceBinding,
) -> Result<EndpointRuntime, ToolFailure> {
    if is_fixture_binding(binding) {
        return Err(ToolFailure::validation(
            "fixture SourceBinding 不能用于真实远端读取",
        ));
    }
    let label = match binding.platform {
        PlatformKind::ZoomkeyCrm => "crm",
        PlatformKind::ZoomkeyJira => "jira",
        PlatformKind::Unknown => {
            return Err(ToolFailure::validation("未知平台，无法打开远端运行时"));
        }
    };
    let vault = session
        .vault()
        .map_err(|e| ToolFailure::validation(e.to_string()))?;
    let dek = session
        .dek()
        .map_err(|e| ToolFailure::validation(e.to_string()))?;
    let cred = binding.credential_entry_id.trim();
    if cred.is_empty() {
        return Err(ToolFailure::validation("SourceBinding 缺少凭据引用"));
    }

    if let Ok(Some(profile)) = vault.credential_profile(dek, cred) {
        let expected = if label == "jira" {
            "zoomkey_jira"
        } else {
            "zoomkey_crm"
        };
        if profile.adapter == expected {
            return zoomkey::build_profile_runtime_for_desktop(session, cred, &profile);
        }
    }

    // Fall back to the ZoomKey policy binding when the credential id matches.
    let policy = zoomkey::load_policy(vault, dek);
    let policy_cred = match label {
        "jira" => policy.jira.credential_id.trim(),
        _ => policy.crm.credential_id.trim(),
    };
    if !policy_cred.is_empty() && policy_cred == cred {
        return zoomkey::build_runtime_for_desktop(session, label);
    }

    Err(ToolFailure::validation(format!(
        "凭据 {cred} 没有可用的 ZoomKey {label} Profile，也未匹配 MCP 策略凭据"
    )))
}
