//! Desktop project workbench: Tauri commands + service over sealbox-core storage.
//!
//! Remote ERP/Jira reads prefer structured ZoomKey adapters ([`adapters`]) when a
//! real SourceBinding / profile is available. Fixture PROJ3733 remains the
//! offline fallback ([`fixture`]).

pub mod adapters;
pub mod commands;
pub mod dto;
pub mod fixture;
pub mod service;

pub use commands::*;
pub use service::clear_session_cache;
