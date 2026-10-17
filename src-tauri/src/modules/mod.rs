pub mod account;
pub mod app_instance;
pub mod account_identity;
pub mod account_index_repair;
pub mod account_selector;
pub mod account_view;
pub mod atomic_write;
pub mod auth_compatibility;
pub mod auth_endpoint;
pub mod auth_transport;
pub mod client_recovery;
pub mod client_version;
pub mod cockpit_migration;
pub mod config;
pub mod connection_diagnostics;
pub mod deferred_account_rewrite;
pub mod key_protection;
pub mod logger;
pub mod native_switch;
pub mod oauth_pending_state;
pub mod official_browser_login;
pub mod process;
pub mod quota_monitor;
pub mod rotation_policy;
pub mod rotation_state;
pub mod switch_adapter;
pub mod secure_account_storage;
pub mod windows_operation;
pub mod client_support;
pub mod account_export;
pub mod windsurf_account;
pub mod windsurf_devin_oauth;
pub mod windsurf_instance;
pub mod windsurf_oauth;

#[cfg(test)]
pub mod test_support {
    pub fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        &LOCK
    }
}
