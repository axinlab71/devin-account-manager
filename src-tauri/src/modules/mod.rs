pub mod account;
pub mod account_index_repair;
pub mod atomic_write;
pub mod auth_transport;
pub mod client_version;
pub mod cockpit_migration;
pub mod config;
pub mod deferred_account_rewrite;
pub mod key_protection;
pub mod logger;
pub mod oauth_pending_state;
pub mod official_browser_login;
pub mod process;
pub mod secure_account_storage;
pub mod windows_operation;
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
