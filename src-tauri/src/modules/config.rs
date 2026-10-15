use serde::{Deserialize, Serialize};
use std::sync::Mutex;
static LOCK: Mutex<()> = Mutex::new(());

#[derive(Default, Serialize, Deserialize)]
pub struct UserConfig {
    pub windsurf_app_path: String,
}

pub fn get_user_config() -> UserConfig {
    crate::modules::account::get_data_dir()
        .ok()
        .and_then(|p| std::fs::read_to_string(p.join("settings.json")).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn patch_user_config(
    f: impl FnOnce(&mut UserConfig) -> Result<(), String>,
) -> Result<(), String> {
    let _lock = LOCK.lock().map_err(|_| "设置锁不可用")?;
    let mut cfg = get_user_config();
    f(&mut cfg)?;
    let path = crate::modules::account::get_data_dir()?.join("settings.json");
    crate::modules::atomic_write::write_string_atomic(
        &path,
        &serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?,
    )
}
