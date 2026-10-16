pub mod error;
pub mod models;
pub mod modules;
#[cfg(test)]
mod regression_tests;
#[cfg(test)]
mod security_tests;
pub mod utils;

use models::windsurf::WindsurfOAuthStartResponse;
use modules::account_view::{views, AccountView};
use modules::{windsurf_account as accounts, windsurf_instance as client, windsurf_oauth as auth};
use serde::Serialize;
use std::path::Path;
static LOGIN_PHASE: std::sync::Mutex<Option<(String, String)>> = std::sync::Mutex::new(None);
fn login_phase(id: &str, phase: &str) {
    if let Ok(mut p) = LOGIN_PHASE.lock() {
        *p = Some((id.into(), phase.into()));
    }
}
static CLIENT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tauri::command]
fn list_windsurf_accounts() -> Result<Vec<AccountView>, String> {
    accounts::list_accounts_checked().map(views)
}
#[tauri::command]
fn delete_windsurf_account(account_id: String) -> Result<(), String> {
    accounts::remove_account(&account_id)
}
#[tauri::command]
fn import_cockpit_accounts(
    source_path: Option<String>,
) -> Result<modules::cockpit_migration::MigrationReport, String> {
    modules::cockpit_migration::import(source_path)
}
#[tauri::command]
fn import_windsurf_from_json(json_content: String) -> Result<Vec<AccountView>, String> {
    accounts::import_from_json(&json_content).map(views)
}
#[tauri::command]
async fn add_windsurf_account_with_token(
    github_access_token: String,
) -> Result<AccountView, String> {
    accounts::upsert_account(auth::build_payload_from_token(&github_access_token).await?)
        .map(|a| AccountView::from(&a))
}
#[tauri::command]
async fn import_windsurf_from_local() -> Result<Vec<AccountView>, String> {
    let _guard = CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    let _file_guard = modules::process::lock_client_operation()?;
    let mut local = modules::official_browser_login::read_local_login()?
        .ok_or("未找到本机登录态，请先在官方 Devin Desktop 登录")?;
    modules::official_browser_login::remove_observation_metadata(&mut local);
    let mut payload = auth::build_payload_from_local_auth_status(local).await?;
    if payload.github_login.trim().is_empty() {
        if let Some(hint) = accounts::read_local_login_hint() {
            payload.github_login = hint;
        }
    }
    Ok(vec![AccountView::from(&accounts::upsert_account(payload)?)])
}
#[tauri::command]
async fn refresh_windsurf_token(account_id: String) -> Result<AccountView, String> {
    accounts::refresh_account_token(&account_id)
        .await
        .map(|a| AccountView::from(&a))
}
#[tauri::command]
async fn windsurf_oauth_login_start() -> Result<WindsurfOAuthStartResponse, String> {
    let response = auth::start_login().await?;
    if open::that_detached(&response.verification_uri).is_err() {
        let _ = auth::cancel_login(Some(&response.login_id));
        return Err("无法打开系统浏览器，请检查默认浏览器设置".into());
    }
    login_phase(&response.login_id, "waiting");
    Ok(response)
}

#[tauri::command]
async fn windsurf_oauth_login_poll(login_id: String) -> Result<Option<AccountView>, String> {
    if auth::callback_received(&login_id) {
        login_phase(&login_id, "verifying");
    }
    let result = auth::poll_login(&login_id).await;
    match result {
        Ok(Some(payload)) => {
            login_phase(&login_id, "saving");
            let saved = accounts::upsert_account(payload);
            match saved {
                Ok(a) => {
                    login_phase(&login_id, "saved");
                    Ok(Some(AccountView::from(&a)))
                }
                Err(e) => {
                    login_phase(&login_id, "failed");
                    Err(e)
                }
            }
        }
        Ok(None) => Ok(None),
        Err(e) => {
            login_phase(&login_id, "failed");
            Err(e)
        }
    }
}
#[tauri::command]
fn get_oauth_login_phase(login_id: String) -> String {
    let phase = LOGIN_PHASE
        .lock()
        .ok()
        .and_then(|p| {
            p.as_ref()
                .filter(|(id, _)| id == &login_id)
                .map(|(_, p)| p.clone())
        })
        .unwrap_or_else(|| "waiting".into());
    if phase == "waiting" && auth::callback_received(&login_id) {
        "callback_received".into()
    } else {
        phase
    }
}

#[tauri::command]
fn windsurf_oauth_login_cancel(login_id: String) -> Result<(), String> {
    if get_oauth_login_phase(login_id.clone()) != "saved" {
        login_phase(&login_id, "cancelled");
    }
    auth::cancel_login(Some(&login_id))
}

#[tauri::command]
async fn official_browser_login_start(
) -> Result<modules::official_browser_login::StartResponse, String> {
    let _guard = CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    let _file_guard = modules::process::lock_client_operation()?;
    modules::official_browser_login::start()
}
#[tauri::command]
async fn official_browser_login_poll(login_id: String) -> Result<Option<AccountView>, String> {
    let _guard = CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    let _file_guard = modules::process::lock_client_operation()?;
    modules::official_browser_login::poll(&login_id)
        .await
        .map(|a| a.as_ref().map(AccountView::from))
}
#[tauri::command]
fn official_browser_login_cancel(login_id: String) -> Result<(), String> {
    modules::official_browser_login::cancel(&login_id)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientStatus {
    installed: bool,
    app_path: Option<String>,
    current_account_id: Option<String>,
    data_dir: String,
}

fn current_account_id() -> Option<String> {
    let local = modules::official_browser_login::read_local_login()
        .ok()
        .flatten()?;
    let list = accounts::list_accounts_checked().ok()?;
    modules::account_identity::current_id(&local, &list)
}

#[tauri::command]
fn get_client_status() -> Result<ClientStatus, String> {
    let app_path = client::detect_and_save_windsurf_launch_path(false);
    Ok(ClientStatus {
        installed: app_path.as_ref().is_some_and(|p| Path::new(p).is_file()),
        app_path,
        current_account_id: current_account_id(),
        data_dir: modules::account::get_data_dir()?
            .to_string_lossy()
            .into_owned(),
    })
}

#[tauri::command]
async fn open_official_client() -> Result<String, String> {
    let _guard = CLIENT_LOCK.try_lock().map_err(|_| "正在操作客户端")?;
    let _file_guard = modules::process::lock_client_operation()?;
    client::detect_and_save_windsurf_launch_path(false)
        .ok_or("未找到 Devin Desktop，请安装客户端或设置程序路径")?;
    client::start_windsurf_default_with_args_with_new_window(&[], true)?;
    Ok("已启动官方客户端，请在客户端点击登录；登录后返回这里导入当前账号。".into())
}

#[tauri::command]
fn set_client_path(path: String) -> Result<(), String> {
    let p = Path::new(&path);
    let name = p
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !p.is_absolute() || !p.is_file() || !["devin.exe", "windsurf.exe"].contains(&name.as_str()) {
        return Err("请选择已安装的 Devin.exe 或 Windsurf.exe 完整路径".into());
    }
    modules::config::patch_user_config(move |cfg| {
        cfg.windsurf_app_path = path;
        Ok(())
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SwitchResult {
    message: String,
    local_verified: bool,
    backup_path: String,
}

#[tauri::command]
async fn inject_windsurf_to_vscode(account_id: String) -> Result<SwitchResult, String> {
    let _guard = CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    let _file_guard = modules::process::lock_client_operation()?;
    client::detect_and_save_windsurf_launch_path(false)
        .ok_or("未找到 Devin Desktop，请先安装或设置路径")?;
    client::ensure_windsurf_launch_path_configured()?;
    let account = accounts::load_account(&account_id).ok_or("账号不存在")?;
    // Unlike upstream's warning-only fallback, do not inject stale auth1 credentials after a failed refresh.
    if account
        .devin_auth1_token
        .as_deref()
        .is_some_and(|s| s.starts_with("auth1_"))
    {
        accounts::refresh_account_token(&account_id)
            .await
            .map_err(|e| format!("切换前刷新失败，未修改客户端：{}", e))?;
    }
    let profile = client::get_default_windsurf_user_data_dir()?;
    let db = profile.join("User/globalStorage/state.vscdb");
    if !db.is_file() {
        return Err("请先启动官方客户端完成初始化和登录".into());
    }
    modules::auth_endpoint::validate_account(
        &accounts::load_account(&account_id).ok_or("账号不存在")?,
    )?;
    let was_running = client::profile_is_running(&profile);
    client::close_windsurf(&[profile.to_string_lossy().into_owned()], 20)?;
    let result = modules::client_recovery::guarded_with_close(
        &profile,
        || {
            client::inject_account_to_profile(&profile, &account_id)?;
            if current_account_id().as_deref() != Some(&account_id) {
                return Err("客户端本地登录态校验失败".into());
            }
            client::start_windsurf_default_with_args_with_new_window(&[], true)?;
            Ok(())
        },
        || client::close_windsurf(&[profile.to_string_lossy().into_owned()], 20),
    );
    let backup = match result {
        Ok(p) => p,
        Err(error) => {
            if was_running && error.safe_to_restart && !client::profile_is_running(&profile) {
                if client::start_windsurf_default_with_args_with_new_window(&[], true).is_err() {
                    return Err(format!("{}；请手动启动客户端。", error.message));
                }
            }
            return Err(error.message);
        }
    };
    let verified = true;
    let message = if accounts::mark_switched(&account_id).is_ok() {
        "已写入目标账号并启动客户端，请在 Devin Desktop 确认账号及服务连接。"
    } else {
        "账号已写入并启动，但最近切换记录未能保存；请检查本地目录权限。"
    };
    Ok(SwitchResult {
        message: message.into(),
        local_verified: verified,
        backup_path: backup.to_string_lossy().into_owned(),
    })
}

#[tauri::command]
fn get_recovery_status() -> Result<modules::client_recovery::Status, String> {
    modules::client_recovery::status()
}
#[tauri::command]
async fn restore_last_client_state() -> Result<String, String> {
    let _guard = CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    let _file_guard = modules::process::lock_client_operation()?;
    let profile = client::get_default_windsurf_user_data_dir()?;
    modules::client_recovery::preflight(&profile)?;
    let was_running = client::profile_is_running(&profile);
    client::close_windsurf(&[profile.to_string_lossy().into_owned()], 20)?;
    modules::client_recovery::restore(&profile).map_err(|e| format!("恢复未完成，客户端保持关闭；恢复点仍保留：{e}"))?;
    if was_running {
        let restart = client::start_windsurf_default_with_args_with_new_window(&[], true);
        if restart.is_err() {
            return Err("恢复操作结束，但客户端启动失败；请手动启动并检查账号".into());
        }
    }
    if let Some(id) = current_account_id() {
        let _ = accounts::mark_switched(&id);
    }
    Ok("已恢复上一次切换前的数据库，请在客户端确认账号。".into())
}

#[tauri::command]
fn cleanup_legacy_client_backups() -> Result<usize, String> {
    let _guard = CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    let _file_guard = modules::process::lock_client_operation()?;
    modules::client_recovery::cleanup_legacy(&client::get_default_windsurf_user_data_dir()?)
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_windsurf_accounts,
            delete_windsurf_account,
            import_windsurf_from_json,
            import_cockpit_accounts,
            add_windsurf_account_with_token,
            import_windsurf_from_local,
            refresh_windsurf_token,
            windsurf_oauth_login_start,
            windsurf_oauth_login_poll,
            windsurf_oauth_login_cancel,
            official_browser_login_start,
            official_browser_login_poll,
            official_browser_login_cancel,
            get_client_status,
            get_recovery_status,
            cleanup_legacy_client_backups,
            get_oauth_login_phase,
            restore_last_client_state,
            open_official_client,
            set_client_path,
            inject_windsurf_to_vscode
        ])
        .run(tauri::generate_context!())
        .expect("Devin Switcher could not start");
}
