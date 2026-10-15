pub mod error;
pub mod models;
pub mod modules;
#[cfg(test)]
mod regression_tests;
pub mod utils;

use models::windsurf::{WindsurfAccount, WindsurfOAuthStartResponse};
use modules::{windsurf_account as accounts, windsurf_instance as client, windsurf_oauth as auth};
use serde::Serialize;
use std::path::Path;
static CLIENT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tauri::command]
fn list_windsurf_accounts() -> Result<Vec<WindsurfAccount>, String> {
    accounts::list_accounts_checked()
}
#[tauri::command]
fn delete_windsurf_account(account_id: String) -> Result<(), String> {
    accounts::remove_account(&account_id)
}
#[tauri::command]
fn import_windsurf_from_json(json_content: String) -> Result<Vec<WindsurfAccount>, String> {
    accounts::import_from_json(&json_content)
}
#[tauri::command]
async fn add_windsurf_account_with_token(
    github_access_token: String,
) -> Result<WindsurfAccount, String> {
    accounts::upsert_account(auth::build_payload_from_token(&github_access_token).await?)
}
#[tauri::command]
async fn import_windsurf_from_local() -> Result<Vec<WindsurfAccount>, String> {
    let _guard = CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    let mut local = modules::official_browser_login::read_local_login()?
        .ok_or("未找到本机登录态，请先在官方 Devin Desktop 登录")?;
    modules::official_browser_login::remove_observation_metadata(&mut local);
    let mut payload = auth::build_payload_from_local_auth_status(local).await?;
    if payload.github_login.trim().is_empty() {
        if let Some(hint) = accounts::read_local_login_hint() {
            payload.github_login = hint;
        }
    }
    Ok(vec![accounts::upsert_account(payload)?])
}
#[tauri::command]
async fn refresh_windsurf_token(account_id: String) -> Result<WindsurfAccount, String> {
    accounts::refresh_account_token(&account_id).await
}
#[tauri::command]
async fn windsurf_oauth_login_start() -> Result<WindsurfOAuthStartResponse, String> {
    let response = auth::start_login().await?;
    if open::that_detached(&response.verification_uri).is_err() {
        let _ = auth::cancel_login(Some(&response.login_id));
        return Err("无法打开系统浏览器，请检查默认浏览器设置".into());
    }
    Ok(response)
}

#[tauri::command]
async fn windsurf_oauth_login_poll(login_id: String) -> Result<Option<WindsurfAccount>, String> {
    match auth::poll_login(&login_id).await? {
        Some(payload) => Ok(Some(accounts::upsert_account(payload)?)),
        None => Ok(None),
    }
}
#[tauri::command]
fn windsurf_oauth_login_cancel(login_id: String) -> Result<(), String> {
    auth::cancel_login(Some(&login_id))
}

#[tauri::command]
async fn official_browser_login_start(
) -> Result<modules::official_browser_login::StartResponse, String> {
    let _guard = CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    modules::official_browser_login::start()
}
#[tauri::command]
async fn official_browser_login_poll(login_id: String) -> Result<Option<WindsurfAccount>, String> {
    let _guard = CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    modules::official_browser_login::poll(&login_id).await
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
    // Compare actual persisted client credentials, never the last-selected UI row.
    list.into_iter()
        .find(|a| {
            ["apiKey", "sessionToken"]
                .iter()
                .filter_map(|k| local.get(k).and_then(|v| v.as_str()))
                .any(|token| {
                    !token.is_empty()
                        && (a.windsurf_api_key.as_deref() == Some(token)
                            || a.windsurf_auth_token.as_deref() == Some(token)
                            || a.github_access_token == token)
                })
        })
        .map(|a| a.id)
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
    client::close_windsurf(&[profile.to_string_lossy().into_owned()], 20)?;
    let backup_dir = modules::account::get_data_dir()?.join("client-backups");
    std::fs::create_dir_all(&backup_dir).map_err(|e| e.to_string())?;
    let backup = backup_dir.join(format!("state-{}.vscdb", uuid::Uuid::new_v4()));
    let source = rusqlite::Connection::open(&db).map_err(|e| e.to_string())?;
    source
        .backup(rusqlite::DatabaseName::Main, &backup, None)
        .map_err(|e| format!("备份失败，未修改登录态：{}", e))?;
    drop(source);
    client::inject_account_to_profile(&profile, &account_id)?;
    let verified = current_account_id().as_deref() == Some(&account_id);
    if !verified {
        return Err("客户端本地登录态校验失败；已保留切换前数据库备份".into());
    }
    client::start_windsurf_default_with_args_with_new_window(&[], true)
        .map_err(|e| format!("登录态已写入且本地校验通过，但客户端启动失败：{}", e))?;
    Ok(SwitchResult {
        message: "已写入目标账号并启动客户端，请在 Devin Desktop 确认账号及服务连接。".into(),
        local_verified: verified,
        backup_path: backup.to_string_lossy().into_owned(),
    })
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_windsurf_accounts,
            delete_windsurf_account,
            import_windsurf_from_json,
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
            open_official_client,
            set_client_path,
            inject_windsurf_to_vscode
        ])
        .run(tauri::generate_context!())
        .expect("Devin Switcher could not start");
}
