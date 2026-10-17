pub mod error;
pub mod models;
pub mod modules;
#[cfg(test)]
mod auth_compat_tests;
#[cfg(test)]
mod rotation_tests;
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
pub(crate) static CLIENT_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

fn project_link_url(destination: &str) -> Result<&'static str, String> {
    let url = match destination {
        "repository" => "https://github.com/axinlab71/devin-account-manager",
        "issues" => "https://github.com/axinlab71/devin-account-manager/issues",
        "releases" => "https://github.com/axinlab71/devin-account-manager/releases",
        "upstream" => "https://github.com/jlcodes99/cockpit-tools",
        _ => return Err("不支持的项目链接".into()),
    };
    Ok(url)
}

#[cfg(test)]
mod project_link_tests {
    #[test]
    fn project_links_use_fixed_repository_and_reject_arbitrary_destinations() {
        assert_eq!(super::project_link_url("repository").unwrap(), "https://github.com/axinlab71/devin-account-manager");
        assert_eq!(super::project_link_url("issues").unwrap(), "https://github.com/axinlab71/devin-account-manager/issues");
        assert!(super::project_link_url("https://example.com").is_err());
        assert!(super::project_link_url("file:///C:/Windows").is_err());
    }
}

#[tauri::command]
async fn open_project_link(destination: String) -> Result<(), String> {
    let url = project_link_url(&destination)?;
    open::that_detached(url).map_err(|_| "无法打开系统浏览器，请手动复制页面中的仓库地址".into())
}

#[tauri::command]
async fn open_client_for_diagnostics() -> Result<(), String> {
    let _guard = CLIENT_LOCK.try_lock().map_err(|_| "正在操作客户端，请稍后再试")?;
    tokio::task::spawn_blocking(|| {
        let _file_guard = modules::process::lock_client_operation()?;
        modules::quota_monitor::global().ensure_no_in_flight_switch()
            .map_err(|code| modules::quota_monitor::confirm_error_message(&code))?;
        client::detect_and_save_windsurf_launch_path(false)
            .ok_or("未找到 Devin Desktop，请先在客户端设置中指定路径")?;
        client::start_windsurf_default_with_args_with_new_window(&[], false).map(|_| ())
    }).await.map_err(|_| "打开客户端任务失败".to_string())?
}

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
async fn add_windsurf_account_with_password(
    email: String,
    password: String,
) -> Result<AccountView, String> {
    accounts::upsert_account(auth::build_payload_from_password(&email, &password).await?)
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
    // A durable in-flight record means an official `devin://` login may
    // still be processed by the running client — a restart switch now
    // would race it and could leave Devin on a different account than the
    // one written here.
    modules::quota_monitor::global()
        .ensure_no_in_flight_switch()
        .map_err(|code| modules::quota_monitor::confirm_error_message(&code))?;
    inject_windsurf_to_vscode_inner(&account_id).await
}

/// The standard restart switch body, callable without re-acquiring the
/// client locks — `confirm_rotation` already holds them when it dispatches
/// here for the default (standard) switch method.
async fn inject_windsurf_to_vscode_inner(account_id: &str) -> Result<SwitchResult, String> {
    client::detect_and_save_windsurf_launch_path(false)
        .ok_or("未找到 Devin Desktop，请先安装或设置路径")?;
    client::ensure_windsurf_launch_path_configured()?;
    let account = accounts::load_account(account_id).ok_or("账号不存在")?;
    // Unlike upstream's warning-only fallback, do not inject stale auth1 credentials after a failed refresh.
    if account
        .devin_auth1_token
        .as_deref()
        .is_some_and(|s| s.starts_with("auth1_"))
    {
        accounts::refresh_account_token(account_id)
            .await
            .map_err(|e| format!("切换前刷新失败，未修改客户端：{}", e))?;
    }
    let profile = client::get_default_windsurf_user_data_dir()?;
    let db = profile.join("User/globalStorage/state.vscdb");
    if !db.is_file() {
        return Err("请先启动官方客户端完成初始化和登录".into());
    }
    modules::auth_endpoint::validate_account(
        &accounts::load_account(account_id).ok_or("账号不存在")?,
    )?;
    let was_running = client::profile_is_running(&profile);
    client::close_windsurf(&[profile.to_string_lossy().into_owned()], 20)?;
    let result = modules::client_recovery::guarded_with_close(
        &profile,
        || {
            client::inject_account_to_profile(&profile, account_id)?;
            if current_account_id().as_deref() != Some(account_id) {
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
    let message = if accounts::mark_switched(account_id).is_ok() {
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
    // Restoring the client DB while an official `devin://` login may still
    // be processing would resurrect a pre-login state over a live request.
    modules::quota_monitor::global()
        .ensure_no_in_flight_switch()
        .map_err(|code| modules::quota_monitor::confirm_error_message(&code))?;
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

/// Read-only audit of the official profile's auth-related ItemTable keys.
/// Never writes, decrypts, or returns credential material.
#[tauri::command]
fn probe_auth_compatibility(
) -> Result<modules::auth_compatibility::AuthCompatibilityReport, String> {
    let configured = modules::config::get_user_config().windsurf_app_path;
    let configured = configured.trim();
    let configured = if configured.is_empty() {
        None
    } else {
        Some(configured)
    };
    modules::auth_compatibility::probe_default_profile(configured)
}

// ---------- Rotation monitor (phase 2: read-only decisions, no client writes) ----------

#[tauri::command]
fn get_rotation_status() -> Result<modules::rotation_policy::RotationStatusDto, String> {
    Ok(modules::quota_monitor::global().status())
}

#[tauri::command]
fn set_rotation_config(
    config: modules::rotation_state::RotationConfig,
) -> Result<modules::rotation_policy::RotationStatusDto, String> {
    modules::quota_monitor::global().set_config(config)
}

#[tauri::command]
fn pause_rotation(reason: Option<String>) -> Result<modules::rotation_policy::RotationStatusDto, String> {
    modules::quota_monitor::global().pause(reason.as_deref().unwrap_or("user"))
}

#[tauri::command]
fn resume_rotation() -> Result<modules::rotation_policy::RotationStatusDto, String> {
    modules::quota_monitor::global().resume()
}

/// One serial quota scan across the enabled pool + current account. Read-only:
/// uses the same endpoint as manual refresh, never writes to the client.
#[tauri::command]
async fn scan_rotation_now(
) -> Result<modules::rotation_policy::RotationStatusDto, String> {
    let current = current_account_id();
    let monitor = modules::quota_monitor::global();
    monitor
        .run_scan_once(&modules::quota_monitor::DevinUserStatusFetcher, current)
        .await?;
    Ok(monitor.status())
}

/// What switch execution paths are actually usable. Evidence-based: anything
/// without verified acceptance reports `unsupported`/`blocked`, never hopes.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SwitchCapabilitiesDto {
    /// Standard restart switch via the existing manual command.
    restart_switch: &'static str,
    /// L2 same-process switch: no verified external interface exists.
    native_hot_switch: &'static str,
    isolated_profile_switch: &'static str,
    /// Full-auto rotation requires verified L2 + auth compat + workload
    /// safety detection — none are established yet.
    auto_rotation: &'static str,
    notes: Vec<String>,
}

#[tauri::command]
fn get_switch_capabilities() -> SwitchCapabilitiesDto {
    SwitchCapabilitiesDto {
        restart_switch: "manual_confirmed_only",
        native_hot_switch: "implemented_unverified",
        isolated_profile_switch: "unsupported",
        auto_rotation: "blocked_no_l2_evidence",
        notes: vec![
            "阶段一写入修正已实施（见 docs/AUTH_COMPATIBILITY.md §5），自动执行仍待真实验收".into(),
            "L2 研究见 docs/HOT_SWITCH_RESEARCH.md：devin:// URI 登录是未实测的候选路径".into(),
        ],
    }
}

/// Confirm a pending recommendation. Phase A re-validates everything
/// server-side (gate); phase B dispatches by the user's switch-method
/// preference: `native` → the experimental official `devin://` URI login;
/// anything else (the default `standard`) → the standard save-and-restart
/// switch. A blocked/failed adapter outcome performs zero writes.
#[tauri::command]
async fn confirm_rotation(
    suggestion_id: String,
    target_account_id: String,
    expected_current_account_id: Option<String>,
    switch_method: Option<String>,
) -> Result<modules::switch_adapter::SwitchOutcome, String> {
    use modules::switch_adapter::{
        AdapterKind, RollbackStatus, SwitchOutcome, Verification,
    };
    // Same serialization domain as manual switching/recovery: a rotation
    // launch must not overlap any other client operation.
    let _guard = CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    let _file_guard = modules::process::lock_client_operation()?;
    let current = current_account_id();
    let request = modules::switch_adapter::SwitchRequest {
        suggestion_id,
        target_account_id,
        expected_current_id: expected_current_account_id
            .or_else(|| current.clone())
            .unwrap_or_default(),
        confirmed: true,
    };
    let monitor = modules::quota_monitor::global();
    monitor.begin_confirm(current, &request)?;
    let outcome = if switch_method.as_deref() == Some("native") {
        modules::native_switch::execute(&request.target_account_id).await
    } else {
        // Default: standard save-and-restart. The inject path already
        // re-validates, backs up, writes, restarts and verifies the local
        // session — a success is a completed switch, not a pending one.
        match inject_windsurf_to_vscode_inner(&request.target_account_id).await {
            Ok(r) => SwitchOutcome {
                target_account_id: request.target_account_id.clone(),
                adapter: Some(AdapterKind::SafeRestart),
                restart_required: true,
                local_match: if r.local_verified {
                    Verification::Passed
                } else {
                    Verification::Unknown
                },
                client_recognized: Verification::Unknown,
                remote_verified: Verification::NotAttempted,
                rollback: RollbackStatus::NotNeeded,
                failure_code: None,
                message: r.message,
            },
            Err(e) => {
                let mut o = SwitchOutcome::blocked(
                    &request.target_account_id,
                    "standard_switch_failed",
                    format!("标准切号失败: {e}"),
                );
                o.adapter = Some(AdapterKind::SafeRestart);
                o.restart_required = true;
                o
            }
        }
    };
    monitor.finish_confirm(&request, &outcome);
    // A completed standard restart passed the local write+identity check
    // only — record `executed` (cooldown/last-switch bookkeeping), NOT
    // `verified`: client recognition and remote ACP status are unconfirmed.
    // The native path stays `awaiting_client` until `verify_native_login`
    // observes the official session change.
    if outcome.adapter == Some(AdapterKind::SafeRestart) && outcome.failure_code.is_none() {
        monitor.mark_executed(&request.target_account_id);
    }
    Ok(outcome)
}

/// Read-only post-launch check: did the official client's stored session
/// switch to the target account? On `verified` the monitor records the
/// completed switch (cooldown + last-switch timestamp).
#[tauri::command]
async fn verify_native_login(
    target_account_id: String,
) -> Result<modules::native_switch::NativeVerifyResult, String> {
    let result = modules::native_switch::verify(&target_account_id).await?;
    if result.completes_switch() {
        modules::quota_monitor::global().mark_verified(&target_account_id);
    }
    Ok(result)
}

/// Manual experimental same-process switch: launches the official `devin://`
/// login URI for a chosen account WITHOUT needing a low-quota recommendation.
/// Experimental — the official client shows its own confirmation modal; we
/// write nothing to client files. Verify afterwards via `verify_native_login`.
#[tauri::command]
async fn try_native_switch(
    account_id: String,
) -> Result<modules::switch_adapter::SwitchOutcome, String> {
    let _guard = CLIENT_LOCK
        .try_lock()
        .map_err(|_| "正在操作客户端，请稍后再试")?;
    let _file_guard = modules::process::lock_client_operation()?;
    // Same durable in-flight record as the recommendation path: persisted
    // BEFORE the URI launch so a crash is recoverable, and every gate
    // (recovery, concurrent confirm, second manual launch, config save)
    // sees the operation.
    let monitor = modules::quota_monitor::global();
    let record_id = monitor
        .begin_manual_switch(&account_id, current_account_id())
        .map_err(|code| match code.as_str() {
            "recovery_review_required" => {
                "轮换状态从备份恢复，请先核对当前登录账号".to_string()
            }
            "switch_in_progress" => {
                "已有切换等待官方客户端确认，请先验证或关闭后再发起".to_string()
            }
            other => other.to_string(),
        })?;
    let outcome = modules::native_switch::execute(&account_id).await;
    monitor.finish_manual_switch(&record_id, &outcome);
    Ok(outcome)
}

/// Dismiss the pending recommendation without executing anything.
#[tauri::command]
fn dismiss_rotation(suggestion_id: String) -> Result<(), String> {
    modules::quota_monitor::global().dismiss(&suggestion_id)
}

/// User acknowledgement that the recovered-from-backup state is reconciled:
/// only meaningful when no in-flight record exists to verify/dismiss.
#[tauri::command]
fn acknowledge_rotation_recovery(
) -> Result<modules::rotation_policy::RotationStatusDto, String> {
    modules::quota_monitor::global().acknowledge_recovery()
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
    // The guard stays alive throughout the blocking event loop. A duplicate
    // launch only activates the existing manager; it never starts a second
    // quota monitor or reads/writes the shared rotation state.
    let Some(_instance_guard) = modules::app_instance::acquire()
        .expect("无法取得管理器实例锁") else {
        modules::app_instance::show_existing();
        return;
    };
    tauri::Builder::default()
        .setup(|app| {
            let monitor = modules::quota_monitor::global();
            monitor.attach_app(app.handle().clone());
            // Background poll scans resolve the current account through the
            // same local-matching path the command layer uses.
            monitor.set_current_id_resolver(current_account_id);
            // Honour persisted config: mode defaults to Off on first install.
            monitor.start_if_configured();
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_windsurf_accounts,
            delete_windsurf_account,
            import_windsurf_from_json,
            import_cockpit_accounts,
            add_windsurf_account_with_token,
            add_windsurf_account_with_password,
            import_windsurf_from_local,
            refresh_windsurf_token,
            windsurf_oauth_login_start,
            windsurf_oauth_login_poll,
            windsurf_oauth_login_cancel,
            official_browser_login_start,
            official_browser_login_poll,
            official_browser_login_cancel,
            get_client_status,
            probe_auth_compatibility,
            get_rotation_status,
            set_rotation_config,
            pause_rotation,
            resume_rotation,
            scan_rotation_now,
            confirm_rotation,
            try_native_switch,
            verify_native_login,
            dismiss_rotation,
            acknowledge_rotation_recovery,
            get_switch_capabilities,
            get_recovery_status,
            cleanup_legacy_client_backups,
            get_oauth_login_phase,
            restore_last_client_state,
            open_official_client,
            open_project_link,
            open_client_for_diagnostics,
            modules::client_support::export_devin_logs,
            modules::client_support::open_log_export_folder,
            modules::client_support::complete_restart_devin,
            modules::account_export::export_account_credentials,
            modules::account_export::open_account_exports_folder,
            set_client_path,
            inject_windsurf_to_vscode,
            modules::connection_diagnostics::run_connection_diagnostics,
            modules::connection_diagnostics::get_last_diagnostics,
            modules::connection_diagnostics::export_diagnostics_report,
            modules::connection_diagnostics::preview_diagnostics_report,
            modules::connection_diagnostics::apply_client_proxy_fix,
            modules::connection_diagnostics::revert_client_proxy_fix,
            modules::connection_diagnostics::get_proxy_fix_state,
            modules::connection_diagnostics::record_recovery_feedback,
            modules::connection_diagnostics::clear_stale_pac_config,
            modules::connection_diagnostics::restart_devin_client
        ])
        .run(tauri::generate_context!())
        .expect("Devin Switcher could not start");
}
