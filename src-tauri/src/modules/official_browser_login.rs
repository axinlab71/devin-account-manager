//! Delegate browser login to the real Devin Desktop callback handler, then
//! import only a newly persisted client credential. No loopback callback,
//! protocol registration, browser token capture, or server allowlist bypass.
use super::{windsurf_account, windsurf_instance, windsurf_oauth};
use crate::models::windsurf::WindsurfAccount;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Pending {
    login_id: String,
    baseline: Option<String>,
    created: Instant,
}
static PENDING: Mutex<Option<Pending>> = Mutex::new(None);
const TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartResponse {
    pub login_id: String,
    pub expires_in: u64,
}

pub fn build_official_login_url(state: &str) -> String {
    // Exactly the branch confirmed in official Desktop 3.10.48 and the user's
    // actual client link. This client_id is not registered as our own client.
    let mut url =
        url::Url::parse("https://windsurf.com/devin/account/login").expect("fixed official URL");
    url.query_pairs_mut()
        .append_pair("response_type", "token")
        .append_pair("client_id", "3GUryQ7ldAeKEuD2obYnppsnmj58eP5u")
        .append_pair("redirect_uri", "devin://codeium.windsurf")
        .append_pair("state", state)
        .append_pair("redirect_parameters_type", "fragment");
    url.into()
}

fn credential(auth: &Value) -> Option<&str> {
    ["sessionToken", "apiKey"].into_iter().find_map(|key| {
        auth.get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    })
}

fn fingerprint(auth: &Value) -> Option<String> {
    credential(auth).map(|token| {
        let mut digest = Sha256::new();
        digest.update(token.as_bytes());
        digest.update([0]);
        if let Some(id) = auth
            .get("_switcherDesktopSessionId")
            .and_then(Value::as_str)
        {
            digest.update(id.as_bytes());
        }
        format!("{:x}", digest.finalize())
    })
}

pub fn remove_observation_metadata(auth: &mut Value) {
    if let Some(obj) = auth.as_object_mut() {
        obj.remove("_switcherDesktopSessionId");
    }
}

pub fn read_local_login() -> Result<Option<Value>, String> {
    let legacy = windsurf_account::read_local_auth_status()?.filter(|v| fingerprint(v).is_some());
    #[cfg(target_os = "windows")]
    {
        let profile = windsurf_instance::get_default_windsurf_user_data_dir()?;
        match windsurf_instance::read_profile_session_auth_status(&profile) {
            Ok(Some(session)) => {
                // Preserve upstream auth1 and display metadata only if it belongs
                // to this exact credential, never to the previous logged-in user.
                if let Some(mut existing) = legacy
                    .clone()
                    .filter(|old| credential(old) == credential(&session))
                {
                    if let (Some(old), Some(new)) = (existing.as_object_mut(), session.as_object())
                    {
                        old.extend(new.clone());
                    }
                    return Ok(Some(existing));
                }
                return Ok(Some(session));
            }
            Ok(None) => {}
            Err(error) if legacy.is_none() => return Err(error),
            Err(_) => {}
        }
    }
    Ok(legacy)
}

pub fn start() -> Result<StartResponse, String> {
    let mut guard = PENDING.lock().map_err(|_| "登录会话锁不可用")?;
    if guard
        .as_ref()
        .is_some_and(|p| p.created.elapsed() < TIMEOUT)
    {
        return Err("已有网页授权正在进行，请完成或取消后重试".into());
    }
    windsurf_instance::detect_and_save_windsurf_launch_path(false)
        .ok_or("网页授权需要已安装的官方 Devin Desktop 接收回调，请先安装或设置路径")?;
    let baseline = read_local_login()?.as_ref().and_then(fingerprint);
    // The official app must receive devin://. Never register this protocol here.
    if windsurf_instance::resolve_windsurf_pid(None, None).is_none() {
        windsurf_instance::start_windsurf_default_with_args_with_new_window(&[], true)?;
    }
    let login_id = uuid::Uuid::new_v4().to_string();
    let url = build_official_login_url(&login_id);
    *guard = Some(Pending {
        login_id: login_id.clone(),
        baseline,
        created: Instant::now(),
    });
    if open::that_detached(url).is_err() {
        *guard = None;
        return Err("无法打开系统浏览器，请检查默认浏览器设置".into());
    }
    Ok(StartResponse {
        login_id,
        expires_in: TIMEOUT.as_secs(),
    })
}

pub fn cancel(login_id: &str) -> Result<(), String> {
    let mut guard = PENDING.lock().map_err(|_| "登录会话锁不可用")?;
    if guard.as_ref().is_some_and(|p| p.login_id == login_id) {
        *guard = None;
    }
    Ok(())
}

pub async fn poll(login_id: &str) -> Result<Option<WindsurfAccount>, String> {
    let baseline = {
        let mut guard = PENDING.lock().map_err(|_| "登录会话锁不可用")?;
        let pending = guard
            .as_ref()
            .filter(|p| p.login_id == login_id)
            .ok_or("登录已取消或不存在")?;
        if pending.created.elapsed() >= TIMEOUT {
            *guard = None;
            return Err("网页授权超时，请重新开始".into());
        }
        pending.baseline.clone()
    };
    let Some(mut local) = read_local_login()? else {
        return Ok(None);
    };
    let Some(current) = fingerprint(&local) else {
        return Ok(None);
    };
    if Some(&current) == baseline.as_ref() {
        return Ok(None);
    }
    remove_observation_metadata(&mut local);
    let mut payload = windsurf_oauth::build_payload_from_local_auth_status(local).await?;
    if payload.github_login.trim().is_empty() {
        if let Some(hint) = windsurf_account::read_local_login_hint() {
            payload.github_login = hint;
        }
    }
    let mut guard = PENDING.lock().map_err(|_| "登录会话锁不可用")?;
    if !guard
        .as_ref()
        .is_some_and(|p| p.login_id == login_id && p.created.elapsed() < TIMEOUT)
    {
        return Err("登录已取消或超时，未保存账号".into());
    }
    // Protect against another client account switch while remote validation ran.
    if read_local_login()?.as_ref().and_then(fingerprint).as_ref() != Some(&current) {
        return Err("客户端账号在导入期间发生变化，请重新授权".into());
    }
    let account = windsurf_account::upsert_account(payload)?;
    *guard = None;
    Ok(Some(account))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn official_url_uses_client_callback_and_fresh_state() {
        let a = uuid::Uuid::new_v4().to_string();
        let b = uuid::Uuid::new_v4().to_string();
        let url = url::Url::parse(&build_official_login_url(&a)).unwrap();
        assert_eq!(url.host_str(), Some("windsurf.com"));
        assert_eq!(url.path(), "/devin/account/login");
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["redirect_uri"], "devin://codeium.windsurf");
        assert_eq!(query["state"], a);
        assert_eq!(query["redirect_parameters_type"], "fragment");
        assert!(!query.contains_key("login_hint"));
        assert_ne!(build_official_login_url(&a), build_official_login_url(&b));
    }
    #[test]
    fn previous_account_is_not_a_completed_browser_login() {
        let before = serde_json::json!({"apiKey":"synthetic-old"});
        let same = serde_json::json!({"apiKey":"synthetic-old","name":"updated label"});
        let after = serde_json::json!({"apiKey":"synthetic-new"});
        assert_eq!(fingerprint(&before), fingerprint(&same));
        assert_ne!(fingerprint(&before), fingerprint(&after));
        assert_eq!(fingerprint(&Value::Null), None);
        let renewed = serde_json::json!({"apiKey":"synthetic-old","_switcherDesktopSessionId":"fresh-session"});
        assert_ne!(fingerprint(&before), fingerprint(&renewed));
        let mut stripped = renewed.clone();
        remove_observation_metadata(&mut stripped);
        assert_eq!(stripped, before);
    }

    #[tokio::test]
    async fn cancellation_and_expiry_do_not_read_or_import_credentials() {
        *PENDING.lock().unwrap() = Some(Pending {
            login_id: "fixture".into(),
            baseline: None,
            created: Instant::now(),
        });
        cancel("unrelated").unwrap();
        assert!(PENDING.lock().unwrap().is_some());
        cancel("fixture").unwrap();
        assert!(poll("fixture").await.is_err());
        *PENDING.lock().unwrap() = Some(Pending {
            login_id: "expired".into(),
            baseline: None,
            created: Instant::now() - TIMEOUT - Duration::from_secs(1),
        });
        assert!(poll("expired").await.unwrap_err().contains("超时"));
        assert!(PENDING.lock().unwrap().is_none());
    }
}
