//! NativeAuthSwitchAdapter — drives the *official* `devin://codeium.windsurf`
//! URI handler (analysis in docs/HOT_SWITCH_RESEARCH.md).
//!
//! Safety properties:
//! - We never register, re-register or hijack `devin://`; we merely launch a
//!   URI, exactly like the browser redirect at the end of web OAuth.
//! - The URI carries an `access_token` the official extension validates
//!   server-side (`registerUser`). We never write the client's files, DB,
//!   secrets or extension.
//! - With no pending login `state`, the official handler shows its own
//!   "log in using a different account?" modal — a second, in-client
//!   confirmation the user can still cancel.
//! - Credentials are passed via process argument to `rundll32` for a few
//!   milliseconds; they are never logged or sent anywhere but the official
//!   client.
//!
//! Credential sources, in preference order:
//! 1. A *fresh* `ott$` minted server-side from stored devin-session fields
//!    (`GetOneTimeAuthToken`, same call our add-account flow already uses).
//! 2. A stored `ott$`/`oidc$` token (may already be consumed — the official
//!    flow then fails gracefully inside the client).
//! `sk-ws-` ide tokens and `devin-session-token$` are NOT accepted by the
//! handler and are never put into a URI.
//!
//! All of this is *unverified on a live client* — the adapter reports what
//! it actually did (URI launched) and verification is a separate read-only
//! step (`verify`) that inspects the session the client itself stored.

use serde::Serialize;
use serde_json::Value;

use super::switch_adapter::{AdapterKind, RollbackStatus, SwitchOutcome, Verification};

/// Official redirect authority: `${env.uriScheme}://${publisher}.${name}`.
const OFFICIAL_LOGIN_URI_PREFIX: &str = "devin://codeium.windsurf";

fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// The URI the official URI handler routes to `maybeHandleUriWithToken`.
/// Empty path + `#access_token=` fragment mirrors the web-login redirect.
fn login_uri(access_token: &str) -> String {
    format!(
        "{}/#access_token={}",
        OFFICIAL_LOGIN_URI_PREFIX,
        encode_uri_component(access_token)
    )
}

fn looks_like_uri_acceptable_token(token: &str) -> bool {
    token.starts_with("ott$") || token.starts_with("oidc$")
}

/// Pick a credential the official handler can consume, minting a fresh
/// one-time token from stored devin-session fields when available.
/// Returns `Err(code)` when no usable credential exists.
async fn resolve_login_token(
    account: &crate::models::windsurf::WindsurfAccount,
) -> Result<String, &'static str> {
    let session = account
        .devin_session_token
        .as_deref()
        .map(str::trim)
        .filter(|s| s.starts_with("devin-session-token$"));
    let auth1 = account
        .devin_auth1_token
        .as_deref()
        .map(str::trim)
        .filter(|s| s.starts_with("auth1_"));
    let acc_id = account
        .devin_account_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let org_id = account
        .devin_org_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let (Some(session), Some(auth1), Some(acc_id), Some(org_id)) =
        (session, auth1, acc_id, org_id)
    {
        if let Ok(client) = super::windsurf_devin_oauth::build_client() {
            // Server-side mint; failure falls through to a stored ott$/oidc$.
            if let Ok(ott) =
                super::windsurf_devin_oauth::get_one_time_auth_token(
                    &client, session, auth1, acc_id, org_id,
                )
                .await
            {
                return Ok(ott);
            }
        }
    }

    for stored in [&account.windsurf_auth_token, &account.windsurf_api_key] {
        if let Some(t) = stored
            .as_deref()
            .map(str::trim)
            .filter(|t| looks_like_uri_acceptable_token(t))
        {
            return Ok(t.to_string());
        }
    }
    Err("no_uri_compatible_credential")
}

#[cfg(target_os = "windows")]
fn launch_uri(uri: &str) -> Result<(), String> {
    // rundll32 url.dll,FileProtocolHandler dispatches to the registered
    // protocol handler (the official client). No console window, no shell
    // quoting pitfalls — the URI travels as a single argument.
    std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", uri])
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("无法调用系统协议分发: {e}"))
}

/// Execute a same-process login request on the running official client.
/// This only *launches* the official URI; the actual session change happens
/// inside the client after its own confirmation modal, and is verified
/// afterwards by `verify`.
pub async fn execute(target_account_id: &str) -> SwitchOutcome {
    let blocked = |code: &str, msg: &str| {
        SwitchOutcome::blocked(target_account_id, code, msg)
    };

    #[cfg(not(target_os = "windows"))]
    return blocked(
        "platform_unsupported",
        "官方 URI 登录路径目前仅在 Windows 上实现",
    );

    #[cfg(target_os = "windows")]
    {
        let user_data = match super::windsurf_instance::get_default_windsurf_user_data_dir() {
            Ok(p) => p,
            Err(e) => return blocked("no_user_data_dir", &e),
        };
        if !super::windsurf_instance::profile_is_running(&user_data) {
            return blocked(
                "client_not_running",
                "官方客户端未运行；URI 登录要求客户端处于打开状态，请先启动 Devin Desktop。",
            );
        }
        let Some(account) = super::windsurf_account::load_account(target_account_id) else {
            return blocked("target_account_missing", "目标账号在本地存储中不存在");
        };
        let token = match resolve_login_token(&account).await {
            Ok(t) => t,
            Err(code) => {
                return blocked(
                    code,
                    "目标账号没有官方 URI 可接受的凭据（需要 devin-session 字段或可用的 ott$/oidc$）。",
                )
            }
        };
        if let Err(e) = launch_uri(&login_uri(&token)) {
            return blocked("uri_launch_failed", &e);
        }
        SwitchOutcome {
            target_account_id: target_account_id.to_string(),
            adapter: Some(AdapterKind::Native),
            restart_required: false,
            local_match: Verification::NotAttempted,
            client_recognized: Verification::NotAttempted,
            remote_verified: Verification::NotAttempted,
            rollback: RollbackStatus::NotNeeded,
            failure_code: None,
            message: "已向 Devin 发起官方登录请求，请在客户端弹出的确认框中确认；完成后点击「验证生效」。".into(),
        }
    }
}

/// Result of the read-only post-launch check.
// Enum-level `rename_all` only renames variants — struct-variant fields need
// explicit renames or the IPC payload silently ships `session_label` while
// the frontend reads `sessionLabel`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum NativeVerifyResult {
    /// Client's stored session matches the target account.
    Verified {
        #[serde(rename = "sessionLabel")]
        session_label: String,
    },
    /// Session exists but belongs to a different/unknown account — the user
    /// has not confirmed yet, or confirmed a different login.
    Pending {
        #[serde(rename = "sessionLabel")]
        session_label: Option<String>,
    },
    /// No session stored yet (client hasn't processed the login).
    #[serde(rename = "no_session")]
    NoSession,
}

/// Read-only verification: decrypt the client's stored session (same read
/// path as the existing auth-status reader; never writes) and compare the
/// session account label against the target account's known identities.
#[cfg(not(target_os = "windows"))]
pub fn verify(_target_account_id: &str) -> Result<NativeVerifyResult, String> {
    Err("官方会话读取目前仅在 Windows 上实现".into())
}

#[cfg(target_os = "windows")]
pub fn verify(target_account_id: &str) -> Result<NativeVerifyResult, String> {
    let user_data = super::windsurf_instance::get_default_windsurf_user_data_dir()?;
    let auth = super::windsurf_instance::read_profile_session_auth_status(&user_data)?;
    let Some(auth) = auth else {
        return Ok(NativeVerifyResult::NoSession);
    };
    let label = auth
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // An empty label doesn't rule out verification — the session's Devin
    // user id may still match the target account below.
    let Some(account) = super::windsurf_account::load_account(target_account_id) else {
        return Ok(NativeVerifyResult::Pending {
            session_label: Some(label),
        });
    };
    // Strongest available signal: the session's Devin user id vs the stored
    // `devin_account_id`. Display labels are NOT unique (same name different
    // person, same email different org), so when both ids are present the id
    // comparison is authoritative and label matching is skipped.
    let session_account_id = auth
        .get("_switcherDesktopAccountId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let target_devin_id = account
        .devin_account_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let id_path = matches!(session_account_id, Some(_))
        && matches!(target_devin_id, Some(_));
    let matched = match (session_account_id, target_devin_id) {
        (Some(sid), Some(tid)) => sid == tid,
        _ => {
            // Fallback for legacy accounts without a Devin user id: match
            // the official session label against every stored identity.
            let raw = account.windsurf_auth_status_raw.as_ref();
            let raw_field =
                |p: &str| raw.and_then(|v| v.pointer(p)).and_then(Value::as_str);
            let candidates = [
                Some(account.github_login.as_str()),
                account.github_name.as_deref(),
                account.github_email.as_deref(),
                target_devin_id,
                raw_field("/name"),
                raw_field("/email"),
                raw_field("/user/name"),
                raw_field("/user/email"),
                raw_field("/account/label"),
            ];
            if label.is_empty() {
                false
            } else {
                let lower = label.to_lowercase();
                candidates
                    .iter()
                    .flatten()
                    .map(|s| s.trim().to_lowercase())
                    .any(|c| !c.is_empty() && c == lower)
            }
        }
    };
    // Ambiguity guard: never claim Verified when the observed identity is
    // shared by another stored account — e.g. the same Devin user under a
    // different org, or two accounts with the same login email. The session
    // record carries no org field, so local checks cannot disambiguate;
    // `Pending` is the honest answer (and `mark_verified` won't apply).
    // Fail-closed: if the account store can't be enumerated completely,
    // "couldn't check" is NOT "no ambiguity" — report Pending.
    let all_accounts = match super::windsurf_account::list_accounts_strict() {
        Ok(list) => list,
        Err(_) => {
            return Ok(NativeVerifyResult::Pending {
                session_label: if label.is_empty() {
                    None
                } else {
                    Some(label)
                },
            });
        }
    };
    let ambiguous = matched
        && all_accounts
            .iter()
            .any(|a| {
                if a.id == account.id {
                    return false;
                }
                if id_path {
                    a.devin_account_id
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        == target_devin_id
                } else {
                    let raw = a.windsurf_auth_status_raw.as_ref();
                    let f = |p: &str| {
                        raw.and_then(|v| v.pointer(p)).and_then(Value::as_str)
                    };
                    let lower = label.to_lowercase();
                    [
                        Some(a.github_login.as_str()),
                        a.github_name.as_deref(),
                        a.github_email.as_deref(),
                        a.devin_account_id.as_deref(),
                        f("/name"),
                        f("/email"),
                        f("/user/name"),
                        f("/user/email"),
                        f("/account/label"),
                    ]
                    .iter()
                    .flatten()
                    .map(|s| s.trim().to_lowercase())
                    .any(|c| !c.is_empty() && c == lower)
                }
            });
    if matched && !ambiguous {
        Ok(NativeVerifyResult::Verified {
            session_label: label,
        })
    } else {
        Ok(NativeVerifyResult::Pending {
            session_label: Some(label),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_uri_encodes_token_into_fragment() {
        let uri = login_uri("ott$abc$+/=?");
        assert!(uri.starts_with("devin://codeium.windsurf/#access_token="));
        assert!(uri.contains("ott%24abc%24%2B%2F%3D%3F"));
        assert!(!uri.contains("ott$"));
    }

    #[test]
    fn verify_result_uses_frontend_field_and_state_names() {
        // IPC contract: `state` uses snake_case values, `sessionLabel` is
        // camelCase — enum-level rename_all does NOT cover variant fields.
        let pending = serde_json::to_value(NativeVerifyResult::Pending {
            session_label: Some("synthetic".into()),
        })
        .unwrap();
        assert_eq!(pending["state"], "pending");
        assert_eq!(pending["sessionLabel"], "synthetic");
        assert!(pending.get("session_label").is_none());
        let verified = serde_json::to_value(NativeVerifyResult::Verified {
            session_label: "x".into(),
        })
        .unwrap();
        assert_eq!(verified["state"], "verified");
        assert_eq!(verified["sessionLabel"], "x");
        let none = serde_json::to_value(NativeVerifyResult::NoSession).unwrap();
        assert_eq!(none["state"], "no_session");
    }

    #[test]
    fn decision_kind_is_a_plain_string_not_a_tagged_object() {
        // RotationDecision.kind must serialize as a string for the frontend
        // union type; internally-tagging would nest an object.
        let v = serde_json::to_value(
            crate::modules::rotation_policy::DecisionKind::Recommendation,
        )
        .unwrap();
        assert_eq!(v, "recommendation");
        let v = serde_json::to_value(
            crate::modules::rotation_policy::DecisionKind::Blocked,
        )
        .unwrap();
        assert_eq!(v, "blocked");
    }

    #[test]
    fn acceptable_tokens_are_only_ott_and_oidc() {
        assert!(looks_like_uri_acceptable_token("ott$x"));
        assert!(looks_like_uri_acceptable_token("oidc$x"));
        assert!(!looks_like_uri_acceptable_token("devin-session-token$x"));
        assert!(!looks_like_uri_acceptable_token("sk-ws-x"));
        assert!(!looks_like_uri_acceptable_token("auth1_x"));
    }
}
