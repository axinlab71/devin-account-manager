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
//! 2. A stored `oidc$` credential when there is no session to mint from.
//! Stored `ott$` values are never replayed: they may already be consumed.
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
/// Fragment mirrors the OAuth completion redirect the official client
/// expects: `#access_token=…&state=…&token_type=Bearer` with no `/`
/// before `#` — a bare `access_token` fragment is ignored by the handler.
fn login_uri(access_token: &str) -> String {
    debug_assert!(looks_like_uri_acceptable_token(access_token));
    format!(
        "{}#access_token={}&state={}&token_type=Bearer",
        OFFICIAL_LOGIN_URI_PREFIX,
        encode_uri_component(access_token),
        uuid::Uuid::new_v4()
    )
}

fn looks_like_uri_acceptable_token(token: &str) -> bool {
    token.starts_with("ott$") || token.starts_with("oidc$")
}

/// Read-only credential check: does the account hold a credential the
/// official URI handler could consume — either the devin-session fields
/// used to mint a fresh one-time token, or a stored `oidc$` credential?
/// This is a precondition, not proof the official client will accept
/// the login — that needs real-client validation. Exposed to the UI so
/// unsupported accounts can be labeled before the user clicks;
/// `execute` still re-resolves the credential at launch.
/// Locate a Devin session token anywhere it can be stored: the dedicated
/// field (auth1-derived accounts), or the generic credential slots used by
/// session-token imports, browser OAuth and local-client imports.
fn find_devin_session_token(
    account: &crate::models::windsurf::WindsurfAccount,
) -> Option<&str> {
    [
        account.devin_session_token.as_deref(),
        account.windsurf_auth_token.as_deref(),
        account.windsurf_api_key.as_deref(),
        Some(account.github_access_token.as_str()),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .find(|s| s.starts_with("devin-session-token$"))
}

fn find_stored_uri_token(
    account: &crate::models::windsurf::WindsurfAccount,
) -> Option<&str> {
    [&account.windsurf_auth_token, &account.windsurf_api_key]
        .into_iter()
        .filter_map(|t| t.as_deref())
        .map(str::trim)
        .find(|t| t.starts_with("oidc$") && t.len() > "oidc$".len())
}

pub fn has_uri_compatible_credential(
    account: &crate::models::windsurf::WindsurfAccount,
) -> bool {
    find_devin_session_token(account).is_some() || find_stored_uri_token(account).is_some()
}

/// Which credential went into the URI — surfaced (not the token itself) in
/// the outcome message so a server-side rejection can be told apart from a
/// mint failure that silently fell back to a possibly-stale stored token.
enum TokenSource {
    MintedOtt,
    StoredOidc,
}

/// Pick a credential the official handler can consume, minting a fresh
/// one-time token from a stored devin-session credential when available.
/// auth1/account/org headers are sent only when present — a session token
/// alone may still be accepted by the official endpoint; if it is not, the
/// launch fails before URI dispatch, without trying older credentials.
/// Returns `Err(code)` when no usable credential exists.
async fn resolve_login_token(
    account: &crate::models::windsurf::WindsurfAccount,
) -> Result<(String, TokenSource), String> {
    let session = find_devin_session_token(account);
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
    if let Some(session) = session {
        let client = super::windsurf_devin_oauth::build_client()?;
        // Never conceal a mint failure by replaying an older credential.
        let ott = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            super::windsurf_devin_oauth::get_one_time_auth_token(
                &client, session, auth1, acc_id, org_id,
            ),
        ).await.map_err(|_| "ott_mint_timeout".to_string())??;
        return Ok((ott, TokenSource::MintedOtt));
    }

    if let Some(t) = find_stored_uri_token(account) {
        return Ok((t.to_string(), TokenSource::StoredOidc));
    }
    Err("no_uri_compatible_credential".to_string())
}

/// How far our URI observably traveled. A new client log-session dir only
/// proves a second `Devin.exe` was *spawned* (it forwards the URI to the
/// running instance); handler trace lines appended to a `renderer.log`
/// prove the URI actually reached the extension's auth handler.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryEvidence {
    ClientProcess,
    ExtensionHandler,
}

/// URI-handler trace markers the official extension writes to
/// `window*/renderer.log` while handling auth URIs — observed live as
/// `Failed to handle auth redirect URI` plus `maybeHandleUriWithToken` /
/// `handleAuthToken` / `handleCodeiumAuthToken` in its stack trace. Any of
/// them appearing AFTER our launch counts as handler-level delivery.
#[cfg(target_os = "windows")]
const URI_HANDLER_MARKERS: &[&str] = &[
    "maybeHandleUriWithToken",
    "handleAuthToken",
    "handleCodeiumAuthToken",
    "auth redirect URI",
];

#[cfg(target_os = "windows")]
fn appended_text_has_uri_marker(text: &str) -> bool {
    URI_HANDLER_MARKERS.iter().any(|m| text.contains(m))
}

/// Every `window*/renderer.log` under a logs root (any session dir).
#[cfg(target_os = "windows")]
fn renderer_logs(logs_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(sessions) = std::fs::read_dir(logs_dir) else {
        return out;
    };
    for session in sessions.flatten() {
        let Ok(windows) = std::fs::read_dir(session.path()) else {
            continue;
        };
        for w in windows.flatten() {
            let p = w.path().join("renderer.log");
            if p.is_file() {
                out.push(p);
            }
        }
    }
    out
}

/// Read only bytes appended to `path` after `offset` and look for a URI
/// handler marker. Existing content never counts — the client may hold
/// old handler traces from previous launches.
#[cfg(target_os = "windows")]
fn log_grew_with_uri_marker(path: &std::path::Path, offset: u64) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let Ok(meta) = f.metadata() else {
        return false;
    };
    if meta.len() <= offset {
        return false;
    }
    if f.seek(SeekFrom::Start(offset)).is_err() {
        return false;
    }
    let mut buf = Vec::with_capacity(256 * 1024);
    let take = (meta.len() - offset).min(256 * 1024);
    if f.take(take).read_to_end(&mut buf).is_err() {
        return false;
    }
    appended_text_has_uri_marker(&String::from_utf8_lossy(&buf))
}

/// Poll up to `secs` for delivery evidence: handler-level trace beats
/// process-level; a new session dir alone still counts as ClientProcess.
#[cfg(target_os = "windows")]
async fn await_delivery_evidence(
    logs_dir: &std::path::Path,
    existing_sessions: &std::collections::HashSet<String>,
    log_offsets: std::collections::HashMap<std::path::PathBuf, u64>,
    secs: u64,
) -> Option<DeliveryEvidence> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut saw_new_session = false;
    while std::time::Instant::now() < deadline {
        if let Ok(rd) = std::fs::read_dir(logs_dir) {
            for e in rd.flatten() {
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false)
                    && !existing_sessions.contains(&e.file_name().to_string_lossy().into_owned())
                {
                    saw_new_session = true;
                }
            }
        }
        for path in renderer_logs(logs_dir) {
            let offset = log_offsets.get(&path).copied().unwrap_or(0);
            if log_grew_with_uri_marker(&path, offset) {
                return Some(DeliveryEvidence::ExtensionHandler);
            }
        }
        if saw_new_session {
            // Delivery is not login success. Return immediately and let the
            // independent identity check observe completion, rather than
            // delaying feedback two seconds for optional diagnostic traces.
            return Some(DeliveryEvidence::ClientProcess);
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    if saw_new_session {
        Some(DeliveryEvidence::ClientProcess)
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
async fn launch_uri(uri: &str) -> Result<DeliveryEvidence, String> {
    use std::os::windows::process::CommandExt;
    // PowerShell Start-Process delegates to ShellExecute → the registered
    // `devin://` handler (`Devin.exe --open-url -- %1`). rundll32's
    // FileProtocolHandler is avoided because it is file-URL oriented and
    // can drop the `#fragment` carrying the access_token; the URI here
    // contains only percent-encoded characters, `=`, `&`, `#`, `:` — no
    // quotes — so single-quote wrapping is safe.
    //
    // ELECTRON_RUN_AS_NODE must NOT propagate: when this app (or the shell
    // it was launched from) runs inside a Devin/VS Code integrated terminal
    // the var is inherited, Devin.exe boots in Node mode and dies with
    // `bad option: --open-url` before the URI is forwarded — observed on
    // the live client. VSCODE_DEV likewise switches data dirs.
    let logs_dir = super::windsurf_instance::get_default_windsurf_user_data_dir()
        .ok()
        .map(|p| p.join("logs"));
    let Some(logs_dir) = logs_dir else {
        return Err("uri_delivery_unconfirmed".to_string());
    };
    let existing_sessions: std::collections::HashSet<String> = std::fs::read_dir(&logs_dir)
        .map(|rd| {
            rd.filter_map(|e| {
                e.ok().map(|e| e.file_name().to_string_lossy().into_owned())
            })
            .collect()
        })
        .unwrap_or_default();
    // Snapshot current renderer.log sizes so only content appended after
    // this launch counts as handler evidence.
    let log_offsets: std::collections::HashMap<std::path::PathBuf, u64> =
        renderer_logs(&logs_dir)
            .into_iter()
            .map(|p| {
                let len = p.metadata().map(|m| m.len()).unwrap_or(0);
                (p, len)
            })
            .collect();
    let mut child = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("Start-Process '{uri}'"),
        ])
        .env_remove("ELECTRON_RUN_AS_NODE")
        .env_remove("VSCODE_DEV")
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn()
        .map_err(|e| format!("无法调用系统协议分发: {e}"))?;
    // Wait for the launcher — but with a hard bound: a hung PowerShell must
    // not hold the client-operation lock forever. On timeout kill it and
    // fall through to the delivery probe, which can still observe the URI.
    let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if !status.success() => {
                return Err(format!("系统协议分发进程退出码异常: {status}"));
            }
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= wait_deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => return Err(format!("等待协议分发进程失败: {e}")),
        }
    }
    await_delivery_evidence(&logs_dir, &existing_sessions, log_offsets, 6)
        .await
        .ok_or_else(|| "uri_delivery_unconfirmed".to_string())
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
        let (token, source) = match resolve_login_token(&account).await {
            Ok(t) => t,
            Err(code) => {
                let (failure, message) = if code == "no_uri_compatible_credential" {
                    (
                        code.as_str(),
                        "此账号缺少可生成新登录凭据的会话。已保存的一次性令牌不能重复使用；请重新网页登录或导入官方客户端当前账号，或使用标准切号。",
                    )
                } else {
                    (
                        "ott_mint_failed",
                        "未能获取新的登录凭据，尚未向 Devin 发送登录请求，也未回退使用旧一次性令牌。请检查网络或刷新账号后重试；也可使用标准切号。",
                    )
                };
                return blocked(failure, message);
            }
        };
        let evidence = match launch_uri(&login_uri(&token)).await {
            Ok(e) => e,
            Err(e) => {
                let msg = if e == "uri_delivery_unconfirmed" {
                    "URI 已交给系统分发，但未观察到 Devin 客户端响应（可能未送达，也可能仍在处理——请稍候点击「验证生效」核对后再决定是否重试）。"
                } else {
                    &e
                };
                return blocked(
                    if e == "uri_delivery_unconfirmed" {
                        "uri_delivery_unconfirmed"
                    } else {
                        "uri_launch_failed"
                    },
                    msg,
                );
            }
        };
        SwitchOutcome {
            target_account_id: target_account_id.to_string(),
            adapter: Some(AdapterKind::Native),
            restart_required: false,
            local_match: Verification::NotAttempted,
            client_recognized: Verification::NotAttempted,
            remote_verified: Verification::NotAttempted,
            rollback: RollbackStatus::NotNeeded,
            failure_code: None,
            message: format!(
                "{}（凭据来源：{}）。服务端登录结果未知——请稍候点击「验证生效」核对身份。",
                match evidence {
                    DeliveryEvidence::ExtensionHandler => {
                        "已确认 URI 进入 Devin 扩展处理器"
                    }
                    DeliveryEvidence::ClientProcess => {
                        "已确认 Devin 客户端进程收到分发（未观察到扩展处理痕迹）"
                    }
                },
                match source {
                    TokenSource::MintedOtt => "服务端新铸一次性令牌",
                    TokenSource::StoredOidc => "账号内已存的 OIDC 凭据",
                }
            ),
        }
    }
}

/// Result of the remote probe run after a local session match: a read-only
/// `GetUserStatus` call with the client's own current session token.
/// `Passed` proves the backend accepts the token (strong evidence the
/// login produced a working credential — still not proof the ACP agent
/// uses this identity; only a real AI request shows that). `Rejected`
/// means 401/403. `Unavailable` covers transport errors or a session
/// shape we cannot probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteCheck {
    Passed,
    Rejected,
    Unavailable,
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
        /// Outcome of the remote session-token probe (`remoteStatus` in IPC).
        #[serde(rename = "remoteStatus")]
        remote_status: RemoteCheck,
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

impl NativeVerifyResult {
    /// Only a matched identity with an accepted remote credential completes
    /// the operation. Offline/rejected checks keep the recovery gate intact.
    pub fn completes_switch(&self) -> bool {
        matches!(self, Self::Verified { remote_status: RemoteCheck::Passed, .. })
    }
}

/// Read-only verification: decrypt the client's stored session (same read
/// path as the existing auth-status reader; never writes) and compare the
/// session account label against the target account's known identities.
#[cfg(not(target_os = "windows"))]
pub async fn verify(_target_account_id: &str) -> Result<NativeVerifyResult, String> {
    Err("官方会话读取目前仅在 Windows 上实现".into())
}

/// Probe whether the official backend accepts the session token the client
/// currently holds — the same read-only `GetUserStatus` call the quota
/// monitor already uses for stored credentials, applied to the *client's*
/// token. Read-only: no writes, no retry.
#[cfg(target_os = "windows")]
async fn remote_session_check(auth: &Value) -> RemoteCheck {
    let token = auth
        .get("sessionToken")
        .or_else(|| auth.get("apiKey"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(token) = token else {
        return RemoteCheck::Unavailable;
    };
    match tokio::time::timeout(
        std::time::Duration::from_secs(6),
        super::windsurf_devin_oauth::fetch_devin_user_status_detailed(token),
    ).await {
        Ok(Ok(_)) => RemoteCheck::Passed,
        Ok(Err(super::windsurf_devin_oauth::UserStatusError::Http { status, .. }))
            if status == 401 || status == 403 =>
        {
            RemoteCheck::Rejected
        }
        _ => RemoteCheck::Unavailable,
    }
}

#[cfg(target_os = "windows")]
pub async fn verify(target_account_id: &str) -> Result<NativeVerifyResult, String> {
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
        // Local identity matched — additionally probe whether the backend
        // accepts the client's current session token. The probe result is
        // diagnostic: a local match still verifies the switch record even
        // when the remote check is unavailable (offline, proxy…).
        let remote_status = remote_session_check(&auth).await;
        Ok(NativeVerifyResult::Verified {
            session_label: label,
            remote_status,
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
    fn stored_one_time_token_is_not_a_reusable_switch_credential() {
        let mut account = crate::models::windsurf::WindsurfAccount::default();
        account.windsurf_auth_token = Some("ott$synthetic-already-consumed".into());
        account.windsurf_api_key = Some("ott$another-old-token".into());
        assert!(!has_uri_compatible_credential(&account));
        assert!(find_stored_uri_token(&account).is_none());
        account.devin_session_token = Some("devin-session-token$synthetic".into());
        assert!(has_uri_compatible_credential(&account));
        account.devin_session_token = None;
        account.windsurf_api_key = Some("oidc$synthetic".into());
        assert!(has_uri_compatible_credential(&account));
        assert_eq!(find_stored_uri_token(&account), Some("oidc$synthetic"));
        account.windsurf_api_key = Some("oidc$".into());
        assert!(!has_uri_compatible_credential(&account));
    }

    #[test]
    fn rejected_or_unavailable_remote_check_does_not_complete_switch() {
        for remote_status in [RemoteCheck::Rejected, RemoteCheck::Unavailable] {
            assert!(!NativeVerifyResult::Verified {
                session_label: "synthetic".into(), remote_status,
            }.completes_switch());
        }
        assert!(NativeVerifyResult::Verified {
            session_label: "synthetic".into(), remote_status: RemoteCheck::Passed,
        }.completes_switch());
        assert!(!NativeVerifyResult::Pending { session_label: None }.completes_switch());
        assert!(!NativeVerifyResult::NoSession.completes_switch());
    }

    #[test]
    fn login_uri_encodes_token_into_fragment() {
        let uri = login_uri("ott$abc$+/=?");
        assert!(uri.starts_with("devin://codeium.windsurf#access_token="));
        assert!(uri.contains("ott%24abc%24%2B%2F%3D%3F"));
        assert!(uri.contains("&state="));
        assert!(uri.contains("&token_type=Bearer"));
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
            remote_status: RemoteCheck::Passed,
        })
        .unwrap();
        assert_eq!(verified["state"], "verified");
        assert_eq!(verified["sessionLabel"], "x");
        assert_eq!(verified["remoteStatus"], "passed");
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
    #[cfg(target_os = "windows")]
    fn uri_handler_markers_match_real_log_traces() {
        // The strings observed in window*/renderer.log when the extension
        // actually processes an auth URI.
        assert!(appended_text_has_uri_marker(
            "[Windsurf] Failed to handle auth redirect URI: Error: invalid auth token\n    at L.maybeHandleUriWithToken"
        ));
        assert!(appended_text_has_uri_marker(
            "at L.handleAuthToken (workbench.desktop.main.js"
        ));
        assert!(!appended_text_has_uri_marker(
            "ordinary renderer log line about something else"
        ));
        assert!(!appended_text_has_uri_marker(""));
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
