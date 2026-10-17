use crate::models::windsurf::{WindsurfAccount, WindsurfOAuthCompletePayload};
fn clean(v: Option<&str>) -> Option<&str> {
    v.map(str::trim).filter(|s| !s.is_empty())
}
fn ids<'a>(a: Option<&'a str>, o: Option<&'a str>) -> Option<(&'a str, Option<&'a str>)> {
    Some((clean(a)?, clean(o)))
}
fn raw_id<'a>(raw: Option<&'a serde_json::Value>, key: &str) -> Option<&'a str> {
    raw.and_then(|v| v.get(key))
        .and_then(|v| v.as_str())
        .and_then(|s| clean(Some(s)))
}
pub fn scope(a: &WindsurfAccount) -> (Option<&str>, Option<&str>) {
    (
        clean(a.devin_account_id.as_deref())
            .or_else(|| raw_id(a.windsurf_auth_status_raw.as_ref(), "accountId")),
        clean(a.devin_org_id.as_deref())
            .or_else(|| raw_id(a.windsurf_auth_status_raw.as_ref(), "primaryOrgId")),
    )
}
pub fn payload_scope(a: &WindsurfOAuthCompletePayload) -> (Option<&str>, Option<&str>) {
    (
        clean(a.devin_account_id.as_deref())
            .or_else(|| raw_id(a.windsurf_auth_status_raw.as_ref(), "accountId")),
        clean(a.devin_org_id.as_deref())
            .or_else(|| raw_id(a.windsurf_auth_status_raw.as_ref(), "primaryOrgId")),
    )
}
pub fn same(a: &WindsurfAccount, b: &WindsurfAccount) -> bool {
    match (ids(scope(a).0, scope(a).1), ids(scope(b).0, scope(b).1)) {
        (Some(a), Some(b)) => a == b,
        (Some(_), None) | (None, Some(_)) => false,
        (None, None) => {
            a.id == b.id
                || (a.github_id > 0
                    && a.github_id == b.github_id
                    && clean(Some(&a.github_access_token))
                        .is_some_and(|t| t == b.github_access_token))
        }
    }
}
pub fn matches_payload(a: &WindsurfAccount, b: &WindsurfOAuthCompletePayload) -> bool {
    match (
        ids(scope(a).0, scope(a).1),
        ids(payload_scope(b).0, payload_scope(b).1),
    ) {
        (Some(a), Some(b)) => a == b,
        (Some(_), None) | (None, Some(_)) => false,
        (None, None) => {
            a.github_id > 0
                && a.github_id == b.github_id
                && a.github_access_token == b.github_access_token
        }
    }
}
pub fn scoped_id(id: &str, account: Option<&str>, org: Option<&str>) -> String {
    match ids(account, org) {
        Some((a, o)) => format!("windsurf_devin_{:x}", {
            use sha2::Digest;
            sha2::Sha256::digest(serde_json::to_vec(&(a, o)).expect("identity strings serialize"))
        }),
        None => id.into(),
    }
}

pub fn validate_refresh(
    a: &WindsurfAccount,
    b: &WindsurfOAuthCompletePayload,
) -> Result<(), String> {
    let (old_id, old_org) = scope(a);
    let (new_id, new_org) = payload_scope(b);
    if old_id.zip(new_id).is_some_and(|(a, b)| a != b)
        || old_org.zip(new_org).is_some_and(|(a, b)| a != b)
    {
        return Err("官方返回的账号或组织与已保存身份不同，已保留原账号。请在官方客户端选择目标组织后重新导入。".into());
    }
    Ok(())
}

/// Identity signals the client session reader produces:
/// - `_switcherDesktopAccountId`: the session's Devin user id — survives a
///   URI/native login where the stored access token is brand new and
///   matches none of our stored credentials.
/// - `name`/`email`: the official session label — weaker, used only when it
///   uniquely identifies one stored account.
/// A shared session token alone cannot distinguish multiple organizations.
pub fn current_id(local: &serde_json::Value, accounts: &[WindsurfAccount]) -> Option<String> {
    let text = |key: &str| {
        local
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
    };
    // Strongest post-login signal: the session's Devin user id vs the
    // account's stored `devin_account_id`/auth-raw `accountId`. Works even
    // when the client's new session token is unknown to us.
    if let Some(desktop_id) = text("_switcherDesktopAccountId") {
        let matches: Vec<_> = accounts
            .iter()
            .filter(|a| scope(a).0 == Some(desktop_id))
            .collect();
        if matches.len() == 1 {
            return Some(matches[0].id.clone());
        }
        // Ambiguous (same Devin user under different stored orgs) — fall
        // through to the token check which may still disambiguate.
    }
    let matches: Vec<_> = accounts
        .iter()
        .filter(|a| {
            if text("accountId").is_some_and(|id| scope(a).0 != Some(id))
                || text("primaryOrgId").is_some_and(|id| scope(a).1 != Some(id))
            {
                return false;
            }
            ["apiKey", "sessionToken"]
                .iter()
                .filter_map(|k| text(k))
                .any(|t| {
                    a.windsurf_api_key.as_deref() == Some(t)
                        || a.windsurf_auth_token.as_deref() == Some(t)
                        || a.github_access_token == t
                })
        })
        .collect();
    if matches.len() == 1 {
        return Some(matches[0].id.clone());
    }
    // Last resort: the official session label exactly equals one stored
    // identity (login/email/name/auth-raw fields). Same rule as the
    // native-switch verify fallback — only a unique match counts.
    let label = text("name").or_else(|| text("email"))?;
    let lower = label.trim().to_lowercase();
    let matches: Vec<_> = accounts
        .iter()
        .filter(|a| {
            let raw = a.windsurf_auth_status_raw.as_ref();
            let raw_field = |p: &str| raw.and_then(|v| v.pointer(p)).and_then(|v| v.as_str());
            [
                Some(a.github_login.as_str()),
                a.github_name.as_deref(),
                a.github_email.as_deref(),
                a.devin_account_id.as_deref(),
                raw_field("/name"),
                raw_field("/email"),
                raw_field("/user/name"),
                raw_field("/user/email"),
                raw_field("/account/label"),
            ]
            .iter()
            .flatten()
            .map(|s| s.trim().to_lowercase())
            .any(|c| !c.is_empty() && c == lower)
        })
        .collect();
    if matches.len() == 1 {
        Some(matches[0].id.clone())
    } else {
        None
    }
}
