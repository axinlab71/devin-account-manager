//! Explicit IPC view: credentials and opaque auth payloads never leave Rust.
use crate::models::windsurf::WindsurfAccount;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;
use serde_json::{Map, Value};
#[derive(Serialize)]
pub struct AccountView {
    pub id: String,
    pub github_login: String,
    pub github_id: u64,
    pub github_name: Option<String>,
    pub github_email: Option<String>,
    pub tags: Option<Vec<String>>,
    pub copilot_plan: Option<String>,
    pub copilot_expires_at: Option<i64>,
    pub copilot_quota_snapshots: Option<Value>,
    pub copilot_limited_user_quotas: Option<Value>,
    pub copilot_quota_reset_date: Option<String>,
    pub copilot_limited_user_reset_date: Option<i64>,
    pub windsurf_plan_status: Option<Value>,
    pub windsurf_user_status: Option<Value>,
    pub usage_proto_b64: Option<String>,
    pub display_token_claims: Map<String, Value>,
    pub quota_query_last_error: Option<String>,
    pub quota_query_last_error_at: Option<i64>,
    pub usage_updated_at: Option<i64>,
    pub created_at: i64,
    pub last_used: i64,
    pub last_switched_at: Option<i64>,
    pub credentials_updated_at: Option<i64>,
    pub credential_state: &'static str,
    /// The account holds a credential the official URI login could
    /// consume — a precondition only, NOT proof the client accepts it.
    /// UI affordance; launch re-checks, success needs real validation.
    pub native_switch_credential_ready: bool,
}
fn plan(raw: &str) -> Option<String> {
    let v = raw.trim().to_uppercase().replace([' ', '-'], "_");
    let v = v
        .strip_prefix("WINDSURF_")
        .or_else(|| v.strip_prefix("TEAMS_TIER_"))
        .unwrap_or(&v)
        .to_string();
    match v.as_str() {
        "FREE" | "FREE_LIMITED" | "TRIAL" | "FREE_TRIAL" | "PRO" | "INDIVIDUAL"
        | "INDIVIDUAL_PRO" | "PRO_ULTIMATE" | "TEAMS" | "TEAM" | "TEAMS_ULTIMATE" | "BUSINESS"
        | "ENTERPRISE" | "UNKNOWN" => Some(v),
        _ => None,
    }
}
fn safe_value(value: &Value, depth: usize) -> Option<Value> {
    if depth > 12 {
        return None;
    }
    let object = value.as_object()?;
    let mut out = Map::new();
    for (k, v) in object {
        if !USAGE_KEYS.contains(&k.as_str()) {
            continue;
        }
        let safe = match v {
            Value::Object(_) => safe_value(v, depth + 1),
            Value::Number(_) | Value::Bool(_) => Some(v.clone()),
            Value::String(s) => {
                if matches!(
                    k.as_str(),
                    "planName" | "plan_name" | "teamsTier" | "teams_tier"
                ) {
                    plan(s).map(Value::String)
                } else if matches!(k.as_str(), "billingStrategy" | "billing_strategy") {
                    let t = s.to_uppercase();
                    [
                        "QUOTA",
                        "CREDITS",
                        "BILLING_STRATEGY_QUOTA",
                        "BILLING_STRATEGY_CREDITS",
                    ]
                    .contains(&t.as_str())
                    .then_some(Value::String(t))
                } else if s.len() < 48
                    && !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_digit() || ".-:+TZ ".contains(c))
                {
                    Some(v.clone())
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(safe) = safe {
            out.insert(k.clone(), safe);
        }
    }
    (!out.is_empty()).then_some(Value::Object(out))
}
const USAGE_KEYS: &[&str] = &[
    "addOnCreditsAvailable",
    "add_on_credits_available",
    "availableAddOnCredits",
    "availableFlexCredits",
    "availablePromptCredits",
    "availableTopUpCredits",
    "available_add_on_credits",
    "available_flex_credits",
    "available_prompt_credits",
    "available_top_up_credits",
    "billingStrategy",
    "billing_strategy",
    "chat",
    "completions",
    "currentPeriodEnd",
    "currentPeriodStart",
    "current_period_end",
    "current_period_start",
    "dailyQuotaRemainingPercent",
    "dailyQuotaResetAtUnix",
    "daily_quota_remaining_percent",
    "daily_quota_reset_at_unix",
    "entitlement",
    "flexCreditsAvailable",
    "flex_credits_available",
    "limit",
    "monthlyAddOnCredits",
    "monthlyFlexCreditPurchaseAmount",
    "monthlyPromptCredits",
    "monthlyTopUpCredits",
    "monthly_add_on_credits",
    "monthly_flex_credit_purchase_amount",
    "monthly_prompt_credits",
    "monthly_top_up_credits",
    "nanos",
    "overageBalanceMicros",
    "overage_balance_micros",
    "percent_remaining",
    "planEnd",
    "planInfo",
    "planName",
    "planStart",
    "planStatus",
    "plan_end",
    "plan_name",
    "plan_start",
    "premium_interactions",
    "premium_models",
    "quotaUsage",
    "remaining",
    "seconds",
    "teamsTier",
    "teams_tier",
    "topUpCreditsAvailable",
    "top_up_credits_available",
    "total",
    "unlimited",
    "used",
    "usedAddOnCredits",
    "usedFlexCredits",
    "usedPromptCredits",
    "usedTopUpCredits",
    "used_add_on_credits",
    "used_flex_credits",
    "used_prompt_credits",
    "used_top_up_credits",
    "userStatus",
    "weeklyQuotaRemainingPercent",
    "weeklyQuotaResetAtUnix",
    "weekly_quota_remaining_percent",
    "weekly_quota_reset_at_unix",
    "windsurfPlanInfo",
    "windsurfPlanStatus",
    "windsurfUserStatus",
];
// Only copy known usage protobuf fields; discard user identity and every unknown field.
fn filter_proto(data: &[u8], kind: u8) -> Option<Vec<u8>> {
    use crate::utils::protobuf::{
        encode_len_delim_field, encode_varint_field, read_varint, skip_field,
    };
    if data.len() > 1024 * 1024 {
        return None;
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let (tag, start) = read_varint(data, at).ok()?;
        let field = (tag >> 3) as u32;
        let wire = (tag & 7) as u8;
        if wire == 0 {
            let (v, end) = read_varint(data, start).ok()?;
            let allowed = match kind {
                1 => matches!(field, 4 | 6 | 7 | 8 | 14 | 15 | 16 | 17 | 18),
                2 => matches!(field, 12 | 14),
                3 => field == 1,
                4 => field == 2,
                _ => false,
            };
            if allowed {
                out.extend(encode_varint_field(field, v));
            }
            at = end;
        } else if wire == 2 {
            let (len, pos) = read_varint(data, start).ok()?;
            let end = pos.checked_add(usize::try_from(len).ok()?)?;
            let part = data.get(pos..end)?;
            let child = match (kind, field) {
                (0, 13) => filter_proto(part, 1),
                (1, 1) => filter_proto(part, 2),
                (1, 2 | 3) => filter_proto(part, 3),
                (1, 10) => filter_proto(part, 4),
                (2, 2) => std::str::from_utf8(part)
                    .ok()
                    .and_then(plan)
                    .map(|s| s.into_bytes()),
                _ => None,
            };
            if let Some(child) = child {
                out.extend(encode_len_delim_field(field, &child));
            }
            at = end;
        } else {
            at = skip_field(data, start, wire).ok()?;
        }
    }
    Some(out)
}
impl From<&WindsurfAccount> for AccountView {
    fn from(a: &WindsurfAccount) -> Self {
        let usage_proto_b64 = a
            .devin_user_status_proto_b64
            .as_deref()
            .or_else(|| {
                a.windsurf_auth_status_raw
                    .as_ref()?
                    .get("userStatusProtoBinaryBase64")?
                    .as_str()
            })
            .or_else(|| {
                a.windsurf_auth_status_raw
                    .as_ref()?
                    .get("userStatusProtoBinary")?
                    .as_str()
            })
            .and_then(|s| STANDARD.decode(s).ok())
            .and_then(|b| filter_proto(&b, 0))
            .filter(|b| !b.is_empty())
            .map(|b| STANDARD.encode(b));
        let mut claims = Map::new();
        for part in a.copilot_token.split(';') {
            if let Some((k, v)) = part.split_once('=') {
                let k = k.trim();
                let value = if k == "sku" {
                    plan(v).map(Value::String)
                } else if ["cq", "tq", "rd"].contains(&k) {
                    v.split(':')
                        .next()
                        .and_then(|s| s.parse::<u64>().ok())
                        .map(|n| Value::String(n.to_string()))
                } else {
                    None
                };
                if let Some(v) = value {
                    claims.insert(k.into(), v);
                }
            }
        }
        let clean = |v: &Option<Value>| v.as_ref().and_then(|v| safe_value(v, 0));
        Self {
            id: a.id.clone(),
            github_login: a.github_login.clone(),
            github_id: a.github_id,
            github_name: a.github_name.clone().or_else(|| {
                a.windsurf_auth_status_raw
                    .as_ref()?
                    .get("name")?
                    .as_str()
                    .map(str::to_string)
            }),
            github_email: a.github_email.clone().or_else(|| {
                a.windsurf_auth_status_raw
                    .as_ref()?
                    .get("email")?
                    .as_str()
                    .map(str::to_string)
            }),
            tags: a.tags.clone(),
            copilot_plan: a.copilot_plan.as_deref().and_then(plan),
            copilot_expires_at: a.copilot_expires_at,
            copilot_quota_snapshots: clean(&a.copilot_quota_snapshots),
            copilot_limited_user_quotas: clean(&a.copilot_limited_user_quotas),
            copilot_quota_reset_date: a
                .copilot_quota_reset_date
                .as_ref()
                .filter(|s| {
                    s.len() < 48
                        && s.chars()
                            .all(|c| c.is_ascii_digit() || ".-:+TZ ".contains(c))
                })
                .cloned(),
            copilot_limited_user_reset_date: a.copilot_limited_user_reset_date,
            windsurf_plan_status: clean(&a.windsurf_plan_status),
            windsurf_user_status: clean(&a.windsurf_user_status),
            usage_proto_b64,
            display_token_claims: claims,
            quota_query_last_error: a
                .quota_query_last_error
                .as_ref()
                .map(|_| "额度查询失败，请稍后重试".into()),
            quota_query_last_error_at: a.quota_query_last_error_at,
            usage_updated_at: a.usage_updated_at,
            created_at: a.created_at,
            last_used: a.last_used,
            last_switched_at: a.last_switched_at,
            credentials_updated_at: a.credentials_updated_at,
            credential_state: if a
                .copilot_expires_at
                .is_some_and(|t| t < chrono::Utc::now().timestamp())
            {
                "expired"
            } else {
                "unverified"
            },
            native_switch_credential_ready: super::native_switch::has_uri_compatible_credential(a),
        }
    }
}
pub fn views(accounts: Vec<WindsurfAccount>) -> Vec<AccountView> {
    accounts.iter().map(AccountView::from).collect()
}
