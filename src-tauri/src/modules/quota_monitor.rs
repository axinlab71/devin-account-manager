//! Quota snapshot model, stored-field extraction, and the read-only monitor.
//!
//! Phase-2 scope: produce trustworthy snapshots and deterministic decisions
//! WITHOUT writing to the official client. The monitor never triggers
//! registration, token exchange, client writes, or long-term credential
//! refresh — it only issues the same read-only user-status query the manual
//! refresh path already performs. Failed/expired credentials surface as
//! `NoUsableCredential`/`AuthRejected` and the user is told to use the
//! existing manual refresh.
//!
//! Semantics honesty: `availablePromptCredits` is documented as "monthly
//! total" by the frontend parser and as "remaining" by an upstream comment.
//! Limits derived from ambiguous fields are marked
//! [`SemanticsConfidence::UnverifiedMapping`] and can produce at most an
//! informational warning — never an executable recommendation.

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::windsurf::WindsurfAccount;
use crate::modules::rotation_state::{RotationMode, RotationState};
use crate::modules::{rotation_policy, rotation_state, windsurf_devin_oauth};

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------- Snapshot model ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    DailyWindow,
    WeeklyWindow,
    PromptCredits,
    FlowCredits,
    FlexCredits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitApplicability {
    Applicable,
    NotApplicable,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaLimit {
    pub kind: LimitKind,
    pub applicability: LimitApplicability,
    /// Remaining percent 0..=100 when the source expresses it directly.
    /// Absent when unknown — never zero-filled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent_remaining: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_units: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_units: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_at_ms: Option<i64>,
}

/// How well the field→limit mapping is understood for this snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticsConfidence {
    /// Every limit came from fields with one agreed meaning.
    Verified,
    /// At least one limit was derived from a field whose meaning is in
    /// dispute (e.g. availablePromptCredits) or from an unverified source
    /// shape. Informational warnings only.
    UnverifiedMapping,
}

/// Failure classification for a single account query. Distinct kinds drive
/// distinct policy/backoff behaviour — 429 is NOT exhaustion.
impl QueryFailure {
    /// Generic, credential-free message persisted onto the account card.
    pub fn user_message(&self) -> &'static str {
        match self {
            QueryFailure::AuthRejected => "凭据已失效，请手动刷新该账号",
            QueryFailure::PolicyDenied => "服务端拒绝额度查询",
            QueryFailure::RateLimited { .. } => "额度查询被限流",
            QueryFailure::Network => "额度查询网络错误",
            QueryFailure::ServerError { .. } => "额度查询服务端错误",
            QueryFailure::ParseFailed => "额度响应解析失败",
            QueryFailure::NoUsableCredential => "缺少可用凭据，请手动刷新该账号",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum QueryFailure {
    /// 401 / explicit credential rejection. Prompt manual refresh.
    AuthRejected,
    /// 403 / policy denial. Do not retry aggressively.
    PolicyDenied,
    /// 429 rate limit with optional server-provided Retry-After (ms).
    RateLimited {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<i64>,
    },
    /// Transport-level failure (connect/TLS/timeout).
    Network,
    /// Other non-2xx, e.g. 5xx.
    ServerError { status: u16 },
    /// 2xx but body could not be interpreted.
    ParseFailed,
    /// Account has no credential usable for a read-only status query.
    NoUsableCredential,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum QueryHealth {
    Healthy,
    Failed { failure: QueryFailure },
}

/// Point-in-time quota observation for one account. Contains no credentials.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaSnapshot {
    /// Internal account id (manager storage id).
    pub account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devin_account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devin_org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_name: Option<String>,
    pub limits: Vec<QuotaLimit>,
    pub queried_at_ms: i64,
    pub confidence: SemanticsConfidence,
    pub health: QueryHealth,
}

impl QuotaSnapshot {
    /// Smallest remaining percent among applicable limits with a known
    /// percent. `None` when nothing applicable is measurable.
    pub fn min_applicable_percent(&self) -> Option<f64> {
        self.limits
            .iter()
            .filter(|l| l.applicability == LimitApplicability::Applicable)
            .filter_map(|l| l.percent_remaining)
            .fold(None, |acc, p| Some(acc.map_or(p, |a: f64| a.min(p))))
    }

    /// True when at least one applicable limit has a remaining percent at or
    /// below `threshold`. Unknown/not-applicable limits never count.
    pub fn is_low(&self, threshold: f64) -> bool {
        self.limits.iter().any(|l| {
            l.applicability == LimitApplicability::Applicable
                && l.percent_remaining.is_some_and(|p| p <= threshold)
        })
    }
}

// ---------- Extraction from stored/live plan JSON ----------

fn get_path<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = root;
    for seg in path {
        cur = cur.get(*seg)?;
    }
    Some(cur)
}

fn first_record<'a>(
    roots: &[Option<&'a Value>],
) -> Option<&'a serde_json::Map<String, Value>> {
    roots.iter().flatten().find_map(|v| v.as_object())
}

fn num_from(obj: Option<&serde_json::Map<String, Value>>, keys: &[&str]) -> Option<f64> {
    let obj = obj?;
    for k in keys {
        if let Some(v) = obj.get(*k) {
            match v {
                Value::Number(n) => {
                    if let Some(f) = n.as_f64() {
                        return Some(f);
                    }
                }
                Value::String(s) => {
                    if let Ok(f) = s.trim().parse::<f64>() {
                        return Some(f);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn secs_to_ms(v: Option<f64>) -> Option<i64> {
    v.map(|s| (s * 1000.0) as i64)
}

fn plan_status_obj<'a>(account: &'a WindsurfAccount) -> Option<&'a serde_json::Map<String, Value>> {
    {
        let candidates: &[Option<&Value>] = &[
            account
                .windsurf_plan_status
                .as_ref()
                .and_then(|v| get_path(v, &["planStatus"])),
            account.windsurf_plan_status.as_ref(),
            account
                .copilot_quota_snapshots
                .as_ref()
                .and_then(|v| get_path(v, &["windsurfPlanStatus", "planStatus"])),
            account
                .copilot_quota_snapshots
                .as_ref()
                .and_then(|v| get_path(v, &["windsurfPlanStatus"])),
            account
                .windsurf_user_status
                .as_ref()
                .and_then(|v| get_path(v, &["userStatus", "planStatus"])),
            account
                .windsurf_user_status
                .as_ref()
                .and_then(|v| get_path(v, &["planStatus"])),
            account
                .copilot_quota_snapshots
                .as_ref()
                .and_then(|v| get_path(v, &["windsurfUserStatus", "userStatus", "planStatus"])),
            account
                .copilot_quota_snapshots
                .as_ref()
                .and_then(|v| get_path(v, &["windsurfUserStatus", "planStatus"])),
        ];
        first_record(candidates)
    }
}

fn plan_info_obj<'a>(
    account: &'a WindsurfAccount,
    plan_status: Option<&'a serde_json::Map<String, Value>>,
) -> Option<&'a serde_json::Map<String, Value>> {
    let candidates: &[Option<&Value>] = &[
        plan_status.and_then(|ps| ps.get("planInfo")),
        account
            .windsurf_plan_status
            .as_ref()
            .and_then(|v| get_path(v, &["planStatus", "planInfo"])),
        account
            .windsurf_plan_status
            .as_ref()
            .and_then(|v| get_path(v, &["planInfo"])),
        account
            .copilot_quota_snapshots
            .as_ref()
            .and_then(|v| get_path(v, &["windsurfPlanInfo"])),
        account
            .copilot_quota_snapshots
            .as_ref()
            .and_then(|v| get_path(v, &["windsurfPlanStatus", "planStatus", "planInfo"])),
        account
            .copilot_quota_snapshots
            .as_ref()
            .and_then(|v| get_path(v, &["windsurfPlanStatus", "planInfo"])),
        account
            .windsurf_user_status
            .as_ref()
            .and_then(|v| get_path(v, &["userStatus", "planInfo"])),
        account
            .windsurf_user_status
            .as_ref()
            .and_then(|v| get_path(v, &["planInfo"])),
        account
            .copilot_quota_snapshots
            .as_ref()
            .and_then(|v| get_path(v, &["windsurfUserStatus", "userStatus", "planInfo"])),
    ];
    first_record(candidates)
}

fn str_from(obj: Option<&serde_json::Map<String, Value>>, keys: &[&str]) -> Option<String> {
    let obj = obj?;
    for k in keys {
        if let Some(s) = obj.get(*k).and_then(Value::as_str) {
            let s = s.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Mirror the frontend's normalizeProtoCreditsValue: values ≥1000, or
/// multiples of 100 ≥100, are hundredths; smaller values are already units.
fn credits_units(v: Option<f64>) -> Option<f64> {
    v.map(|x| {
        if x >= 1000.0 || (x >= 100.0 && x % 100.0 == 0.0) {
            x / 100.0
        } else {
            x
        }
    })
}

fn proto_summary(account: &WindsurfAccount) -> Option<crate::utils::protobuf::UserStatusQuotaSummary> {
    let b64 = account
        .devin_user_status_proto_b64
        .as_deref()
        .or_else(|| {
            account
                .windsurf_auth_status_raw
                .as_ref()?
                .get("userStatusProtoBinaryBase64")
                .or_else(|| {
                    account.windsurf_auth_status_raw.as_ref()?.get("userStatusProtoBinary")
                })?
                .as_str()
        })?;
    crate::utils::protobuf::parse_user_status_quota(b64)
}

/// Build a snapshot from the quota fields already stored on an account —
/// or from a live `GetUserStatus` response placed under the same key.
/// Pure function: no IO, no writes.
pub fn snapshot_from_stored(account: &WindsurfAccount, queried_at_ms: i64) -> QuotaSnapshot {
    let plan_status = plan_status_obj(account);
    let plan_info = plan_info_obj(account, plan_status);
    // Proto snapshot fills only fields the JSON shape didn't provide.
    let proto = proto_summary(account);

    let mut limits = Vec::new();
    let mut confidence = SemanticsConfidence::Verified;

    // Daily / weekly windows: remaining percent is explicit.
    for (idx, (kind, pct_keys, reset_keys)) in [
        (
            LimitKind::DailyWindow,
            &["dailyQuotaRemainingPercent", "daily_quota_remaining_percent"][..],
            &["dailyQuotaResetAtUnix", "daily_quota_reset_at_unix"][..],
        ),
        (
            LimitKind::WeeklyWindow,
            &["weeklyQuotaRemainingPercent", "weekly_quota_remaining_percent"][..],
            &["weeklyQuotaResetAtUnix", "weekly_quota_reset_at_unix"][..],
        ),
    ]
    .iter()
    .enumerate()
    {
        let (proto_pct, proto_reset) = match idx {
            0 => (
                proto.as_ref().and_then(|p| p.daily_remaining_percent),
                proto.as_ref().and_then(|p| p.daily_reset_at_secs.map(|s| s * 1000)),
            ),
            _ => (
                proto.as_ref().and_then(|p| p.weekly_remaining_percent),
                proto.as_ref().and_then(|p| p.weekly_reset_at_secs.map(|s| s * 1000)),
            ),
        };
        let pct = num_from(plan_status, pct_keys).or(proto_pct);
        let reset = secs_to_ms(num_from(plan_status, reset_keys)).or(proto_reset);
        if pct.is_none() && reset.is_none() {
            limits.push(QuotaLimit {
                kind: *kind,
                applicability: LimitApplicability::Unknown,
                percent_remaining: None,
                remaining_units: None,
                total_units: None,
                reset_at_ms: None,
            });
        } else {
            limits.push(QuotaLimit {
                kind: *kind,
                applicability: LimitApplicability::Applicable,
                percent_remaining: pct.map(|p| p.clamp(0.0, 100.0)),
                remaining_units: None,
                total_units: None,
                reset_at_ms: reset,
            });
        }
    }

    // Prompt credits: monthlyPromptCredits is the total, usedPromptCredits is
    // consumed. `availablePromptCredits` is disputed (total per frontend
    // decoder vs remaining per upstream comment) — treat it as unverified.
    let monthly = credits_units(num_from(
        plan_info,
        &["monthlyPromptCredits", "monthly_prompt_credits"],
    ))
    .or_else(|| proto.as_ref().and_then(|p| p.prompt_credits_monthly));
    let used = credits_units(num_from(
        plan_status,
        &["usedPromptCredits", "used_prompt_credits"],
    ))
    .or_else(|| proto.as_ref().and_then(|p| p.prompt_credits_used));
    let available = credits_units(num_from(
        plan_status,
        &["availablePromptCredits", "available_prompt_credits"],
    ))
    .or_else(|| proto.as_ref().and_then(|p| p.prompt_credits_available));
    let (prompt_total, prompt_remaining) = match (monthly, used) {
        (Some(t), Some(u)) => (Some(t), Some((t - u).max(0.0))),
        // `available` standing in for "remaining" is an assumed mapping —
        // without `used` we cannot tell remaining vs total, so this path is
        // never Verified (blocks executable recommendations by design).
        (Some(t), None) => {
            if available.is_some() {
                confidence = SemanticsConfidence::UnverifiedMapping;
            }
            (Some(t), available)
        }
        (None, _) => {
            if available.is_some() {
                confidence = SemanticsConfidence::UnverifiedMapping;
            }
            (available, None)
        }
    };
    let prompt_applicability = if prompt_total.is_some() || used.is_some() {
        LimitApplicability::Applicable
    } else {
        LimitApplicability::Unknown
    };
    let prompt_pct = match (prompt_total, prompt_remaining) {
        (Some(t), Some(r)) if t > 0.0 => Some((r / t * 100.0).clamp(0.0, 100.0)),
        _ => None,
    };
    limits.push(QuotaLimit {
        kind: LimitKind::PromptCredits,
        applicability: prompt_applicability,
        percent_remaining: prompt_pct,
        remaining_units: prompt_remaining,
        total_units: prompt_total,
        reset_at_ms: None,
    });

    // Flex/add-on credits follow the same ambiguous "available" shape.
    let flex_monthly = credits_units(num_from(
        plan_info,
        &["monthlyFlexCredits", "monthly_flex_credits"],
    ))
    .or_else(|| proto.as_ref().and_then(|p| p.flex_credits_monthly));
    let flex_used = credits_units(num_from(
        plan_status,
        &["usedFlexCredits", "used_flex_credits"],
    ))
    .or_else(|| proto.as_ref().and_then(|p| p.flex_credits_used));
    let flex_available = credits_units(num_from(
        plan_status,
        &[
            "availableFlexCredits",
            "available_flex_credits",
            "availableAddOnCredits",
            "available_add_on_credits",
            "availableTopUpCredits",
            "available_top_up_credits",
        ],
    ))
    .or_else(|| proto.as_ref().and_then(|p| p.flex_credits_available));
    let (flex_total, flex_remaining) = match (flex_monthly, flex_used) {
        (Some(t), Some(u)) => (Some(t), Some((t - u).max(0.0))),
        (Some(t), None) => {
            if flex_available.is_some() {
                confidence = SemanticsConfidence::UnverifiedMapping;
            }
            (Some(t), flex_available)
        }
        (None, _) => {
            if flex_available.is_some() {
                confidence = SemanticsConfidence::UnverifiedMapping;
            }
            (flex_available, None)
        }
    };
    let flex_pct = match (flex_total, flex_remaining) {
        (Some(t), Some(r)) if t > 0.0 => Some((r / t * 100.0).clamp(0.0, 100.0)),
        _ => None,
    };
    limits.push(QuotaLimit {
        kind: LimitKind::FlexCredits,
        applicability: if flex_total.is_some() || flex_used.is_some() {
            LimitApplicability::Applicable
        } else {
            LimitApplicability::NotApplicable
        },
        percent_remaining: flex_pct,
        remaining_units: flex_remaining,
        total_units: flex_total,
        reset_at_ms: None,
    });

    // Flow credits: JSON-only (the proto map has no flow fields).
    let flow_monthly = credits_units(num_from(
        plan_info,
        &["monthlyFlowCredits", "monthly_flow_credits"],
    ));
    let flow_used = credits_units(num_from(
        plan_status,
        &["usedFlowCredits", "used_flow_credits"],
    ));
    let flow_available = credits_units(num_from(
        plan_status,
        &["availableFlowCredits", "available_flow_credits"],
    ));
    let (flow_total, flow_remaining) = match (flow_monthly, flow_used) {
        (Some(t), Some(u)) => (Some(t), Some((t - u).max(0.0))),
        (Some(t), None) => {
            if flow_available.is_some() {
                confidence = SemanticsConfidence::UnverifiedMapping;
            }
            (Some(t), flow_available)
        }
        (None, _) => {
            if flow_available.is_some() {
                confidence = SemanticsConfidence::UnverifiedMapping;
            }
            (flow_available, None)
        }
    };
    let flow_pct = match (flow_total, flow_remaining) {
        (Some(t), Some(r)) if t > 0.0 => Some((r / t * 100.0).clamp(0.0, 100.0)),
        _ => None,
    };
    limits.push(QuotaLimit {
        kind: LimitKind::FlowCredits,
        applicability: if flow_total.is_some() || flow_used.is_some() {
            LimitApplicability::Applicable
        } else {
            LimitApplicability::NotApplicable
        },
        percent_remaining: flow_pct,
        remaining_units: flow_remaining,
        total_units: flow_total,
        reset_at_ms: None,
    });

    let plan_name = str_from(plan_info, &["planName", "plan_name", "name"])
        .or_else(|| str_from(plan_status, &["planName", "plan_name"]))
        .or_else(|| proto.as_ref().and_then(|p| p.plan_name.clone()));

    QuotaSnapshot {
        account_id: account.id.clone(),
        devin_account_id: account.devin_account_id.clone(),
        devin_org_id: account.devin_org_id.clone(),
        plan_name,
        limits,
        queried_at_ms,
        confidence,
        health: QueryHealth::Healthy,
    }
}

/// Same extraction for a live `GetUserStatus` JSON response.
pub fn snapshot_from_status_response(
    account_id: &str,
    devin_account_id: Option<String>,
    devin_org_id: Option<String>,
    response: &Value,
    queried_at_ms: i64,
) -> QuotaSnapshot {
    // Reuse the stored-field extractor by wrapping the response in the same
    // shape: the backend payload already nests under userStatus/planStatus.
    let probe = WindsurfAccount {
        id: account_id.to_string(),
        github_login: String::new(),
        github_id: 0,
        github_access_token: String::new(),
        copilot_token: String::new(),
        windsurf_user_status: Some(response.clone()),
        created_at: 0,
        last_used: 0,
        ..Default::default()
    };
    let mut snap = snapshot_from_stored(&probe, queried_at_ms);
    snap.devin_account_id = devin_account_id;
    snap.devin_org_id = devin_org_id;
    snap
}

pub fn failed_snapshot(
    account: &WindsurfAccount,
    failure: QueryFailure,
    queried_at_ms: i64,
) -> QuotaSnapshot {
    let mut snap = snapshot_from_stored(account, queried_at_ms);
    snap.health = QueryHealth::Failed { failure };
    snap
}

// ---------- Query source (injectable for tests) ----------

pub trait QuotaFetcher: Send + Sync {
    fn fetch<'a>(
        &'a self,
        account: &'a WindsurfAccount,
    ) -> BoxFuture<'a, Result<QuotaSnapshot, QueryFailure>>;
}

/// Resolve the credential usable for a read-only GetUserStatus call.
/// No refresh or exchange is ever attempted here.
fn query_token(account: &WindsurfAccount) -> Option<String> {
    for candidate in [
        account.devin_session_token.as_deref(),
        account.windsurf_auth_token.as_deref(),
        account.windsurf_api_key.as_deref(),
    ] {
        if let Some(t) = candidate.map(str::trim).filter(|s| !s.is_empty()) {
            if t.starts_with("devin-session-token$")
                || t.starts_with("sk-ws-")
                || t.starts_with("cog_")
            {
                return Some(t.to_string());
            }
        }
    }
    account
        .windsurf_auth_status_raw
        .as_ref()
        .and_then(|v| {
            v.get("sessionToken")
                .or_else(|| v.get("session_token"))
                .or_else(|| v.get("apiKey"))
                .or_else(|| v.get("api_key"))
        })
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Read-only fetcher backed by the existing GetUserStatus endpoint with its
/// existing TLS/proxy/no-redirect protections.
pub struct DevinUserStatusFetcher;

impl QuotaFetcher for DevinUserStatusFetcher {
    fn fetch<'a>(
        &'a self,
        account: &'a WindsurfAccount,
    ) -> BoxFuture<'a, Result<QuotaSnapshot, QueryFailure>> {
        Box::pin(async move {
            let token = query_token(account).ok_or(QueryFailure::NoUsableCredential)?;
            let result =
                windsurf_devin_oauth::fetch_devin_user_status_detailed(&token).await;
            match result {
                Ok(value) => {
                    // Persist the fresh read-only status so account cards
                    // reflect monitor polls too (own encrypted store only).
                    crate::modules::windsurf_account::record_quota_query(
                        &account.id,
                        Some(&value),
                        None,
                    );
                    Ok(snapshot_from_status_response(
                        &account.id,
                        account.devin_account_id.clone(),
                        account.devin_org_id.clone(),
                        &value,
                        now_ms(),
                    ))
                }
                Err(e) => {
                    let failure: QueryFailure = e.into();
                    crate::modules::windsurf_account::record_quota_query(
                        &account.id,
                        None,
                        Some(failure.user_message()),
                    );
                    Err(failure)
                }
            }
        })
    }
}

// ---------- Monitor service ----------

struct MonitorInner {
    state: RotationState,
    snapshots: HashMap<String, QuotaSnapshot>,
    last_decision: Option<rotation_policy::RotationDecision>,
    running_task: Option<tauri::async_runtime::JoinHandle<()>>,
    scanning: bool,
    app: Option<tauri::AppHandle>,
    /// Resolves the locally-matched current account for background scans that
    /// run without the command layer's `current_id_override`.
    current_id_resolver: Option<fn() -> Option<String>>,
    /// Completion time of the last scan (success or failure), for UI display.
    last_scan_at_ms: Option<i64>,
    /// account_id -> don't query before this timestamp (server Retry-After).
    retry_after_until: HashMap<String, i64>,
}

/// Single-flight, cancellable quota monitor. Owns the poll loop; the UI only
/// sees the sanitized [`rotation_policy::RotationDecision`] and snapshot
/// summaries — never credentials.
pub struct QuotaMonitor {
    inner: Mutex<MonitorInner>,
    wake: tokio::sync::Notify,
}

pub fn global() -> &'static QuotaMonitor {
    static MONITOR: std::sync::LazyLock<QuotaMonitor> =
        std::sync::LazyLock::new(QuotaMonitor::new);
    &MONITOR
}

impl QuotaMonitor {
    fn new() -> Self {
        Self {
            inner: Mutex::new(MonitorInner {
                state: rotation_state::load(),
                snapshots: HashMap::new(),
                last_decision: None,
                running_task: None,
                scanning: false,
                app: None,
                current_id_resolver: None,
                last_scan_at_ms: None,
                retry_after_until: HashMap::new(),
            }),
            wake: tokio::sync::Notify::new(),
        }
    }

    pub fn attach_app(&self, app: tauri::AppHandle) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.app = Some(app);
        }
    }

    /// Wire the current-account resolver used by background poll scans (the
    /// command layer passes it explicitly for manual scans).
    pub fn set_current_id_resolver(&self, resolver: fn() -> Option<String>) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.current_id_resolver = Some(resolver);
        }
    }

    /// Called once at startup: honour the persisted config (monitor stays off
    /// on first install since mode defaults to Off).
    pub fn start_if_configured(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            self.ensure_task(&mut inner);
        }
    }

    fn emit_status(inner: &MonitorInner) {
        use tauri::Emitter;
        if let Some(app) = &inner.app {
            let dto = Self::status_dto(inner);
            let _ = app.emit("rotation-status", &dto);
        }
    }

    /// Rebuild a displayable decision for an in-flight recommendation
    /// (`executing`/`awaiting_client`). Used both when a poll scan produces
    /// a fresh decision mid-flight and on startup, so a persisted in-flight
    /// record always surfaces its verify/dismiss entry — even while paused.
    fn in_flight_decision(inner: &MonitorInner) -> Option<rotation_policy::RotationDecision> {
        let r = inner.state.last_recommendation.as_ref()?;
        if !matches!(
            r.resolution.as_deref(),
            Some("executing") | Some("awaiting_client")
        ) {
            return None;
        }
        let min_pct = inner
            .snapshots
            .get(&r.target_account_id)
            .map(|s| {
                s.limits
                    .iter()
                    .filter(|l| l.applicability == LimitApplicability::Applicable)
                    .filter_map(|l| l.percent_remaining)
                    .fold(f64::INFINITY, f64::min)
            })
            .filter(|p| p.is_finite())
            .unwrap_or(0.0);
        Some(rotation_policy::RotationDecision {
            kind: rotation_policy::DecisionKind::Recommendation,
            reasons: vec!["switch_in_progress".into()],
            target: Some(rotation_policy::CandidateSummary {
                account_id: r.target_account_id.clone(),
                org_id: None,
                min_applicable_percent: min_pct,
                cross_org: r.cross_org,
            }),
            suggestion_id: Some(r.id.clone()),
            expires_at_ms: Some(r.expires_at_ms),
            requires_confirmation: true,
            record_low_observation: false,
            clear_low_observation: false,
            resolution: r.resolution.clone(),
        })
    }


    /// Snapshot of monitor state safe for IPC. No credentials.
    pub fn status(&self) -> rotation_policy::RotationStatusDto {
        self.inner
            .lock()
            .map(|inner| Self::status_dto(&inner))
            .unwrap_or_else(|e| Self::status_dto(&e.into_inner()))
    }

    fn status_dto(inner: &MonitorInner) -> rotation_policy::RotationStatusDto {
        rotation_policy::RotationStatusDto {
            config: inner.state.config.clone(),
            mode: inner.state.config.mode,
            paused: inner.state.paused,
            pause_reason: inner.state.pause_reason.clone(),
            threshold_percent: inner.state.config.threshold_percent,
            poll_interval_secs: inner.state.config.poll_interval_secs,
            enabled_pool: inner.state.config.enabled_pool.clone(),
            scanning: inner.scanning,
            monitoring_active: inner.running_task.is_some()
                && inner.state.config.mode != RotationMode::Off
                && !inner.state.paused,
            consecutive_failures: inner.state.consecutive_failures,
            recovered_from_backup: inner.state.recovered_from_backup,
            last_scan_at_ms: inner.last_scan_at_ms,
            // An in-flight record always wins: it must remain visible (verify/
            // dismiss) even after a restart, when no scan has populated
            // `last_decision` yet and monitoring may be paused.
            last_decision: {
                let mut d = Self::in_flight_decision(inner)
                    .or_else(|| inner.last_decision.clone());
                if let (Some(d), Some(rec)) =
                    (d.as_mut(), inner.state.last_recommendation.as_ref())
                {
                    if d.suggestion_id.as_deref() == Some(rec.id.as_str()) {
                        d.resolution = rec.resolution.clone();
                    }
                }
                d
            },
            snapshots: inner
                .snapshots
                .values()
                .map(rotation_policy::SnapshotSummary::from)
                .collect(),
        }
    }

    pub fn set_config(
        &self,
        config: rotation_state::RotationConfig,
    ) -> Result<rotation_policy::RotationStatusDto, String> {
        config.validate()?;
        let mut inner = self.inner.lock().map_err(|_| "监控状态锁不可用")?;
        // A config save must not discard an in-flight operation: the official
        // confirmation modal may still be open for the current record.
        if let Some(rec) = inner.state.last_recommendation.as_ref() {
            if matches!(
                rec.resolution.as_deref(),
                Some("executing") | Some("awaiting_client")
            ) {
                return Err("存在进行中的切换确认，请先完成或关闭后再修改设置".into());
            }
        }
        inner.state.config = config;
        rotation_state::save(&inner.state)?;
        // New config invalidates pending recommendations and observations.
        inner.state.last_recommendation = None;
        inner.state.low_quota_observations.clear();
        self.ensure_task(&mut inner);
        Self::emit_status(&inner);
        Ok(Self::status_dto(&inner))
    }

    pub fn pause(&self, reason: &str) -> Result<rotation_policy::RotationStatusDto, String> {
        let mut inner = self.inner.lock().map_err(|_| "监控状态锁不可用")?;
        inner.state.paused = true;
        inner.state.pause_reason = Some(reason.to_string());
        rotation_state::save(&inner.state)?;
        self.wake.notify_one();
        Self::emit_status(&inner);
        Ok(Self::status_dto(&inner))
    }

    pub fn resume(&self) -> Result<rotation_policy::RotationStatusDto, String> {
        let mut inner = self.inner.lock().map_err(|_| "监控状态锁不可用")?;
        inner.state.paused = false;
        inner.state.pause_reason = None;
        // Resume also clears the failure breaker only via explicit user intent.
        inner.state.consecutive_failures = 0;
        rotation_state::save(&inner.state)?;
        self.ensure_task(&mut inner);
        self.wake.notify_one();
        Self::emit_status(&inner);
        Ok(Self::status_dto(&inner))
    }

    /// Ensure the background task is running iff monitoring should be active.
    /// A finished-but-retained handle (task exited on its own) is cleared so
    /// resume/scan can respawn it; aborting also clears a stale `scanning`
    /// flag left behind by a cancelled in-flight scan.
    fn ensure_task(&self, inner: &mut MonitorInner) {
        let should_run = inner.state.config.mode != RotationMode::Off && !inner.state.paused;
        if inner
            .running_task
            .as_ref()
            .is_some_and(|t| t.inner().is_finished())
        {
            inner.running_task = None;
            inner.scanning = false;
        }
        if should_run && inner.running_task.is_none() {
            inner.scanning = false;
            inner.running_task = Some(tauri::async_runtime::spawn(Self::loop_task()));
        } else if !should_run {
            if let Some(task) = inner.running_task.take() {
                task.abort();
            }
            inner.scanning = false;
        }
        self.wake.notify_one();
    }

    /// The poll loop: serial scans only, bounded period, exits when stopped.
    async fn loop_task() {
        loop {
            let (interval_secs, active) = {
                let inner = match global().inner.lock() {
                    Ok(i) => i,
                    Err(_) => return,
                };
                (
                    inner.state.config.poll_interval_secs,
                    inner.state.config.mode != RotationMode::Off && !inner.state.paused,
                )
            };
            if !active {
                return;
            }
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)) => {}
                _ = global().wake.notified() => {}
            }
            let (active, scanning) = {
                let inner = match global().inner.lock() {
                    Ok(i) => i,
                    Err(_) => return,
                };
                (
                    inner.state.config.mode != RotationMode::Off && !inner.state.paused,
                    inner.scanning,
                )
            };
            if !active {
                return;
            }
            if scanning {
                continue; // no overlapping scans
            }
            // Background polls resolve the current account themselves — the
            // command layer only overrides this for manual "scan now" calls.
            let _ = global()
                .run_scan_once(&DevinUserStatusFetcher, None)
                .await;
        }
    }

    /// One serial scan: query each pool account + current, evaluate policy,
    /// persist state, emit. `current_id_override` lets the command layer pass
    /// the locally-matched identity without the monitor touching the client.
    pub async fn run_scan_once<F: QuotaFetcher>(
        &self,
        fetcher: &F,
        current_id_override: Option<String>,
    ) -> Result<rotation_policy::RotationDecision, String> {
        {
            let mut inner = self.inner.lock().map_err(|_| "监控状态锁不可用")?;
            if inner.scanning {
                return Err("已有扫描进行中".into());
            }
            inner.scanning = true;
        }
        let result = self.scan_inner(fetcher, current_id_override).await;
        if let Ok(mut inner) = self.inner.lock() {
            inner.scanning = false;
            inner.last_scan_at_ms = Some(now_ms());
            Self::emit_status(&inner);
        }
        result
    }

    async fn scan_inner<F: QuotaFetcher>(
        &self,
        fetcher: &F,
        current_id_override: Option<String>,
    ) -> Result<rotation_policy::RotationDecision, String> {
        let now = now_ms();
        let (account_ids, current_id) = {
            let inner = self.inner.lock().map_err(|_| "监控状态锁不可用")?;
            let current = current_id_override
                .or_else(|| inner.current_id_resolver.and_then(|f| f()));
            let mut ids: Vec<String> = inner.state.config.enabled_pool.clone();
            if let Some(cid) = current.clone() {
                if !ids.contains(&cid) {
                    ids.push(cid);
                }
            }
            (ids, current)
        };

        // Serial queries; each result is stored individually so a single
        // failure never aborts the rest.
        for id in &account_ids {
            // Honor a server-provided Retry-After: skip the query entirely
            // (the previous snapshot stays and ages out naturally).
            {
                let inner = self.inner.lock().map_err(|_| "监控状态锁不可用")?;
                if inner
                    .retry_after_until
                    .get(id)
                    .is_some_and(|until| *until > now)
                {
                    continue;
                }
            }
            let Some(account) = crate::modules::windsurf_account::load_account(id) else {
                let mut inner = self.inner.lock().map_err(|_| "监控状态锁不可用")?;
                inner.snapshots.remove(id);
                continue;
            };
            let snap = match fetcher.fetch(&account).await {
                Ok(s) => s,
                Err(failure) => {
                    if let QueryFailure::RateLimited {
                        retry_after_ms: Some(wait_ms),
                    } = &failure
                    {
                        let mut inner =
                            self.inner.lock().map_err(|_| "监控状态锁不可用")?;
                        inner
                            .retry_after_until
                            .insert(id.clone(), now + (*wait_ms).clamp(0, 3_600_000));
                    }
                    // Completion time, not scan start: the snapshot age must
                    // reflect when the query actually finished.
                    failed_snapshot(&account, failure, now_ms())
                }
            };
            let mut inner = self.inner.lock().map_err(|_| "监控状态锁不可用")?;
            inner.snapshots.insert(id.clone(), snap);
        }

        let mut inner = self.inner.lock().map_err(|_| "监控状态锁不可用")?;
        // Fresh timestamp AFTER the serial queries — snapshots carry their
        // completion time, so comparing them against the scan start would
        // misread a slow network as "snapshot from the future".
        let decision_now = now_ms();
        let decision = rotation_policy::evaluate(
            &inner.state,
            current_id.as_deref(),
            &inner.snapshots,
            decision_now,
            /* auto_capable */ false,
        );

        // Persist observation bookkeeping based on the decision flags.
        match &decision.kind {
            rotation_policy::DecisionKind::Blocked { .. }
            | rotation_policy::DecisionKind::NoAction => {
                if decision.clear_low_observation {
                    if let Some(cid) = current_id.as_ref() {
                        inner.state.low_quota_observations.remove(cid);
                        inner.state.suppressed_at.remove(cid);
                    }
                }
            }
            _ => {}
        }
        if decision.record_low_observation {
            if let Some(cid) = current_id.as_ref() {
                let entry = inner
                    .state
                    .low_quota_observations
                    .entry(cid.clone())
                    .or_insert(rotation_state::LowQuotaObservation {
                        first_at_ms: now,
                        last_at_ms: now,
                        count: 0,
                    });
                entry.count += 1;
                entry.last_at_ms = now;
            }
        }

        // An in-flight suggestion (executing / awaiting the official modal)
        // outlives scan cycles AND its own suggestion TTL: expiry bounds the
        // *offer*, not the operation already launched — the client modal may
        // still be open. Only explicit verify/dismiss resolves it; until then
        // keep the record and the banner pointing at it.
        let mut decision = decision;
        if let Some(in_flight) = Self::in_flight_decision(&inner) {
            decision = in_flight;
        }

        // Record the emitted recommendation so confirm_rotation can re-verify
        // against suggestion id + expiry later.
        if matches!(decision.kind, rotation_policy::DecisionKind::Recommendation)
            && inner
                .state
                .last_recommendation
                .as_ref()
                .map(|r| r.id.as_str())
                != decision.suggestion_id.as_deref()
        {
            if let (Some(target), Some(id), Some(exp)) = (
                decision.target.clone(),
                decision.suggestion_id.clone(),
                decision.expires_at_ms,
            ) {
                inner.state.last_recommendation = Some(rotation_state::RecommendationRecord {
                    id,
                    target_account_id: target.account_id,
                    from_account_id: current_id.clone().unwrap_or_default(),
                    cross_org: target.cross_org,
                    created_at_ms: now,
                    expires_at_ms: exp,
                    resolution: None,
                });
            }
        }

        inner.last_decision = Some(decision.clone());
        let _ = rotation_state::save(&inner.state);
        Ok(decision)
    }

    /// Phase A of a confirmed switch: re-validate everything server-side
    /// (`confirmed` alone never suffices). On success the suggestion is
    /// marked `executing` so a concurrent confirm cannot double-fire;
    /// retryable states stay retryable.
    pub fn begin_confirm(
        &self,
        current_id: Option<String>,
        request: &super::switch_adapter::SwitchRequest,
    ) -> Result<(), String> {
        let now = now_ms();
        let mut inner = self.inner.lock().map_err(|_| "监控状态锁不可用")?;
        super::switch_adapter::validate(
            &inner.state,
            &inner.snapshots,
            request,
            current_id.as_deref(),
            now,
        )
        .map_err(|code| confirm_error_message(&code))?;
        if let Some(rec) = inner.state.last_recommendation.as_mut() {
            if rec.id == request.suggestion_id {
                rec.resolution = Some("executing".into());
            }
        }
        // The in-flight record MUST be durable before the adapter runs:
        // if the process dies after the URI launch but before this save,
        // nothing is recoverable. A failed save aborts the launch and the
        // in-memory marker is reverted so the suggestion stays confirmable.
        if let Err(e) = rotation_state::save(&inner.state) {
            if let Some(rec) = inner.state.last_recommendation.as_mut() {
                if rec.id == request.suggestion_id
                    && rec.resolution.as_deref() == Some("executing")
                {
                    rec.resolution = None;
                }
            }
            return Err(format!("无法持久化切换记录，已阻止本次执行: {}", e));
        }
        Ok(())
    }

    /// Phase B: record the adapter outcome. A launched-but-unconfirmed
    /// official login is `awaiting_client` — cooldowns and `last_switch`
    /// are only applied once `mark_verified` observes the client session.
    /// Adapter failures feed the consecutive-failure circuit breaker.
    pub fn finish_confirm(
        &self,
        request: &super::switch_adapter::SwitchRequest,
        outcome: &super::switch_adapter::SwitchOutcome,
    ) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(rec) = inner.state.last_recommendation.as_mut() {
                if rec.id == request.suggestion_id {
                    rec.resolution = Some(
                        if outcome.failure_code.is_some() {
                            "failed"
                        } else {
                            "awaiting_client"
                        }
                        .into(),
                    );
                }
            }
            if outcome.failure_code.is_some() {
                inner.state.consecutive_failures += 1;
            }
            let _ = rotation_state::save(&inner.state);
            Self::emit_status(&inner);
        }
    }

    /// Called when read-only verification observes the official client's
    /// session matching the switch target. Only applies when the matching
    /// suggestion is actually awaiting client confirmation — verification
    /// cannot upgrade an arbitrary/other-account state to `verified`.
    pub fn mark_verified(&self, target_account_id: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            let now = now_ms();
            let from = inner
                .state
                .last_recommendation
                .as_ref()
                .filter(|r| {
                    r.target_account_id == target_account_id
                        && r.resolution.as_deref() == Some("awaiting_client")
                })
                .map(|r| (r.id.clone(), r.from_account_id.clone()));
            if let Some((rec_id, from_id)) = from {
                if let Some(rec) = inner.state.last_recommendation.as_mut() {
                    if rec.id == rec_id {
                        rec.resolution = Some("verified".into());
                    }
                }
                inner.state.last_switch_at_ms = Some(now);
                inner.state.consecutive_failures = 0;
                inner.state.recovered_from_backup = false;
                let cooldown_ms = (inner.state.config.cooldown_secs as i64) * 1000;
                inner.state.cooldowns.insert(from_id.clone(), now + cooldown_ms);
                inner.state.cooldown_reasons.insert(from_id.clone(), "switched_away".into());
                inner.state.switched_away_at.insert(from_id, now);
                let _ = rotation_state::save(&inner.state);
                Self::emit_status(&inner);
            }
        }
    }

    /// Dismiss a pending recommendation; it will not re-fire for the same
    /// low-quota state until a new observation cycle starts. Also closes an
    /// `awaiting_client` suggestion the user abandons (e.g. they cancelled
    /// the official modal), so no late verification can resolve it.
    pub fn dismiss(&self, suggestion_id: &str) -> Result<(), String> {
        let mut inner = self.inner.lock().map_err(|_| "监控状态锁不可用")?;
        let mut reconciled = false;
        if let Some(rec) = inner.state.last_recommendation.as_mut() {
            let closable = rec.resolution.is_none()
                || rec.resolution.as_deref() == Some("awaiting_client");
            if rec.id == suggestion_id && closable {
                rec.resolution = Some("dismissed".into());
                reconciled = true;
                // Suppress re-recommendation for this same low cycle; a new
                // cycle (observation cleared then re-recorded) notifies again.
                let from = rec.from_account_id.clone();
                if let Some(obs) = inner.state.low_quota_observations.get(&from) {
                    let first = obs.first_at_ms;
                    inner.state.suppressed_at.insert(from, first);
                }
            }
        }
        if reconciled {
            // The user has reconciled the record — recovery uncertainty about
            // this suggestion is resolved.
            inner.state.recovered_from_backup = false;
        }
        inner.last_decision = None;
        let _ = rotation_state::save(&inner.state);
        Self::emit_status(&inner);
        Ok(())
    }

    /// Explicit user acknowledgement of a recovered-from-backup state that
    /// has no in-flight record to verify/dismiss (e.g. the backup predates
    /// any recommendation). Clears the persisted recovery gate.
    pub fn acknowledge_recovery(
        &self,
    ) -> Result<rotation_policy::RotationStatusDto, String> {
        let mut inner = self.inner.lock().map_err(|_| "监控状态锁不可用")?;
        inner.state.recovered_from_backup = false;
        rotation_state::save(&inner.state)?;
        Self::emit_status(&inner);
        Ok(Self::status_dto(&inner))
    }
}

fn confirm_error_message(code: &str) -> String {
    match code {
        "not_confirmed" => "未确认，未执行任何切换".into(),
        "recovery_review_required" => {
            "轮换状态从备份恢复，请先核对当前登录账号（验证或关闭在途记录）后再切换".into()
        }
        "no_pending_suggestion" => "没有待处理的轮换建议".into(),
        "suggestion_mismatch" => "建议与当前状态不匹配，可能已过期".into(),
        "suggestion_already_resolved" => "该建议已处理".into(),
        "suggestion_expired" => "建议已过期，请等待下一次扫描".into(),
        "monitor_paused" => "监控已暂停".into(),
        "circuit_open_failures" => "连续失败已熔断，请先查看原因再恢复".into(),
        "current_identity_unknown" => "无法唯一确认当前账号，已停止".into(),
        "current_identity_changed" => "当前账号已变化，建议作废".into(),
        "target_not_in_pool" => "目标账号不在已启用的备用池中".into(),
        "target_in_cooldown" => "目标账号仍在冷却期".into(),
        "target_snapshot_missing" => "缺少目标账号的额度快照".into(),
        "target_snapshot_stale" => "目标账号额度数据已过期".into(),
        "target_query_unhealthy" => "目标账号额度查询失败".into(),
        "target_semantics_unverified" => "目标账号额度语义未验证".into(),
        "target_no_longer_eligible" => "目标账号额度已不满足安全余量".into(),
        "min_switch_interval" => "距上次切换间隔不足".into(),
        other => format!("未执行：{}", other),
    }
}
