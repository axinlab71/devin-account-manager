//! Pure rotation decision logic. No IO, no network, no storage, no clocks
//! other than the injected `now_ms` — every rule is reproducible offline.
//!
//! Ordering of gates matters: identity/staleness/health problems always
//! produce `Blocked` before any candidate is considered, and unverified
//! quota semantics can produce at most an informational `Warning`.

use serde::Serialize;
use std::collections::HashMap;

use super::account_selector::{self, Candidate};
use super::quota_monitor::{QueryHealth, QuotaSnapshot, SemanticsConfidence};
use super::rotation_state::{RotationMode, RotationState};

// Serialized as a plain snake_case string (`"kind":"recommendation"`) to match
// the frontend union — internally-tagging this enum would nest an object into
// the `kind` field of RotationDecision and silently break IPC consumers.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// Nothing to do; healthy or still gathering confirmations.
    NoAction,
    /// Informational only — never executable (e.g. unverified semantics).
    Warning,
    /// A concrete candidate exists. `requires_confirmation` is always true
    /// in phase 2/3 because no execution path is cleared yet.
    Recommendation,
    /// Evaluation cannot proceed safely; structured reason in `reasons`.
    Blocked,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateSummary {
    pub account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    pub min_applicable_percent: f64,
    pub cross_org: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationDecision {
    pub kind: DecisionKind,
    /// Machine-readable reason codes, e.g. "current_snapshot_stale".
    pub reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<CandidateSummary>,
    /// Suggestion id + expiry; None unless kind == Recommendation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
    /// Always true while no execution adapter has verified capability.
    pub requires_confirmation: bool,
    /// Instruction for the caller's bookkeeping (not a decision input).
    #[serde(skip)]
    pub record_low_observation: bool,
    #[serde(skip)]
    pub clear_low_observation: bool,
    /// Resolution of the stored recommendation matching this decision
    /// (`awaiting_client`, `verified`, …); populated at status-emit time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
}

impl RotationDecision {
    fn simple(kind: DecisionKind, reasons: &[&str]) -> Self {
        Self {
            kind,
            reasons: reasons.iter().map(|s| s.to_string()).collect(),
            target: None,
            suggestion_id: None,
            expires_at_ms: None,
            requires_confirmation: true,
            record_low_observation: false,
            clear_low_observation: false,
            resolution: None,
        }
    }
    fn no_action(reason: &str) -> Self {
        Self::simple(DecisionKind::NoAction, &[reason])
    }
    fn warning(reason: &str) -> Self {
        Self::simple(DecisionKind::Warning, &[reason])
    }
    fn blocked(reason: &str) -> Self {
        Self::simple(DecisionKind::Blocked, &[reason])
    }
}

/// Sanitized per-account snapshot summary for IPC/status output.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotSummary {
    pub account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_applicable_percent: Option<f64>,
    pub queried_at_ms: i64,
    pub confidence: SemanticsConfidence,
    pub healthy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_kind: Option<String>,
}

impl From<&QuotaSnapshot> for SnapshotSummary {
    fn from(s: &QuotaSnapshot) -> Self {
        let (healthy, failure_kind) = match &s.health {
            QueryHealth::Healthy => (true, None),
            QueryHealth::Failed { failure } => {
                (false, Some(serde_json::to_value(failure)
                    .ok()
                    .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(str::to_string))
                    .unwrap_or_else(|| "unknown".into())))
            }
        };
        Self {
            account_id: s.account_id.clone(),
            org_id: s.devin_org_id.clone(),
            plan_name: s.plan_name.clone(),
            min_applicable_percent: s.min_applicable_percent(),
            queried_at_ms: s.queried_at_ms,
            confidence: s.confidence,
            healthy,
            failure_kind,
        }
    }
}

/// Status payload emitted over `rotation-status` and returned by IPC.
/// Contains no credentials and no raw account fields.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationStatusDto {
    /// Full effective config so settings UIs can round-trip every field.
    pub config: super::rotation_state::RotationConfig,
    pub mode: RotationMode,
    pub paused: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<String>,
    pub threshold_percent: f64,
    pub poll_interval_secs: u64,
    pub enabled_pool: Vec<String>,
    pub scanning: bool,
    pub monitoring_active: bool,
    pub consecutive_failures: u32,
    /// True when the state file was recovered from its `.bak` copy —
    /// executions stay blocked until the user reconciles.
    #[serde(default)]
    pub recovered_from_backup: bool,
    /// Completion time (unix ms) of the most recent scan, for UI display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_decision: Option<RotationDecision>,
    pub snapshots: Vec<SnapshotSummary>,
}

/// Tolerated forward skew for locally-produced timestamps.
const CLOCK_SKEW_TOLERANCE_MS: i64 = 5_000;

fn snapshot_is_fresh(snap: &QuotaSnapshot, now_ms: i64, max_age_secs: u64) -> bool {
    snap.queried_at_ms > 0
        && snap.queried_at_ms <= now_ms + CLOCK_SKEW_TOLERANCE_MS
        && now_ms - snap.queried_at_ms <= (max_age_secs as i64) * 1000
}

fn snapshot_from_future(snap: &QuotaSnapshot, now_ms: i64) -> bool {
    snap.queried_at_ms > now_ms + CLOCK_SKEW_TOLERANCE_MS
}

fn cooldown_active(state: &RotationState, account_id: &str, now_ms: i64) -> bool {
    state
        .cooldowns
        .get(account_id)
        .is_some_and(|until| *until > now_ms)
}

/// Evaluate the rotation policy against a fixed world view.
///
/// `auto_capable` must reflect *verified* capability evidence only — the
/// caller passes false until native switching and auth compatibility have
/// real acceptance evidence. When false, Auto mode still requires
/// confirmation (never silently degrades to an unverified execution).
pub fn evaluate(
    state: &RotationState,
    current_id: Option<&str>,
    snapshots: &HashMap<String, QuotaSnapshot>,
    now_ms: i64,
    auto_capable: bool,
) -> RotationDecision {
    let config = &state.config;

    if config.mode == RotationMode::Off {
        return RotationDecision::no_action("monitoring_disabled");
    }
    if state.paused {
        return RotationDecision::blocked("monitor_paused");
    }
    if state.consecutive_failures >= config.max_consecutive_failures {
        return RotationDecision::blocked("circuit_open_failures");
    }

    // Current identity must be uniquely known — never guess by e-mail.
    let Some(current_id) = current_id else {
        return RotationDecision::blocked("current_identity_unknown");
    };
    let Some(current_snap) = snapshots.get(current_id) else {
        return RotationDecision::blocked("current_snapshot_missing");
    };
    // A snapshot timestamped in the future means the clock moved backward —
    // stop rather than trust any ordering derived from it.
    if snapshot_from_future(current_snap, now_ms) {
        return RotationDecision::blocked("clock_anomaly");
    }
    if !snapshot_is_fresh(current_snap, now_ms, config.snapshot_max_age_secs) {
        return RotationDecision::blocked("current_snapshot_stale");
    }
    if let QueryHealth::Failed { failure } = &current_snap.health {
        let reason = match failure {
            super::quota_monitor::QueryFailure::AuthRejected => "current_auth_rejected",
            super::quota_monitor::QueryFailure::PolicyDenied => "current_policy_denied",
            super::quota_monitor::QueryFailure::RateLimited { .. } => "current_rate_limited",
            super::quota_monitor::QueryFailure::Network => "current_query_network_error",
            super::quota_monitor::QueryFailure::ServerError { .. } => "current_query_server_error",
            super::quota_monitor::QueryFailure::ParseFailed => "current_query_parse_failed",
            super::quota_monitor::QueryFailure::NoUsableCredential => "current_no_usable_credential",
        };
        let mut d = RotationDecision::blocked(reason);
        d.clear_low_observation = true;
        return d;
    }

    let threshold = config.threshold_percent;
    // No measurable applicable limit ≠ healthy: unknown is never 0.
    let any_measurable = current_snap
        .limits
        .iter()
        .any(|l| l.applicability == super::quota_monitor::LimitApplicability::Applicable
            && l.percent_remaining.is_some());
    if !any_measurable {
        let mut d = RotationDecision::blocked("current_limits_unknown");
        d.clear_low_observation = true;
        return d;
    }
    let low = current_snap.is_low(threshold);
    if !low {
        let mut d = RotationDecision::no_action("healthy");
        d.clear_low_observation = true;
        return d;
    }

    // Unverified field semantics: warn, never recommend.
    if current_snap.confidence == SemanticsConfidence::UnverifiedMapping {
        let mut d = RotationDecision::warning("unverified_quota_semantics");
        d.clear_low_observation = true;
        return d;
    }

    // Two independent successful observations at least `gap` apart.
    let observation_first = state
        .low_quota_observations
        .get(current_id)
        .map(|obs| obs.first_at_ms);
    let confirmed = observation_first.is_some_and(|first| {
        state
            .low_quota_observations
            .get(current_id)
            .is_some_and(|obs| obs.count >= 1 && now_ms - first >= config.low_confirm_gap_ms)
    });
    if !confirmed {
        let mut d = RotationDecision::no_action("awaiting_second_low_confirmation");
        d.record_low_observation = true;
        return d;
    }

    // User dismissed this exact low cycle — stay quiet until it recovers.
    if let (Some(suppressed), Some(first)) =
        (state.suppressed_at.get(current_id), observation_first)
    {
        if *suppressed == first {
            return RotationDecision::no_action("dismissed_low_cycle");
        }
    }

    // Notifications do not execute a switch: neither the switch cooldown
    // nor the candidate pool should hide an already confirmed low quota.
    if config.mode == RotationMode::NotifyOnly {
        return RotationDecision::warning("low_quota_notify_only");
    }

    // Global minimum interval between executed switches.
    if let Some(last) = state.last_switch_at_ms {
        if now_ms - last < (config.min_switch_interval_secs as i64) * 1000 {
            return RotationDecision::blocked("min_switch_interval");
        }
    }

    let current_org = current_snap.devin_org_id.clone();

    // Build candidates from the user-enabled pool only.
    let mut candidates: Vec<Candidate> = Vec::new();
    for id in &config.enabled_pool {
        if id == current_id {
            continue;
        }
        if cooldown_active(state, id, now_ms) {
            continue;
        }
        let Some(snap) = snapshots.get(id) else {
            continue;
        };
        if snapshot_from_future(snap, now_ms) {
            continue; // clock anomaly: never trust ordering from the future
        }
        if !snapshot_is_fresh(snap, now_ms, config.snapshot_max_age_secs) {
            continue;
        }
        if !matches!(snap.health, QueryHealth::Healthy) {
            continue;
        }
        if snap.confidence != SemanticsConfidence::Verified {
            continue;
        }
        // Every applicable limit must clear threshold + margin. Unknown or
        // not-applicable limits are ignored (never treated as 0).
        let margin = threshold + config.candidate_margin_points;
        let all_clear = snap
            .limits
            .iter()
            .filter(|l| l.applicability == super::quota_monitor::LimitApplicability::Applicable)
            .all(|l| l.percent_remaining.is_some_and(|p| p > margin));
        let has_any_applicable = snap
            .limits
            .iter()
            .any(|l| l.applicability == super::quota_monitor::LimitApplicability::Applicable);
        if !has_any_applicable || !all_clear {
            continue;
        }
        candidates.push(Candidate {
            account_id: id.clone(),
            org_id: snap.devin_org_id.clone(),
            min_applicable_percent: snap.min_applicable_percent().unwrap_or(0.0),
            priority: config.priorities.get(id).copied().unwrap_or(0),
            next_reset_ms: snap
                .limits
                .iter()
                .filter_map(|l| l.reset_at_ms)
                .filter(|t| *t > now_ms)
                .min(),
            last_switched_ms: state.switched_away_at.get(id).copied(),
            cross_org: snap.devin_org_id.is_some()
                && current_org.is_some()
                && snap.devin_org_id != current_org,
        });
    }

    if candidates.is_empty() {
        return RotationDecision::blocked("no_eligible_candidate");
    }

    let ranked = account_selector::rank(candidates, config.sort_mode);
    let top = ranked.into_iter().next().unwrap();
    let suggestion_id = uuid::Uuid::new_v4().to_string();
    // Recommendations expire with the snapshot validity window.
    let expires = now_ms + (config.snapshot_max_age_secs as i64) * 1000;

    match config.mode {
        // Auto requires verified capability; absent evidence it degrades to
        // the same confirmed-recommendation behaviour as SmartConfirm.
        RotationMode::SmartConfirm | RotationMode::Auto => RotationDecision {
            kind: DecisionKind::Recommendation,
            reasons: vec!["low_quota_confirmed".into()],
            target: Some(CandidateSummary {
                account_id: top.account_id,
                org_id: top.org_id,
                min_applicable_percent: top.min_applicable_percent,
                cross_org: top.cross_org,
            }),
            suggestion_id: Some(suggestion_id),
            expires_at_ms: Some(expires),
            // Auto never self-executes without capability evidence; cross-org
            // auto is permanently disabled.
            requires_confirmation: !auto_capable || top.cross_org,
            record_low_observation: false,
            clear_low_observation: true,
            resolution: None,
        },
        RotationMode::Off | RotationMode::NotifyOnly => unreachable!(),
    }
}

