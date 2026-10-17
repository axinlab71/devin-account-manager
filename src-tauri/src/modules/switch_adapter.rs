//! Switch-execution adapters and the execution gate.
//!
//! Phase-3 scope: unified types + a gate that re-validates every request
//! server-side (suggestion id, expiry, identity, pool membership, freshness,
//! global interval) before dispatching to an adapter. No adapter currently
//! has verified capability, so `execute` returns a structured `blocked`
//! outcome — confirmation never bypasses missing evidence, and a blocked
//! outcome performs zero client writes.
//!
//! `NativeAuthSwitchAdapter` / `IsolatedProfileAdapter` are declared
//! `unsupported` until phase-4 evidence exists. `SafeRestartSwitchAdapter`
//! stays `blocked` until the phase-1 auth-write findings are fixed with
//! approval and verified on a real round-trip.

use serde::Serialize;

use super::quota_monitor::{LimitApplicability, QueryHealth, QuotaSnapshot, SemanticsConfidence};
use super::rotation_state::RotationState;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    Native,
    IsolatedProfile,
    SafeRestart,
}

/// Verified support level.
/// `Supported` = passed real-client acceptance; may run unattended.
/// `Experimental` = implemented against static evidence only; may execute
///   behind explicit user confirmation plus the client's own confirmation
///   modal, and every outcome is verified read-only. Never eligible for
///   unattended `auto` mode.
/// `Blocked` = path exists but is gated pending fixes/evidence; never runs.
/// `Unsupported` = no known interface exists.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "level")]
pub enum AdapterSupport {
    Supported,
    Experimental { reason: String },
    Blocked { reason: String },
    Unsupported { reason: String },
}

/// Verification status for a single claim in the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    NotAttempted,
    Passed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStatus {
    NotNeeded,
    Attempted,
    Succeeded,
    Failed,
}

/// What the caller asks for. The backend never trusts `confirmed` alone:
/// every re-check below still runs.
#[derive(Debug, Clone)]
pub struct SwitchRequest {
    pub suggestion_id: String,
    pub target_account_id: String,
    /// The identity the caller believes is current; verified again inside.
    pub expected_current_id: String,
    /// User explicitly accepted the execution method (e.g. restart).
    pub confirmed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwitchOutcome {
    pub target_account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<AdapterKind>,
    /// Whether a client restart was required AND happened.
    pub restart_required: bool,
    pub local_match: Verification,
    pub client_recognized: Verification,
    pub remote_verified: Verification,
    pub rollback: RollbackStatus,
    /// Machine-readable failure/block reason; absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub message: String,
}

impl SwitchOutcome {
    pub fn blocked(target: &str, code: &str, message: impl Into<String>) -> Self {
        Self {
            target_account_id: target.to_string(),
            adapter: None,
            restart_required: false,
            local_match: Verification::NotAttempted,
            client_recognized: Verification::NotAttempted,
            remote_verified: Verification::NotAttempted,
            rollback: RollbackStatus::NotNeeded,
            failure_code: Some(code.to_string()),
            message: message.into(),
        }
    }
}

/// Declared capability of each adapter for the current build/evidence.
pub fn capabilities() -> Vec<(AdapterKind, AdapterSupport)> {
    vec![
        (
            AdapterKind::Native,
            // Implemented against static evidence: launches the official
            // devin:// URI handler; the client's own modal confirms the
            // login. Executes only behind the double confirmation; NOT yet
            // verified on a live client — `experimental`, not `supported`.
            AdapterSupport::Experimental {
                reason: "已实现（官方 URI 登录），仅静态分析证据；经用户确认+官方弹窗后执行，结果只读验证".into(),
            },
        ),
        (
            AdapterKind::IsolatedProfile,
            AdapterSupport::Unsupported {
                reason: "隔离实例方案未实测，暂不开放".into(),
            },
        ),
        (
            AdapterKind::SafeRestart,
            AdapterSupport::Blocked {
                reason: "写入修正已完成，待真实 A→B→A 验收后开放".into(),
            },
        ),
    ]
}

/// Pure validation half of the execution gate. `Ok(())` means the request
/// may be dispatched to an adapter; `Err(code)` blocks before any side
/// effect. Any terminal or in-flight resolution blocks re-confirmation
/// (`executed`/`verified`/`blocked`/`dismissed`/`executing`/
/// `awaiting_client`) — only `failed` stays retryable. A user who cancelled
/// the official modal can dismiss; the next scan re-recommends.
pub fn validate(
    state: &RotationState,
    snapshots: &HashMap<String, QuotaSnapshot>,
    request: &SwitchRequest,
    current_id: Option<&str>,
    now: i64,
) -> Result<(), String> {
    let code = |c: &str| Err(c.to_string());

    if !request.confirmed {
        return code("not_confirmed");
    }
    let Some(rec) = &state.last_recommendation else {
        return code("no_pending_suggestion");
    };
    if rec.id != request.suggestion_id || rec.target_account_id != request.target_account_id {
        return code("suggestion_mismatch");
    }
    // Fail-closed on resolution: only pending (None) and `failed` may be
    // confirmed again. Every terminal, in-flight, or UNKNOWN value blocks —
    // a tampered/foreign resolution string must never reopen execution.
    match rec.resolution.as_deref() {
        None | Some("failed") => {}
        Some(_) => return code("suggestion_already_resolved"),
    }
    if now > rec.expires_at_ms {
        return code("suggestion_expired");
    }
    if state.paused {
        return code("monitor_paused");
    }
    // Recovered state is unverifiable until the user reconciles it: the
    // pre-corruption snapshot may omit a launch that already happened.
    if state.recovered_from_backup {
        return code("recovery_review_required");
    }
    if state.consecutive_failures >= state.config.max_consecutive_failures {
        return code("circuit_open_failures");
    }

    // Identity re-check: the account that was low must still be current.
    let Some(actual_current) = current_id else {
        return code("current_identity_unknown");
    };
    if actual_current != rec.from_account_id || actual_current != request.expected_current_id {
        return code("current_identity_changed");
    }

    // Trigger re-check: the suggestion only stays executable while the
    // current account is still measurably low on a fresh, healthy,
    // verified-semantics snapshot. A recovered or unverifiable current
    // snapshot revokes the offer — confirming it later must fail.
    let Some(cur_snap) = snapshots.get(&rec.from_account_id) else {
        return code("current_snapshot_missing");
    };
    if cur_snap.queried_at_ms > now + 5_000 {
        return code("clock_anomaly");
    }
    if cur_snap.queried_at_ms <= 0
        || now - cur_snap.queried_at_ms
            > (state.config.snapshot_max_age_secs as i64) * 1000
    {
        return code("current_snapshot_stale");
    }
    if !matches!(cur_snap.health, QueryHealth::Healthy) {
        return code("current_query_unhealthy");
    }
    if cur_snap.confidence != SemanticsConfidence::Verified {
        return code("current_semantics_unverified");
    }
    if !cur_snap.is_low(state.config.threshold_percent) {
        return code("current_no_longer_low");
    }

    // Target must still be an enabled, non-cooled-down pool member.
    if !state.config.enabled_pool.contains(&request.target_account_id) {
        return code("target_not_in_pool");
    }
    if state
        .cooldowns
        .get(&request.target_account_id)
        .is_some_and(|until| *until > now)
    {
        return code("target_in_cooldown");
    }

    // Target snapshot must still be fresh, healthy and eligible.
    let Some(snap) = snapshots.get(&request.target_account_id) else {
        return code("target_snapshot_missing");
    };
    if snap.queried_at_ms > now + 5_000 {
        return code("clock_anomaly");
    }
    if snap.queried_at_ms <= 0
        || now - snap.queried_at_ms > (state.config.snapshot_max_age_secs as i64) * 1000
    {
        return code("target_snapshot_stale");
    }
    if !matches!(snap.health, QueryHealth::Healthy) {
        return code("target_query_unhealthy");
    }
    if snap.confidence != SemanticsConfidence::Verified {
        return code("target_semantics_unverified");
    }
    let margin = state.config.threshold_percent + state.config.candidate_margin_points;
    let eligible = snap
        .limits
        .iter()
        .any(|l| l.applicability == LimitApplicability::Applicable)
        && snap
            .limits
            .iter()
            .filter(|l| l.applicability == LimitApplicability::Applicable)
            .all(|l| l.percent_remaining.is_some_and(|p| p > margin));
    if !eligible {
        return code("target_no_longer_eligible");
    }

    // Global minimum interval re-checked at execution, not only at recommend.
    if let Some(last) = state.last_switch_at_ms {
        if now - last < (state.config.min_switch_interval_secs as i64) * 1000 {
            return code("min_switch_interval");
        }
    }

    Ok(())
}

/// Server-side execution gate kept for tests/callers that only need the
/// "gate + no adapter" behaviour: validation plus the fixed blocked
/// dispatch. `confirm` uses `validate` + the real adapter instead.
pub fn execute(
    state: &RotationState,
    snapshots: &HashMap<String, QuotaSnapshot>,
    request: &SwitchRequest,
    current_id: Option<&str>,
    now: i64,
) -> Result<SwitchOutcome, String> {
    validate(state, snapshots, request, current_id, now)?;
    Ok(SwitchOutcome::blocked(
        &request.target_account_id,
        "no_verified_adapter",
        "当前版本没有已验证的切换执行通道；阶段一认证兼容审核与热切换验收完成后才会开放。",
    ))
}
