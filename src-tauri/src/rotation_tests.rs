//! Phase-2 synthetic tests: quota extraction, policy decisions, candidate
//! ranking, state persistence. Fully offline — fake snapshots injected, no
//! network, no client files.

use crate::models::windsurf::WindsurfAccount;
use crate::modules::account_selector::{self, Candidate};
use crate::modules::quota_monitor::{
    self, LimitApplicability, LimitKind, QuotaLimit, QuotaSnapshot, QueryFailure, QueryHealth,
    SemanticsConfidence,
};
use crate::modules::rotation_policy::{self, DecisionKind, RotationDecision};
use crate::modules::rotation_state::{
    LowQuotaObservation, RotationConfig, RotationMode, RotationState, SortMode,
};
use serde_json::json;
use std::collections::HashMap;

const NOW: i64 = 1_700_000_000_000;

fn limit(kind: LimitKind, pct: Option<f64>) -> QuotaLimit {
    QuotaLimit {
        kind,
        applicability: LimitApplicability::Applicable,
        percent_remaining: pct,
        remaining_units: None,
        total_units: None,
        reset_at_ms: None,
    }
}

fn snap(id: &str, org: Option<&str>, daily: Option<f64>, weekly: Option<f64>) -> QuotaSnapshot {
    QuotaSnapshot {
        account_id: id.into(),
        devin_account_id: Some(format!("acct-{}", id)),
        devin_org_id: org.map(str::to_string),
        plan_name: Some("PRO".into()),
        limits: vec![limit(LimitKind::DailyWindow, daily), limit(LimitKind::WeeklyWindow, weekly)],
        queried_at_ms: NOW,
        confidence: SemanticsConfidence::Verified,
        health: QueryHealth::Healthy,
    }
}

fn state_with(cfg: RotationConfig) -> RotationState {
    RotationState {
        config: cfg,
        ..Default::default()
    }
}

fn cfg_monitoring(pool: &[&str]) -> RotationConfig {
    RotationConfig {
        mode: RotationMode::SmartConfirm,
        enabled_pool: pool.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

fn eval(
    state: &RotationState,
    current: Option<&str>,
    snaps: &HashMap<String, QuotaSnapshot>,
) -> RotationDecision {
    rotation_policy::evaluate(state, current, snaps, NOW, false)
}

fn snaps_of(list: Vec<QuotaSnapshot>) -> HashMap<String, QuotaSnapshot> {
    list.into_iter().map(|s| (s.account_id.clone(), s)).collect()
}

// ---------- snapshot extraction ----------

#[test]
fn snapshot_extracts_daily_weekly_remaining_and_resets() {
    let account = WindsurfAccount {
        id: "a".into(),
        windsurf_plan_status: Some(json!({
            "planStatus": {
                "dailyQuotaRemainingPercent": 42,
                "weeklyQuotaRemainingPercent": "77",
                "dailyQuotaResetAtUnix": 1_700_100_000,
                "weeklyQuotaResetAtUnix": 1_700_500_000
            },
            "planInfo": {"planName": "PRO", "monthlyPromptCredits": 50000}
        })),
        ..Default::default()
    };
    let s = quota_monitor::snapshot_from_stored(&account, NOW);
    let daily = s.limits.iter().find(|l| l.kind == LimitKind::DailyWindow).unwrap();
    assert_eq!(daily.percent_remaining, Some(42.0));
    assert_eq!(daily.reset_at_ms, Some(1_700_100_000_000));
    let weekly = s.limits.iter().find(|l| l.kind == LimitKind::WeeklyWindow).unwrap();
    assert_eq!(weekly.percent_remaining, Some(77.0));
    assert_eq!(s.plan_name.as_deref(), Some("PRO"));
    // monthlyPromptCredits alone ⇒ total known, remaining ambiguous.
    let prompt = s.limits.iter().find(|l| l.kind == LimitKind::PromptCredits).unwrap();
    assert_eq!(prompt.total_units, Some(500.0));
}

#[test]
fn snapshot_marks_ambiguous_available_credits_unverified() {
    let account = WindsurfAccount {
        id: "a".into(),
        windsurf_plan_status: Some(json!({
            "planStatus": {"availablePromptCredits": 3000}
        })),
        ..Default::default()
    };
    let s = quota_monitor::snapshot_from_stored(&account, NOW);
    assert_eq!(s.confidence, SemanticsConfidence::UnverifiedMapping);
    let prompt = s.limits.iter().find(|l| l.kind == LimitKind::PromptCredits).unwrap();
    // available* alone is treated as total, remaining stays unknown — never 0.
    assert_eq!(prompt.percent_remaining, None);
}

#[test]
fn snapshot_decodes_proto_only_account() {
    // Account whose quota lives ONLY in devin_user_status_proto_b64.
    use crate::utils::protobuf::{encode_len_delim_field, encode_string_field, encode_varint_field};
    use base64::{engine::general_purpose::STANDARD, Engine};

    let plan_info = [
        encode_string_field(2, "PRO"),
        encode_varint_field(12, 50000),
    ]
    .concat();
    let plan_status = [
        encode_len_delim_field(1, &plan_info),
        encode_varint_field(14, 8),  // daily remaining 8%
        encode_varint_field(15, 40), // weekly remaining 40%
        encode_varint_field(17, 1_700_100_000),
    ]
    .concat();
    let user_status = encode_len_delim_field(13, &plan_status);
    let b64 = STANDARD.encode(&user_status);

    let account = WindsurfAccount {
        id: "proto".into(),
        devin_user_status_proto_b64: Some(b64),
        ..Default::default()
    };
    let s = quota_monitor::snapshot_from_stored(&account, NOW);
    let daily = s.limits.iter().find(|l| l.kind == LimitKind::DailyWindow).unwrap();
    assert_eq!(daily.percent_remaining, Some(8.0));
    assert_eq!(daily.reset_at_ms, Some(1_700_100_000_000));
    let weekly = s.limits.iter().find(|l| l.kind == LimitKind::WeeklyWindow).unwrap();
    assert_eq!(weekly.percent_remaining, Some(40.0));
    assert_eq!(s.plan_name.as_deref(), Some("PRO"));
    // monthlyPromptCredits alone → total known, remaining stays unknown;
    // nothing fabricated, still Verified.
    assert_eq!(s.confidence, SemanticsConfidence::Verified);
    let prompt = s.limits.iter().find(|l| l.kind == LimitKind::PromptCredits).unwrap();
    assert_eq!(prompt.percent_remaining, None);
    assert!(s.is_low(10.0));
}

#[test]
fn corrupt_proto_falls_back_to_unknown_not_zero() {
    let account = WindsurfAccount {
        id: "bad".into(),
        devin_user_status_proto_b64: Some("not-valid-base64!!!".into()),
        ..Default::default()
    };
    let s = quota_monitor::snapshot_from_stored(&account, NOW);
    let daily = s.limits.iter().find(|l| l.kind == LimitKind::DailyWindow).unwrap();
    assert_eq!(daily.applicability, LimitApplicability::Unknown);
    assert!(!s.is_low(10.0));
    assert_eq!(s.min_applicable_percent(), None);
}

#[test]
fn snapshot_extracts_flow_credits_and_marks_ambiguity() {
    let account = WindsurfAccount {
        id: "f".into(),
        windsurf_plan_status: Some(json!({
            "planStatus": {
                "dailyQuotaRemainingPercent": 50,
                "usedFlowCredits": 200,
            },
            "planInfo": {"monthlyFlowCredits": 1000}
        })),
        ..Default::default()
    };
    let s = quota_monitor::snapshot_from_stored(&account, NOW);
    let flow = s.limits.iter().find(|l| l.kind == LimitKind::FlowCredits).unwrap();
    assert_eq!(flow.applicability, LimitApplicability::Applicable);
    assert_eq!(flow.total_units, Some(10.0));
    assert_eq!(flow.remaining_units, Some(8.0));
    assert_eq!(flow.percent_remaining, Some(80.0));

    // availableFlowCredits alone is ambiguous → unverified, not fabricated.
    let account2 = WindsurfAccount {
        id: "f2".into(),
        windsurf_plan_status: Some(json!({
            "planStatus": {"availableFlowCredits": 500, "dailyQuotaRemainingPercent": 50}
        })),
        ..Default::default()
    };
    let s2 = quota_monitor::snapshot_from_stored(&account2, NOW);
    assert_eq!(s2.confidence, SemanticsConfidence::UnverifiedMapping);
    let flow2 = s2.limits.iter().find(|l| l.kind == LimitKind::FlowCredits).unwrap();
    assert_eq!(flow2.percent_remaining, None);
}

#[test]
fn snapshot_zero_remaining_is_low_not_missing() {
    let account = WindsurfAccount {
        id: "a".into(),
        windsurf_plan_status: Some(json!({
            "planStatus": {"dailyQuotaRemainingPercent": 0, "weeklyQuotaRemainingPercent": 55}
        })),
        ..Default::default()
    };
    let s = quota_monitor::snapshot_from_stored(&account, NOW);
    assert!(s.is_low(10.0));
    assert_eq!(s.min_applicable_percent(), Some(0.0));
}

// ---------- policy ----------

#[test]
fn disabled_monitoring_is_no_action() {
    let st = state_with(RotationConfig::default());
    let snaps = snaps_of(vec![snap("cur", Some("o1"), Some(5.0), Some(5.0))]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::NoAction));
    assert_eq!(d.reasons, vec!["monitoring_disabled"]);
}

#[test]
fn unknown_current_identity_blocks() {
    let st = state_with(cfg_monitoring(&["b"]));
    let snaps = snaps_of(vec![snap("b", Some("o1"), Some(90.0), Some(90.0))]);
    let d = eval(&st, None, &snaps);
    assert!(matches!(d.kind, DecisionKind::Blocked));
    assert_eq!(d.reasons, vec!["current_identity_unknown"]);
}

#[test]
fn stale_current_snapshot_blocks() {
    let st = state_with(cfg_monitoring(&[]));
    let mut s = snap("cur", Some("o1"), Some(5.0), Some(50.0));
    s.queried_at_ms = NOW - 600_000; // 10 min old > 120s window
    let snaps = snaps_of(vec![s]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Blocked));
    assert_eq!(d.reasons, vec!["current_snapshot_stale"]);
}

#[test]
fn rate_limited_is_blocked_not_exhaustion() {
    let st = state_with(cfg_monitoring(&[]));
    let mut s = snap("cur", Some("o1"), Some(5.0), Some(5.0));
    s.health = QueryHealth::Failed {
        failure: QueryFailure::RateLimited {
            retry_after_ms: Some(30_000),
        },
    };
    let snaps = snaps_of(vec![s]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Blocked));
    assert_eq!(d.reasons, vec!["current_rate_limited"]);
}

#[test]
fn low_quota_needs_two_observations_five_seconds_apart() {
    let mut st = state_with(cfg_monitoring(&["b"]));
    let snaps = snaps_of(vec![
        snap("cur", Some("o1"), Some(8.0), Some(40.0)),
        snap("b", Some("o1"), Some(90.0), Some(90.0)),
    ]);
    // First sighting → record observation, no recommendation yet.
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::NoAction));
    assert_eq!(d.reasons, vec!["awaiting_second_low_confirmation"]);
    assert!(d.record_low_observation);

    // Second sighting only 1s later → still waiting.
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation {
            first_at_ms: NOW,
            last_at_ms: NOW,
            count: 1,
        },
    );
    let d = eval(&st, Some("cur"), &snaps);
    assert_eq!(d.reasons, vec!["awaiting_second_low_confirmation"]);

    // 5s+ later → confirmed → recommendation.
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation {
            first_at_ms: NOW - 6_000,
            last_at_ms: NOW,
            count: 1,
        },
    );
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Recommendation));
    assert_eq!(d.target.as_ref().unwrap().account_id, "b");
    assert!(d.requires_confirmation);
    assert!(d.suggestion_id.is_some());
}

#[test]
fn failure_between_two_low_results_blocks_not_confirms() {
    let mut st = state_with(cfg_monitoring(&["b"]));
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation {
            first_at_ms: NOW - 60_000,
            last_at_ms: NOW - 50_000,
            count: 1,
        },
    );
    // Second query failed with network error → blocked, observation cleared.
    let mut s = snap("cur", Some("o1"), Some(5.0), Some(5.0));
    s.health = QueryHealth::Failed {
        failure: QueryFailure::Network,
    };
    let snaps = snaps_of(vec![s, snap("b", Some("o1"), Some(90.0), Some(90.0))]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Blocked));
    assert_eq!(d.reasons, vec!["current_query_network_error"]);
    assert!(d.clear_low_observation);
}

#[test]
fn candidate_with_any_low_limit_is_excluded() {
    let mut st = state_with(cfg_monitoring(&["b", "c"]));
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 10_000, last_at_ms: NOW, count: 2 },
    );
    let snaps = snaps_of(vec![
        snap("cur", Some("o1"), Some(8.0), Some(40.0)),
        // b: daily fine but weekly exhausted → excluded (0 is not > 15)
        snap("b", Some("o1"), Some(90.0), Some(0.0)),
        snap("c", Some("o1"), Some(80.0), Some(70.0)),
    ]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Recommendation));
    assert_eq!(d.target.as_ref().unwrap().account_id, "c");
}

#[test]
fn no_eligible_candidate_blocks() {
    let mut st = state_with(cfg_monitoring(&["b"]));
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 10_000, last_at_ms: NOW, count: 2 },
    );
    let snaps = snaps_of(vec![
        snap("cur", Some("o1"), Some(5.0), Some(5.0)),
        snap("b", Some("o1"), Some(12.0), Some(50.0)), // 12 ≤ 15 margin
    ]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Blocked));
    assert_eq!(d.reasons, vec!["no_eligible_candidate"]);
}

#[test]
fn candidate_in_cooldown_is_excluded() {
    let mut st = state_with(cfg_monitoring(&["b", "c"]));
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 10_000, last_at_ms: NOW, count: 2 },
    );
    st.cooldowns.insert("b".into(), NOW + 600_000);
    let snaps = snaps_of(vec![
        snap("cur", Some("o1"), Some(5.0), Some(5.0)),
        snap("b", Some("o1"), Some(99.0), Some(99.0)),
        snap("c", Some("o1"), Some(50.0), Some(50.0)),
    ]);
    let d = eval(&st, Some("cur"), &snaps);
    assert_eq!(d.target.as_ref().unwrap().account_id, "c");
}

#[test]
fn min_switch_interval_blocks_repeat_switch() {
    let mut st = state_with(cfg_monitoring(&["b"]));
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 10_000, last_at_ms: NOW, count: 2 },
    );
    st.last_switch_at_ms = Some(NOW - 60_000); // 1 min ago < 10 min
    let snaps = snaps_of(vec![
        snap("cur", Some("o1"), Some(5.0), Some(5.0)),
        snap("b", Some("o1"), Some(90.0), Some(90.0)),
    ]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Blocked));
    assert_eq!(d.reasons, vec!["min_switch_interval"]);
}

#[test]
fn circuit_breaker_pauses_after_failures() {
    let mut st = state_with(cfg_monitoring(&["b"]));
    st.consecutive_failures = 3;
    let snaps = snaps_of(vec![
        snap("cur", Some("o1"), Some(5.0), Some(5.0)),
        snap("b", Some("o1"), Some(90.0), Some(90.0)),
    ]);
    let d = eval(&st, Some("cur"), &snaps);
    assert_eq!(d.reasons, vec!["circuit_open_failures"]);
}

#[test]
fn unverified_semantics_warns_without_recommendation() {
    let mut st = state_with(cfg_monitoring(&["b"]));
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 10_000, last_at_ms: NOW, count: 2 },
    );
    let mut cur = snap("cur", Some("o1"), Some(5.0), Some(5.0));
    cur.confidence = SemanticsConfidence::UnverifiedMapping;
    let snaps = snaps_of(vec![cur, snap("b", Some("o1"), Some(90.0), Some(90.0))]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Warning));
    assert_eq!(d.reasons, vec!["unverified_quota_semantics"]);
    assert!(d.target.is_none());
}

#[test]
fn unverified_candidate_is_excluded() {
    let mut st = state_with(cfg_monitoring(&["b"]));
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 10_000, last_at_ms: NOW, count: 2 },
    );
    let mut b = snap("b", Some("o1"), Some(90.0), Some(90.0));
    b.confidence = SemanticsConfidence::UnverifiedMapping;
    let snaps = snaps_of(vec![snap("cur", Some("o1"), Some(5.0), Some(5.0)), b]);
    let d = eval(&st, Some("cur"), &snaps);
    assert_eq!(d.reasons, vec!["no_eligible_candidate"]);
}

#[test]
fn cross_org_candidate_is_flagged_and_needs_confirmation() {
    let mut st = state_with(cfg_monitoring(&["b"]));
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 10_000, last_at_ms: NOW, count: 2 },
    );
    let snaps = snaps_of(vec![
        snap("cur", Some("org-A"), Some(5.0), Some(5.0)),
        snap("b", Some("org-B"), Some(90.0), Some(90.0)),
    ]);
    // Even with auto_capable=true, cross-org always requires confirmation.
    let d = rotation_policy::evaluate(&st, Some("cur"), &snaps, NOW, true);
    assert!(matches!(d.kind, DecisionKind::Recommendation));
    let target = d.target.unwrap();
    assert!(target.cross_org);
    assert!(d.requires_confirmation);
}

#[test]
fn auto_mode_without_capability_still_requires_confirmation() {
    let mut cfg = cfg_monitoring(&["b"]);
    cfg.mode = RotationMode::Auto;
    let mut st = state_with(cfg);
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 10_000, last_at_ms: NOW, count: 2 },
    );
    let snaps = snaps_of(vec![
        snap("cur", Some("o1"), Some(5.0), Some(5.0)),
        snap("b", Some("o1"), Some(90.0), Some(90.0)),
    ]);
    let d = eval(&st, Some("cur"), &snaps); // auto_capable=false
    assert!(matches!(d.kind, DecisionKind::Recommendation));
    assert!(d.requires_confirmation);
}

#[test]
fn notify_only_mode_warns() {
    let mut cfg = cfg_monitoring(&["b"]);
    cfg.mode = RotationMode::NotifyOnly;
    let mut st = state_with(cfg);
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 10_000, last_at_ms: NOW, count: 2 },
    );
    let snaps = snaps_of(vec![
        snap("cur", Some("o1"), Some(5.0), Some(5.0)),
        snap("b", Some("o1"), Some(90.0), Some(90.0)),
    ]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Warning));
    assert!(d.target.is_none());
}

#[test]
fn zero_threshold_only_triggers_on_exhaustion() {
    let mut cfg = cfg_monitoring(&["b"]);
    cfg.threshold_percent = 0.0;
    let mut st = state_with(cfg);
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 10_000, last_at_ms: NOW, count: 2 },
    );
    // 1% remaining > 0 → not low.
    let snaps = snaps_of(vec![
        snap("cur", Some("o1"), Some(1.0), Some(50.0)),
        snap("b", Some("o1"), Some(90.0), Some(90.0)),
    ]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::NoAction));
    assert_eq!(d.reasons, vec!["healthy"]);
    // 0% → low → recommend.
    let snaps = snaps_of(vec![
        snap("cur", Some("o1"), Some(0.0), Some(50.0)),
        snap("b", Some("o1"), Some(90.0), Some(90.0)),
    ]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Recommendation));
}

#[test]
fn not_applicable_limits_do_not_trigger_or_block() {
    let mut st = state_with(cfg_monitoring(&["b"]));
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 10_000, last_at_ms: NOW, count: 2 },
    );
    // Candidate with a NotApplicable flex limit at no percent must pass;
    // NotApplicable zero is never treated as exhaustion.
    let mut b = snap("b", Some("o1"), Some(90.0), Some(90.0));
    b.limits.push(QuotaLimit {
        kind: LimitKind::FlexCredits,
        applicability: LimitApplicability::NotApplicable,
        percent_remaining: None,
        remaining_units: Some(0.0),
        total_units: None,
        reset_at_ms: None,
    });
    let snaps = snaps_of(vec![snap("cur", Some("o1"), Some(5.0), Some(5.0)), b]);
    let d = eval(&st, Some("cur"), &snaps);
    assert_eq!(d.target.as_ref().unwrap().account_id, "b");
}

#[test]
fn unmeasurable_current_limits_block_not_healthy() {
    // e.g. an account whose quota only exists in the binary proto snapshot —
    // unknown must not be treated as healthy/zero.
    let st = state_with(cfg_monitoring(&["b"]));
    let mut cur = snap("cur", Some("o1"), None, None);
    cur.limits.iter_mut().for_each(|l| {
        l.applicability = LimitApplicability::Unknown;
    });
    let snaps = snaps_of(vec![cur, snap("b", Some("o1"), Some(90.0), Some(90.0))]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Blocked));
    assert_eq!(d.reasons, vec!["current_limits_unknown"]);
}

#[test]
fn future_dated_snapshot_is_clock_anomaly_not_fresh() {
    // Clock moved backward after the snapshot was taken → stop, don't trust it.
    let mut st = state_with(cfg_monitoring(&["b"]));
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 10_000, last_at_ms: NOW, count: 2 },
    );
    let mut cur = snap("cur", Some("o1"), Some(5.0), Some(5.0));
    cur.queried_at_ms = NOW + 60_000; // 1 min in the future
    let snaps = snaps_of(vec![cur, snap("b", Some("o1"), Some(90.0), Some(90.0))]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Blocked));
    assert_eq!(d.reasons, vec!["clock_anomaly"]);

    // Same anomaly on the CANDIDATE excludes it → no eligible candidate.
    let mut b = snap("b", Some("o1"), Some(90.0), Some(90.0));
    b.queried_at_ms = NOW + 60_000;
    let snaps = snaps_of(vec![snap("cur", Some("o1"), Some(5.0), Some(5.0)), b]);
    let d = eval(&st, Some("cur"), &snaps);
    assert_eq!(d.reasons, vec!["no_eligible_candidate"]);
}

#[test]
fn dismissed_low_cycle_stays_suppressed_until_recovery() {
    let mut st = state_with(cfg_monitoring(&["b"]));
    let first = NOW - 10_000;
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: first, last_at_ms: NOW, count: 2 },
    );
    // User dismissed the recommendation for THIS low cycle.
    st.suppressed_at.insert("cur".into(), first);
    let snaps = snaps_of(vec![
        snap("cur", Some("o1"), Some(5.0), Some(5.0)),
        snap("b", Some("o1"), Some(90.0), Some(90.0)),
    ]);
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::NoAction));
    assert_eq!(d.reasons, vec!["dismissed_low_cycle"]);

    // A NEW low cycle (quota recovered then dropped again → new observation
    // with a different first_at) is not suppressed.
    st.low_quota_observations.insert(
        "cur".into(),
        LowQuotaObservation { first_at_ms: NOW - 8_000, last_at_ms: NOW, count: 3 },
    );
    let d = eval(&st, Some("cur"), &snaps);
    assert!(matches!(d.kind, DecisionKind::Recommendation));
}

// ---------- selector ----------

fn cand(id: &str, pct: f64, prio: i64, reset: Option<i64>, switched: Option<i64>) -> Candidate {
    Candidate {
        account_id: id.into(),
        org_id: None,
        min_applicable_percent: pct,
        priority: prio,
        next_reset_ms: reset,
        last_switched_ms: switched,
        cross_org: false,
    }
}

#[test]
fn default_rank_orders_by_remaining_then_priority_then_reset() {
    let ranked = account_selector::rank(
        vec![
            cand("c", 80.0, 0, Some(100), Some(1)),
            cand("a", 90.0, 0, Some(50), Some(1)),
            cand("b", 90.0, 5, Some(50), Some(1)),
            cand("d", 90.0, 5, Some(10), Some(1)),
        ],
        SortMode::MinRemainingDesc,
    );
    let ids: Vec<_> = ranked.iter().map(|c| c.account_id.as_str()).collect();
    // 90% group first; within it priority 5 beats 0; within that earlier reset wins.
    assert_eq!(ids, vec!["d", "b", "a", "c"]);
}

#[test]
fn rank_never_switched_counts_as_longest_idle() {
    let ranked = account_selector::rank(
        vec![
            cand("recent", 90.0, 0, Some(10), Some(999)),
            cand("never", 90.0, 0, Some(10), None),
        ],
        SortMode::MinRemainingDesc,
    );
    assert_eq!(ranked[0].account_id, "never");
}

#[test]
fn alternate_sort_modes_promote_their_key() {
    let cands = || {
        vec![
            cand("rich", 95.0, 0, Some(50), Some(1)),
            cand("prio", 80.0, 9, Some(50), Some(1)),
            cand("idle", 70.0, 0, Some(50), None),
        ]
    };
    assert_eq!(
        account_selector::rank(cands(), SortMode::PriorityFirst)[0].account_id,
        "prio"
    );
    assert_eq!(
        account_selector::rank(cands(), SortMode::LongestIdle)[0].account_id,
        "idle"
    );
    assert_eq!(
        account_selector::rank(
            vec![
                cand("later", 90.0, 0, Some(200), None),
                cand("sooner", 90.0, 0, Some(100), None),
                cand("unknown", 90.0, 0, None, None),
            ],
            SortMode::EarliestReset,
        )[0]
        .account_id,
        "sooner"
    );
}

// ---------- switch-adapter execution gate ----------

mod gate {
    use super::*;
    use crate::modules::rotation_state::RecommendationRecord;
    use crate::modules::switch_adapter::{
        execute, RollbackStatus, SwitchRequest, Verification,
    };

    pub(super) fn armed_state() -> RotationState {
        let mut st = state_with(cfg_monitoring(&["b"]));
        st.last_recommendation = Some(RecommendationRecord {
            id: "sug-1".into(),
            target_account_id: "b".into(),
            from_account_id: "cur".into(),
            cross_org: false,
            created_at_ms: NOW,
            expires_at_ms: NOW + 120_000,
            resolution: None,
        });
        st
    }

    pub(super) fn req() -> SwitchRequest {
        SwitchRequest {
            suggestion_id: "sug-1".into(),
            target_account_id: "b".into(),
            expected_current_id: "cur".into(),
            confirmed: true,
        }
    }

    pub(super) fn good_snaps() -> HashMap<String, QuotaSnapshot> {
        snaps_of(vec![
            snap("cur", Some("o1"), Some(5.0), Some(5.0)),
            snap("b", Some("o1"), Some(90.0), Some(90.0)),
        ])
    }

    #[test]
    fn unconfirmed_request_rejected() {
        let st = armed_state();
        let mut r = req();
        r.confirmed = false;
        assert_eq!(
            execute(&st, &good_snaps(), &r, Some("cur"), NOW).unwrap_err(),
            "not_confirmed"
        );
    }

    #[test]
    fn missing_mismatched_or_expired_suggestions_rejected() {
        // No pending suggestion at all.
        let st = state_with(cfg_monitoring(&["b"]));
        assert_eq!(
            execute(&st, &good_snaps(), &req(), Some("cur"), NOW).unwrap_err(),
            "no_pending_suggestion"
        );
        let st = armed_state();
        let mut r = req();
        r.suggestion_id = "other".into();
        assert_eq!(
            execute(&st, &good_snaps(), &r, Some("cur"), NOW).unwrap_err(),
            "suggestion_mismatch"
        );
        let mut st2 = armed_state();
        st2.last_recommendation.as_mut().unwrap().expires_at_ms = NOW - 1;
        assert_eq!(
            execute(&st2, &good_snaps(), &req(), Some("cur"), NOW).unwrap_err(),
            "suggestion_expired"
        );
        st2.last_recommendation.as_mut().unwrap().resolution = Some("dismissed".into());
        st2.last_recommendation.as_mut().unwrap().expires_at_ms = NOW + 1000;
        assert_eq!(
            execute(&st2, &good_snaps(), &req(), Some("cur"), NOW).unwrap_err(),
            "suggestion_already_resolved"
        );
    }

    #[test]
    fn changed_current_identity_rejected() {
        let st = armed_state();
        assert_eq!(
            execute(&st, &good_snaps(), &req(), Some("other"), NOW).unwrap_err(),
            "current_identity_changed"
        );
        assert_eq!(
            execute(&st, &good_snaps(), &req(), None, NOW).unwrap_err(),
            "current_identity_unknown"
        );
    }

    #[test]
    fn target_pool_cooldown_and_staleness_rechecked() {
        let mut st = armed_state();
        st.config.enabled_pool = vec![];
        assert_eq!(
            execute(&st, &good_snaps(), &req(), Some("cur"), NOW).unwrap_err(),
            "target_not_in_pool"
        );
        let mut st = armed_state();
        st.cooldowns.insert("b".into(), NOW + 1_000);
        assert_eq!(
            execute(&st, &good_snaps(), &req(), Some("cur"), NOW).unwrap_err(),
            "target_in_cooldown"
        );
        let st = armed_state();
        let mut snaps = good_snaps();
        snaps.get_mut("b").unwrap().queried_at_ms = NOW - 600_000;
        assert_eq!(
            execute(&st, &snaps, &req(), Some("cur"), NOW).unwrap_err(),
            "target_snapshot_stale"
        );
    }

    #[test]
    fn valid_request_is_blocked_without_writes_not_silent_restart() {
        let st = armed_state();
        let outcome = execute(&st, &good_snaps(), &req(), Some("cur"), NOW).unwrap();
        // Gated: no adapter is verified. The outcome must show nothing was
        // attempted — no local write, no restart, no rollback.
        assert_eq!(outcome.failure_code.as_deref(), Some("no_verified_adapter"));
        assert_eq!(outcome.adapter, None);
        assert!(!outcome.restart_required);
        assert_eq!(outcome.local_match, Verification::NotAttempted);
        assert_eq!(outcome.client_recognized, Verification::NotAttempted);
        assert_eq!(outcome.remote_verified, Verification::NotAttempted);
        assert_eq!(outcome.rollback, RollbackStatus::NotNeeded);
    }
}

// ---------- config validation ----------

#[test]
fn config_rejects_out_of_range_values() {
    let mut c = RotationConfig::default();
    c.threshold_percent = 31.0;
    assert!(c.validate().is_err());
    c.threshold_percent = 0.0;
    c.poll_interval_secs = 10;
    assert!(c.validate().is_err());
    c.poll_interval_secs = 60;
    c.candidate_margin_points = 31.0;
    assert!(c.validate().is_err());
    c.candidate_margin_points = 5.0;
    c.threshold_percent = 30.0;
    assert!(c.validate().is_ok());
}

// ---------- backup-restore recovery gate ----------

mod recovery_gate {
    use super::gate::{armed_state, good_snaps, req};
    use super::*;
    use crate::modules::rotation_state::{self, RecommendationRecord};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rot_recovery_{}_{}_{}",
            tag,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn state_with_rec(resolution: Option<&str>) -> RotationState {
        let mut st = RotationState::default();
        st.config.mode = RotationMode::SmartConfirm;
        st.last_recommendation = Some(RecommendationRecord {
            id: "sug-r".into(),
            target_account_id: "b".into(),
            from_account_id: "cur".into(),
            cross_org: false,
            created_at_ms: NOW,
            expires_at_ms: NOW + 120_000,
            resolution: resolution.map(str::to_string),
        });
        st
    }

    /// Simulate: main file corrupted, `.bak` holds an older snapshot whose
    /// recommendation has the given resolution. Returns the isolated dir.
    fn corrupt_main_with_bak(bak_state: &RotationState, tag: &str) -> PathBuf {
        let dir = temp_dir(tag);
        std::env::set_var("COCKPIT_TOOLS_TEST_DATA_DIR", &dir);
        let path = dir.join("rotation-state.json");
        fs::write(&path, "{ not json").unwrap();
        fs::write(
            dir.join("rotation-state.json.bak"),
            serde_json::to_string(bak_state).unwrap(),
        )
        .unwrap();
        dir
    }

    #[test]
    fn restored_pending_is_promoted_and_the_gate_persists() {
        let dir = corrupt_main_with_bak(&state_with_rec(None), "pending");
        let s = rotation_state::load();
        assert_eq!(
            s.last_recommendation.as_ref().unwrap().resolution.as_deref(),
            Some("awaiting_client"),
            "restored pending must surface as outcome-unknown"
        );
        assert!(s.recovered_from_backup);
        // The gate must be durable: a second load (file now restored +
        // saved) must NOT fall back to the old pending state.
        let s2 = rotation_state::load();
        assert!(s2.recovered_from_backup);
        assert_eq!(
            s2.last_recommendation
                .as_ref()
                .unwrap()
                .resolution
                .as_deref(),
            Some("awaiting_client")
        );
        std::env::remove_var("COCKPIT_TOOLS_TEST_DATA_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restored_failed_is_promoted_too() {
        // failed → relaunch → corrupt → .bak still says `failed`: must not
        // become retryable again.
        let dir = corrupt_main_with_bak(&state_with_rec(Some("failed")), "failed");
        let s = rotation_state::load();
        assert_eq!(
            s.last_recommendation.as_ref().unwrap().resolution.as_deref(),
            Some("awaiting_client")
        );
        assert!(s.recovered_from_backup);
        std::env::remove_var("COCKPIT_TOOLS_TEST_DATA_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovered_state_blocks_confirmation_until_reconciled() {
        let mut st = armed_state();
        st.recovered_from_backup = true;
        assert_eq!(
            crate::modules::switch_adapter::validate(
                &st,
                &good_snaps(),
                &req(),
                Some("cur"),
                NOW
            )
            .unwrap_err(),
            "recovery_review_required"
        );
    }

    #[test]
    fn unknown_resolution_fails_closed() {
        let mut st = armed_state();
        st.last_recommendation
            .as_mut()
            .unwrap()
            .resolution = Some("tampered_value".into());
        assert_eq!(
            crate::modules::switch_adapter::validate(
                &st,
                &good_snaps(),
                &req(),
                Some("cur"),
                NOW
            )
            .unwrap_err(),
            "suggestion_already_resolved"
        );
    }
}
