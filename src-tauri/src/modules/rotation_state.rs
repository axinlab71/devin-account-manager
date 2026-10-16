//! Persistent rotation state (`rotation-state.json` in the manager data dir).
//!
//! Stores configuration, the user-enabled candidate pool, cooldowns, recent
//! switch timestamps, failure counters and the latest recommendation. Holds
//! no credentials and does not touch the official client's storage.
//! Writes go through `atomic_write`; corrupt files are quarantined, never
//! silently overwritten.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::modules::{account, atomic_write};

pub const ROTATION_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationMode {
    /// Monitoring disabled (first-install default).
    Off,
    /// Only surface a warning; never produce an executable recommendation.
    NotifyOnly,
    /// Recommend a candidate and wait for explicit user confirmation.
    SmartConfirm,
    /// Execute without confirmation. Only reachable when every capability
    /// gate has real evidence; unknown capabilities downgrade to
    /// SmartConfirm behaviour at decision time.
    Auto,
}

impl Default for RotationMode {
    fn default() -> Self {
        RotationMode::Off
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortMode {
    /// Default: highest minimum applicable remaining ratio first.
    MinRemainingDesc,
    PriorityFirst,
    EarliestReset,
    LongestIdle,
}

impl Default for SortMode {
    fn default() -> Self {
        SortMode::MinRemainingDesc
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationConfig {
    pub mode: RotationMode,
    /// Low-quota trigger percent, 0..=30. A limit at exactly 0% only triggers
    /// when the threshold is 0 (i.e. exhaustion) or above.
    pub threshold_percent: f64,
    /// Poll cadence, 30..=3600 seconds.
    pub poll_interval_secs: u64,
    /// Snapshots older than this are stale and block decisions.
    pub snapshot_max_age_secs: u64,
    /// Every applicable candidate limit must exceed the threshold by at
    /// least this many percentage points.
    pub candidate_margin_points: f64,
    /// Global minimum interval between executed switches.
    pub min_switch_interval_secs: u64,
    /// Cooldown applied to an account after it is switched away from.
    pub cooldown_secs: u64,
    /// Consecutive switch-execution failures that pause the monitor.
    pub max_consecutive_failures: u32,
    /// Minimum separation between the two low-quota confirmations.
    pub low_confirm_gap_ms: i64,
    pub sort_mode: SortMode,
    /// Internal account ids the user enabled for recommendations.
    pub enabled_pool: Vec<String>,
    /// Per-account priority weights (higher = preferred).
    pub priorities: HashMap<String, i64>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            mode: RotationMode::Off,
            threshold_percent: 10.0,
            poll_interval_secs: 60,
            snapshot_max_age_secs: 120,
            candidate_margin_points: 5.0,
            min_switch_interval_secs: 600,
            cooldown_secs: 1800,
            max_consecutive_failures: 3,
            low_confirm_gap_ms: 5_000,
            sort_mode: SortMode::MinRemainingDesc,
            enabled_pool: Vec::new(),
            priorities: HashMap::new(),
        }
    }
}

impl RotationConfig {
    /// Strict validation: invalid configs are rejected, never clamped into
    /// surprising values. The previous persisted config stays untouched.
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=30.0).contains(&self.threshold_percent) {
            return Err("阈值需在 0~30% 之间".into());
        }
        if !(30..=3600).contains(&self.poll_interval_secs) {
            return Err("轮询间隔需在 30~3600 秒之间".into());
        }
        if !(5..=3600).contains(&self.snapshot_max_age_secs) {
            return Err("快照有效期需在 5~3600 秒之间".into());
        }
        if self.candidate_margin_points < 0.0 || self.candidate_margin_points > 30.0 {
            return Err("候选安全余量需在 0~30 个百分点之间".into());
        }
        if self.min_switch_interval_secs == 0 || self.min_switch_interval_secs > 86_400 {
            return Err("全局切换间隔需在 1~86400 秒之间".into());
        }
        if self.cooldown_secs > 7 * 86_400 {
            return Err("冷却时间不能超过 7 天".into());
        }
        if self.max_consecutive_failures == 0 || self.max_consecutive_failures > 100 {
            return Err("熔断次数需在 1~100 之间".into());
        }
        if self.low_confirm_gap_ms < 0 {
            return Err("低额度确认间隔不能为负".into());
        }
        if self.mode == RotationMode::Auto {
            // Cross-org full-auto is permanently disallowed; auto itself is
            // additionally gated at decision time by capability evidence.
        }
        Ok(())
    }
}

/// Two-confirmation tracking for a low-quota observation on one account.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LowQuotaObservation {
    pub first_at_ms: i64,
    pub last_at_ms: i64,
    pub count: u32,
}

/// Latest emitted recommendation; expires and is invalidated by any
/// identity/config/state change relevant to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendationRecord {
    pub id: String,
    pub target_account_id: String,
    pub from_account_id: String,
    pub cross_org: bool,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    /// None = pending offer; `executing`/`awaiting_client` = in-flight
    /// (launched, awaiting the official modal — survives TTL and restart,
    /// normalized on load); `failed` = adapter refused/failed, retryable;
    /// `verified`/`executed`/`blocked`/`dismissed` = terminal. Any other
    /// value also blocks re-confirmation (unknown states fail closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationState {
    pub schema_version: u32,
    pub config: RotationConfig,
    /// account_id -> cooldown-until (unix ms).
    #[serde(default)]
    pub cooldowns: HashMap<String, i64>,
    #[serde(default)]
    pub cooldown_reasons: HashMap<String, String>,
    #[serde(default)]
    pub last_switch_at_ms: Option<i64>,
    /// account_id -> last time this account was switched AWAY from (unix ms).
    /// Drives the LongestIdle ranking; never-switched accounts sort oldest.
    #[serde(default)]
    pub switched_away_at: HashMap<String, i64>,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub paused: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<String>,
    #[serde(default)]
    pub low_quota_observations: HashMap<String, LowQuotaObservation>,
    /// account_id -> first_at_ms of the low-quota observation the user
    /// dismissed. Suppresses re-recommendation for the SAME low cycle; a
    /// later cycle (new observation after recovery) notifies again.
    #[serde(default)]
    pub suppressed_at: HashMap<String, i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_recommendation: Option<RecommendationRecord>,
    /// Set when state was recovered from the `.bak` copy: everything in it
    /// predates the corruption, so a switch may have been launched that the
    /// restored record doesn't reflect. Persisted gate — all new executions
    /// block until the user explicitly reconciles (verify/dismiss the
    /// in-flight record, or acknowledge when there is none).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recovered_from_backup: bool,
}

impl Default for RotationState {
    fn default() -> Self {
        Self {
            schema_version: ROTATION_STATE_SCHEMA_VERSION,
            config: RotationConfig::default(),
            cooldowns: HashMap::new(),
            cooldown_reasons: HashMap::new(),
            last_switch_at_ms: None,
            switched_away_at: HashMap::new(),
            consecutive_failures: 0,
            paused: false,
            pause_reason: None,
            low_quota_observations: HashMap::new(),
            suppressed_at: HashMap::new(),
            last_recommendation: None,
            recovered_from_backup: false,
        }
    }
}

pub fn state_path() -> Result<PathBuf, String> {
    Ok(account::get_data_dir()?.join("rotation-state.json"))
}

/// Load persisted state. Missing file → defaults. Corrupt file → the
/// `.bak` auto-restore path runs first; unrestorable input falls back to
/// defaults (fail-closed: a broken file never produces phantom cooldowns
/// or approvals).
pub fn load() -> RotationState {
    let path = match state_path() {
        Ok(p) => p,
        Err(_) => return RotationState::default(),
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return RotationState::default(),
    };
    // Parse directly first so we can tell whether the .bak auto-restore ran:
    // a restored recommendation is an OLDER snapshot — a pending/executing
    // record there may actually describe a launched login whose final state
    // was lost with the corruption. Those must surface as "outcome unknown"
    // (awaiting_client: verify/dismiss only), never as a fresh pending offer.
    let (mut state, restored_from_backup): (RotationState, bool) =
        match serde_json::from_str::<RotationState>(&content) {
            Ok(s) => (s, false),
            Err(_) => match atomic_write::parse_json_with_auto_restore(&path, &content) {
                Ok(s) => (s, true),
                // Corrupt and unrestorable: quarantined upstream if possible;
                // never honour a broken file.
                Err(_) => return RotationState::default(),
            },
        };
    if state.schema_version != ROTATION_STATE_SCHEMA_VERSION {
        // Unknown/newer schema: do not guess field semantics.
        state = RotationState::default();
    }
    if state.config.validate().is_err() {
        // A persisted config that fails validation is never honoured.
        state.config = RotationConfig::default();
    }
    if let Some(rec) = state.last_recommendation.as_mut() {
        // `executing` only exists while an adapter call is in flight; a
        // persisted one means the process died mid-switch and the outcome is
        // UNKNOWN — the URI may already have been launched and the official
        // modal may still be open. `awaiting_client` is the honest state:
        // verify or dismiss resolves it, retry does not.
        if rec.resolution.as_deref() == Some("executing") {
            rec.resolution = Some("awaiting_client".into());
        }
        // A .bak restore rewinds to an OLDER snapshot: any record that is not
        // terminal — pending, executing, awaiting, even `failed` — may hide a
        // launch that happened after the backup was taken. Promote all of
        // them to `awaiting_client` (outcome unknown: verify/dismiss only).
        if restored_from_backup
            && matches!(
                rec.resolution.as_deref(),
                None | Some("executing") | Some("awaiting_client") | Some("failed")
            )
        {
            rec.resolution = Some("awaiting_client".into());
        }
    }
    if restored_from_backup {
        // The gate must be durable: a pure in-memory promotion is lost on the
        // next restart (the main file now *is* the old backup). Persist now;
        // if this fails the in-memory gate still holds for this session.
        state.recovered_from_backup = true;
        let _ = save(&state);
    }
    state
}

pub fn save(state: &RotationState) -> Result<(), String> {
    state
        .config
        .validate()
        .map_err(|e| format!("拒绝保存无效轮换配置: {}", e))?;
    let path = state_path()?;
    let body =
        serde_json::to_string_pretty(state).map_err(|e| format!("序列化轮换状态失败: {}", e))?;
    atomic_write::write_string_atomic(&path, &body)
}
