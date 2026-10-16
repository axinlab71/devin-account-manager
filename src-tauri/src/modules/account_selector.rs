//! Deterministic candidate ranking for rotation. Pure: no IO, no clocks.
//!
//! Default order: min applicable remaining percent desc → priority desc →
//! earliest upcoming reset asc (never-reset last) → last switched asc
//! (never switched = longest idle first) → account id asc.
//! Alternate modes promote one key to primary and keep the rest as tiebreak.

use super::rotation_state::SortMode;

#[derive(Debug, Clone)]
pub struct Candidate {
    pub account_id: String,
    pub org_id: Option<String>,
    /// Smallest percent remaining across the candidate's applicable limits.
    pub min_applicable_percent: f64,
    pub priority: i64,
    /// Earliest reset time in the future (ms); None = unknown/past → sort last.
    pub next_reset_ms: Option<i64>,
    /// Last time this account was switched away from (ms); None = never.
    pub last_switched_ms: Option<i64>,
    pub cross_org: bool,
}

fn cmp_default_chain(a: &Candidate, b: &Candidate) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    b.min_applicable_percent
        .partial_cmp(&a.min_applicable_percent)
        .unwrap_or(Ordering::Equal)
        .then_with(|| b.priority.cmp(&a.priority))
        // Earliest reset first; unknown reset sorts last.
        .then_with(|| match (a.next_reset_ms, b.next_reset_ms) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        // Least-recently switched first; never-switched = longest idle.
        .then_with(|| match (a.last_switched_ms, b.last_switched_ms) {
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(x), Some(y)) => x.cmp(&y),
            (None, None) => Ordering::Equal,
        })
        .then_with(|| a.account_id.cmp(&b.account_id))
}

fn cmp_priority(a: &Candidate, b: &Candidate) -> std::cmp::Ordering {
    b.priority.cmp(&a.priority).then_with(|| cmp_default_chain(a, b))
}

fn cmp_earliest_reset(a: &Candidate, b: &Candidate) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a.next_reset_ms, b.next_reset_ms) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
    .then_with(|| cmp_default_chain(a, b))
}

fn cmp_longest_idle(a: &Candidate, b: &Candidate) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a.last_switched_ms, b.last_switched_ms) {
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(x), Some(y)) => x.cmp(&y),
        (None, None) => Ordering::Equal,
    }
    .then_with(|| cmp_default_chain(a, b))
}

/// Stable, deterministic ranking. Equal keys fall back to account id so the
/// output never depends on input order.
pub fn rank(mut candidates: Vec<Candidate>, mode: SortMode) -> Vec<Candidate> {
    let cmp = match mode {
        SortMode::MinRemainingDesc => cmp_default_chain,
        SortMode::PriorityFirst => cmp_priority,
        SortMode::EarliestReset => cmp_earliest_reset,
        SortMode::LongestIdle => cmp_longest_idle,
    };
    candidates.sort_by(cmp);
    candidates
}
