//! Per-rule approval caching and rate limiting.
//!
//! State lives behind a `Mutex` so it survives the move to per-connection
//! threads in Step 7 without a retrofit.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Injectable clock (for testing without sleeping)
// ---------------------------------------------------------------------------

/// A source of monotonic time. Injected so tests can advance the clock.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// The real wall-clock.
pub struct RealClock;
impl Clock for RealClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

// ---------------------------------------------------------------------------
// Scoping state
// ---------------------------------------------------------------------------

/// Per-rule scoping configuration (loaded from config, immutable after start).
#[derive(Debug, Clone)]
pub struct RuleScope {
    /// After one approval, auto-approve the identical argv for this many seconds.
    /// `0` = always prompt.
    pub cache_ttl_secs: u64,
    /// Maximum approvals per minute. `0` = unlimited.
    pub rate_per_min: u32,
}

/// Mutable approval state shared across connections.
pub struct ApprovalState {
    /// `(rule_index, exact_argv_key)` → time of last approval.
    ///
    /// Keyed on exact argv (not just rule index) so that `pacman -S rg` being
    /// cached does NOT auto-approve `pacman -S evil` under the same `**` rule.
    /// This is the critical safety property of the TTL cache.
    cache: HashMap<(usize, Vec<String>), Instant>,
    /// `rule_index` → ring of recent approval timestamps (for rate limiting).
    rate: HashMap<usize, VecDeque<Instant>>,
}

impl ApprovalState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            rate: HashMap::new(),
        }
    }
}

impl Default for ApprovalState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public API (called while NOT holding the ApprovalState mutex)
// ---------------------------------------------------------------------------

/// Outcome returned by [`check_cache`].
pub enum CacheVerdict {
    /// A fresh cache entry exists — skip the approver; audit `approved-cached`.
    Hit,
    /// No valid cache entry — must prompt the human.
    Miss,
}

/// Check whether the request can be auto-approved from cache.
///
/// Call this *before* locking for the approver. The lock is acquired internally
/// and released before returning.
pub fn check_cache(
    state: &Mutex<ApprovalState>,
    scopes: &[RuleScope],
    rule_index: usize,
    argv: &[String],
    clock: &dyn Clock,
) -> CacheVerdict {
    let ttl = scopes.get(rule_index).map_or(0, |s| s.cache_ttl_secs);
    if ttl == 0 {
        return CacheVerdict::Miss;
    }
    let key = (rule_index, argv.to_vec());
    let now = clock.now();
    let guard = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(&last) = guard.cache.get(&key)
        && now.duration_since(last).as_secs() < ttl
    {
        return CacheVerdict::Hit;
    }
    CacheVerdict::Miss
}

/// Check whether this rule has exceeded its rate limit.
///
/// Returns `true` if the request is over-limit (should be denied).
/// The window is the last 60 seconds.
pub fn is_rate_limited(
    state: &Mutex<ApprovalState>,
    scopes: &[RuleScope],
    rule_index: usize,
    clock: &dyn Clock,
) -> bool {
    let limit = scopes.get(rule_index).map_or(0, |s| s.rate_per_min);
    if limit == 0 {
        return false;
    }
    let now = clock.now();
    let cutoff = now.checked_sub(Duration::from_mins(1)).unwrap_or(now);
    let mut guard = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let window = guard.rate.entry(rule_index).or_default();
    // Drop timestamps older than the 60-second window.
    while window.front().is_some_and(|&t| t <= cutoff) {
        window.pop_front();
    }
    window.len() >= limit as usize
}

/// Record an approval (update cache and rate-limit window).
///
/// Call this *after* a successful human approval. The lock is acquired
/// internally and released before returning.
pub fn record_approval(
    state: &Mutex<ApprovalState>,
    scopes: &[RuleScope],
    rule_index: usize,
    argv: &[String],
    clock: &dyn Clock,
) {
    let now = clock.now();
    let mut guard = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // Update cache if TTL is configured.
    let ttl = scopes.get(rule_index).map_or(0, |s| s.cache_ttl_secs);
    if ttl > 0 {
        guard.cache.insert((rule_index, argv.to_vec()), now);
    }

    note_execution(&mut guard, scopes, rule_index, now);
}

/// Record a cache-hit execution in the rate-limit window.
///
/// `rate_per_min` limits *executions*, not just human approvals. Cache hits
/// bypass the approver but are still counted so the operator's configured
/// rate cap applies to all executions uniformly.
pub fn record_cache_hit(
    state: &Mutex<ApprovalState>,
    scopes: &[RuleScope],
    rule_index: usize,
    clock: &dyn Clock,
) {
    let now = clock.now();
    let mut guard = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    note_execution(&mut guard, scopes, rule_index, now);
}

/// Record an execution in the rate-limit window — but only for rules that have
/// a rate cap. Rules with `rate_per_min = 0` are never pruned (the prune loop
/// lives behind the `limit == 0` early-return in [`is_rate_limited`]), so
/// pushing to their window would leak unboundedly.
fn note_execution(
    guard: &mut ApprovalState,
    scopes: &[RuleScope],
    rule_index: usize,
    now: Instant,
) {
    let rate = scopes.get(rule_index).map_or(0, |s| s.rate_per_min);
    if rate > 0 {
        guard.rate.entry(rule_index).or_default().push_back(now);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Fake clock backed by a shared atomic so tests can advance time.
    struct FakeClock {
        base: Instant,
        offset_secs: Arc<AtomicU64>,
    }

    impl FakeClock {
        fn new() -> (Self, Arc<AtomicU64>) {
            let offset = Arc::new(AtomicU64::new(0));
            let c = Self {
                base: Instant::now(),
                offset_secs: Arc::clone(&offset),
            };
            (c, offset)
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.base + Duration::from_secs(self.offset_secs.load(Ordering::Relaxed))
        }
    }

    fn scopes(ttl: u64, rate: u32) -> Vec<RuleScope> {
        vec![RuleScope {
            cache_ttl_secs: ttl,
            rate_per_min: rate,
        }]
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn cache_hit_within_ttl() {
        let state = Mutex::new(ApprovalState::new());
        let scopes = scopes(60, 0);
        let (clock, _offset) = FakeClock::new();
        let args = argv(&["pacman", "-S", "rg"]);

        // No approval yet → miss.
        assert!(matches!(
            check_cache(&state, &scopes, 0, &args, &clock),
            CacheVerdict::Miss
        ));

        record_approval(&state, &scopes, 0, &args, &clock);

        // Within TTL → hit.
        assert!(matches!(
            check_cache(&state, &scopes, 0, &args, &clock),
            CacheVerdict::Hit
        ));
    }

    #[test]
    fn cache_miss_after_ttl_expiry() {
        let state = Mutex::new(ApprovalState::new());
        let scopes = scopes(60, 0);
        let (clock, offset) = FakeClock::new();
        let args = argv(&["pacman", "-S", "rg"]);

        record_approval(&state, &scopes, 0, &args, &clock);
        // Advance past TTL.
        offset.store(61, Ordering::Relaxed);
        assert!(matches!(
            check_cache(&state, &scopes, 0, &args, &clock),
            CacheVerdict::Miss
        ));
    }

    #[test]
    fn different_argv_under_same_rule_is_a_miss() {
        let state = Mutex::new(ApprovalState::new());
        let scopes = scopes(60, 0);
        let (clock, _offset) = FakeClock::new();

        record_approval(&state, &scopes, 0, &argv(&["pacman", "-S", "rg"]), &clock);

        // Different package → must NOT be a cache hit (safety property).
        assert!(matches!(
            check_cache(&state, &scopes, 0, &argv(&["pacman", "-S", "evil"]), &clock),
            CacheVerdict::Miss
        ));
    }

    #[test]
    fn zero_ttl_never_caches() {
        let state = Mutex::new(ApprovalState::new());
        let scopes = scopes(0, 0); // TTL = 0 → always prompt
        let (clock, _offset) = FakeClock::new();
        let args = argv(&["id"]);

        record_approval(&state, &scopes, 0, &args, &clock);
        assert!(matches!(
            check_cache(&state, &scopes, 0, &args, &clock),
            CacheVerdict::Miss
        ));
    }

    #[test]
    fn rate_limit_allows_up_to_limit() {
        let state = Mutex::new(ApprovalState::new());
        let scopes = scopes(0, 2);
        let (clock, _offset) = FakeClock::new();

        assert!(!is_rate_limited(&state, &scopes, 0, &clock));
        record_approval(&state, &scopes, 0, &argv(&["id"]), &clock);
        assert!(!is_rate_limited(&state, &scopes, 0, &clock));
        record_approval(&state, &scopes, 0, &argv(&["id"]), &clock);
        // Third request → over limit.
        assert!(is_rate_limited(&state, &scopes, 0, &clock));
    }

    #[test]
    fn rate_window_slides() {
        let state = Mutex::new(ApprovalState::new());
        let scopes = scopes(0, 2);
        let (clock, offset) = FakeClock::new();

        record_approval(&state, &scopes, 0, &argv(&["id"]), &clock);
        record_approval(&state, &scopes, 0, &argv(&["id"]), &clock);
        assert!(is_rate_limited(&state, &scopes, 0, &clock));

        // Advance 61 seconds — the two old entries fall out of the window.
        offset.store(61, Ordering::Relaxed);
        assert!(!is_rate_limited(&state, &scopes, 0, &clock));
    }

    #[test]
    fn zero_rate_is_never_limited() {
        let state = Mutex::new(ApprovalState::new());
        let scopes = scopes(0, 0); // rate = 0 → unlimited
        let (clock, _offset) = FakeClock::new();
        for _ in 0..100 {
            record_approval(&state, &scopes, 0, &argv(&["id"]), &clock);
        }
        assert!(!is_rate_limited(&state, &scopes, 0, &clock));
    }

    #[test]
    fn zero_rate_rule_does_not_accumulate_timestamps() {
        // A rule with a cache TTL but no rate cap must not grow its rate window:
        // is_rate_limited never prunes a zero-limit rule, so any push leaks.
        let state = Mutex::new(ApprovalState::new());
        let scopes = scopes(60, 0); // ttl > 0, rate = 0
        let (clock, _offset) = FakeClock::new();
        let args = argv(&["id"]);

        for _ in 0..100 {
            record_approval(&state, &scopes, 0, &args, &clock);
            record_cache_hit(&state, &scopes, 0, &clock);
        }

        let guard = state.lock().unwrap();
        assert!(
            guard.rate.get(&0).is_none_or(VecDeque::is_empty),
            "zero-rate rule must not buffer timestamps"
        );
    }

    #[test]
    fn cache_hits_count_toward_rate_limit() {
        // TTL > 0 so the cache stays warm; rate = 1 so the second execution is over limit.
        let state = Mutex::new(ApprovalState::new());
        let scopes = scopes(60, 1);
        let (clock, _offset) = FakeClock::new();
        let args = argv(&["pacman", "-S", "rg"]);

        // Fresh approval: records in both cache and rate window.
        assert!(!is_rate_limited(&state, &scopes, 0, &clock));
        record_approval(&state, &scopes, 0, &args, &clock);

        // First cache hit: should consume rate budget.
        assert!(matches!(
            check_cache(&state, &scopes, 0, &args, &clock),
            CacheVerdict::Hit
        ));
        record_cache_hit(&state, &scopes, 0, &clock);

        // Second cache hit: rate budget exhausted — must be rate-limited now.
        assert!(is_rate_limited(&state, &scopes, 0, &clock));
    }
}
