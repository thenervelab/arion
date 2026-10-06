//! Admission of inbound QUIC connection attempts.
//!
//! quinn-proto 0.11 silently abandons an `Incoming` that is accepted more
//! than `max_idle_timeout` after it was received ("abandoning accept of
//! stale initial"): no packet goes back, the client times out its connect
//! and retries. Once the accept pipeline falls behind, every new attempt
//! arrives stale, is dropped silently and is retried — a self-sustaining
//! overload measured on a test bench (thousands of Initials in 20 s, zero
//! Initial/Handshake sent back) while established connections kept working.
//!
//! Three bounds turn that silent loss into explicit, fast answers:
//! - `max_incoming` caps the attempts quinn queues for us; above it quinn
//!   itself answers CONNECTION_REFUSED.
//! - an attempt that waited longer than `stale_after` between leaving
//!   quinn's queue and reaching `accept` is refused (CONNECTION_REFUSED),
//!   well before quinn would drop it silently at the idle timeout.
//! - an attempt arriving while the connection cap is reached is refused.
//!
//! quinn does not expose when an `Incoming` was received, so the measured
//! wait starts when the accept loop dequeues it; the time spent in quinn's
//! own queue is bounded by `max_incoming` instead.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Default QUIC idle timeout (quinn's own default, now explicit: it is also
/// the age past which quinn drops a queued attempt without answering).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Default cap on attempts queued by quinn (`MINER_QUIC_MAX_INCOMING`).
pub const DEFAULT_MAX_INCOMING: usize = 1024;
/// Default wait past which an attempt is refused (`MINER_QUIC_STALE_INCOMING_SECS`).
pub const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(5);

/// Refusals are logged on the first one and then once every this many.
const REFUSAL_LOG_EVERY: u64 = 500;

/// Resolved admission bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptConfig {
    pub idle_timeout: Duration,
    pub max_incoming: usize,
    pub stale_after: Duration,
}

impl Default for AcceptConfig {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_incoming: DEFAULT_MAX_INCOMING,
            stale_after: DEFAULT_STALE_AFTER,
        }
    }
}

impl AcceptConfig {
    /// Resolve from the process environment.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::resolve(|name| std::env::var(name).ok())
    }

    /// Resolve with an injectable lookup. An unparseable or out-of-range
    /// value is an error, never a silent default.
    pub fn resolve(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let mut cfg = Self::default();
        if let Some(raw) = lookup("MINER_QUIC_MAX_INCOMING") {
            let n: usize = raw.trim().parse().map_err(|_| {
                anyhow::anyhow!("MINER_QUIC_MAX_INCOMING '{raw}' is not an integer")
            })?;
            anyhow::ensure!(n >= 1, "MINER_QUIC_MAX_INCOMING must be >= 1");
            cfg.max_incoming = n;
        }
        if let Some(raw) = lookup("MINER_QUIC_STALE_INCOMING_SECS") {
            let secs: u64 = raw.trim().parse().map_err(|_| {
                anyhow::anyhow!("MINER_QUIC_STALE_INCOMING_SECS '{raw}' is not an integer")
            })?;
            cfg.stale_after = Duration::from_secs(secs);
        }
        anyhow::ensure!(
            !cfg.stale_after.is_zero() && cfg.stale_after < cfg.idle_timeout,
            "MINER_QUIC_STALE_INCOMING_SECS must be in 1..{} (below the idle timeout)",
            cfg.idle_timeout.as_secs()
        );
        Ok(cfg)
    }
}

/// What to do with one inbound attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptDecision {
    Accept,
    /// Waited too long: quinn would soon drop it silently.
    RefuseStale,
    /// The inbound connection cap is reached.
    RefuseFull,
}

/// Decide the fate of an attempt that waited `waited` since dequeue.
pub fn decide(waited: Duration, stale_after: Duration, has_permit: bool) -> AcceptDecision {
    if waited >= stale_after {
        AcceptDecision::RefuseStale
    } else if !has_permit {
        AcceptDecision::RefuseFull
    } else {
        AcceptDecision::Accept
    }
}

static ACCEPTED: AtomicU64 = AtomicU64::new(0);
static REFUSED_STALE: AtomicU64 = AtomicU64::new(0);
static REFUSED_FULL: AtomicU64 = AtomicU64::new(0);

/// Count a decision. Returns `true` when this refusal should be logged
/// (the first, then one every [`REFUSAL_LOG_EVERY`]).
pub fn record(decision: AcceptDecision) -> bool {
    let counter = match decision {
        AcceptDecision::Accept => {
            ACCEPTED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        AcceptDecision::RefuseStale => &REFUSED_STALE,
        AcceptDecision::RefuseFull => &REFUSED_FULL,
    };
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    n == 1 || n.is_multiple_of(REFUSAL_LOG_EVERY)
}

/// Totals: (accepted, refused_stale, refused_full).
pub fn totals() -> (u64, u64, u64) {
    (
        ACCEPTED.load(Ordering::Relaxed),
        REFUSED_STALE.load(Ordering::Relaxed),
        REFUSED_FULL.load(Ordering::Relaxed),
    )
}

/// Prometheus text for the admission counters.
pub fn render_prometheus() -> String {
    let (accepted, stale, full) = totals();
    format!(
        "# TYPE miner_quic_incoming_total counter\n\
         miner_quic_incoming_total{{outcome=\"accepted\"}} {accepted}\n\
         miner_quic_incoming_total{{outcome=\"refused_stale\"}} {stale}\n\
         miner_quic_incoming_total{{outcome=\"refused_full\"}} {full}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn fresh_attempt_with_permit_is_accepted() {
        let d = decide(Duration::from_millis(10), DEFAULT_STALE_AFTER, true);
        assert_eq!(d, AcceptDecision::Accept);
    }

    #[test]
    fn attempt_at_or_past_the_bound_is_refused_stale() {
        let bound = Duration::from_secs(5);
        assert_eq!(decide(bound, bound, true), AcceptDecision::RefuseStale);
        assert_eq!(
            decide(Duration::from_secs(29), bound, true),
            AcceptDecision::RefuseStale
        );
        assert_eq!(
            decide(bound - Duration::from_millis(1), bound, true),
            AcceptDecision::Accept
        );
    }

    #[test]
    fn fresh_attempt_without_permit_is_refused_full() {
        let d = decide(Duration::ZERO, DEFAULT_STALE_AFTER, false);
        assert_eq!(d, AcceptDecision::RefuseFull);
    }

    #[test]
    fn stale_wins_over_full() {
        let d = decide(Duration::from_secs(10), DEFAULT_STALE_AFTER, false);
        assert_eq!(d, AcceptDecision::RefuseStale);
    }

    #[test]
    fn defaults_without_env() {
        let cfg = AcceptConfig::resolve(env(&[])).unwrap();
        assert_eq!(cfg, AcceptConfig::default());
        assert_eq!(cfg.idle_timeout, Duration::from_secs(30));
        assert_eq!(cfg.max_incoming, 1024);
        assert_eq!(cfg.stale_after, Duration::from_secs(5));
    }

    #[test]
    fn env_overrides_are_applied() {
        let cfg = AcceptConfig::resolve(env(&[
            ("MINER_QUIC_MAX_INCOMING", " 256 "),
            ("MINER_QUIC_STALE_INCOMING_SECS", "3"),
        ]))
        .unwrap();
        assert_eq!(cfg.max_incoming, 256);
        assert_eq!(cfg.stale_after, Duration::from_secs(3));
    }

    #[test]
    fn invalid_env_values_are_errors() {
        for pairs in [
            [("MINER_QUIC_MAX_INCOMING", "lots")],
            [("MINER_QUIC_MAX_INCOMING", "0")],
            [("MINER_QUIC_STALE_INCOMING_SECS", "0")],
            [("MINER_QUIC_STALE_INCOMING_SECS", "30")],
            [("MINER_QUIC_STALE_INCOMING_SECS", "-1")],
        ] {
            assert!(AcceptConfig::resolve(env(&pairs)).is_err(), "{pairs:?}");
        }
    }

    #[test]
    fn refusals_are_counted_and_log_rate_limited() {
        let (_, stale_before, _) = totals();
        let logged = (0..REFUSAL_LOG_EVERY * 2)
            .filter(|_| record(AcceptDecision::RefuseStale))
            .count();
        let (_, stale_after, _) = totals();
        assert_eq!(stale_after - stale_before, REFUSAL_LOG_EVERY * 2);
        // At most the first refusal plus one per period.
        assert!((2..=3).contains(&logged), "logged {logged}");
        assert!(!record(AcceptDecision::Accept));
        assert!(render_prometheus().contains("outcome=\"refused_stale\""));
    }
}
