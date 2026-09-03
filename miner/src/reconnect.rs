//! Validator failure classification and reconnect backoff.
//!
//! Every miner in the fleet talks to the same validator, so a validator
//! restart, warm-up or overload is seen by all of them at the same moment.
//! Two things must therefore hold for registration and heartbeat failures:
//!
//! - A transient failure must never exit the process. An exit means a
//!   systemd restart (cold start, re-registration, inventory rescan, cache
//!   loss), and when the whole fleet exits together the re-registration
//!   storm overloads the validator again — a self-sustaining cascade.
//! - Retries must not happen in lockstep. Hundreds of miners retrying on
//!   the same schedule are a synchronized load spike on the validator.
//!
//! This module is the single place where "does this failure warrant shutting
//! down?" (`classify_validator_failure`) and "how long do we wait before the
//! next attempt?" (`DecorrelatedBackoff`) are decided.

use rand::Rng;
use std::time::Duration;

/// How the miner must react to a registration or heartbeat failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The validator explicitly refuses this miner as configured. Shut down.
    Permanent,
    /// Validator restart, warm-up, rate limiting or network trouble.
    /// Back off and retry; never exit.
    Transient,
}

/// Classify a registration or heartbeat failure by its error text.
///
/// Only an explicit, validator-issued permanent rejection is `Permanent`.
/// Everything else — including acks we do not recognise — is `Transient`:
/// exiting on a condition we do not understand is exactly the fleet-wide
/// cascade this module exists to prevent.
pub fn classify_validator_failure(error: &str) -> FailureKind {
    if error.starts_with("FAMILY_REJECTED") {
        FailureKind::Permanent
    } else {
        FailureKind::Transient
    }
}

/// Exponential backoff with decorrelated jitter, after the AWS Architecture
/// Blog's "Exponential Backoff And Jitter":
///
/// ```text
/// sleep = random_between(base, min(cap, prev_sleep * 3))
/// ```
///
/// Each delay is drawn from a range that grows with the previous delay, so
/// retries spread out instead of clustering on fixed exponential steps.
/// The cap is applied to the upper bound of the draw rather than to the
/// result (the original formula is `min(cap, random(base, prev * 3))`):
/// clamping the result would pile most of the fleet up at exactly `cap`
/// once `prev * 3 > cap`, which is the lockstep this exists to avoid.
/// Delays are always within `[base, cap]`.
#[derive(Debug, Clone)]
pub struct DecorrelatedBackoff {
    base: Duration,
    cap: Duration,
    prev: Duration,
}

impl DecorrelatedBackoff {
    /// Create a backoff that starts at `base` and never exceeds `cap`.
    pub fn new(base: Duration, cap: Duration) -> Self {
        let cap = cap.max(base);
        Self {
            base,
            cap,
            prev: base,
        }
    }

    /// Next delay, drawn from the thread-local RNG.
    pub fn next_delay(&mut self) -> Duration {
        self.next_delay_with(&mut rand::rng())
    }

    /// Next delay, drawn from `rng` (seedable for tests).
    pub fn next_delay_with<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Duration {
        let upper = self.prev.saturating_mul(3).min(self.cap).max(self.base);
        let delay = rng.random_range(self.base..=upper);
        self.prev = delay;
        delay
    }

    /// Forget the failure history. Call on the first success so the next
    /// failure starts again from `base`.
    pub fn reset(&mut self) {
        self.prev = self.base;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const BASE: Duration = Duration::from_secs(5);
    const CAP: Duration = Duration::from_secs(120);

    /// A generator that always draws the upper bound of the range, so the
    /// delay sequence is deterministic: `base*3^n` until it clamps at `cap`.
    struct MaxRng;
    impl rand::RngCore for MaxRng {
        fn next_u32(&mut self) -> u32 {
            u32::MAX
        }
        fn next_u64(&mut self) -> u64 {
            u64::MAX
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0xff);
        }
    }

    /// Every string the validator can answer with, plus the local error
    /// texts the registration/heartbeat paths produce. Anything not listed
    /// as Permanent must keep the miner running.
    #[test]
    fn classification_table() {
        use FailureKind::*;
        let table: &[(&str, FailureKind)] = &[
            // Explicit permanent rejection: registration ack, with or without reason.
            ("FAMILY_REJECTED", Permanent),
            ("FAMILY_REJECTED:cached_rejection", Permanent),
            ("FAMILY_REJECTED:not a member of family", Permanent),
            // Validator state that clears on its own.
            ("UNKNOWN", Transient),
            ("Re-registration needed", Transient),
            ("WARMING_UP", Transient),
            ("Validator warming up", Transient),
            ("RATE_LIMITED", Transient),
            // Local error texts on the registration path.
            ("ACK timeout", Transient),
            ("deadline has elapsed", Transient),
            ("connect timeout", Transient),
            ("connect error: connection refused", Transient),
            ("connect error: timed out", Transient),
            ("connection reset by peer", Transient),
            ("connection closed: application closed", Transient),
            ("Registration failed: BUSY", Transient),
            // Unknown or malformed acks are not a reason to exit.
            ("Registration failed: INVALID_SIG", Transient),
            ("Registration failed: BLACKLISTED", Transient),
            ("Registration failed: ", Transient),
            ("", Transient),
            ("Broken pipe (os error 32)", Transient),
        ];
        for (input, expected) in table {
            assert_eq!(
                classify_validator_failure(input),
                *expected,
                "classification of {input:?}"
            );
        }
    }

    #[test]
    fn backoff_stays_within_bounds_and_respects_cap() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut backoff = DecorrelatedBackoff::new(BASE, CAP);
        let mut prev = BASE;
        for _ in 0..200 {
            let d = backoff.next_delay_with(&mut rng);
            assert!(d >= BASE, "{d:?} below base");
            assert!(d <= CAP, "{d:?} above cap");
            // Decorrelated: never more than 3x the previous delay.
            assert!(
                d <= prev.saturating_mul(3).min(CAP),
                "{d:?} jumped past 3x{prev:?}"
            );
            prev = d;
        }
    }

    #[test]
    fn backoff_reaches_cap_and_stays_monotone_at_cap() {
        let mut backoff = DecorrelatedBackoff::new(BASE, CAP);
        let mut rng = MaxRng;
        // 5s, 15s, 45s, then clamped at 120s for good.
        assert_eq!(backoff.next_delay_with(&mut rng), Duration::from_secs(15));
        assert_eq!(backoff.next_delay_with(&mut rng), Duration::from_secs(45));
        for _ in 0..10 {
            assert_eq!(backoff.next_delay_with(&mut rng), CAP);
        }
    }

    #[test]
    fn backoff_is_jittered_across_seeds() {
        // Two miners at the same attempt count must not sleep the same time.
        let draws: Vec<Duration> = (0..8u64)
            .map(|seed| {
                let mut rng = StdRng::seed_from_u64(seed);
                let mut backoff = DecorrelatedBackoff::new(BASE, CAP);
                for _ in 0..4 {
                    backoff.next_delay_with(&mut rng);
                }
                backoff.next_delay_with(&mut rng)
            })
            .collect();
        let mut distinct = draws.clone();
        distinct.sort();
        distinct.dedup();
        assert!(
            distinct.len() >= 6,
            "expected distinct delays across seeds, got {draws:?}"
        );
    }

    #[test]
    fn backoff_reset_restarts_from_base() {
        let mut rng = MaxRng;
        let mut backoff = DecorrelatedBackoff::new(BASE, CAP);
        for _ in 0..5 {
            backoff.next_delay_with(&mut rng);
        }
        assert_eq!(backoff.next_delay_with(&mut rng), CAP);
        backoff.reset();
        assert_eq!(backoff.next_delay_with(&mut rng), BASE * 3);
    }

    #[test]
    fn cap_below_base_is_clamped_to_base() {
        let mut backoff = DecorrelatedBackoff::new(BASE, Duration::from_secs(1));
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..5 {
            assert_eq!(backoff.next_delay_with(&mut rng), BASE);
        }
    }

    /// Simulated brownout: a validator restart is seen as UNKNOWN, then the
    /// re-registration storm answers WARMING_UP / RATE_LIMITED / timeouts,
    /// then it recovers. Drives the same decisions the heartbeat loop makes:
    /// no failure in the sequence is Permanent (so the shutdown path is never
    /// taken), delays stay bounded and grow to the cap, and success resets
    /// the backoff.
    #[test]
    fn brownout_never_exits_and_resets_on_success() {
        let mut rng = MaxRng;
        let mut backoff = DecorrelatedBackoff::new(BASE, CAP);
        let brownout = ["UNKNOWN", "Re-registration needed", "WARMING_UP"]
            .into_iter()
            .chain(std::iter::repeat_n("RATE_LIMITED", 6))
            .chain(std::iter::repeat_n("connect timeout", 10))
            .chain(std::iter::repeat_n("ACK timeout", 10))
            .chain(std::iter::repeat_n("Validator warming up", 10));

        let mut attempts = 0u32;
        let mut shutdown_taken = false;
        let mut last_delay = Duration::ZERO;
        for err in brownout {
            match classify_validator_failure(err) {
                FailureKind::Permanent => shutdown_taken = true,
                FailureKind::Transient => {
                    attempts += 1;
                    last_delay = backoff.next_delay_with(&mut rng);
                    assert!(last_delay >= BASE && last_delay <= CAP);
                }
            }
        }
        assert!(
            !shutdown_taken,
            "a transient failure took the shutdown path"
        );
        assert!(
            attempts > 10,
            "brownout must outlast the old exit threshold"
        );
        assert_eq!(last_delay, CAP, "backoff should sit at the cap by now");

        // First successful heartbeat: backoff resets, next failure starts small.
        backoff.reset();
        assert_eq!(backoff.next_delay_with(&mut rng), BASE * 3);

        // A genuine permanent rejection still takes the shutdown path.
        assert_eq!(
            classify_validator_failure("FAMILY_REJECTED:not_in_family"),
            FailureKind::Permanent
        );
    }
}
