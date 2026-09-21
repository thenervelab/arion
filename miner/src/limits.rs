//! Boot-time resource limits derived from the machine's RAM.
//!
//! Two limits used to be compile-time constants sized for one node class:
//! the packed-store in-flight write budget (128 MiB) and the cap on
//! concurrent P2P stream handlers (2048). Miners run on machines from a
//! few GiB of RAM to several hundred, so the same constant was either a
//! needless stall on the big ones or an OOM risk on the small ones. Since 0.1.34 both are
//! derived once at boot from the total physical memory:
//!
//! - `inflight_budget = clamp(total_ram / 8, 256 MiB, 4 GiB)`
//! - `max_handlers    = clamp(inflight_budget / 3 MiB, 256, 8192)`
//!
//! (3 MiB is the working set of one Store handler at the largest shard
//! size: the payload buffer, its queued copy and the writer's batch share.)
//!
//! Each is overridable by an environment variable, read once:
//! `PACKED_INFLIGHT_MAX_BYTES` (bytes, floor 8 MiB, cap 4 GiB) and
//! `MINER_MAX_CONCURRENT_HANDLERS` (count, floor 16, cap 65 536). A value
//! that does not parse is ignored with a warning and the derived default
//! stands. The chosen values and their origin are logged once at boot
//! (`resource limits`).

use std::sync::OnceLock;

/// Floor of the derived in-flight budget.
pub const MIN_INFLIGHT_BUDGET: u64 = 256 << 20;
/// Cap of the derived in-flight budget. Also the cap on the env override:
/// the byte budget is a tokio semaphore taken with `acquire_many(u32)`.
pub const MAX_INFLIGHT_BUDGET: u64 = 4 << 30;
/// RAM fraction the budget takes.
pub const RAM_DIVISOR: u64 = 8;
/// Working set charged per concurrent handler when deriving the cap.
pub const HANDLER_BYTES_EACH: u64 = 3 << 20;
/// Floor of the derived handler cap.
pub const MIN_HANDLERS: usize = 256;
/// Cap of the derived handler cap.
pub const MAX_HANDLERS: usize = 8192;

/// Floor accepted from `PACKED_INFLIGHT_MAX_BYTES` (tests and tiny nodes).
pub const ENV_MIN_INFLIGHT_BUDGET: u64 = 8 << 20;
/// Floor accepted from `MINER_MAX_CONCURRENT_HANDLERS`.
pub const ENV_MIN_HANDLERS: usize = 16;
/// Cap accepted from `MINER_MAX_CONCURRENT_HANDLERS`.
pub const ENV_MAX_HANDLERS: usize = 65_536;

pub const INFLIGHT_BUDGET_ENV: &str = "PACKED_INFLIGHT_MAX_BYTES";
pub const HANDLERS_ENV: &str = "MINER_MAX_CONCURRENT_HANDLERS";

/// Where a limit's value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Derived from the total RAM.
    Ram,
    /// Total RAM unknown: the derivation floor.
    Floor,
    /// Taken from the environment variable.
    Env,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Ram => "ram",
            Source::Floor => "floor",
            Source::Env => "env",
        }
    }
}

/// The resolved limits of this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Total physical memory, `None` when the OS did not tell.
    pub total_ram_bytes: Option<u64>,
    /// Bytes admitted to the packed-store writer queue at once.
    pub inflight_budget_bytes: u64,
    pub inflight_budget_source: Source,
    /// Concurrent inbound P2P stream handlers.
    pub max_concurrent_handlers: usize,
    pub max_concurrent_handlers_source: Source,
}

/// Total physical memory as the OS reports it (`sysconf`), `None` on
/// failure or on a platform without the two queries.
pub fn total_ram_bytes() -> Option<u64> {
    // SAFETY: sysconf takes an integer name and returns a long; no memory
    // is touched.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages <= 0 || page_size <= 0 {
        return None;
    }
    (pages as u64).checked_mul(page_size as u64)
}

/// The derivation alone: `(inflight_budget, max_handlers)` for a total
/// RAM, floors when unknown.
pub fn derive(total_ram_bytes: Option<u64>) -> (u64, usize) {
    let budget = match total_ram_bytes {
        Some(total) => (total / RAM_DIVISOR).clamp(MIN_INFLIGHT_BUDGET, MAX_INFLIGHT_BUDGET),
        None => MIN_INFLIGHT_BUDGET,
    };
    let handlers = usize::try_from(budget / HANDLER_BYTES_EACH)
        .unwrap_or(MAX_HANDLERS)
        .clamp(MIN_HANDLERS, MAX_HANDLERS);
    (budget, handlers)
}

/// Resolve the limits from a variable lookup and a RAM figure. Pure: the
/// process-wide instance is [`get`].
pub fn resolve(lookup: impl Fn(&str) -> Option<String>, total_ram_bytes: Option<u64>) -> Limits {
    let (derived_budget, derived_handlers) = derive(total_ram_bytes);
    let derived_source = if total_ram_bytes.is_some() {
        Source::Ram
    } else {
        Source::Floor
    };

    let (inflight_budget_bytes, inflight_budget_source) =
        match parse_env::<u64>(&lookup, INFLIGHT_BUDGET_ENV) {
            Some(v) => (
                v.clamp(ENV_MIN_INFLIGHT_BUDGET, MAX_INFLIGHT_BUDGET),
                Source::Env,
            ),
            None => (derived_budget, derived_source),
        };
    let (max_concurrent_handlers, max_concurrent_handlers_source) =
        match parse_env::<usize>(&lookup, HANDLERS_ENV) {
            Some(v) => (v.clamp(ENV_MIN_HANDLERS, ENV_MAX_HANDLERS), Source::Env),
            None => (derived_handlers, derived_source),
        };

    Limits {
        total_ram_bytes,
        inflight_budget_bytes,
        inflight_budget_source,
        max_concurrent_handlers,
        max_concurrent_handlers_source,
    }
}

fn parse_env<T: std::str::FromStr>(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &str,
) -> Option<T> {
    let raw = lookup(name)?;
    match raw.trim().parse::<T>() {
        Ok(v) => Some(v),
        Err(_) => {
            tracing::warn!(var = name, value = %raw, "unparseable value ignored, derived default kept");
            None
        }
    }
}

static LIMITS: OnceLock<Limits> = OnceLock::new();

/// The process-wide limits, resolved on first use from the environment
/// and `sysconf`. Stable for the life of the process.
pub fn get() -> &'static Limits {
    LIMITS.get_or_init(|| resolve(|n| std::env::var(n).ok(), total_ram_bytes()))
}

/// Log the resolved limits once (call from startup).
pub fn log_once() {
    static LOGGED: OnceLock<()> = OnceLock::new();
    LOGGED.get_or_init(|| {
        let l = get();
        tracing::info!(
            total_ram_mib = l.total_ram_bytes.map(|b| b >> 20),
            inflight_budget_mib = l.inflight_budget_bytes >> 20,
            inflight_budget_source = l.inflight_budget_source.as_str(),
            max_concurrent_handlers = l.max_concurrent_handlers,
            max_concurrent_handlers_source = l.max_concurrent_handlers_source.as_str(),
            "resource limits"
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;

    #[test]
    fn derivation_follows_ram_and_clamps() {
        // Unknown RAM: floors.
        assert_eq!(derive(None), (256 * MIB, 256));
        // 1 GiB: total/8 = 128 MiB, clamped up to the floor.
        assert_eq!(derive(Some(GIB)), (256 * MIB, 256));
        // 8 GiB: 1 GiB budget, 341 handlers.
        assert_eq!(derive(Some(8 * GIB)), (GIB, 341));
        // 16 GiB: 2 GiB budget, 682 handlers.
        assert_eq!(derive(Some(16 * GIB)), (2 * GIB, 682));
        // 32 GiB: 4 GiB budget (the cap), 1365 handlers.
        assert_eq!(derive(Some(32 * GIB)), (4 * GIB, 1365));
        // 512 GiB: still the cap.
        assert_eq!(derive(Some(512 * GIB)), (4 * GIB, 1365));
        // The handler floor is what a 2 GiB budget or less yields, the cap
        // is only reachable through the env override.
        assert!(derive(Some(4 * GIB)).1 == MIN_HANDLERS);
    }

    #[test]
    fn env_overrides_win_and_are_clamped() {
        let ram = Some(16 * GIB);
        let none = resolve(|_| None, ram);
        assert_eq!(none.inflight_budget_bytes, 2 * GIB);
        assert_eq!(none.inflight_budget_source, Source::Ram);
        assert_eq!(none.max_concurrent_handlers, 682);
        assert_eq!(none.max_concurrent_handlers_source, Source::Ram);

        let both = resolve(
            |n| match n {
                INFLIGHT_BUDGET_ENV => Some(" 536870912 ".into()),
                HANDLERS_ENV => Some("4096".into()),
                _ => None,
            },
            ram,
        );
        assert_eq!(both.inflight_budget_bytes, 512 * MIB);
        assert_eq!(both.inflight_budget_source, Source::Env);
        assert_eq!(both.max_concurrent_handlers, 4096);
        assert_eq!(both.max_concurrent_handlers_source, Source::Env);

        // Out-of-range overrides are clamped, not refused.
        let wild = resolve(
            |n| match n {
                INFLIGHT_BUDGET_ENV => Some("1".into()),
                HANDLERS_ENV => Some("999999999".into()),
                _ => None,
            },
            ram,
        );
        assert_eq!(wild.inflight_budget_bytes, ENV_MIN_INFLIGHT_BUDGET);
        assert_eq!(wild.max_concurrent_handlers, ENV_MAX_HANDLERS);
        let huge = resolve(
            |n| (n == INFLIGHT_BUDGET_ENV).then(|| u64::MAX.to_string()),
            ram,
        );
        assert_eq!(huge.inflight_budget_bytes, MAX_INFLIGHT_BUDGET);
    }

    #[test]
    fn garbage_env_keeps_the_derived_default() {
        let l = resolve(
            |n| match n {
                INFLIGHT_BUDGET_ENV => Some("lots".into()),
                HANDLERS_ENV => Some("-5".into()),
                _ => None,
            },
            Some(8 * GIB),
        );
        assert_eq!(l.inflight_budget_bytes, GIB);
        assert_eq!(l.inflight_budget_source, Source::Ram);
        assert_eq!(l.max_concurrent_handlers, 341);
        assert_eq!(l.max_concurrent_handlers_source, Source::Ram);
        let floor = resolve(|_| None, None);
        assert_eq!(floor.inflight_budget_source, Source::Floor);
        assert_eq!(floor.inflight_budget_bytes, MIN_INFLIGHT_BUDGET);
    }

    #[test]
    fn this_machine_reports_ram() {
        let total = total_ram_bytes().expect("sysconf");
        assert!(total >= 64 * MIB, "{total}");
        let l = get();
        assert!(l.inflight_budget_bytes >= ENV_MIN_INFLIGHT_BUDGET);
        assert!(l.max_concurrent_handlers >= ENV_MIN_HANDLERS);
    }
}
