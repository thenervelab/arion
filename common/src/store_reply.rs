//! Reply of a miner to a `StoreV2` push.
//!
//! The reply has always been a short ASCII line on the same stream:
//! `OK`, `RATE_LIMITED`, `ERROR: <reason>`. Every sender (gateway and
//! validator `shard_distribution`) reads at most 64 bytes, treats exactly
//! `OK` as success and anything else as a retryable failure, and
//! classifies a reply containing `RATE_LIMITED` as its own overload
//! (`store_rate_limited`, not penalised) rather than a miner fault.
//!
//! 0.1.34 adds one structured reply, [`StoreReply::Busy`], sent when the
//! miner's in-flight write budget cannot take the shard: it carries the
//! delay after which a retry is worth making. The encoding is additive
//! on the wire:
//!
//! ```text
//! RATE_LIMITED {"kind":"Busy","retry_after_ms":1500}
//! ```
//!
//! - the line keeps the `RATE_LIMITED` prefix, so a sender that predates
//!   this module still classifies it as its overload and retries with its
//!   own backoff (the JSON tail is opaque to it: `!= b"OK"` and
//!   `contains("RATE_LIMITED")` are all it checks);
//! - the whole line stays under the 64-byte read cap;
//! - the JSON is internally tagged (`kind`) so a decoder that knows fewer
//!   variants than the encoder lands on [`StoreReply::Unknown`] instead of
//!   failing (`#[serde(other)]`), and a decoder that knows more variants
//!   than the encoder decodes the old lines as before.

use serde::{Deserialize, Serialize};

/// Legacy bare overload reply, also the prefix of every structured one.
pub const RATE_LIMITED_PREFIX: &str = "RATE_LIMITED";
/// Legacy success reply.
pub const OK: &[u8] = b"OK";
/// Legacy error prefix.
pub const ERROR_PREFIX: &str = "ERROR: ";
/// Senders read the reply with `read_to_end(64)`: an encoded reply longer
/// than this is truncated on their side and misparsed.
pub const MAX_WIRE_LEN: usize = 64;
/// Bounds of `retry_after_ms` in a [`StoreReply::Busy`].
pub const RETRY_AFTER_MS_MIN: u32 = 500;
pub const RETRY_AFTER_MS_MAX: u32 = 5_000;
/// The delay a legacy bare `RATE_LIMITED` maps to when decoded.
pub const LEGACY_RATE_LIMITED_RETRY_MS: u32 = 2_000;

/// The structured tail of a `RATE_LIMITED` line. Internally tagged so an
/// unknown `kind` decodes to [`Unknown`](StructuredTail::Unknown).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind")]
enum StructuredTail {
    Busy {
        retry_after_ms: u32,
    },
    #[serde(other)]
    Unknown,
}

/// Decoded reply to a `StoreV2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreReply {
    /// Stored and recorded.
    Ok,
    /// The miner's write budget is exhausted; retry after `retry_after_ms`
    /// (500..=5000). Sent by miners since 0.1.34; a legacy bare
    /// `RATE_LIMITED` decodes to this with [`LEGACY_RATE_LIMITED_RETRY_MS`].
    Busy { retry_after_ms: u32 },
    /// `ERROR: <reason>`.
    Error(String),
    /// A line this decoder does not know (a newer structured kind, or
    /// bytes outside the protocol). Treat as a retryable failure.
    Unknown(Vec<u8>),
}

impl StoreReply {
    /// Clamp a delay into the `Busy` bounds.
    pub fn busy(retry_after_ms: u32) -> Self {
        StoreReply::Busy {
            retry_after_ms: retry_after_ms.clamp(RETRY_AFTER_MS_MIN, RETRY_AFTER_MS_MAX),
        }
    }

    /// The bytes written on the stream. Always at most [`MAX_WIRE_LEN`].
    pub fn encode(&self) -> Vec<u8> {
        match self {
            StoreReply::Ok => OK.to_vec(),
            StoreReply::Busy { retry_after_ms } => {
                let tail = serde_json::to_string(&StructuredTail::Busy {
                    retry_after_ms: (*retry_after_ms).clamp(RETRY_AFTER_MS_MIN, RETRY_AFTER_MS_MAX),
                })
                .expect("fixed shape");
                format!("{RATE_LIMITED_PREFIX} {tail}").into_bytes()
            }
            StoreReply::Error(reason) => {
                let mut line = format!("{ERROR_PREFIX}{reason}").into_bytes();
                line.truncate(MAX_WIRE_LEN);
                line
            }
            StoreReply::Unknown(raw) => raw.clone(),
        }
    }

    /// Parse a reply line. Never fails: what is not understood is
    /// [`StoreReply::Unknown`].
    pub fn decode(raw: &[u8]) -> Self {
        if raw == OK {
            return StoreReply::Ok;
        }
        let Ok(text) = std::str::from_utf8(raw) else {
            return StoreReply::Unknown(raw.to_vec());
        };
        if let Some(reason) = text.strip_prefix(ERROR_PREFIX) {
            return StoreReply::Error(reason.to_string());
        }
        if let Some(rest) = text.strip_prefix(RATE_LIMITED_PREFIX) {
            let rest = rest.trim();
            if rest.is_empty() {
                return StoreReply::Busy {
                    retry_after_ms: LEGACY_RATE_LIMITED_RETRY_MS,
                };
            }
            return match serde_json::from_str::<StructuredTail>(rest) {
                Ok(StructuredTail::Busy { retry_after_ms }) => StoreReply::busy(retry_after_ms),
                Ok(StructuredTail::Unknown) | Err(_) => StoreReply::Unknown(raw.to_vec()),
            };
        }
        StoreReply::Unknown(raw.to_vec())
    }

    /// Whether a sender should retry this reply after a pause (everything
    /// but `Ok`, which is success, and `Error`, which is the miner's
    /// verdict on the request itself).
    pub fn is_overload(&self) -> bool {
        matches!(self, StoreReply::Busy { .. } | StoreReply::Unknown(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_and_error_round_trip_as_before() {
        assert_eq!(StoreReply::Ok.encode(), b"OK");
        assert_eq!(StoreReply::decode(b"OK"), StoreReply::Ok);
        assert_eq!(
            StoreReply::Error("Hash mismatch".into()).encode(),
            b"ERROR: Hash mismatch"
        );
        assert_eq!(
            StoreReply::decode(b"ERROR: UNAUTHORIZED"),
            StoreReply::Error("UNAUTHORIZED".into())
        );
    }

    #[test]
    fn busy_round_trips_and_clamps() {
        for ms in [500u32, 1500, 5000] {
            let r = StoreReply::Busy { retry_after_ms: ms };
            assert_eq!(StoreReply::decode(&r.encode()), r, "{ms}");
        }
        assert_eq!(
            StoreReply::decode(&StoreReply::Busy { retry_after_ms: 1 }.encode()),
            StoreReply::Busy {
                retry_after_ms: RETRY_AFTER_MS_MIN
            }
        );
        assert_eq!(
            StoreReply::decode(
                &StoreReply::Busy {
                    retry_after_ms: u32::MAX
                }
                .encode()
            ),
            StoreReply::Busy {
                retry_after_ms: RETRY_AFTER_MS_MAX
            }
        );
        assert_eq!(
            StoreReply::busy(7),
            StoreReply::Busy {
                retry_after_ms: 500
            }
        );
    }

    /// What a sender that predates this module does with a Busy line: it
    /// reads at most 64 bytes, compares with b"OK", and looks for the
    /// RATE_LIMITED substring to classify its own overload.
    #[test]
    fn busy_is_a_rate_limited_line_for_legacy_senders() {
        let wire = StoreReply::Busy {
            retry_after_ms: 5000,
        }
        .encode();
        assert!(wire.len() <= MAX_WIRE_LEN, "{}", wire.len());
        assert_ne!(wire, b"OK");
        let text = String::from_utf8(wire.clone()).unwrap();
        assert!(text.starts_with("RATE_LIMITED "), "{text}");
        assert!(text.contains("RATE_LIMITED"));
        assert!(!text.contains("Miner error"));
        // And the exact bytes, so a change here is a deliberate one.
        assert_eq!(
            text,
            r#"RATE_LIMITED {"kind":"Busy","retry_after_ms":5000}"#
        );
    }

    #[test]
    fn legacy_bare_rate_limited_decodes_to_busy() {
        assert_eq!(
            StoreReply::decode(b"RATE_LIMITED"),
            StoreReply::Busy {
                retry_after_ms: LEGACY_RATE_LIMITED_RETRY_MS
            }
        );
        assert!(StoreReply::decode(b"RATE_LIMITED").is_overload());
    }

    /// A decoder that knows fewer kinds than the encoder (a future miner
    /// sending a kind this build has never heard of) must land on Unknown,
    /// never on a parse failure or a wrong variant.
    #[test]
    fn unknown_structured_kind_is_unknown_not_an_error() {
        let future = br#"RATE_LIMITED {"kind":"Throttled","until_ms":9}"#;
        let decoded = StoreReply::decode(future);
        assert_eq!(decoded, StoreReply::Unknown(future.to_vec()));
        assert!(decoded.is_overload());
        // Garbage after the prefix, non-UTF-8, and foreign lines likewise.
        assert!(matches!(
            StoreReply::decode(b"RATE_LIMITED {not json"),
            StoreReply::Unknown(_)
        ));
        assert!(matches!(
            StoreReply::decode(&[0xff, 0xfe]),
            StoreReply::Unknown(_)
        ));
        assert!(matches!(
            StoreReply::decode(b"HAS:true"),
            StoreReply::Unknown(_)
        ));
        // Unknown re-encodes byte-for-byte (a relay does not rewrite it).
        assert_eq!(decoded.encode(), future.to_vec());
    }

    #[test]
    fn every_reply_fits_the_senders_read_cap() {
        let long = StoreReply::Error("x".repeat(200)).encode();
        assert_eq!(long.len(), MAX_WIRE_LEN);
        assert!(
            StoreReply::Busy {
                retry_after_ms: 5000
            }
            .encode()
            .len()
                <= MAX_WIRE_LEN
        );
        assert!(StoreReply::Ok.encode().len() <= MAX_WIRE_LEN);
    }
}
