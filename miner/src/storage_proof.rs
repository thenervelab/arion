//! Miner side of the storage chunk proof protocol v1
//! (`docs/storage-proof-protocol.md` §1–§3, §5).
//!
//! The challenge arrives as [`common::MinerControlMessage::StorageProofChallenge`]
//! carrying the exact framed challenge bytes. This module admits it with the
//! common prover (`admit_challenge`: canonical form, identifier, issuer
//! authorization, strict signature, recipient/incarnation, common geometry
//! derivation, indices and bounds), reads the shard from the store, builds
//! the Bao outboard with grouping 1 KiB (`BlockSize::ZERO`) bound to the
//! authoritative digest, encodes the four requested slices and signs the
//! response with the miner's Ed25519 identity. The caller writes the frame
//! on the same stream through [`StorageProofService::write_answer`], bounded
//! by the challenge expiry, and FINs: exactly one frame per flow, never
//! buffered twice, never a handler pinned past the window by a peer that
//! stops draining.
//!
//! Decisions that produce no bytes (malformed, unauthorized) close the flow
//! without a response, as §3 requires. A valid challenge the miner cannot
//! execute (another challenge from the same requester in flight, rate
//! limit, no proof permit, expired by the local clock, shard absent or not
//! matching the digest) receives the signed 200-byte BUSY: missing
//! coverage, never a fault.
//!
//! Not wired here: the dedicated ALPN, client-certificate authorization,
//! rolling IP budgets and the priority profile of §5 — the challenge rides
//! the existing `hippius/miner-control` connection, whose TLS identity is
//! the issuer key checked by admission.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::storage_proof::derive_shard_geometry;
use common::storage_proof::prover::{
    ChallengeRejection, ProverError, ShardOutboard, admit_challenge, build_busy_response,
    build_proof_response,
};
use common::storage_proof::sig::PublicKey;
use common::storage_proof::wire::{
    BUSY_FRAMED_LEN, Challenge, MAX_PROOF_FRAMED_LEN, encode_hash_hex,
};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use ed25519_dalek::SigningKey;
use tracing::{debug, warn};

use crate::helpers::truncate_for_log;
use crate::store::BlobStore;

/// Per-sender rate limit: at most this many admitted challenges per fixed
/// window get work; up to twice as many get a signed BUSY; beyond that the
/// flow is closed without bytes. The scheduler contract is 50 per hour per
/// miner (§5); this local cap only bounds a misbehaving issuer and is far
/// above a compliant cadence. A fixed window lets a burst straddling the
/// boundary reach twice the cap once: an abuse bound, not a budget.
pub const RATE_LIMIT_MAX_PER_WINDOW: u32 = 60;
/// Window of the per-sender rate limit.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Why a valid challenge was answered BUSY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusyReason {
    /// Another challenge from the same requester is in flight (§5).
    Concurrent,
    /// The requester exceeded [`RATE_LIMIT_MAX_PER_WINDOW`].
    RateLimited,
    /// No proof permit immediately available (§5: no unbounded queue).
    NoPermit,
    /// The miner's own clock says the window is over (§3).
    ExpiredLocally,
    /// The store has no live blob under the requested digest.
    ShardAbsent,
    /// The store failed to read the blob.
    StoreError,
    /// The stored bytes do not form an outboard under the authoritative
    /// digest and derived length (§1: outboard not ready): wrong length
    /// (an oversized entry is refused before it is read), wrong root, or
    /// beyond the on-demand cap.
    OutboardNotReady,
}

/// Why the flow is closed without any response bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// The peer identity is not a 32-byte hex key.
    UnknownPeer,
    /// The peer is neither the validator nor an authorized warden.
    UnauthorizedSender,
    /// Admission failed (§3, "Admission du challenge").
    Rejected(ChallengeRejection),
    /// The requester is far over its window: not even BUSY is affordable.
    RateLimited,
    /// The requester already has a response and a BUSY in flight: no
    /// third write is started for it (§5: BUSY only under budget).
    Concurrent,
    /// The response could not be produced within the contract's exact
    /// size; nothing non-conformant is ever written.
    Internal,
    /// The read-and-prove job did not end before the challenge expiry:
    /// the handler stops waiting (the job finishes detached, still
    /// holding its permit and the requester's slot) and writes nothing.
    ProofTooLate,
}

/// Result of handling one challenge frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Signed PROOF frame, exactly `max_response_bytes` long.
    Proof(Vec<u8>),
    /// Signed BUSY frame, exactly 200 bytes.
    Busy(Vec<u8>, BusyReason),
    /// Close the flow without writing anything.
    Close(CloseReason),
}

impl Reply {
    /// Bytes to write on the flow, if any.
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Proof(b) | Self::Busy(b, _) => Some(b),
            Self::Close(_) => None,
        }
    }
}

/// Upper bounds (milliseconds) of the outboard build time histogram.
const OUTBOARD_BUCKETS_MS: [u64; 10] = [1, 2, 5, 10, 20, 50, 100, 250, 500, 1000];

/// Fixed-bucket histogram in microseconds, rendered in seconds.
#[derive(Debug, Default)]
pub struct DurationHistogram {
    buckets: [AtomicU64; OUTBOARD_BUCKETS_MS.len()],
    sum_us: AtomicU64,
    count: AtomicU64,
}

impl DurationHistogram {
    pub fn observe(&self, d: Duration) {
        let us = u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        for (bucket, &le_ms) in self.buckets.iter().zip(OUTBOARD_BUCKETS_MS.iter()) {
            if us <= le_ms * 1000 {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.sum_us.fetch_add(us, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn sum(&self) -> Duration {
        Duration::from_micros(self.sum_us.load(Ordering::Relaxed))
    }

    fn render(&self, name: &str, out: &mut String) {
        use std::fmt::Write as _;
        let _ = writeln!(out, "# TYPE {name} histogram");
        for (bucket, &le_ms) in self.buckets.iter().zip(OUTBOARD_BUCKETS_MS.iter()) {
            let _ = writeln!(
                out,
                "{name}_bucket{{le=\"{}\"}} {}",
                le_ms as f64 / 1000.0,
                bucket.load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {}", self.count());
        let _ = writeln!(out, "{name}_sum {}", self.sum().as_secs_f64());
        let _ = writeln!(out, "{name}_count {}", self.count());
    }
}

/// Counters of the storage-proof handler, Prometheus text exposition via
/// [`Metrics::render_prometheus`]. The miner binary has no scrape endpoint
/// today (no HTTP server, no metrics registry): the exposition hook is
/// ready for the endpoint that will expose it and is exercised by tests.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Challenge frames received on the control protocol.
    pub received: AtomicU64,
    /// PROOF responses generated (not necessarily delivered: see
    /// `write_completed`).
    pub answered: AtomicU64,
    /// BUSY responses generated, all reasons (absent shards included).
    pub busy: AtomicU64,
    /// BUSY responses caused by an absent shard.
    pub absent: AtomicU64,
    /// Flows closed without a response (unauthorized, malformed, internal).
    pub rejected: AtomicU64,
    /// Response bytes generated (PROOF and BUSY frames, prefix included).
    pub response_bytes: AtomicU64,
    /// Response frames fully handed to the transport by
    /// [`StorageProofService::write_answer`].
    pub write_completed: AtomicU64,
    /// Response frames whose write failed or timed out: generated, never
    /// (fully) delivered.
    pub write_failed: AtomicU64,
    /// Subset of `write_failed`: the peer did not drain the frame before
    /// the challenge expiry.
    pub write_timed_out: AtomicU64,
    /// Response bytes of completed writes.
    pub written_bytes: AtomicU64,
    /// Time to build the Bao outboard of the challenged shard.
    pub outboard_build: DurationHistogram,
}

impl Metrics {
    pub fn render_prometheus(&self, out: &mut String) {
        use std::fmt::Write as _;
        let counters = [
            (
                "miner_storage_proof_challenges_received_total",
                &self.received,
            ),
            (
                "miner_storage_proof_challenges_answered_total",
                &self.answered,
            ),
            ("miner_storage_proof_challenges_busy_total", &self.busy),
            ("miner_storage_proof_challenges_absent_total", &self.absent),
            (
                "miner_storage_proof_challenges_rejected_total",
                &self.rejected,
            ),
            (
                "miner_storage_proof_response_bytes_total",
                &self.response_bytes,
            ),
            (
                "miner_storage_proof_response_writes_completed_total",
                &self.write_completed,
            ),
            (
                "miner_storage_proof_response_writes_failed_total",
                &self.write_failed,
            ),
            (
                "miner_storage_proof_response_writes_timed_out_total",
                &self.write_timed_out,
            ),
            (
                "miner_storage_proof_written_bytes_total",
                &self.written_bytes,
            ),
        ];
        for (name, counter) in counters {
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name} {}", counter.load(Ordering::Relaxed));
        }
        self.outboard_build
            .render("miner_storage_proof_outboard_build_seconds", out);
    }
}

#[derive(Debug)]
struct RateWindow {
    started: Instant,
    count: u32,
}

/// Verdict of the per-sender rate window for one admitted challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateDecision {
    Admit,
    /// Over the limit: the 200-byte BUSY is still affordable.
    Busy,
    /// Over twice the limit: no more signed bytes for this sender in
    /// this window, close without a response.
    Close,
}

/// Largest shard the miner agrees to read and hash on the challenge path
/// (the outboard is built on demand, see the module docs). Beyond this,
/// the outboard is "not ready": BUSY before any read. 32 MiB is 16x the
/// largest shard a 2 MiB stripe with k >= 1 can produce; with the
/// default two permits the on-demand path holds at most ~70 MiB.
pub const MAX_ON_DEMAND_SHARD_LENGTH: u64 = 32 * 1024 * 1024;

/// Most proof jobs in flight per process (§5: "au plus 16 travaux de
/// preuve/verifications en vol par processus"). The configured pool size
/// is clamped to `1..=16`.
pub const MAX_PROOF_CONCURRENCY: usize = 16;

/// Handler state shared by every control connection.
#[derive(Debug)]
pub struct StorageProofService {
    store: Arc<dyn BlobStore>,
    signing_key: Arc<SigningKey>,
    my_id: PublicKey,
    incarnation: [u8; 16],
    /// Bounds concurrent proof jobs (read + outboard + slices), separate
    /// from the legacy PoS pool so neither protocol starves the other.
    proof_sem: Arc<tokio::sync::Semaphore>,
    /// Requesters with a challenge in flight, held until the response is
    /// written and the flow finished (§5: one at a time per requester).
    /// Every reply produced while the slot is free (PROOF or BUSY) holds
    /// it: one response write per requester at a time.
    in_flight: Arc<DashMap<PublicKey, ()>>,
    /// Requesters with a BUSY(Concurrent) write in flight: the one signed
    /// refusal a requester can collect while its response is pending.
    /// Beyond it the flow is closed without bytes, so a requester pins at
    /// most two handlers, each bounded by the write deadline.
    busy_in_flight: Arc<DashMap<PublicKey, ()>>,
    /// Per-requester fixed windows. Only authorized senders reach it, so
    /// the map is bounded by the authorization list.
    rate: DashMap<PublicKey, RateWindow>,
    rate_limit: u32,
    rate_window: Duration,
    pub metrics: Metrics,
}

/// Marks the requester as in flight until dropped. Returned inside
/// [`Answer`] so the caller keeps it across the stream write and FIN.
#[derive(Debug)]
pub struct InFlightToken {
    set: Arc<DashMap<PublicKey, ()>>,
    peer: PublicKey,
}

impl Drop for InFlightToken {
    fn drop(&mut self) {
        self.set.remove(&self.peer);
    }
}

/// Outcome of one challenge: the reply to write and, while a requester is
/// in flight, the token that releases it. Drop the answer only after the
/// bytes are written and the flow is finished.
#[derive(Debug)]
pub struct Answer {
    pub reply: Reply,
    /// The admitted challenge's `expires_at_ms`: the write deadline.
    expires_at_ms: Option<u64>,
    _in_flight: Option<InFlightToken>,
}

impl Answer {
    fn closed(reason: CloseReason) -> Self {
        Self {
            reply: Reply::Close(reason),
            expires_at_ms: None,
            _in_flight: None,
        }
    }

    /// Time left to write the reply at `now_ms`: never past the challenge
    /// expiry (§3), zero when the window is over (the write still gets one
    /// poll, enough for a peer with receive credit; a stalled peer never
    /// pins the handler). A reply without bytes has no budget to spend.
    pub fn send_budget(&self, now_ms: u64) -> Duration {
        Duration::from_millis(
            self.expires_at_ms
                .map_or(0, |expires| expires.saturating_sub(now_ms)),
        )
    }

    /// Release the in-flight token and keep the reply (test drivers; the
    /// host keeps the answer alive until the flow is finished).
    pub fn into_reply(self) -> Reply {
        self.reply
    }
}

/// Why the reply bytes did not reach the sink.
#[derive(Debug)]
pub enum WriteError {
    /// The peer did not drain the frame before the challenge expired:
    /// the caller abandons the stream (reset) and releases everything.
    Timeout,
    Io(std::io::Error),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => f.write_str("response write not drained before the challenge expiry"),
            Self::Io(e) => write!(f, "response write failed: {e}"),
        }
    }
}

impl std::error::Error for WriteError {}

impl StorageProofService {
    /// `incarnation` must be non-zero (§1); a zero value admits nothing.
    /// `proof_concurrency` bounds concurrent proof jobs, clamped to
    /// `1..=MAX_PROOF_CONCURRENCY` (a warning names the configured value).
    pub fn new(
        store: Arc<dyn BlobStore>,
        signing_key: Arc<SigningKey>,
        incarnation: [u8; 16],
        proof_concurrency: usize,
    ) -> Self {
        let my_id = signing_key.verifying_key().to_bytes();
        let effective = proof_concurrency.clamp(1, MAX_PROOF_CONCURRENCY);
        if effective != proof_concurrency {
            warn!(
                configured = proof_concurrency,
                effective,
                bound = MAX_PROOF_CONCURRENCY,
                "storage-proof: proof concurrency clamped to the protocol bound (§5)"
            );
        }
        Self {
            store,
            signing_key,
            my_id,
            incarnation,
            proof_sem: Arc::new(tokio::sync::Semaphore::new(effective)),
            in_flight: Arc::new(DashMap::new()),
            busy_in_flight: Arc::new(DashMap::new()),
            rate: DashMap::new(),
            rate_limit: RATE_LIMIT_MAX_PER_WINDOW,
            rate_window: RATE_LIMIT_WINDOW,
            metrics: Metrics::default(),
        }
    }

    /// Proof permits not currently held (the pool size, at rest).
    pub fn proof_permits_available(&self) -> usize {
        self.proof_sem.available_permits()
    }

    /// Override the per-sender rate limit.
    #[cfg(test)]
    pub fn with_rate_limit(mut self, max_per_window: u32, window: Duration) -> Self {
        self.rate_limit = max_per_window;
        self.rate_window = window;
        self
    }

    /// Handle one framed challenge from the authenticated peer `peer_hex`
    /// (hex of its Ed25519 key, the TLS identity of the connection).
    /// `authorized` is the provisioned issuer list (validator and wardens).
    /// `now_ms` reads the miner's civil clock; it is consulted at admission
    /// and again after the proof is built, only to choose BUSY over a
    /// response the miner itself deems expired, never to judge delay.
    pub async fn handle(
        &self,
        peer_hex: &str,
        authorized: &[PublicKey],
        frame: &[u8],
        now_ms: impl Fn() -> u64 + Sync,
    ) -> Answer {
        self.metrics.received.fetch_add(1, Ordering::Relaxed);
        let answer = self.decide(peer_hex, authorized, frame, &now_ms).await;
        match &answer.reply {
            Reply::Proof(bytes) => {
                self.metrics.answered.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .response_bytes
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
            Reply::Busy(bytes, reason) => {
                self.metrics.busy.fetch_add(1, Ordering::Relaxed);
                if *reason == BusyReason::ShardAbsent {
                    self.metrics.absent.fetch_add(1, Ordering::Relaxed);
                }
                self.metrics
                    .response_bytes
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
            Reply::Close(_) => {
                self.metrics.rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
        answer
    }

    /// Write the reply bytes, if any, within the answer's send budget at
    /// `now_ms`. A sink that stops draining (a requester withholding QUIC
    /// receive credit) cannot hold the caller past the challenge expiry:
    /// on [`WriteError::Timeout`] the caller must abandon the stream. The
    /// answer stays borrowed, so its in-flight token is released by the
    /// caller after the flow is finished or reset.
    pub async fn write_answer<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        sink: &mut W,
        answer: &Answer,
        now_ms: u64,
    ) -> Result<(), WriteError> {
        use tokio::io::AsyncWriteExt as _;
        let Some(bytes) = answer.reply.bytes() else {
            return Ok(());
        };
        let result =
            match tokio::time::timeout(answer.send_budget(now_ms), sink.write_all(bytes)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(WriteError::Io(e)),
                Err(_elapsed) => Err(WriteError::Timeout),
            };
        match &result {
            Ok(()) => {
                self.metrics.write_completed.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .written_bytes
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
            Err(e) => {
                self.metrics.write_failed.fetch_add(1, Ordering::Relaxed);
                if matches!(e, WriteError::Timeout) {
                    self.metrics.write_timed_out.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        result
    }

    async fn decide(
        &self,
        peer_hex: &str,
        authorized: &[PublicKey],
        frame: &[u8],
        now_ms: &(dyn Fn() -> u64 + Sync),
    ) -> Answer {
        let Some(peer) = decode_node_id(peer_hex) else {
            return Answer::closed(CloseReason::UnknownPeer);
        };
        // Sender authorization first, like the legacy PosChallenge path:
        // an unknown peer costs no signature verification.
        if !authorized.contains(&peer) {
            return Answer::closed(CloseReason::UnauthorizedSender);
        }
        let admitted = match admit_challenge(
            frame,
            authorized,
            &peer,
            &self.my_id,
            &self.incarnation,
            now_ms(),
        ) {
            Ok(a) => a,
            Err(rejection) => {
                debug!(peer = %truncate_for_log(peer_hex, 8), ?rejection, "storage-proof challenge rejected");
                return Answer::closed(CloseReason::Rejected(rejection));
            }
        };
        let challenge = admitted.challenge;
        // Every admitted challenge counts against the sender's window, so
        // no path below can be used to solicit unbounded signed BUSYs.
        let rate = self.rate_admit(peer);
        if rate == RateDecision::Close {
            return Answer::closed(CloseReason::RateLimited);
        }
        // One response write per requester at a time: every signed reply
        // below holds the slot until the host has written it and finished
        // (or reset) the flow. A requester whose slot is taken gets one
        // BUSY(Concurrent) in flight, then nothing.
        let Some(token) = take_slot(&self.in_flight, peer) else {
            return match take_slot(&self.busy_in_flight, peer) {
                Some(busy_token) => self.busy(&challenge, BusyReason::Concurrent, Some(busy_token)),
                None => Answer::closed(CloseReason::Concurrent),
            };
        };
        let token = Some(token);
        if rate == RateDecision::Busy {
            return self.busy(&challenge, BusyReason::RateLimited, token);
        }
        // Local expiry: BUSY before any resource is taken or any disk read.
        if admitted.expired_locally {
            return self.busy(&challenge, BusyReason::ExpiredLocally, token);
        }
        // §5: no waiting in an unbounded queue; no permit now means BUSY.
        let permit = match self.proof_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => return self.busy(&challenge, BusyReason::NoPermit, token),
        };
        // On-demand outboard: refuse to read and hash beyond the local cap.
        if challenge.shard_length > MAX_ON_DEMAND_SHARD_LENGTH {
            return self.busy(&challenge, BusyReason::OutboardNotReady, token);
        }

        // Read and proof run in a detached job that owns the permit and the
        // in-flight token: if this handler future is cancelled during the
        // read (itself a blocking task inside tokio::fs) or the proof, the
        // concurrency bound and the requester's slot hold until the job
        // actually ends. The wait itself is bounded by the challenge
        // expiry: a slow disk cannot keep the host's handler past the
        // window, and a reply built after it would be BUSY anyway (§3).
        let wait = Duration::from_millis(challenge.expires_at_ms.saturating_sub(now_ms()));
        let (proved, token) = match tokio::time::timeout(
            wait,
            self.read_and_prove(&challenge, permit, token),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_elapsed) => {
                debug!(
                    blob = %truncate_for_log(&encode_hash_hex(&challenge.blob_hash), 16),
                    "storage-proof: read and proof not done by the expiry, closed without response"
                );
                return Answer::closed(CloseReason::ProofTooLate);
            }
        };
        let reply = match proved {
            Ok((frame, build_time)) => {
                self.metrics.outboard_build.observe(build_time);
                if frame.len() != challenge.max_response_bytes as usize
                    || frame.len() > MAX_PROOF_FRAMED_LEN
                {
                    warn!(
                        len = frame.len(),
                        bound = challenge.max_response_bytes,
                        "storage-proof: response outside the contract bound, not sent"
                    );
                    Reply::Close(CloseReason::Internal)
                } else if now_ms() >= challenge.expires_at_ms {
                    // Built too late by the local clock: §3 says BUSY.
                    return self.busy(&challenge, BusyReason::ExpiredLocally, token);
                } else {
                    Reply::Proof(frame)
                }
            }
            Err(ProofFailure::Busy(reason)) => return self.busy(&challenge, reason, token),
            Err(ProofFailure::Prover(ProverError::Signature)) => {
                Reply::Close(CloseReason::Internal)
            }
            Err(ProofFailure::Prover(e)) => {
                warn!(
                    blob = %truncate_for_log(&encode_hash_hex(&challenge.blob_hash), 16),
                    error = %e,
                    "storage-proof: outboard not ready"
                );
                return self.busy(&challenge, BusyReason::OutboardNotReady, token);
            }
        };
        Answer {
            reply,
            expires_at_ms: Some(challenge.expires_at_ms),
            _in_flight: token,
        }
    }

    /// Bounded store read then the CPU-bound proof (outboard with grouping
    /// 1 KiB bound to the authoritative digest, four validated slices,
    /// signature) in a task of its own. The permit lives in that task and
    /// the token comes back with the result: neither is released before
    /// the work ends, whatever happens to the awaiting future.
    async fn read_and_prove(
        &self,
        challenge: &Challenge,
        permit: tokio::sync::OwnedSemaphorePermit,
        token: Option<InFlightToken>,
    ) -> (
        Result<(Vec<u8>, Duration), ProofFailure>,
        Option<InFlightToken>,
    ) {
        let store = Arc::clone(&self.store);
        let key = Arc::clone(&self.signing_key);
        let challenge = challenge.clone();
        let job = tokio::spawn(async move {
            let _permit = permit;
            let result = read_shard(&*store, &challenge).await;
            let result = match result {
                Ok(data) => tokio::task::spawn_blocking(move || prove(&challenge, &key, &data))
                    .await
                    .unwrap_or_else(|_| {
                        Err(ProofFailure::Prover(ProverError::Encode(
                            "proof task panicked".to_string(),
                        )))
                    }),
                Err(failure) => Err(failure),
            };
            (result, token)
        });
        match job.await {
            Ok(outcome) => outcome,
            // A panicked job dropped the token: the requester is released.
            Err(_) => (
                Err(ProofFailure::Prover(ProverError::Encode(
                    "proof task panicked".to_string(),
                ))),
                None,
            ),
        }
    }

    fn busy(
        &self,
        challenge: &Challenge,
        reason: BusyReason,
        token: Option<InFlightToken>,
    ) -> Answer {
        let reply = match build_busy_response(challenge, &self.signing_key) {
            Ok(frame) if frame.len() == BUSY_FRAMED_LEN => Reply::Busy(frame, reason),
            _ => Reply::Close(CloseReason::Internal),
        };
        Answer {
            reply,
            expires_at_ms: Some(challenge.expires_at_ms),
            _in_flight: token,
        }
    }

    fn rate_admit(&self, peer: PublicKey) -> RateDecision {
        let now = Instant::now();
        let mut window = self.rate.entry(peer).or_insert_with(|| RateWindow {
            started: now,
            count: 0,
        });
        if now.duration_since(window.started) >= self.rate_window {
            window.started = now;
            window.count = 0;
        }
        window.count = window.count.saturating_add(1);
        if window.count <= self.rate_limit {
            RateDecision::Admit
        } else if window.count <= self.rate_limit.saturating_mul(2) {
            RateDecision::Busy
        } else {
            RateDecision::Close
        }
    }
}

/// Claim `peer`'s slot in `set`, `None` when it is already taken.
fn take_slot(set: &Arc<DashMap<PublicKey, ()>>, peer: PublicKey) -> Option<InFlightToken> {
    match set.entry(peer) {
        Entry::Occupied(_) => None,
        Entry::Vacant(v) => {
            v.insert(());
            Some(InFlightToken {
                set: Arc::clone(set),
                peer,
            })
        }
    }
}

/// Why the read-and-prove job produced no PROOF.
#[derive(Debug)]
enum ProofFailure {
    /// The store could not supply the shard as projected.
    Busy(BusyReason),
    /// The prover refused the stored bytes or failed to sign.
    Prover(ProverError),
}

/// Read the challenged shard, bounded by the derived length (admission
/// checked it against `shard_length`): a store entry longer than the
/// projection is refused by the backend before its content is buffered,
/// so no local file or signed projection can make this path allocate
/// beyond the cap. Any entry that does not fit exactly is "outboard not
/// ready", without hashing.
async fn read_shard(store: &dyn BlobStore, challenge: &Challenge) -> Result<Bytes, ProofFailure> {
    let blob_hex = encode_hash_hex(&challenge.blob_hash);
    let data = match store.read_at_most(&blob_hex, challenge.shard_length).await {
        Ok(data) if !data.is_empty() => data,
        Ok(_) => return Err(ProofFailure::Busy(BusyReason::ShardAbsent)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ProofFailure::Busy(BusyReason::ShardAbsent));
        }
        Err(e) if e.kind() == std::io::ErrorKind::FileTooLarge => {
            warn!(
                blob = %truncate_for_log(&blob_hex, 16),
                expected = challenge.shard_length,
                "storage-proof: stored blob longer than the projected shard, not read"
            );
            return Err(ProofFailure::Busy(BusyReason::OutboardNotReady));
        }
        Err(e) => {
            warn!(blob = %truncate_for_log(&blob_hex, 16), error = %e, "storage-proof: shard read failed");
            return Err(ProofFailure::Busy(BusyReason::StoreError));
        }
    };
    if data.len() as u64 != challenge.shard_length {
        warn!(
            blob = %truncate_for_log(&blob_hex, 16),
            expected = challenge.shard_length,
            actual = data.len(),
            "storage-proof: stored blob shorter than the projected shard"
        );
        return Err(ProofFailure::Busy(BusyReason::OutboardNotReady));
    }
    Ok(data)
}

/// CPU-bound proof: outboard build (timed), slices, signature.
fn prove(
    challenge: &Challenge,
    key: &SigningKey,
    data: &[u8],
) -> Result<(Vec<u8>, Duration), ProofFailure> {
    let geometry = derive_shard_geometry(
        challenge.file_size,
        challenge.stripe_size,
        challenge.k,
        challenge.m,
        challenge.shard_index,
    )
    .map_err(|_| ProofFailure::Prover(ProverError::GeometryMismatch))?;
    let started = Instant::now();
    let outboard = ShardOutboard::build(data, &geometry, &challenge.blob_hash)
        .map_err(ProofFailure::Prover)?;
    let build_time = started.elapsed();
    let frame =
        build_proof_response(challenge, key, data, &outboard).map_err(ProofFailure::Prover)?;
    Ok((frame, build_time))
}

/// Random non-zero 16-byte incarnation for this process run (§1).
pub fn fresh_incarnation() -> [u8; 16] {
    loop {
        let candidate: [u8; 16] = rand::random();
        if candidate != [0u8; 16] {
            return candidate;
        }
    }
}

/// Hex node id (the miner's identity encoding) to a raw Ed25519 key.
pub fn decode_node_id(hex_id: &str) -> Option<PublicKey> {
    hex::decode(hex_id).ok()?.try_into().ok()
}

/// Issuer keys allowed to challenge this miner under the storage-proof
/// protocol: the configured validator, the warden ids it distributes and
/// the storage-proof requesters it distributes (spec §3). Undecodable ids
/// are skipped, duplicates collapsed. No validator and empty lists admit
/// nothing ("liste absente ou obsolete : aucun challenge accepte").
pub fn authorized_issuers(
    validator_node_id: Option<&str>,
    warden_ids: &[String],
    requester_ids: &[String],
) -> Vec<PublicKey> {
    let mut issuers: Vec<PublicKey> = Vec::new();
    let candidates = validator_node_id
        .into_iter()
        .chain(warden_ids.iter().map(String::as_str))
        .chain(requester_ids.iter().map(String::as_str));
    for key in candidates.filter_map(decode_node_id) {
        if !issuers.contains(&key) {
            issuers.push(key);
        }
    }
    issuers
}

/// The `storage_proof_requesters` list of a validator heartbeat reply:
/// `None` when the reply predates the field (keep the current set),
/// `Some` (sorted, deduplicated, possibly empty) when present. An empty
/// list is a revocation, not an omission.
pub fn parse_storage_proof_requesters(reply: &serde_json::Value) -> Option<Vec<String>> {
    let ids = reply.get("storage_proof_requesters")?.as_array()?;
    let mut set: Vec<String> = ids
        .iter()
        .filter_map(|id| id.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    set.sort();
    set.dedup();
    Some(set)
}

#[cfg(test)]
mod tests;
