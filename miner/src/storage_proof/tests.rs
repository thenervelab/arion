//! Refusal, resource and accounting paths of the miner handler (spec §3,
//! §5), driven by challenges issued with the common wire module alone.
//! The round trip against the real verifier is exercised on the verifier
//! side (the warden's integration tests): the miner never depends on it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use common::storage_proof::prover::ChallengeRejection;
use common::storage_proof::sig;
use common::storage_proof::wire::{
    self, BUSY_FRAMED_LEN, CHALLENGE_WINDOW_MS, Challenge, DOMAIN_CHALLENGE, decode_hash_hex,
    encode_hash_hex, expected_records, proof_framed_len,
};
use common::storage_proof::{ShardGeometry, derive_shard_geometry};
use common::{FileManifest, ShardInfo, StripeConfig, encode_stripe};
use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::seq::index::sample;
use rand::{RngCore, SeedableRng};

use super::*;
use crate::flat_store::FlatBlobStore;

// ---------------------------------------------------------------------------
// Store wrapper: counts reads, can hold them
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct CountingStore {
    inner: FlatBlobStore,
    /// Reads of any kind (bounded or not).
    reads: AtomicUsize,
    /// Unbounded `read` calls: the challenge path must never issue one.
    unbounded_reads: AtomicUsize,
    /// Largest `max_len` any bounded read asked for.
    max_len_requested: AtomicU64,
    /// When set, every read announces itself and waits for one release
    /// permit before proceeding; the lock is not held while waiting, so
    /// several reads can be parked at once.
    gate: std::sync::Mutex<Option<Gate>>,
}

#[derive(Debug, Clone)]
struct Gate {
    entered: tokio::sync::mpsc::Sender<()>,
    release: Arc<tokio::sync::Semaphore>,
}

impl Gate {
    fn new(parked: usize) -> (Self, tokio::sync::mpsc::Receiver<()>) {
        let (entered, entered_rx) = tokio::sync::mpsc::channel(parked);
        let gate = Self {
            entered,
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        (gate, entered_rx)
    }
    fn release_one(&self) {
        self.release.add_permits(1);
    }
}

impl CountingStore {
    fn new(inner: FlatBlobStore) -> Self {
        Self {
            inner,
            reads: AtomicUsize::new(0),
            unbounded_reads: AtomicUsize::new(0),
            max_len_requested: AtomicU64::new(0),
            gate: std::sync::Mutex::new(None),
        }
    }

    /// Count the read and, when a gate is set, park until released.
    async fn enter_read(&self) {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let gate = self.gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.entered.send(()).await.unwrap();
            gate.release.acquire().await.unwrap().forget();
        }
    }
}

#[async_trait::async_trait]
impl BlobStore for CountingStore {
    async fn store(&self, hash_hex: &str, data: &[u8]) -> std::io::Result<()> {
        self.inner.store(hash_hex, data).await
    }
    async fn read(&self, hash_hex: &str) -> std::io::Result<Bytes> {
        self.unbounded_reads.fetch_add(1, Ordering::SeqCst);
        self.enter_read().await;
        self.inner.read(hash_hex).await
    }
    async fn read_at_most(&self, hash_hex: &str, max_len: u64) -> std::io::Result<Bytes> {
        self.max_len_requested.fetch_max(max_len, Ordering::SeqCst);
        self.enter_read().await;
        self.inner.read_at_most(hash_hex, max_len).await
    }
    fn has(&self, hash_hex: &str) -> bool {
        self.inner.has(hash_hex)
    }
    fn blob_len(&self, hash_hex: &str) -> Option<u64> {
        self.inner.blob_len(hash_hex)
    }
    async fn delete(&self, hash_hex: &str) -> std::io::Result<()> {
        self.inner.delete(hash_hex).await
    }
    async fn remove(&self, hash_hex: &str) -> std::io::Result<()> {
        self.inner.remove(hash_hex).await
    }
    async fn restore(&self, hash_hex: &str) -> std::io::Result<bool> {
        self.inner.restore(hash_hex).await
    }
    async fn purge_trashed(&self, hash_hex: &str) -> std::io::Result<()> {
        self.inner.purge_trashed(hash_hex).await
    }
    fn list_hashes(&self) -> Vec<String> {
        self.inner.list_hashes()
    }
    fn list_trashed_hashes(&self) -> Vec<String> {
        self.inner.list_trashed_hashes()
    }
    fn has_trashed(&self, hash_hex: &str) -> bool {
        self.inner.has_trashed(hash_hex)
    }
    fn used_bytes(&self) -> u64 {
        self.inner.used_bytes()
    }
    fn trash_bytes(&self) -> u64 {
        self.inner.trash_bytes()
    }
    fn recompute_usage(&self) {
        self.inner.recompute_usage()
    }
    fn cleanup_stale_tmp(&self) -> usize {
        self.inner.cleanup_stale_tmp()
    }
    async fn migrate_legacy_layout(&self, batch: usize, pause: Duration) -> u64 {
        self.inner.migrate_legacy_layout(batch, pause).await
    }
}

// ---------------------------------------------------------------------------
// Issuer built on the common wire module: the shape of a verifier's
// challenge, without the verifier
// ---------------------------------------------------------------------------

/// What the issuer knows about one shard (the verifier's projection).
#[derive(Debug, Clone)]
struct Projection {
    manifest_id: [u8; 32],
    shard_index: u64,
    blob_hash: [u8; 32],
    file_size: u64,
    stripe_size: u64,
    k: u16,
    m: u16,
}

impl Projection {
    fn from_manifest(manifest: &FileManifest, shard_index: u64) -> Self {
        let entry = &manifest.shards[shard_index as usize];
        assert_eq!(entry.index as u64, shard_index);
        Self {
            manifest_id: decode_hash_hex(&manifest.file_hash).unwrap(),
            shard_index,
            blob_hash: decode_hash_hex(&entry.blob_hash).unwrap(),
            file_size: manifest.size,
            stripe_size: manifest.stripe_config.size,
            k: manifest.stripe_config.k as u16,
            m: manifest.stripe_config.m as u16,
        }
    }

    fn geometry(&self) -> ShardGeometry {
        derive_shard_geometry(
            self.file_size,
            self.stripe_size,
            self.k,
            self.m,
            self.shard_index,
        )
        .unwrap()
    }
}

/// A signed, framed challenge and its decoded form.
struct Issued {
    frame: Vec<u8>,
    challenge: Challenge,
}

/// Signs challenges under one verifier key and session.
struct Issuer {
    key: SigningKey,
    id: PublicKey,
    session: [u8; 16],
    rng: StdRng,
}

impl Issuer {
    fn new(key: SigningKey, seed: u64) -> Self {
        let id = key.verifying_key().to_bytes();
        Self {
            key,
            id,
            session: [0xC3; 16],
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// Four distinct sorted indices, nonce, bounds and strict signature,
    /// exactly as the verifier issues them (§1).
    fn issue(
        &mut self,
        miner_id: PublicKey,
        incarnation: [u8; 16],
        projection: &Projection,
        issued_at_ms: u64,
    ) -> Issued {
        let geometry = projection.geometry();
        let mut indices = [0u32; 4];
        let drawn = sample(&mut self.rng, geometry.chunk_count as usize, 4);
        for (slot, value) in indices.iter_mut().zip(drawn.iter()) {
            *slot = value as u32;
        }
        indices.sort_unstable();
        let records = expected_records(&geometry, &indices).unwrap();
        let mut nonce = [0u8; 32];
        self.rng.fill_bytes(&mut nonce);
        let mut challenge = Challenge {
            challenge_id: [0u8; 32],
            verifier_id: self.id,
            verifier_session: self.session,
            miner_id,
            incarnation,
            manifest_id: projection.manifest_id,
            shard_index: projection.shard_index,
            blob_hash: projection.blob_hash,
            file_size: projection.file_size,
            stripe_size: projection.stripe_size,
            k: projection.k,
            m: projection.m,
            shard_length: geometry.shard_length,
            indices,
            nonce,
            issued_at_ms,
            expires_at_ms: issued_at_ms + CHALLENGE_WINDOW_MS,
            max_response_bytes: proof_framed_len(&records) as u32,
            verifier_signature: [0u8; 64],
        };
        let body = challenge.encode_body();
        challenge.challenge_id = Challenge::compute_id(&body);
        let body = challenge.encode_body();
        challenge.verifier_signature = sig::sign_strict(
            &self.key,
            DOMAIN_CHALLENGE,
            &body[..wire::CHALLENGE_SIGNED_LEN],
        )
        .unwrap();
        let frame = wire::frame(&challenge.encode_body());
        Issued { frame, challenge }
    }
}

// ---------------------------------------------------------------------------
// Fixture: real manifest, real shards on a real flat store
// ---------------------------------------------------------------------------

fn file_bytes(size: u64) -> Vec<u8> {
    (0..size).map(|i| ((i * 7 + 3) % 251) as u8).collect()
}

fn build_manifest(file: &[u8], stripe_size: u64) -> (FileManifest, Vec<Vec<u8>>) {
    let config = StripeConfig {
        size: stripe_size,
        k: 10,
        m: 20,
    };
    let mut shards_all = Vec::new();
    let mut infos = Vec::new();
    for stripe in file.chunks(stripe_size as usize) {
        for shard in encode_stripe(stripe, &config).unwrap() {
            infos.push(ShardInfo {
                index: infos.len(),
                blob_hash: encode_hash_hex(blake3::hash(&shard).as_bytes()),
            });
            shards_all.push(shard);
        }
    }
    let manifest = FileManifest {
        shard_holders: Vec::new(),
        file_hash: encode_hash_hex(blake3::hash(file).as_bytes()),
        placement_version: 2,
        placement_epoch: 1,
        size: file.len() as u64,
        stripe_config: config,
        shards: infos,
        filename: None,
        content_type: None,
    };
    (manifest, shards_all)
}

const INCARNATION: [u8; 16] = [0xA5; 16];
const NOW_MS: u64 = 1_700_000_000_000;

struct Harness {
    _tmp: tempfile::TempDir,
    store: Arc<CountingStore>,
    service: StorageProofService,
    issuer: Issuer,
    miner_key: SigningKey,
    miner_id: PublicKey,
    verifier_id: PublicKey,
    verifier_hex: String,
    manifest: FileManifest,
    shards: Vec<Vec<u8>>,
}

impl Harness {
    async fn new(file_size: u64, stripe_size: u64, pos_permits: usize) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(CountingStore::new(FlatBlobStore::new(tmp.path()).unwrap()));
        let file = file_bytes(file_size);
        let (manifest, shards) = build_manifest(&file, stripe_size);
        for (info, shard) in manifest.shards.iter().zip(shards.iter()) {
            store.store(&info.blob_hash, shard).await.unwrap();
        }

        let miner_key = SigningKey::from_bytes(&[0x22; 32]);
        let miner_id = miner_key.verifying_key().to_bytes();
        let service = StorageProofService::new(
            store.clone() as Arc<dyn BlobStore>,
            Arc::new(miner_key.clone()),
            INCARNATION,
            pos_permits,
        );
        let issuer = Issuer::new(SigningKey::from_bytes(&[0x11; 32]), 0x5eed);
        let verifier_id = issuer.id;
        Self {
            _tmp: tmp,
            store,
            service,
            issuer,
            miner_key,
            miner_id,
            verifier_id,
            verifier_hex: hex::encode(verifier_id),
            manifest,
            shards,
        }
    }

    fn now(&self) -> u64 {
        NOW_MS
    }

    fn issue(&mut self, shard_index: u64) -> Issued {
        let projection = Projection::from_manifest(&self.manifest, shard_index);
        self.issue_projection(&projection)
    }

    fn issue_projection(&mut self, projection: &Projection) -> Issued {
        self.issuer
            .issue(self.miner_id, INCARNATION, projection, NOW_MS)
    }

    /// Issue for shard 9 under another verifier key.
    fn issue_from(&self, key: SigningKey) -> Issued {
        let projection = Projection::from_manifest(&self.manifest, 9);
        Issuer::new(key, 0x0dd).issue(self.miner_id, INCARNATION, &projection, NOW_MS)
    }

    /// Handle from the fixture issuer and release the in-flight token.
    async fn handle(&self, frame: &[u8]) -> Reply {
        self.handle_at(frame, self.now()).await
    }

    async fn handle_at(&self, frame: &[u8], now_ms: u64) -> Reply {
        self.service
            .handle(&self.verifier_hex, &[self.verifier_id], frame, || now_ms)
            .await
            .into_reply()
    }

    /// Handle from an arbitrary peer with an arbitrary issuer list.
    async fn handle_as(&self, peer_hex: &str, issuers: &[PublicKey], frame: &[u8]) -> Reply {
        let now = self.now();
        self.service
            .handle(peer_hex, issuers, frame, || now)
            .await
            .into_reply()
    }

    fn reads(&self) -> usize {
        self.store.reads.load(Ordering::SeqCst)
    }
}

/// A sink that never accepts a byte: a peer holding the connection open
/// while withholding QUIC receive credit.
struct StallingSink;

impl tokio::io::AsyncWrite for StallingSink {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Pending
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// The honest path produces a PROOF of the contracted size
// ---------------------------------------------------------------------------

/// A well-formed challenge on a stored shard yields a PROOF of exactly
/// `max_response_bytes`, through one bounded read of the derived length.
/// Its verification against the real verifier is the warden's test.
#[tokio::test]
async fn honest_challenge_yields_a_proof_of_the_contracted_size() {
    for (file_size, stripe_size, shard_index) in [
        (40960u64, 40960u64, 9u64),
        (71681, 40960, 39),
        (2 * 1024 * 1024, 2 * 1024 * 1024, 7),
    ] {
        let mut h = Harness::new(file_size, stripe_size, 2).await;
        let issued = h.issue(shard_index);
        let reply = h.handle(&issued.frame).await;
        let Reply::Proof(frame) = &reply else {
            panic!("expected PROOF, got {reply:?}");
        };
        assert_eq!(frame.len(), issued.challenge.max_response_bytes as usize);
        assert_eq!(h.reads(), 1);
        assert_eq!(h.store.unbounded_reads.load(Ordering::SeqCst), 0);
        assert_eq!(
            h.store.max_len_requested.load(Ordering::SeqCst),
            issued.challenge.shard_length
        );
        assert_eq!(h.service.metrics.answered.load(Ordering::Relaxed), 1);
    }
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

#[tokio::test]
async fn absent_shard_is_signed_busy_not_a_panic() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let issued = h.issue(9);
    h.store
        .inner
        .remove(&h.manifest.shards[9].blob_hash)
        .await
        .unwrap();
    let reply = h.handle(&issued.frame).await;
    let Reply::Busy(frame, BusyReason::ShardAbsent) = &reply else {
        panic!("expected BUSY(ShardAbsent), got {reply:?}");
    };
    assert_eq!(frame.len(), BUSY_FRAMED_LEN);
    assert_eq!(h.service.metrics.absent.load(Ordering::Relaxed), 1);
    assert_eq!(h.service.metrics.busy.load(Ordering::Relaxed), 1);
    assert_eq!(h.service.metrics.answered.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn corrupted_shard_is_busy_never_a_proof_under_the_wrong_root() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let issued = h.issue(9);
    let hash = h.manifest.shards[9].blob_hash.clone();
    let mut corrupted = h.shards[9].clone();
    corrupted[4000] ^= 1;
    h.store.inner.remove(&hash).await.unwrap();
    h.store.store(&hash, &corrupted).await.unwrap();
    let reply = h.handle(&issued.frame).await;
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::OutboardNotReady)),
        "{reply:?}"
    );
    assert_eq!(reply.bytes().unwrap().len(), BUSY_FRAMED_LEN);
}

/// A store entry longer than the projected shard (corrupted file, or an
/// authorized issuer signing a short projection for a big blob's digest)
/// is refused by the bounded read before its content is buffered: the
/// only read issued is bounded by the derived length, never the
/// unbounded `read`, and the reply is BUSY (outboard not ready).
#[tokio::test]
async fn oversized_store_entry_is_refused_by_the_bounded_read() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let issued = h.issue(9);
    let hash = h.manifest.shards[9].blob_hash.clone();
    let mut oversized = h.shards[9].clone();
    oversized.extend_from_slice(&[0x5Au8; 1 << 20]);
    h.store.inner.remove(&hash).await.unwrap();
    h.store.store(&hash, &oversized).await.unwrap();

    let reply = h.handle(&issued.frame).await;
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::OutboardNotReady)),
        "{reply:?}"
    );
    assert_eq!(h.reads(), 1);
    assert_eq!(h.store.unbounded_reads.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.store.max_len_requested.load(Ordering::SeqCst),
        issued.challenge.shard_length,
        "the read is bounded by the derived shard length"
    );
    assert_eq!(h.service.metrics.outboard_build.count(), 0, "never hashed");
    // The honest path issues exactly the same bounded read.
    h.store.inner.remove(&hash).await.unwrap();
    h.store.store(&hash, &h.shards[9].clone()).await.unwrap();
    let issued = h.issue(9);
    assert!(matches!(h.handle(&issued.frame).await, Reply::Proof(_)));
    assert_eq!(h.store.unbounded_reads.load(Ordering::SeqCst), 0);
}

/// A truncated entry is BUSY as well, without a proof attempt.
#[tokio::test]
async fn truncated_store_entry_is_busy_without_hashing() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let issued = h.issue(9);
    let hash = h.manifest.shards[9].blob_hash.clone();
    let truncated = h.shards[9][..h.shards[9].len() - 1].to_vec();
    h.store.inner.remove(&hash).await.unwrap();
    h.store.store(&hash, &truncated).await.unwrap();
    let reply = h.handle(&issued.frame).await;
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::OutboardNotReady)),
        "{reply:?}"
    );
    assert_eq!(h.service.metrics.outboard_build.count(), 0);
}

#[tokio::test]
async fn expired_challenge_is_busy_before_any_disk_read() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let issued = h.issue(9);
    let at_deadline = issued.challenge.issued_at_ms + CHALLENGE_WINDOW_MS;
    let reply = h.handle_at(&issued.frame, at_deadline).await;
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::ExpiredLocally)),
        "{reply:?}"
    );
    assert_eq!(h.reads(), 0, "no disk read for an expired challenge");
    // Before the deadline, with time left for the read and the proof, the
    // miner still works.
    let issued = h.issue(9);
    let reply = h
        .handle_at(&issued.frame, issued.challenge.expires_at_ms - 500)
        .await;
    assert!(matches!(reply, Reply::Proof(_)), "{reply:?}");
    assert_eq!(h.reads(), 1);
}

/// With the single permit held by another requester's parked read, a
/// valid challenge is BUSY(NoPermit) without waiting and without a read.
#[tokio::test]
async fn busy_without_a_proof_permit() {
    let mut h = Harness::new(40960, 40960, 1).await;
    let other_key = SigningKey::from_bytes(&[0x55; 32]);
    let other_id = other_key.verifying_key().to_bytes();
    let issuers = [h.verifier_id, other_id];
    let now = h.now();
    let (gate, mut entered_rx) = Gate::new(1);
    *h.store.gate.lock().unwrap() = Some(gate.clone());
    let holder = h.issue_from(other_key);
    let issued = h.issue(9);

    let service = &h.service;
    let other_hex = hex::encode(other_id);
    let (holder_answer, reply) = tokio::join!(
        service.handle(&other_hex, &issuers, &holder.frame, || now),
        async {
            entered_rx.recv().await.unwrap();
            let reply = service
                .handle(&h.verifier_hex, &issuers, &issued.frame, || now)
                .await
                .into_reply();
            gate.release_one();
            reply
        }
    );
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::NoPermit)),
        "{reply:?}"
    );
    assert_eq!(h.reads(), 1, "the refused challenge read nothing");
    assert!(matches!(holder_answer.reply, Reply::Proof(_)));
    assert_eq!(reply.bytes().unwrap().len(), BUSY_FRAMED_LEN);
}

/// The pool size is clamped to the protocol bound of §5: never zero
/// (a miner that could answer nothing), never more than 16.
#[tokio::test]
async fn proof_concurrency_is_clamped_to_the_protocol_bound() {
    let h = Harness::new(40960, 40960, 2).await;
    for (configured, effective) in [
        (0usize, 1usize),
        (1, 1),
        (2, 2),
        (16, 16),
        (17, 16),
        (1024, 16),
    ] {
        let service = StorageProofService::new(
            h.store.clone() as Arc<dyn BlobStore>,
            Arc::new(h.miner_key.clone()),
            INCARNATION,
            configured,
        );
        assert_eq!(service.proof_permits_available(), effective, "{configured}");
    }
    assert_eq!(MAX_PROOF_CONCURRENCY, 16);
}

/// A second challenge from a requester whose first is still in flight is
/// BUSY; the first completes normally once the store answers. The store
/// gate signals when the first read has started, so the ordering is
/// explicit rather than a polling accident.
#[tokio::test]
async fn second_concurrent_challenge_from_same_requester_is_busy() {
    let mut h = Harness::new(40960, 40960, 4).await;
    let (gate, mut entered_rx) = Gate::new(1);
    *h.store.gate.lock().unwrap() = Some(gate.clone());
    let first = h.issue(9);
    let second = h.issue(9);

    let service = &h.service;
    let issuers = [h.verifier_id];
    let now = h.now();
    let (first_answer, second_answer) = tokio::join!(
        service.handle(&h.verifier_hex, &issuers, &first.frame, || now),
        async {
            entered_rx.recv().await.unwrap();
            let answer = service
                .handle(&h.verifier_hex, &issuers, &second.frame, || now)
                .await;
            gate.release_one();
            answer
        }
    );
    assert!(
        matches!(second_answer.reply, Reply::Busy(_, BusyReason::Concurrent)),
        "{:?}",
        second_answer.reply
    );
    assert!(
        matches!(first_answer.reply, Reply::Proof(_)),
        "{:?}",
        first_answer.reply
    );
    *h.store.gate.lock().unwrap() = None;
    // The requester stays in flight until the answer (its token) is
    // dropped, i.e. until the host has written the frame and finished.
    // While its BUSY(Concurrent) is also in flight, a third challenge is
    // closed without bytes: two handlers per requester, never more.
    let third = h.issue(9);
    let reply = h
        .service
        .handle(&h.verifier_hex, &issuers, &third.frame, || now)
        .await
        .into_reply();
    assert_eq!(reply, Reply::Close(CloseReason::Concurrent));
    // Once the BUSY is written the requester can collect another one.
    drop(second_answer);
    let fourth = h.issue(9);
    let reply = h
        .service
        .handle(&h.verifier_hex, &issuers, &fourth.frame, || now)
        .await
        .into_reply();
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::Concurrent)),
        "{reply:?}"
    );
    drop(first_answer);
    // Once the first answer is released the requester is admitted again.
    let fifth = h.issue(9);
    assert!(matches!(h.handle(&fifth.frame).await, Reply::Proof(_)));
}

/// A signed BUSY holds the requester's slot exactly like a PROOF: while
/// it is being written, the next challenge is BUSY(Concurrent), not more
/// work, and the slot returns when the host drops the answer.
#[tokio::test]
async fn busy_replies_hold_the_requester_slot() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let issuers = [h.verifier_id];
    let expired = h.issue(9);
    let at_deadline = expired.challenge.expires_at_ms;
    let busy_answer = h
        .service
        .handle(&h.verifier_hex, &issuers, &expired.frame, || at_deadline)
        .await;
    assert!(
        matches!(
            busy_answer.reply,
            Reply::Busy(_, BusyReason::ExpiredLocally)
        ),
        "{:?}",
        busy_answer.reply
    );
    assert_eq!(h.reads(), 0);
    let next = h.issue(9);
    let reply = h.handle(&next.frame).await;
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::Concurrent)),
        "{reply:?}"
    );
    assert_eq!(h.reads(), 0, "no work while the requester's slot is taken");
    drop(busy_answer);
    let next = h.issue(9);
    assert!(matches!(h.handle(&next.frame).await, Reply::Proof(_)));
    assert_eq!(h.reads(), 1);
}

/// The response write is bounded by the challenge expiry: a peer that
/// stops draining gets the handler back within the window, the requester
/// slot is released with the answer, and nothing was written twice. A
/// draining sink receives exactly the frame, even at the deadline.
#[tokio::test]
async fn stalled_peer_cannot_pin_the_handler_past_expiry() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let issuers = [h.verifier_id];
    let issued = h.issue(9);
    let now = h.now();
    let answer = h
        .service
        .handle(&h.verifier_hex, &issuers, &issued.frame, || now)
        .await;
    assert!(matches!(answer.reply, Reply::Proof(_)));
    assert_eq!(
        answer.send_budget(now),
        Duration::from_millis(CHALLENGE_WINDOW_MS)
    );
    assert_eq!(answer.send_budget(u64::MAX), Duration::ZERO);

    // 150 ms of budget left, the peer never drains: back within that.
    let late = issued.challenge.expires_at_ms - 150;
    let started = std::time::Instant::now();
    let err = h
        .service
        .write_answer(&mut StallingSink, &answer, late)
        .await
        .unwrap_err();
    assert!(matches!(err, WriteError::Timeout), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "returned in {:?}",
        started.elapsed()
    );
    // Still in flight until the host has reset the stream and dropped it.
    let next = h.issue(9);
    let reply = h.handle(&next.frame).await;
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::Concurrent)),
        "{reply:?}"
    );
    drop(answer);
    // Released: the same requester gets work again, and a draining sink
    // receives exactly the frame, once, even with a zero budget.
    let next = h.issue(9);
    let answer = h
        .service
        .handle(&h.verifier_hex, &issuers, &next.frame, || now)
        .await;
    let Reply::Proof(frame) = &answer.reply else {
        panic!("{:?}", answer.reply);
    };
    let mut sink = Vec::new();
    h.service
        .write_answer(&mut sink, &answer, next.challenge.expires_at_ms)
        .await
        .unwrap();
    assert_eq!(&sink, frame);
    // A closed flow writes nothing and has no budget to spend.
    let stranger = hex::encode([0x33u8; 32]);
    let closed = h
        .service
        .handle(&stranger, &issuers, &next.frame, || now)
        .await;
    assert_eq!(closed.send_budget(0), Duration::ZERO);
    let mut sink = Vec::new();
    h.service
        .write_answer(&mut sink, &closed, now)
        .await
        .unwrap();
    assert!(sink.is_empty());
}

/// The in-flight guard is per requester: another authorized issuer is
/// served concurrently (each verifier holds its own pending).
#[tokio::test]
async fn distinct_authorized_requesters_run_concurrently() {
    let mut h = Harness::new(40960, 40960, 4).await;
    let other_key = SigningKey::from_bytes(&[0x55; 32]);
    let other_id = other_key.verifying_key().to_bytes();
    let (gate, mut entered_rx) = Gate::new(2);
    *h.store.gate.lock().unwrap() = Some(gate.clone());
    let first = h.issue(9);
    let second = h.issue_from(other_key);

    let service = &h.service;
    let issuers = [h.verifier_id, other_id];
    let now = h.now();
    let other_hex = hex::encode(other_id);
    let (first_answer, second_answer, ()) = tokio::join!(
        service.handle(&h.verifier_hex, &issuers, &first.frame, || now),
        service.handle(&other_hex, &issuers, &second.frame, || now),
        async {
            // Both reads are parked in the store before either is released.
            entered_rx.recv().await.unwrap();
            entered_rx.recv().await.unwrap();
            assert_eq!(h.reads(), 2);
            gate.release_one();
            gate.release_one();
        }
    );
    assert!(matches!(first_answer.reply, Reply::Proof(_)));
    assert!(matches!(second_answer.reply, Reply::Proof(_)));
}

/// Cancelling the handler future while the store read is parked does not
/// release the proof permit or the requester's slot: both stay with the
/// detached job until the read actually ends. With one permit, another
/// requester is BUSY(NoPermit) meanwhile and served once the job ends.
#[tokio::test]
async fn cancelled_handler_keeps_permit_and_slot_until_the_read_ends() {
    let mut h = Harness::new(40960, 40960, 1).await;
    let service = Arc::new(StorageProofService::new(
        h.store.clone() as Arc<dyn BlobStore>,
        Arc::new(h.miner_key.clone()),
        INCARNATION,
        1,
    ));
    let other_key = SigningKey::from_bytes(&[0x55; 32]);
    let other_id = other_key.verifying_key().to_bytes();
    let other_hex = hex::encode(other_id);
    let issuers = [h.verifier_id, other_id];
    let now = h.now();

    let (gate, mut entered_rx) = Gate::new(1);
    *h.store.gate.lock().unwrap() = Some(gate.clone());
    let first = h.issue(9);
    let handler = {
        let service = Arc::clone(&service);
        let verifier_hex = h.verifier_hex.clone();
        let frame = first.frame.clone();
        tokio::spawn(async move {
            service
                .handle(&verifier_hex, &issuers, &frame, || now)
                .await
        })
    };
    entered_rx.recv().await.unwrap();
    handler.abort();
    assert!(handler.await.unwrap_err().is_cancelled());

    // The read is still parked: the slot and the only permit are taken.
    let same = h.issue(9);
    let reply = service
        .handle(&h.verifier_hex, &issuers, &same.frame, || now)
        .await
        .into_reply();
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::Concurrent)),
        "{reply:?}"
    );
    let other = h.issue_from(other_key.clone());
    let reply = service
        .handle(&other_hex, &issuers, &other.frame, || now)
        .await
        .into_reply();
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::NoPermit)),
        "{reply:?}"
    );
    assert_eq!(h.reads(), 1, "no second read started");

    // Release the parked read: the detached job ends and frees both.
    *h.store.gate.lock().unwrap() = None;
    gate.release_one();
    let served = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let other = h.issue_from(other_key.clone());
            let reply = service
                .handle(&other_hex, &issuers, &other.frame, || now)
                .await
                .into_reply();
            if matches!(reply, Reply::Proof(_)) {
                break;
            }
            assert!(
                matches!(reply, Reply::Busy(_, BusyReason::NoPermit)),
                "{reply:?}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(served.is_ok(), "permit never came back");
    let same = h.issue(9);
    let reply = service
        .handle(&h.verifier_hex, &issuers, &same.frame, || now)
        .await
        .into_reply();
    assert!(matches!(reply, Reply::Proof(_)), "{reply:?}");
}

/// The wait for the read-and-prove job is bounded by the challenge
/// expiry: with the read parked past it, the handler returns a bytes-free
/// close within the window, while the detached job keeps the requester's
/// slot and the permit until the read actually ends.
#[tokio::test]
async fn slow_read_past_expiry_closes_without_pinning_the_handler() {
    let mut h = Harness::new(40960, 40960, 1).await;
    let issuers = [h.verifier_id];
    let (gate, mut entered_rx) = Gate::new(1);
    *h.store.gate.lock().unwrap() = Some(gate.clone());
    let issued = h.issue(9);
    let late = issued.challenge.expires_at_ms - 150;

    let service = &h.service;
    let started = std::time::Instant::now();
    let (reply, ()) = tokio::join!(
        async {
            service
                .handle(&h.verifier_hex, &issuers, &issued.frame, || late)
                .await
                .into_reply()
        },
        async {
            entered_rx.recv().await.unwrap();
        }
    );
    assert_eq!(reply, Reply::Close(CloseReason::ProofTooLate));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "returned in {:?}",
        started.elapsed()
    );
    // The job is still parked: slot and permit are taken.
    let next = h.issue(9);
    let reply = h.handle(&next.frame).await;
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::Concurrent)),
        "{reply:?}"
    );
    let other_key = SigningKey::from_bytes(&[0x55; 32]);
    let other_id = other_key.verifying_key().to_bytes();
    let other = h.issue_from(other_key);
    let reply = h
        .service
        .handle(
            &hex::encode(other_id),
            &[h.verifier_id, other_id],
            &other.frame,
            || late,
        )
        .await
        .into_reply();
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::NoPermit)),
        "{reply:?}"
    );
    // Released read: the job ends, the requester is served again.
    *h.store.gate.lock().unwrap() = None;
    gate.release_one();
    let served = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let next = h.issue(9);
            if matches!(h.handle(&next.frame).await, Reply::Proof(_)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(served.is_ok(), "slot never came back");
}

/// A shard beyond the on-demand cap is "outboard not ready": BUSY before
/// any read. The projection is synthetic (no data is encoded).
#[tokio::test]
async fn shard_beyond_on_demand_cap_is_busy_without_read() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let big = Projection {
        manifest_id: [0x77; 32],
        shard_index: 3,
        blob_hash: [0x88; 32],
        file_size: 4 << 30,
        stripe_size: 2 << 30,
        k: 10,
        m: 20,
    };
    assert!(big.geometry().shard_length > MAX_ON_DEMAND_SHARD_LENGTH);
    let issued = h.issue_projection(&big);
    let reply = h.handle(&issued.frame).await;
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::OutboardNotReady)),
        "{reply:?}"
    );
    assert_eq!(h.reads(), 0);
    assert_eq!(reply.bytes().unwrap().len(), BUSY_FRAMED_LEN);
}

/// The local clock is consulted again after the proof is built: a proof
/// that became late during the read is replaced by BUSY (§3).
#[tokio::test]
async fn proof_built_after_local_expiry_is_replaced_by_busy() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let issued = h.issue(9);
    let before = issued.challenge.expires_at_ms - 500;
    let calls = std::sync::atomic::AtomicU64::new(0);
    let clock = || {
        // Admission and the wait budget see the challenge in time; the
        // recheck after the proof sees it expired.
        if calls.fetch_add(1, Ordering::SeqCst) < 2 {
            before
        } else {
            before + 500
        }
    };
    let reply = h
        .service
        .handle(&h.verifier_hex, &[h.verifier_id], &issued.frame, clock)
        .await
        .into_reply();
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::ExpiredLocally)),
        "{reply:?}"
    );
    assert_eq!(h.reads(), 1, "the proof was built, then withheld");
    assert_eq!(h.service.metrics.outboard_build.count(), 1);
}

#[tokio::test]
async fn per_sender_rate_limit_answers_busy() {
    let mut h = Harness::new(40960, 40960, 2).await;
    h.service = StorageProofService::new(
        h.store.clone() as Arc<dyn BlobStore>,
        Arc::new(h.miner_key.clone()),
        INCARNATION,
        2,
    )
    .with_rate_limit(1, Duration::from_secs(3600));
    let first = h.issue(9);
    let reply = h.handle(&first.frame).await;
    assert!(matches!(reply, Reply::Proof(_)), "{reply:?}");
    let second = h.issue(9);
    let reply = h.handle(&second.frame).await;
    assert!(
        matches!(reply, Reply::Busy(_, BusyReason::RateLimited)),
        "{reply:?}"
    );
    // Beyond twice the limit not even BUSY is signed: closed without bytes.
    let third = h.issue(9);
    let reply = h.handle(&third.frame).await;
    assert_eq!(reply, Reply::Close(CloseReason::RateLimited));
    // An expired challenge still counts against the window.
    let fourth = h.issue(9);
    let reply = h
        .handle_at(&fourth.frame, fourth.challenge.expires_at_ms)
        .await;
    assert_eq!(reply, Reply::Close(CloseReason::RateLimited));
    assert_eq!(h.reads(), 1);
}

/// Unauthorized or non-admissible challenges are closed without bytes and
/// without any disk read (§3: "ferme sans reponse de preuve, sans I/O").
#[tokio::test]
async fn unauthorized_and_malformed_challenges_close_without_bytes_or_io() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let issued = h.issue(9);

    // Sender not in the issuer list.
    let stranger = hex::encode([0x33u8; 32]);
    let reply = h
        .handle_as(&stranger, &[h.verifier_id], &issued.frame)
        .await;
    assert_eq!(reply, Reply::Close(CloseReason::UnauthorizedSender));
    // Empty issuer list admits nothing, even from the real issuer.
    let reply = h.handle_as(&h.verifier_hex, &[], &issued.frame).await;
    assert_eq!(reply, Reply::Close(CloseReason::UnauthorizedSender));
    // Peer identity that is not a key.
    let reply = h
        .handle_as("not-hex", &[h.verifier_id], &issued.frame)
        .await;
    assert_eq!(reply, Reply::Close(CloseReason::UnknownPeer));
    // Authorized issuer relayed by another authorized peer: TLS peer must
    // be the challenge's verifier (admission PeerMismatch).
    let relay = SigningKey::from_bytes(&[0x44; 32])
        .verifying_key()
        .to_bytes();
    let reply = h
        .handle_as(&hex::encode(relay), &[h.verifier_id, relay], &issued.frame)
        .await;
    assert_eq!(
        reply,
        Reply::Close(CloseReason::Rejected(ChallengeRejection::PeerMismatch))
    );
    // Tampered signature.
    let mut tampered = issued.frame.clone();
    tampered[4 + 308] ^= 1;
    let reply = h.handle(&tampered).await;
    assert_eq!(
        reply,
        Reply::Close(CloseReason::Rejected(ChallengeRejection::InvalidSignature))
    );
    // Truncated frame.
    let reply = h.handle(&issued.frame[..300]).await;
    assert_eq!(
        reply,
        Reply::Close(CloseReason::Rejected(ChallengeRejection::Malformed))
    );
    // Legacy-looking garbage.
    let reply = h.handle(b"{\"PosChallenge\":{}}").await;
    assert_eq!(
        reply,
        Reply::Close(CloseReason::Rejected(ChallengeRejection::Malformed))
    );

    assert_eq!(h.reads(), 0);
    assert_eq!(h.service.metrics.rejected.load(Ordering::Relaxed), 7);
    assert_eq!(h.service.metrics.received.load(Ordering::Relaxed), 7);

    // The untouched challenge still works afterwards.
    let reply = h.handle(&issued.frame).await;
    assert!(matches!(reply, Reply::Proof(_)));
}

/// A requester provisioned by the validator (`storage_proof_requesters`
/// in the heartbeat reply) is admitted like a warden; one that is not in
/// the set is closed without bytes and without touching the store.
#[tokio::test]
async fn distributed_requester_is_admitted_and_stranger_is_closed_without_io() {
    let h = Harness::new(40960, 40960, 2).await;
    let requester_key = SigningKey::from_bytes(&[0x55; 32]);
    let requester_hex = hex::encode(requester_key.verifying_key().to_bytes());
    let issued = h.issue_from(requester_key);
    let validator_hex = h.verifier_hex.clone();

    // Not provisioned: refused at the door.
    let issuers = authorized_issuers(Some(&validator_hex), &[], &[]);
    let reply = h.handle_as(&requester_hex, &issuers, &issued.frame).await;
    assert_eq!(reply, Reply::Close(CloseReason::UnauthorizedSender));
    assert_eq!(h.reads(), 0);

    // Provisioned as a storage-proof requester: served.
    let issuers = authorized_issuers(Some(&validator_hex), &[], &[requester_hex.clone()]);
    let reply = h.handle_as(&requester_hex, &issuers, &issued.frame).await;
    assert!(matches!(reply, Reply::Proof(_)));
    assert_eq!(h.reads(), 1);

    // Revoked on a later heartbeat: refused again.
    let issuers = authorized_issuers(Some(&validator_hex), &[], &[]);
    let reply = h.handle_as(&requester_hex, &issuers, &issued.frame).await;
    assert_eq!(reply, Reply::Close(CloseReason::UnauthorizedSender));
    assert_eq!(h.reads(), 1);

    // Wardens keep their own right, independent of the requester set.
    let issuers = authorized_issuers(Some(&validator_hex), &[requester_hex.clone()], &[]);
    let reply = h.handle_as(&requester_hex, &issuers, &issued.frame).await;
    assert!(matches!(reply, Reply::Proof(_)));
}

#[test]
fn authorized_issuers_merges_sources_and_skips_undecodable_ids() {
    let validator = hex::encode([0x11u8; 32]);
    let warden = hex::encode([0x22u8; 32]);
    let requester = hex::encode([0x33u8; 32]);
    let issuers = authorized_issuers(
        Some(&validator),
        &[warden.clone(), "junk".into(), validator.clone()],
        &[requester.clone(), warden.clone(), String::new()],
    );
    assert_eq!(issuers, vec![[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]]);
    // No validator configured and nothing distributed: nothing admitted.
    assert!(authorized_issuers(None, &[], &[]).is_empty());
    assert!(authorized_issuers(Some("not-hex"), &[], &[]).is_empty());
}

#[test]
fn heartbeat_reply_requester_set_is_replaced_when_present() {
    // Old validator: no field, keep whatever is held.
    let old = serde_json::json!({"status": "OK", "epoch": 1, "warden_node_ids": []});
    assert_eq!(parse_storage_proof_requesters(&old), None);
    // Present: sorted, deduplicated, blanks dropped.
    let reply = serde_json::json!({
        "status": "OK",
        "storage_proof_requesters": ["bb", "aa", "", "bb", 7],
    });
    assert_eq!(
        parse_storage_proof_requesters(&reply),
        Some(vec!["aa".to_string(), "bb".to_string()])
    );
    // Present and empty: a revocation.
    let revoked = serde_json::json!({"status": "OK", "storage_proof_requesters": []});
    assert_eq!(parse_storage_proof_requesters(&revoked), Some(vec![]));
    // Wrong shape: treated as absent.
    let odd = serde_json::json!({"storage_proof_requesters": "aa"});
    assert_eq!(parse_storage_proof_requesters(&odd), None);
}

/// A challenge addressed to another incarnation of this miner is not
/// admitted (the verifier would report WRONG_INCARNATION on a reply).
#[tokio::test]
async fn wrong_incarnation_is_rejected_at_admission() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let projection = Projection::from_manifest(&h.manifest, 9);
    let issued = h.issuer.issue(h.miner_id, [0x5A; 16], &projection, NOW_MS);
    let reply = h.handle(&issued.frame).await;
    assert_eq!(
        reply,
        Reply::Close(CloseReason::Rejected(ChallengeRejection::WrongRecipient))
    );
    assert_eq!(h.reads(), 0);
}

#[tokio::test]
async fn metrics_render_in_prometheus_text_format() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let issued = h.issue(9);
    let Reply::Proof(frame) = h.handle(&issued.frame).await else {
        panic!("expected PROOF");
    };
    let mut out = String::new();
    h.service.metrics.render_prometheus(&mut out);
    assert!(out.contains("miner_storage_proof_challenges_received_total 1\n"));
    assert!(out.contains("miner_storage_proof_challenges_answered_total 1\n"));
    assert!(out.contains(&format!(
        "miner_storage_proof_response_bytes_total {}\n",
        frame.len()
    )));
    assert!(out.contains("miner_storage_proof_outboard_build_seconds_bucket{le=\"+Inf\"} 1\n"));
    assert!(out.contains("miner_storage_proof_outboard_build_seconds_count 1\n"));
    assert_eq!(h.service.metrics.outboard_build.count(), 1);
    // Generated is not delivered: the write counters move only with the
    // transport outcome.
    assert!(out.contains("miner_storage_proof_response_writes_completed_total 0\n"));
    assert!(out.contains("miner_storage_proof_written_bytes_total 0\n"));
}

/// `answered`/`busy`/`response_bytes` count generated replies; the
/// write counters follow the transport: completed with the bytes actually
/// handed over, failed (timed out) when the peer never drained.
#[tokio::test]
async fn write_counters_follow_the_transport_outcome() {
    let mut h = Harness::new(40960, 40960, 2).await;
    let issuers = [h.verifier_id];
    let now = h.now();
    let first = h.issue(9);
    let second = h.issue(9);
    let answer = h
        .service
        .handle(&h.verifier_hex, &issuers, &first.frame, || now)
        .await;
    let frame_len = answer.reply.bytes().unwrap().len() as u64;
    let m = &h.service.metrics;
    assert_eq!(m.answered.load(Ordering::Relaxed), 1);
    assert_eq!(m.response_bytes.load(Ordering::Relaxed), frame_len);
    assert_eq!(m.write_completed.load(Ordering::Relaxed), 0);

    let mut sink = Vec::new();
    h.service
        .write_answer(&mut sink, &answer, now)
        .await
        .unwrap();
    assert_eq!(m.write_completed.load(Ordering::Relaxed), 1);
    assert_eq!(m.written_bytes.load(Ordering::Relaxed), frame_len);
    assert_eq!(m.write_failed.load(Ordering::Relaxed), 0);
    drop(answer);

    let answer = h
        .service
        .handle(&h.verifier_hex, &issuers, &second.frame, || now)
        .await;
    let late = second.challenge.expires_at_ms - 50;
    h.service
        .write_answer(&mut StallingSink, &answer, late)
        .await
        .unwrap_err();
    assert_eq!(m.answered.load(Ordering::Relaxed), 2, "generated");
    assert_eq!(m.write_completed.load(Ordering::Relaxed), 1);
    assert_eq!(m.write_failed.load(Ordering::Relaxed), 1);
    assert_eq!(m.write_timed_out.load(Ordering::Relaxed), 1);
    assert_eq!(m.written_bytes.load(Ordering::Relaxed), frame_len);
    let mut out = String::new();
    m.render_prometheus(&mut out);
    assert!(out.contains("miner_storage_proof_response_writes_failed_total 1\n"));
    assert!(out.contains("miner_storage_proof_response_writes_timed_out_total 1\n"));
}

#[test]
fn fresh_incarnation_is_never_zero() {
    for _ in 0..64 {
        assert_ne!(fresh_incarnation(), [0u8; 16]);
    }
}

/// Timing probe for the outboard build (grouping 1 KiB) on full-size
/// shards; run with `--ignored --nocapture`. Reports the CPU cost an
/// outboard cache would save, separately from the store read.
#[tokio::test]
#[ignore]
async fn measure_outboard_build_time() {
    use common::storage_proof::prover::ShardOutboard;
    use std::time::Instant;
    for shard_len in [209_716usize, 800 * 1024] {
        let data: Vec<u8> = (0..shard_len).map(|i| (i % 253) as u8).collect();
        let g = derive_shard_geometry(shard_len as u64, shard_len as u64, 1, 1, 0).unwrap();
        let root = *blake3::hash(&data).as_bytes();
        let cold = Instant::now();
        let ob = ShardOutboard::build(&data, &g, &root).unwrap();
        let cold = cold.elapsed();
        let mut warm = Duration::ZERO;
        for _ in 0..20 {
            let t = Instant::now();
            let ob2 = ShardOutboard::build(&data, &g, &root).unwrap();
            warm += t.elapsed();
            std::hint::black_box(ob2);
        }
        let slices = Instant::now();
        for i in [0u32, 1, 2, 3] {
            std::hint::black_box(ob.encode_chunk_slice(&data, i).unwrap());
        }
        let slices = slices.elapsed();
        println!(
            "shard {shard_len} B: outboard first {:?}, mean of 20 {:?}, four slices {:?}",
            cold,
            warm / 20,
            slices
        );
    }
}
