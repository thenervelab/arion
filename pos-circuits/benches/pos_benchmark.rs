//! Benchmarks for proof-of-storage operations.
//!
//! Run with: cargo bench -p pos-circuits

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pos_circuits::{
    commitment::{generate_commitment, CommitmentWithTree},
    hash::{poseidon2_hash_bytes, poseidon2_hash_two},
    merkle::MerkleTree,
    prover::generate_proof,
    types::Challenge,
    verifier::verify_proof,
};

/// Benchmark Poseidon2 hashing of different data sizes.
fn bench_poseidon2_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("poseidon2_hash");

    for size in [64, 256, 1024, 4096].iter() {
        let data = vec![0xABu8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| poseidon2_hash_bytes(black_box(data)));
        });
    }

    group.finish();
}

/// Benchmark Poseidon2 two-to-one hashing.
fn bench_poseidon2_two(c: &mut Criterion) {
    let left = poseidon2_hash_bytes(b"left");
    let right = poseidon2_hash_bytes(b"right");

    c.bench_function("poseidon2_two_to_one", |b| {
        b.iter(|| poseidon2_hash_two(black_box(&left), black_box(&right)));
    });
}

/// Benchmark Merkle tree construction for different numbers of chunks.
fn bench_merkle_tree_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_tree_build");

    for num_chunks in [8, 32, 68, 128].iter() {
        let chunk_size = 1024;
        let data = vec![0xCDu8; num_chunks * chunk_size];
        let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(num_chunks),
            &chunks,
            |b, chunks| {
                b.iter(|| MerkleTree::from_chunks(black_box(chunks)));
            },
        );
    }

    group.finish();
}

/// Benchmark Merkle proof generation.
fn bench_merkle_proof(c: &mut Criterion) {
    let data = vec![0xEFu8; 68 * 1024]; // 68 chunks
    let chunks: Vec<&[u8]> = data.chunks(1024).collect();
    let tree = MerkleTree::from_chunks(&chunks).unwrap();

    c.bench_function("merkle_proof_generate", |b| {
        b.iter(|| tree.proof(black_box(33))); // Middle of tree
    });
}

/// Benchmark commitment generation.
fn bench_commitment(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment");

    for size_kb in [4, 32, 68, 128].iter() {
        let data = vec![0x12u8; size_kb * 1024];

        group.throughput(Throughput::Bytes((size_kb * 1024) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size_kb), &data, |b, data| {
            b.iter(|| generate_commitment(black_box(data), 1024));
        });
    }

    group.finish();
}

/// Benchmark proof generation.
fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_generation");

    // Test with different numbers of challenges
    for num_challenges in [1, 2, 4, 8].iter() {
        let data = vec![0x34u8; 68 * 1024]; // 68 chunks
        let commitment = CommitmentWithTree::generate(&data, 1024).unwrap();

        // Generate challenge indices
        let indices: Vec<u32> = (0..*num_challenges as u32).collect();
        let challenge = Challenge::new(
            &commitment.commitment.shard_hash,
            indices,
            commitment.commitment.merkle_root,
            u64::MAX,
        );

        group.bench_with_input(
            BenchmarkId::from_parameter(num_challenges),
            &(&data, &commitment, &challenge),
            |b, (data, commitment, challenge)| {
                b.iter(|| {
                    generate_proof(black_box(data), black_box(commitment), black_box(challenge))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark proof verification.
fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_verification");

    // Generate a valid proof
    let data = vec![0x78u8; 68 * 1024];
    let commitment = CommitmentWithTree::generate(&data, 1024).unwrap();

    for num_challenges in [1, 2, 4].iter() {
        let indices: Vec<u32> = (0..*num_challenges as u32).collect();
        let challenge = Challenge::new(
            &commitment.commitment.shard_hash,
            indices,
            commitment.commitment.merkle_root,
            u64::MAX,
        );

        let proof = generate_proof(&data, &commitment, &challenge).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(num_challenges),
            &(&proof, &commitment.commitment, &challenge),
            |b, (proof, commitment, challenge)| {
                b.iter(|| {
                    verify_proof(
                        black_box(proof),
                        black_box(commitment),
                        Some(black_box(challenge)),
                    )
                });
            },
        );
    }

    group.finish();
}

/// Benchmark end-to-end flow: commitment -> proof -> verify.
fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end");

    let data = vec![0xBCu8; 68 * 1024];

    group.bench_function("commitment_prove_verify", |b| {
        b.iter(|| {
            let commitment = CommitmentWithTree::generate(black_box(&data), 1024).unwrap();
            let challenge = Challenge::new(
                &commitment.commitment.shard_hash,
                vec![0, 17, 34, 51],
                commitment.commitment.merkle_root,
                u64::MAX,
            );
            let proof = generate_proof(
                black_box(&data),
                black_box(&commitment),
                black_box(&challenge),
            )
            .unwrap();
            verify_proof(
                black_box(&proof),
                black_box(&commitment.commitment),
                Some(black_box(&challenge)),
            )
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_poseidon2_hash,
    bench_poseidon2_two,
    bench_merkle_tree_build,
    bench_merkle_proof,
    bench_commitment,
    bench_proof_generation,
    bench_proof_verification,
    bench_end_to_end,
);

criterion_main!(benches);
