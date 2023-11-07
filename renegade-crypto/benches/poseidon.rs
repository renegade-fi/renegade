//! Defines benchmarks for the Poseidon hash function
use constants::Scalar;
use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use mpc_stark::algebra::scalar::Scalar as StarkScalar;
use rand::thread_rng;
use renegade_crypto::{
    constants::{POSEIDON_MDS_MATRIX_T_3, POSEIDON_ROUND_CONSTANTS_T_3},
    hash::{compute_poseidon_hash, Poseidon2Sponge},
};

/// Run a benchmark on the original poseidon hash implementation
fn bench_poseidon1(c: &mut Criterion) {
    let mut rng = thread_rng();

    // The param parsing is memoized, run it once so this does not affect the
    // benchmark
    {
        POSEIDON_MDS_MATRIX_T_3();
        POSEIDON_ROUND_CONSTANTS_T_3();
    }

    let mut group = c.benchmark_group("poseidon1-hash");
    for i in [1, 10, 100, 1000] {
        group.throughput(Throughput::Elements(i));
        group.bench_function(BenchmarkId::from_parameter(i), |b| {
            b.iter_batched(
                || {
                    (0..i)
                        .map(|_| StarkScalar::random(&mut rng))
                        .collect::<Vec<_>>()
                },
                |input| black_box(compute_poseidon_hash(&input)),
                BatchSize::SmallInput,
            );
        });
    }
}

/// Run a benchmark on the Poseidon 2 hash implementation
///
/// TODO: When we expose a better convenience function for the hash, use that
/// instead
fn bench_poseidon2(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut group = c.benchmark_group("poseidon2-hash");
    for i in [1, 10, 100, 1000] {
        group.throughput(Throughput::Elements(i));
        group.bench_function(BenchmarkId::from_parameter(i), |b| {
            b.iter_batched(
                || {
                    (0..i)
                        .map(|_| Scalar::random(&mut rng).inner())
                        .collect::<Vec<_>>()
                },
                |input| {
                    let mut sponge = Poseidon2Sponge::new();
                    black_box(sponge.hash(&input));
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_poseidon1, bench_poseidon2
);
criterion_main!(benches);
