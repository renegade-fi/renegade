//! Defines benchmarks for the Poseidon hash function
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use mpc_stark::algebra::scalar::Scalar;
use rand::thread_rng;
use renegade_crypto::{
    constants::{POSEIDON_MDS_MATRIX_T_3, POSEIDON_ROUND_CONSTANTS_T_3},
    hash::compute_poseidon_hash,
};

/// Run a benchmark on the poseidon hash implementation
fn bench_hash(c: &mut Criterion) {
    let mut rng = thread_rng();

    // The param parsing is memoized, run it once so this does not affect the benchmark
    {
        POSEIDON_MDS_MATRIX_T_3();
        POSEIDON_ROUND_CONSTANTS_T_3();
    }

    let mut group = c.benchmark_group("Poseidon Hash");
    for i in [1, 10, 100, 1000] {
        group.throughput(Throughput::Elements(i));
        group.bench_function(BenchmarkId::from_parameter(i), |b| {
            b.iter_batched(
                || (0..i).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>(),
                |input| compute_poseidon_hash(&input),
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_hash
);
criterion_main!(benches);
