//! Defines benchmarks for the Poseidon hash function

#![allow(missing_docs)]

use constants::Scalar;
use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use rand::thread_rng;
use renegade_crypto::hash::compute_poseidon_hash;

/// Run a benchmark on the Poseidon 2 hash implementation
fn bench_poseidon2(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut group = c.benchmark_group("poseidon2-hash");
    for i in [1, 10, 100, 1000] {
        group.throughput(Throughput::Elements(i));
        group.bench_function(BenchmarkId::from_parameter(i), |b| {
            b.iter_batched(
                || (0..i).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>(),
                |input| {
                    black_box(compute_poseidon_hash(&input));
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_poseidon2
);
criterion_main!(benches);
