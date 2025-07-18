//! Benchmarks for the elgamal implementation

#![allow(missing_docs)]

use constants::Scalar;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::thread_rng;
use renegade_crypto::elgamal::{decrypt_scalar, encrypt_scalar};

/// Run a benchmark on the ElGamal encryption implementation
fn bench_encrypt(c: &mut Criterion) {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("ElGamal encryption");
    group.throughput(Throughput::Elements(1));

    group.bench_function(BenchmarkId::from_parameter(1), |b| {
        b.iter_batched(
            || (Scalar::random(&mut rng), Scalar::random(&mut rng).to_biguint()),
            |(plaintext, public_key)| encrypt_scalar(plaintext, &public_key),
            BatchSize::SmallInput,
        );
    });
}

/// Run a decryption benchmark
fn bench_decrypt(c: &mut Criterion) {
    let mut rng = thread_rng();

    let mut group = c.benchmark_group("ElGamal decryption");
    group.throughput(Throughput::Elements(1));

    group.bench_function(BenchmarkId::from_parameter(1), |b| {
        b.iter_batched(
            || {
                let (cipher, _) = encrypt_scalar(
                    Scalar::random(&mut rng),
                    &Scalar::random(&mut rng).to_biguint(),
                );
                (cipher, Scalar::random(&mut rng).to_biguint())
            },
            |(cipher, secret_key)| decrypt_scalar(cipher, &secret_key),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_encrypt, bench_decrypt
);
criterion_main!(benches);
