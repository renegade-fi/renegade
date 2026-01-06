//! Benchmarks the caching layer
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use circuit_types::Amount;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use darkpool_types::fuzzing::random_address;
use rand::{Rng, thread_rng};
use state::caching::matchable_amount::MatchableAmountMap;
use types_account::account::pair::Pair;

// -----------
// | Helpers |
// -----------

/// Generate test pairs for benchmarking
fn generate_test_pairs(count: usize) -> Vec<Pair> {
    (0..count)
        .map(|_| {
            let base = random_address();
            let quote = random_address();
            Pair::new(base, quote)
        })
        .collect()
}

// --------------
// | Benchmarks |
// --------------

/// Benchmark reading from a populated cache
fn bench_get_populated_cache(c: &mut Criterion) {
    let mut rng = thread_rng();
    let pairs = generate_test_pairs(100);

    // Pre-populate the cache
    let cache = MatchableAmountMap::new();
    for pair in pairs.iter() {
        let amt = rng.gen_range(1..=10_000_000);
        cache.add_amount(*pair, amt);
        cache.add_amount(*pair, amt);
    }

    c.bench_function("get_populated_cache", |b| {
        b.iter(|| {
            for pair in &pairs {
                let _ = black_box(cache.get(pair));
            }
        })
    });
}

/// Benchmark adding amounts to cache
fn bench_add_amount(c: &mut Criterion) {
    let pairs = generate_test_pairs(100);

    c.bench_with_input(
        BenchmarkId::new("add_amount", "sequential"),
        &pairs,
        |b, pairs: &Vec<Pair>| {
            b.iter(|| {
                let cache = MatchableAmountMap::new();
                for (i, pair) in pairs.iter().enumerate() {
                    let amt = (i * 100) as Amount;
                    cache.add_amount(pair.clone(), amt);
                    cache.add_amount(pair.clone(), amt);
                }
            })
        },
    );
}

/// Benchmark subtracting amounts from cache
fn bench_sub_amount(c: &mut Criterion) {
    let pairs = generate_test_pairs(100);

    c.bench_with_input(
        BenchmarkId::new("sub_amount", "sequential"),
        &pairs,
        |b, pairs: &Vec<Pair>| {
            let cache = MatchableAmountMap::new();
            // Setup: Pre-populate cache
            for (i, pair) in pairs.iter().enumerate() {
                let amt = (i * 100) as Amount;
                cache.add_amount(pair.clone(), amt);
                cache.add_amount(pair.clone(), amt);
            }

            b.iter(|| {
                // Then subtract
                for (i, pair) in pairs.iter().enumerate() {
                    let amt = i * 100;
                    cache.sub_amount(pair.clone(), amt as Amount);
                    cache.sub_amount(pair.clone(), amt as Amount);
                }
            })
        },
    );
}

criterion_group!(benches, bench_get_populated_cache, bench_add_amount, bench_sub_amount,);
criterion_main!(benches);
