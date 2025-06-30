//! Benchmarks the caching layer
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use circuit_types::{Amount, order::OrderSide};
use common::types::wallet::{Pair, pair_from_mints};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use num_bigint::BigUint;
use rand::{Rng, thread_rng};
use state::caching::matchable_amount::MatchableAmountMap;
use tokio::runtime::Runtime;

// -----------
// | Helpers |
// -----------

/// Generate test pairs for benchmarking
fn generate_test_pairs(count: usize) -> Vec<Pair> {
    (0..count)
        .map(|i| {
            let base = BigUint::from(i * 2);
            let quote = BigUint::from(i * 2 + 1);
            pair_from_mints(base, quote)
        })
        .collect()
}

// --------------
// | Benchmarks |
// --------------

/// Benchmark reading from a populated cache
fn bench_get_populated_cache(c: &mut Criterion) {
    let mut rng = thread_rng();
    let rt = Runtime::new().unwrap();
    let pairs = generate_test_pairs(100);

    // Pre-populate the cache
    let cache = MatchableAmountMap::new();
    rt.block_on(async {
        for pair in pairs.iter() {
            let amt = rng.gen_range(1..=10_000_000);
            cache.add_amount(pair.clone(), OrderSide::Buy, amt).await;
            cache.add_amount(pair.clone(), OrderSide::Sell, amt).await;
        }
    });

    c.bench_function("get_populated_cache", |b| {
        b.iter(|| {
            rt.block_on(async {
                for pair in &pairs {
                    let _ = black_box(cache.get(pair).await);
                }
            })
        })
    });
}

/// Benchmark adding amounts to cache
fn bench_add_amount(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let pairs = generate_test_pairs(100);

    c.bench_with_input(BenchmarkId::new("add_amount", "sequential"), &pairs, |b, pairs| {
        b.iter(|| {
            let cache = MatchableAmountMap::new();
            rt.block_on(async {
                for (i, pair) in pairs.iter().enumerate() {
                    let amt = (i * 100) as Amount;
                    cache.add_amount(pair.clone(), OrderSide::Buy, amt).await;
                    cache.add_amount(pair.clone(), OrderSide::Sell, amt).await;
                }
            })
        })
    });
}

/// Benchmark subtracting amounts from cache
fn bench_sub_amount(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let pairs = generate_test_pairs(100);

    c.bench_with_input(BenchmarkId::new("sub_amount", "sequential"), &pairs, |b, pairs| {
        let cache = MatchableAmountMap::new();
        rt.block_on(async {
            // Setup: Pre-populate cache
            for (i, pair) in pairs.iter().enumerate() {
                let amt = (i * 100) as Amount;
                cache.add_amount(pair.clone(), OrderSide::Buy, amt).await;
                cache.add_amount(pair.clone(), OrderSide::Sell, amt).await;
            }
        });

        b.iter(|| {
            rt.block_on(async {
                // Then subtract
                for (i, pair) in pairs.iter().enumerate() {
                    let amt = i * 100;
                    cache.sub_amount(pair.clone(), OrderSide::Buy, amt as Amount).await;
                    cache.sub_amount(pair.clone(), OrderSide::Sell, amt as Amount).await;
                }
            })
        })
    });
}

criterion_group!(benches, bench_get_populated_cache, bench_add_amount, bench_sub_amount,);
criterion_main!(benches);
