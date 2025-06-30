//! Benchmarks for the matching engine

#![allow(missing_docs)]

use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use num_bigint::RandBigInt;
use rand::{Rng, thread_rng};
use util::matching_engine::match_orders;

// --------------
// | Test Setup |
// --------------

/// The worst case price for the buy side
const BUY_SIDE_WORST_CASE_PRICE: f32 = 10.;
/// The worst case price for the sell side
const SELL_SIDE_WORST_CASE_PRICE: f32 = 5.;

/// Generate a random buy order
fn random_buy_order() -> Order {
    let mut rng = thread_rng();
    Order {
        base_mint: rng.gen_biguint(64 /* bits */),
        quote_mint: rng.gen_biguint(64 /* bits */),
        side: OrderSide::Buy,
        amount: rng.gen_range(1..1_000_000),
        worst_case_price: BUY_SIDE_WORST_CASE_PRICE.into(),
    }
}

/// Generate a random sell order matching the buy order
fn random_sell_order(buy_order: &Order) -> Order {
    let mut rng = thread_rng();
    Order {
        base_mint: buy_order.base_mint.clone(),
        quote_mint: buy_order.quote_mint.clone(),
        side: OrderSide::Sell,
        amount: rng.gen_range(1..1_000_000),
        worst_case_price: SELL_SIDE_WORST_CASE_PRICE.into(),
    }
}

/// Generate a random balance for a given mint
fn random_balance(mint: &num_bigint::BigUint) -> Balance {
    let mut rng = thread_rng();
    Balance {
        mint: mint.clone(),
        amount: rng.gen_range(1_000_000..10_000_000),
        relayer_fee_balance: 0,
        protocol_fee_balance: 0,
    }
}

// ----------------
// | Benchmarks  |
// ----------------

/// Benchmark the order matching function
fn bench_match_orders(c: &mut Criterion) {
    let mut group = c.benchmark_group("match_orders");
    group.throughput(Throughput::Elements(1));

    group.bench_function(BenchmarkId::from_parameter("valid_match"), |b| {
        b.iter_batched(
            || {
                let buy_order = random_buy_order();
                let sell_order = random_sell_order(&buy_order);
                let buy_balance = random_balance(&buy_order.quote_mint);
                let sell_balance = random_balance(&sell_order.base_mint);
                let price = FixedPoint::from_f64_round_down(7.5); // Between buy/sell worst case
                (buy_order, sell_order, buy_balance, sell_balance, price)
            },
            |(buy_order, sell_order, buy_balance, sell_balance, price)| {
                match_orders(&buy_order, &sell_order, &buy_balance, &sell_balance, 1, price)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_match_orders
);
criterion_main!(benches);
