//! Benchmarks a full match of two orders including the raw MPC and the
//! collaborative proof
#![allow(unused)]
#![allow(missing_docs)]

use std::time::{Duration, Instant};

use ark_mpc::{test_helpers::execute_mock_mpc_with_size_hint, ExecutorSizeHints, PARTY0, PARTY1};
use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    native_helpers::create_wallet_shares_with_randomness,
    order::Order,
    traits::{BaseType, MpcBaseType},
    Fabric,
};
use circuits::{
    mpc_circuits::{r#match::compute_match, settle::settle_match},
    multiprover_prove,
    test_helpers::{dummy_wallet_share, random_indices},
    zk_circuits::valid_match_settle::{
        AuthenticatedValidMatchSettleStatement, AuthenticatedValidMatchSettleWitness,
        SizedValidMatchSettle, ValidMatchSettle,
    },
};
use constants::{Scalar, MAX_BALANCES, MAX_FEES, MAX_ORDERS};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use test_helpers::mpc_network::{
    execute_mock_mpc_with_delay, execute_mock_mpc_with_delay_and_hint,
};
use tokio::runtime::Builder as RuntimeBuilder;

/// A small delay, roughly what would be expected for nodes in the same
/// availability zone
const SMALL_DELAY_MS: u64 = 1;
/// A medium sized delay, roughly what would be expected for nodes in the same
/// region
const MEDIUM_DELAY_MS: u64 = 10;
/// A larger delay, perhaps between different autonomous systems
const LARGE_DELAY_MS: u64 = 100;

// -----------
// | Helpers |
// -----------

/// A witness to `VALID MATCH SETTLE` with default sizing parameters
type SizedValidMatchSettleWitness =
    AuthenticatedValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// A statement of `VALID MATCH SETTLE` with default sizing parameters
type SizedValidMatchSettleStatement =
    AuthenticatedValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// Benchmark a match end-to-end with a given connection latency
///
/// Returns the total time taken for the critical path
async fn run_match_with_delay(delay: Duration) -> Duration {
    let hint = ExecutorSizeHints { n_ops: 28_500, n_results: 9_200_000 };
    let (party0_time, party1_time) = execute_mock_mpc_with_delay_and_hint(
        |fabric| async move {
            let start_time = Instant::now();

            // Generate a proof of `VALID MATCH SETTLE`
            let (witness, statement) = create_witness_and_statement(&fabric).await;
            let proof =
                multiprover_prove::<SizedValidMatchSettle>(witness, statement, fabric).unwrap();

            // Open the proof and await the result
            let _proof = black_box(proof.open_authenticated().await.unwrap());
            start_time.elapsed()
        },
        delay,
        hint,
    )
    .await;

    Duration::max(party0_time, party1_time)
}

/// Create a witness and statement for `VALID MATCH SETTLE` in an mpc
async fn create_witness_and_statement(
    fabric: &Fabric,
) -> (SizedValidMatchSettleWitness, SizedValidMatchSettleStatement) {
    let order1 = Order::default().allocate(PARTY0, fabric);
    let balance1 = Balance::default().allocate(PARTY0, fabric);
    let amount1 = Scalar::one().allocate(PARTY0, fabric);
    let ind1 = random_indices().share_public(PARTY0, fabric).await;
    let party0_pre_shares = dummy_wallet_share().allocate(PARTY0, fabric);

    let order2 = Order::default().allocate(PARTY1, fabric);
    let balance2 = Balance::default().allocate(PARTY1, fabric);
    let amount2 = Scalar::one().allocate(PARTY1, fabric);
    let ind2 = random_indices().share_public(PARTY0, fabric).await;
    let party1_pre_shares = dummy_wallet_share().allocate(PARTY1, fabric);
    let price = FixedPoint::from_integer(1).allocate(PARTY0, fabric);

    // Compute the match and settle it
    let match_res = compute_match(&order1, &amount1, &amount2, &price, fabric);
    let (party0_modified_shares, party1_modified_shares) =
        settle_match(ind1, ind2, &party0_pre_shares, &party1_pre_shares, &match_res);

    (
        SizedValidMatchSettleWitness {
            order1,
            balance1,
            amount1,
            price1: price.clone(),
            order2,
            balance2,
            amount2,
            price2: price,
            party0_public_shares: party0_pre_shares,
            party1_public_shares: party1_pre_shares,
            match_res,
        },
        SizedValidMatchSettleStatement {
            party0_indices: ind1.allocate(PARTY0, fabric),
            party1_indices: ind2.allocate(PARTY0, fabric),
            party0_modified_shares,
            party1_modified_shares,
        },
    )
}

/// Run a criterion benchmark on the match with delay
fn benchmark_match_with_delay(c: &mut Criterion, delay: Duration) {
    let mut group = c.benchmark_group("full_match");
    group.bench_function(BenchmarkId::new("match", delay.as_millis()), |b| {
        // Build a Tokio runtime and spawn the benchmarks within it
        let runtime = RuntimeBuilder::new_multi_thread().enable_all().build().unwrap();
        let mut async_bencher = b.to_async(runtime);

        async_bencher.iter_custom(|n_iters| async move {
            let mut total_time = Duration::default();
            for _ in 0..n_iters {
                total_time += run_match_with_delay(delay).await;
            }
            total_time
        })
    });
}

// --------------
// | Benchmarks |
// --------------

/// Benchmark the full match process at a small latency
#[allow(non_snake_case)]
fn bench_full_match__small_delay(c: &mut Criterion) {
    let delay = Duration::from_millis(SMALL_DELAY_MS);
    benchmark_match_with_delay(c, delay);
}

/// Benchmark the full match process at a medium latency
#[allow(non_snake_case)]
fn bench_full_match__medium_delay(c: &mut Criterion) {
    let delay = Duration::from_millis(MEDIUM_DELAY_MS);
    benchmark_match_with_delay(c, delay);
}

/// Benchmark the full match process at a large latency
#[allow(non_snake_case)]
fn bench_full_match__large_delay(c: &mut Criterion) {
    let delay = Duration::from_millis(LARGE_DELAY_MS);
    benchmark_match_with_delay(c, delay);
}

#[cfg(all(feature = "large_benchmarks", not(feature = "stats")))]
criterion_group! {
    name = full_match;
    config = Criterion::default().sample_size(10);
    targets =
        bench_full_match__small_delay,
        bench_full_match__medium_delay,
        bench_full_match__large_delay
}

#[cfg(all(not(feature = "large_benchmarks"), not(feature = "stats")))]
criterion_group! {
    name = full_match;
    config = Criterion::default().sample_size(10);
    targets =
        bench_full_match__small_delay,
}

#[cfg(not(feature = "stats"))]
criterion_main!(full_match);

#[cfg(feature = "stats")]
#[tokio::main]
async fn main() {
    // Run a single match to collect statistics, the delay does not matter as
    // all collected stats are independent of the delay
    let start = Instant::now();

    let delay = Duration::from_millis(SMALL_DELAY_MS);
    let _ = run_match_with_delay(delay).await;

    println!("Total time: {:?}", start.elapsed());
}
