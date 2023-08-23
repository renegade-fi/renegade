//! Benchmarks a full match of two orders including the raw MPC and the collaborative proof
#![allow(unused)]

use std::time::{Duration, Instant};

use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::Order,
    traits::{LinkableBaseType, LinkableType, MpcBaseType, MultiproverCircuitCommitmentType},
};
use circuits::{
    mpc_circuits::r#match::compute_match,
    multiprover_prove,
    zk_circuits::valid_match_mpc::{AuthenticatedValidMatchMpcWitness, ValidMatchMpcCircuit},
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mpc_stark::{algebra::scalar::Scalar, MpcFabric, PARTY0, PARTY1};
use test_helpers::mpc_network::execute_mock_mpc_with_delay;
use tokio::runtime::Builder as RuntimeBuilder;

/// A small delay, roughly what would be expected for nodes in the same availability zone
const SMALL_DELAY_MS: u64 = 1;
/// A medium sized delay, roughly what would be expected for nodes in the same region
const MEDIUM_DELAY_MS: u64 = 10;
/// A larger delay, perhaps between different autonomous systems
const LARGE_DELAY_MS: u64 = 100;

// -----------
// | Helpers |
// -----------

/// Benchmark a match end-to-end with a given connection latency
///
/// Returns the total time taken for the critical path
async fn run_match_with_delay(delay: Duration) -> Duration {
    let (party0_time, party1_time) = execute_mock_mpc_with_delay(
        |fabric| async move {
            let start_time = Instant::now();
            let order1 = Order::default().to_linkable().allocate(PARTY0, &fabric);
            let balance1 = Balance::default().to_linkable().allocate(PARTY0, &fabric);
            let amount1 = Scalar::one().allocate(PARTY0, &fabric);

            let order2 = Order::default().to_linkable().allocate(PARTY1, &fabric);
            let balance2 = Balance::default().to_linkable().allocate(PARTY1, &fabric);
            let amount2 = Scalar::one().allocate(PARTY1, &fabric);
            let price = FixedPoint::from_integer(1).allocate(PARTY0, &fabric);

            // Run the MPC to generate a witness for the proof
            let match_res = compute_match(&order1, &order2, &amount1, &amount2, &price, &fabric);

            // Generate a proof of `VALID MATCH MPC`
            let witness = AuthenticatedValidMatchMpcWitness {
                order1,
                balance1,
                price1: price.clone(),
                amount1,
                order2,
                balance2,
                price2: price.clone(),
                amount2,
                match_res: match_res.link_commitments(&fabric),
            };

            let (commitments, proof) =
                multiprover_prove::<ValidMatchMpcCircuit>(witness, () /* statement */, fabric)
                    .unwrap();

            // Allocate both openings and then await
            let _proof = black_box(proof.open().await.unwrap());
            let _comms = black_box(commitments.open_and_authenticate().await.unwrap());

            start_time.elapsed()
        },
        delay,
    )
    .await;

    Duration::max(party0_time, party1_time)
}

/// Run a criterion benchmark on the match with delay
fn benchmark_match_with_delay(c: &mut Criterion, delay: Duration) {
    let mut group = c.benchmark_group("full_match");
    group.bench_function(BenchmarkId::new("match", delay.as_millis()), |b| {
        // Build a Tokio runtime and spawn the benchmarks within it
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
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
    let delay = Duration::from_millis(SMALL_DELAY_MS);
    let _ = run_match_with_delay(delay).await;
}
