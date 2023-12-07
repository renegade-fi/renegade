//! Groups integration tests for matching an order and proving `VALID MATCH
//! SETTLE` collaboratively

#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
#![allow(missing_docs)]

use std::time::{Duration, Instant};

use ark_mpc::{PARTY0, PARTY1};
use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::Order,
    r#match::MatchResult,
    traits::{MpcBaseType, MpcType, MultiProverCircuit, MultiproverCircuitBaseType},
    MpcPlonkCircuit,
};
use circuits::{
    mpc_circuits::r#match::compute_match,
    multiprover_prove, singleprover_prove,
    test_helpers::{dummy_wallet_share, random_indices},
    verify_singleprover_proof,
    zk_circuits::valid_match_settle::{
        SizedValidMatchSettle, ValidMatchSettle, ValidMatchSettleStatement, ValidMatchSettleWitness,
    },
};
use constants::{Scalar, MAX_BALANCES, MAX_FEES, MAX_ORDERS};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use mpc_relation::traits::Circuit;
use test_helpers::mpc_network::execute_mock_mpc_with_delay;
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
/// Get a dummy witness and statement for `VALID MATCH SETTLE`
fn dummy_witness_statement() -> (
    ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
) {
    (
        ValidMatchSettleWitness {
            order1: Order::default(),
            balance1: Balance::default(),
            amount1: Scalar::zero(),
            price1: FixedPoint { repr: Scalar::zero() },
            order2: Order::default(),
            balance2: Balance::default(),
            amount2: Scalar::zero(),
            price2: FixedPoint { repr: Scalar::zero() },
            match_res: MatchResult::default(),
            party0_public_shares: dummy_wallet_share(),
            party1_public_shares: dummy_wallet_share(),
        },
        ValidMatchSettleStatement {
            party0_modified_shares: dummy_wallet_share(),
            party1_modified_shares: dummy_wallet_share(),
            party0_indices: random_indices(),
            party1_indices: random_indices(),
        },
    )
}

/// Benchmark the time taken to run the raw `match` MPC circuits with a given
/// connection latency
pub fn bench_match_mpc_with_delay(c: &mut Criterion, delay: Duration) {
    let mut group = c.benchmark_group("match-mpc");
    group.bench_function(BenchmarkId::new("match", delay.as_millis()), |b| {
        // Build a Tokio runtime and spawn the benchmarks within it
        let runtime = RuntimeBuilder::new_multi_thread().enable_all().build().unwrap();
        let mut async_bencher = b.to_async(runtime);

        async_bencher.iter_custom(|n_iters| async move {
            let mut total_time = Duration::from_secs(0);
            for _ in 0..n_iters {
                let (party0_time, party1_time) = execute_mock_mpc_with_delay(
                    |fabric| async move {
                        // Allocate the inputs in the fabric
                        let start = Instant::now();
                        let o1 = Order::default().allocate(PARTY0, &fabric);
                        let amount1 = Scalar::one().allocate(PARTY0, &fabric);
                        let amount2 = Scalar::one().allocate(PARTY1, &fabric);
                        let price = FixedPoint::from_integer(1).allocate(PARTY0, &fabric);

                        // Run the MPC
                        let match_res = compute_match(&o1, &amount1, &amount2, &price, &fabric);

                        // Open the result
                        let _open = match_res.open_and_authenticate().await;
                        start.elapsed()
                    },
                    delay,
                )
                .await;

                total_time += Duration::max(party0_time, party1_time);
            }

            total_time
        });
    });
}

/// Benchmark the constraint generation latency of the raw `match` MPC circuits
/// with a given connection latency
pub fn bench_apply_constraints_with_delay(c: &mut Criterion, delay: Duration) {
    let mut group = c.benchmark_group("match-mpc");

    group.bench_function(BenchmarkId::new("constraint-generation", delay.as_millis()), |b| {
        let runtime = RuntimeBuilder::new_multi_thread().enable_all().build().unwrap();
        let mut async_bencher = b.to_async(runtime);

        async_bencher.iter_custom(|n_iters| async move {
            let mut total_time = Duration::from_secs(0);
            for _ in 0..n_iters {
                // Execute an MPC to generate the constraints
                let (party0_time, party1_time) = execute_mock_mpc_with_delay(
                    |fabric| async move {
                        // Build a witness and statement
                        let (witness, statement) = dummy_witness_statement();
                        let witness = witness.allocate(PARTY0, &fabric);
                        let statement = statement.allocate(PARTY0, &fabric);

                        // Create a constraint system to allocate the constraints within
                        let mut cs = MpcPlonkCircuit::new(fabric.clone());

                        // Start the measurement after the setup code
                        let start = Instant::now();

                        // Allocate the inputs in the constraint system
                        let witness_var = witness.create_shared_witness(&mut cs);
                        let statement_var = statement.create_shared_public_var(&mut cs);

                        ValidMatchSettle::apply_constraints_multiprover(
                            witness_var,
                            statement_var,
                            &fabric,
                            &mut cs,
                        )
                        .unwrap();

                        // There is no great way to await the constraint generation, so we check
                        // that the constraints are satisfied. This
                        // is not an exact way to measure execution time, but it is a decent
                        // approximation. The benchmarks below
                        // measure time taken to generate constraints and prove, so they more
                        // directly estimate constraint generation
                        // latency, but as part of a larger circuit
                        let statement_vals = statement.to_authenticated_scalars();
                        let _satisfied = cs.check_circuit_satisfiability(&statement_vals);
                        start.elapsed()
                    },
                    delay,
                )
                .await;

                total_time += Duration::max(party0_time, party1_time);
            }

            total_time
        });
    });
}

/// Benchmarks the time it takes to prove a `VALID MATCH MPC` statement with a
/// given connection latency
pub fn bench_prover_latency_with_delay(c: &mut Criterion, delay: Duration) {
    let mut group = c.benchmark_group("match-mpc");

    group.bench_function(BenchmarkId::new("prover", delay.as_millis()), |b| {
        let runtime = RuntimeBuilder::new_multi_thread().enable_all().build().unwrap();
        let mut async_bencher = b.to_async(runtime);

        async_bencher.iter_custom(|n_iters| async move {
            let mut total_time = Duration::from_secs(0);
            for _ in 0..n_iters {
                // Execute an MPC to generate the constraints
                let (party0_time, party1_time) = execute_mock_mpc_with_delay(
                    |fabric| async move {
                        // Build a witness and statement
                        let (witness, statement) = dummy_witness_statement();
                        let witness = witness.allocate(PARTY0, &fabric);
                        let statement = statement.allocate(PARTY0, &fabric);

                        // Start the measurement after the setup code
                        let start = Instant::now();

                        // Allocate the inputs in the constraint system
                        let proof = multiprover_prove::<
                            ValidMatchSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
                        >(
                            witness.clone(), statement.clone(), fabric
                        )
                        .unwrap();

                        let _opened_proof = black_box(proof.open_authenticated().await);
                        start.elapsed()
                    },
                    delay,
                )
                .await;

                total_time += Duration::max(party0_time, party1_time);
            }

            total_time
        });
    });
}

// --------------
// | Benchmarks |
// --------------

/// Benchmark the time taken to run the raw `match` MPC circuits with a small
/// delay
#[allow(non_snake_case)]
pub fn bench_match_mpc__small_delay(c: &mut Criterion) {
    bench_match_mpc_with_delay(c, Duration::from_millis(SMALL_DELAY_MS));
}

/// Benchmark the time taken to run the raw `match` MPC circuits with a medium
/// delay
#[allow(non_snake_case)]
pub fn bench_match_mpc__medium_delay(c: &mut Criterion) {
    bench_match_mpc_with_delay(c, Duration::from_millis(MEDIUM_DELAY_MS));
}

/// Benchmark the time taken to run the raw `match` MPC circuits with a large
/// delay
#[allow(non_snake_case)]
pub fn bench_match_mpc__large_delay(c: &mut Criterion) {
    bench_match_mpc_with_delay(c, Duration::from_millis(LARGE_DELAY_MS));
}

/// Benchmark the constraint generation latency of the raw `match` MPC circuits
/// with a small delay
#[allow(non_snake_case)]
pub fn bench_apply_constraints__small_delay(c: &mut Criterion) {
    bench_apply_constraints_with_delay(c, Duration::from_millis(SMALL_DELAY_MS));
}

/// Benchmark the constraint generation latency of the raw `match` MPC circuits
/// with a medium delay
#[allow(non_snake_case)]
pub fn bench_apply_constraints__medium_delay(c: &mut Criterion) {
    bench_apply_constraints_with_delay(c, Duration::from_millis(MEDIUM_DELAY_MS));
}

/// Benchmark the constraint generation latency of the raw `match` MPC circuits
/// with a large delay
#[allow(non_snake_case)]
pub fn bench_apply_constraints__large_delay(c: &mut Criterion) {
    bench_apply_constraints_with_delay(c, Duration::from_millis(LARGE_DELAY_MS));
}

/// Benchmark the time it takes to prove a `VALID MATCH MPC` statement with a
/// small delay
#[allow(non_snake_case)]
pub fn bench_prover_latency__small_delay(c: &mut Criterion) {
    bench_prover_latency_with_delay(c, Duration::from_millis(SMALL_DELAY_MS));
}

/// Benchmark the time it takes to prove a `VALID MATCH MPC` statement with a
/// medium delay
#[allow(non_snake_case)]
pub fn bench_prover_latency__medium_delay(c: &mut Criterion) {
    bench_prover_latency_with_delay(c, Duration::from_millis(MEDIUM_DELAY_MS));
}

/// Benchmark the time it takes to prove a `VALID MATCH MPC` statement with a
/// large delay
#[allow(non_snake_case)]
pub fn bench_prover_latency__large_delay(c: &mut Criterion) {
    bench_prover_latency_with_delay(c, Duration::from_millis(LARGE_DELAY_MS));
}

/// Benchmarks the verification latency of a `VALID MATCH MPC` statement
pub fn bench_verifier_latency(c: &mut Criterion) {
    // Create a dummy proof to verify in the benchmark loop
    let (witness, statement) = dummy_witness_statement();
    let proof = singleprover_prove::<SizedValidMatchSettle>(witness, statement.clone()).unwrap();

    let mut group = c.benchmark_group("match-mpc");
    group.bench_function(BenchmarkId::new("verifier", ""), |b| {
        b.iter(|| {
            assert!(verify_singleprover_proof::<
                ValidMatchSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
            >(statement.clone(), &proof)
            .is_err());
        })
    });
}

// -------------------
// | Criterion Setup |
// -------------------

#[cfg(feature = "large_benchmarks")]
criterion_group! {
    name = match_mpc;
    config = Criterion::default().sample_size(10);
    targets =
        bench_match_mpc__small_delay,
        bench_match_mpc__medium_delay,
        bench_match_mpc__large_delay,
        bench_apply_constraints__small_delay,
        bench_apply_constraints__medium_delay,
        bench_apply_constraints__large_delay,
        bench_prover_latency__small_delay,
        bench_prover_latency__medium_delay,
        bench_prover_latency__large_delay,
        bench_verifier_latency,
}

#[cfg(not(feature = "large_benchmarks"))]
criterion_group! {
    name = match_mpc;
    config = Criterion::default().sample_size(10);
    targets =
        bench_match_mpc__small_delay,
        bench_apply_constraints__small_delay,
        bench_prover_latency__small_delay,
        bench_verifier_latency,
}

criterion_main!(match_mpc);
