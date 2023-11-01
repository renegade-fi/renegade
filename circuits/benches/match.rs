//! Groups integration tests for matching an order and proving `VALID MATCH MPC`
//! collaboratively
//!
//! TODO: Benchmark with various simulated latencies

#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use std::time::{Duration, Instant};

use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::Order,
    r#match::LinkableMatchResult,
    traits::{
        LinkableBaseType, MpcBaseType, MpcType, MultiProverCircuit, MultiproverCircuitBaseType,
    },
};
use circuits::{
    mpc_circuits::r#match::compute_match,
    multiprover_prove, singleprover_prove, verify_singleprover_proof,
    zk_circuits::valid_match_mpc::{
        test_helpers::create_dummy_witness, ValidMatchMpcCircuit, ValidMatchMpcSingleProver,
        ValidMatchMpcWitness,
    },
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use merlin::HashChainTranscript;
use mpc_bulletproof::{r1cs_mpc::MpcProver, PedersenGens};
use mpc_stark::{algebra::scalar::Scalar, PARTY0, PARTY1};
use rand::thread_rng;
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

/// Get a dummy, single-prover witness for `VALID MATCH MPC`
pub fn get_dummy_singleprover_witness() -> ValidMatchMpcWitness {
    // Generate a proof that will be used by the benchmarks to verify
    ValidMatchMpcWitness {
        order1: Order::default().to_linkable(),
        order2: Order::default().to_linkable(),
        balance1: Balance::default().to_linkable(),
        balance2: Balance::default().to_linkable(),
        amount1: Scalar::one(),
        amount2: Scalar::one(),
        price1: FixedPoint::from_integer(1),
        price2: FixedPoint::from_integer(1),
        match_res: LinkableMatchResult {
            quote_mint: Scalar::one().to_linkable(),
            base_mint: Scalar::one().to_linkable(),
            quote_amount: Scalar::one().to_linkable(),
            base_amount: Scalar::one().to_linkable(),
            direction: Scalar::one().to_linkable(),
            max_minus_min_amount: Scalar::one().to_linkable(),
            min_amount_order_index: Scalar::one().to_linkable(),
        },
    }
}

/// Benchmark the time taken to run the raw `match` MPC circuits with a given
/// connection latency
pub fn bench_match_mpc_with_delay(c: &mut Criterion, delay: Duration) {
    let mut group = c.benchmark_group("match-mpc");
    group.bench_function(BenchmarkId::new("match", delay.as_millis()), |b| {
        // Build a Tokio runtime and spawn the benchmarks within it
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut async_bencher = b.to_async(runtime);

        async_bencher.iter_custom(|n_iters| async move {
            let mut total_time = Duration::from_secs(0);
            for _ in 0..n_iters {
                let (party0_time, party1_time) = execute_mock_mpc_with_delay(
                    |fabric| async move {
                        // Allocate the inputs in the fabric
                        let start = Instant::now();
                        let o1 = Order::default().to_linkable().allocate(PARTY0, &fabric);
                        let o2 = Order::default().to_linkable().allocate(PARTY1, &fabric);
                        let amount1 = Scalar::one().allocate(PARTY0, &fabric);
                        let amount2 = Scalar::one().allocate(PARTY1, &fabric);
                        let price = FixedPoint::from_integer(1).allocate(PARTY0, &fabric);

                        // Run the MPC
                        let match_res =
                            compute_match(&o1, &o2, &amount1, &amount2, &price, &fabric);

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

    group.bench_function(
        BenchmarkId::new("constraint-generation", delay.as_millis()),
        |b| {
            let runtime = RuntimeBuilder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let mut async_bencher = b.to_async(runtime);

            async_bencher.iter_custom(|n_iters| async move {
                let mut total_time = Duration::from_secs(0);
                for _ in 0..n_iters {
                    // Execute an MPC to generate the constraints
                    let (party0_time, party1_time) = execute_mock_mpc_with_delay(
                        |fabric| async move {
                            // Create a witness to the proof
                            let witness = create_dummy_witness(&fabric);

                            // Create a constraint system to allocate the constraints within
                            let pc_gens = PedersenGens::default();
                            let transcript = HashChainTranscript::new(b"test");
                            let mut prover =
                                MpcProver::new_with_fabric(fabric.clone(), transcript, pc_gens);

                            // Start the measurement after the setup code
                            let start = Instant::now();

                            // Allocate the inputs in the constraint system
                            let (witness_var, _) = witness
                                .commit_shared(&mut thread_rng(), &mut prover)
                                .unwrap();
                            ValidMatchMpcCircuit::apply_constraints_multiprover(
                                witness_var,
                                (),
                                fabric,
                                &mut prover,
                            )
                            .unwrap();

                            // There is no great way to await the constraint generation, so we check
                            // that the constraints are satisfied. This
                            // is not an exact way to measure execution time, but it is a decent
                            // approximation. The benchmarks below
                            // measure time taken to generate constraints and prove, so they more
                            // directly estimate constraint generation
                            // latency, but as part of a larger circuit
                            let _satisfied = prover.constraints_satisfied().await;
                            start.elapsed()
                        },
                        delay,
                    )
                    .await;

                    total_time += Duration::max(party0_time, party1_time);
                }

                total_time
            });
        },
    );
}

/// Benchmarks the time it takes to prove a `VALID MATCH MPC` statement with a
/// given connection latency
pub fn bench_prover_latency_with_delay(c: &mut Criterion, delay: Duration) {
    let mut group = c.benchmark_group("match-mpc");

    group.bench_function(BenchmarkId::new("prover", delay.as_millis()), |b| {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut async_bencher = b.to_async(runtime);

        async_bencher.iter_custom(|n_iters| async move {
            let mut total_time = Duration::from_secs(0);
            for _ in 0..n_iters {
                // Execute an MPC to generate the constraints
                let (party0_time, party1_time) = execute_mock_mpc_with_delay(
                    |fabric| async move {
                        // Create a witness to the proof
                        let witness = create_dummy_witness(&fabric);

                        // Start the measurement after the setup code
                        let start = Instant::now();

                        // Allocate the inputs in the constraint system
                        let (_comm, proof) = multiprover_prove::<ValidMatchMpcCircuit>(
                            witness.clone(),
                            (), // statement
                            fabric,
                        )
                        .unwrap();

                        let _opened_proof = black_box(proof.open().await);
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
    let dummy_witness = get_dummy_singleprover_witness();
    let (witness_comm, proof) =
        singleprover_prove::<ValidMatchMpcSingleProver>(dummy_witness, ()).unwrap();

    let mut group = c.benchmark_group("match-mpc");
    group.bench_function(BenchmarkId::new("verifier", ""), |b| {
        b.iter(|| {
            assert!(verify_singleprover_proof::<ValidMatchMpcSingleProver>(
                (), // statement
                witness_comm.clone(),
                proof.clone()
            )
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
