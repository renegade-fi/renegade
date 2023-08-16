//! Benchmarks for the `VALID WALLET UPDATE` circuit

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use circuit_types::{
    order::Order,
    traits::{CircuitBaseType, SingleProverCircuit},
    transfers::ExternalTransfer,
    wallet::Wallet,
};
use circuits::{
    singleprover_prove, verify_singleprover_proof,
    zk_circuits::valid_wallet_update::{
        test_helpers::construct_witness_statement, ValidWalletUpdate, ValidWalletUpdateStatement,
        ValidWalletUpdateWitness,
    },
};
use constants::{MAX_BALANCES, MAX_FEES, MAX_ORDERS, MERKLE_HEIGHT};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use merlin::HashChainTranscript;
use mpc_bulletproof::{r1cs::Prover, PedersenGens};
use rand::thread_rng;

/// The parameter set for the small sized circuit (MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT)
const SMALL_PARAM_SET: (usize, usize, usize, usize) = (2, 2, 1, 5);
/// The parameter set for the large sized circuit
const LARGE_PARAM_SET: (usize, usize, usize, usize) =
    (MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT);

// -----------
// | Helpers |
// -----------

/// Construct a dummy witness and statement for the circuit
pub fn create_witness_statement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
    const MERKLE_HEIGHT: usize,
>() -> (
    ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>,
    ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
)
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // Take a default wallet and cancel an order
    let original_wallet = Wallet::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>::default();
    let mut modified_wallet = original_wallet.clone();
    modified_wallet.orders[0] = Order::default();

    construct_witness_statement(
        original_wallet,
        modified_wallet,
        ExternalTransfer::default(),
    )
}

/// Benchmark constraint generation for the circuit
pub fn bench_apply_constraints_with_sizes<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
    const MERKLE_HEIGHT: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    let mut group = c.benchmark_group("valid_wallet_update");
    let benchmark_id = BenchmarkId::new(
        "constraint-generation",
        format!(
            "({}, {}, {}, {})",
            MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT
        ),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement, then allocate them in the proof system
        let mut rng = thread_rng();
        let mut transcript = HashChainTranscript::new(b"test");
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let (witness, statement) =
            create_witness_statement::<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>();
        let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover);
        let statement_var = statement.commit_public(&mut prover);

        b.iter(|| {
            ValidWalletUpdate::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut prover,
            )
            .unwrap();
        });
    });
}

/// Benchmark proving time for the circuit
pub fn bench_prover_with_sizes<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
    const MERKLE_HEIGHT: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    let mut group = c.benchmark_group("valid_wallet_update");
    let benchmark_id = BenchmarkId::new(
        "prover",
        format!(
            "({}, {}, {}, {})",
            MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT
        ),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement to prove on ahead of time
        let (witness, statement) =
            create_witness_statement::<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>();

        b.iter(|| {
            singleprover_prove::<
                ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>,
            >(witness.clone(), statement.clone())
            .unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID WALLET UPDATE`
pub fn bench_verifier<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
    const MERKLE_HEIGHT: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    let mut group = c.benchmark_group("valid_wallet_update");
    let benchmark_id = BenchmarkId::new(
        "verifier",
        format!(
            "({}, {}, {}, {})",
            MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT
        ),
    );

    group.bench_function(benchmark_id, |b| {
        // First generate a proof that will be verified multiple times
        let (witness, statement) =
            create_witness_statement::<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>();

        let (commitments, proof) = singleprover_prove::<
            ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>,
        >(witness, statement.clone())
        .unwrap();

        b.iter(|| {
            verify_singleprover_proof::<
                ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>,
            >(statement.clone(), commitments.clone(), proof.clone())
            .unwrap();
        });
    });
}

// --------------
// | Benchmarks |
// --------------

/// Benchmark constraint generation for the small circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__small_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<
        { SMALL_PARAM_SET.0 },
        { SMALL_PARAM_SET.1 },
        { SMALL_PARAM_SET.2 },
        { SMALL_PARAM_SET.3 },
    >(c);
}

/// Benchmark prover latency for the small circuit
#[allow(non_snake_case)]
pub fn bench_prover__small_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<
        { SMALL_PARAM_SET.0 },
        { SMALL_PARAM_SET.1 },
        { SMALL_PARAM_SET.2 },
        { SMALL_PARAM_SET.3 },
    >(c);
}

/// Benchmark verifier latency for the small circuit
#[allow(non_snake_case)]
pub fn bench_verifier__small_circuit(c: &mut Criterion) {
    bench_verifier::<
        { SMALL_PARAM_SET.0 },
        { SMALL_PARAM_SET.1 },
        { SMALL_PARAM_SET.2 },
        { SMALL_PARAM_SET.3 },
    >(c);
}

/// Benchmark constraint generation for the large circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__large_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<
        { LARGE_PARAM_SET.0 },
        { LARGE_PARAM_SET.1 },
        { LARGE_PARAM_SET.2 },
        { LARGE_PARAM_SET.3 },
    >(c);
}

/// Benchmark prover latency for the large circuit
#[allow(non_snake_case)]
pub fn bench_prover__large_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<
        { LARGE_PARAM_SET.0 },
        { LARGE_PARAM_SET.1 },
        { LARGE_PARAM_SET.2 },
        { LARGE_PARAM_SET.3 },
    >(c);
}

/// Benchmark verifier latency for the large circuit
#[allow(non_snake_case)]
pub fn bench_verifier__large_circuit(c: &mut Criterion) {
    bench_verifier::<
        { LARGE_PARAM_SET.0 },
        { LARGE_PARAM_SET.1 },
        { LARGE_PARAM_SET.2 },
        { LARGE_PARAM_SET.3 },
    >(c);
}

// -------------------
// | Criterion Setup |
// -------------------

#[cfg(feature = "large_benchmarks")]
criterion_group!(
    name = valid_wallet_update;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints__small_circuit,
        bench_prover__small_circuit,
        bench_verifier__small_circuit,
        bench_apply_constraints__large_circuit,
        bench_prover__large_circuit,
        bench_verifier__large_circuit
);

#[cfg(not(feature = "large_benchmarks"))]
criterion_group!(
    name = valid_wallet_update;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints__small_circuit,
        bench_prover__small_circuit,
        bench_verifier__small_circuit,
);

criterion_main!(valid_wallet_update);
