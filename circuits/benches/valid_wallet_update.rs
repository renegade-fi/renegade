//! Benchmarks for the `VALID WALLET UPDATE` circuit

#![allow(incomplete_features)]
#![allow(missing_docs)]
#![feature(generic_const_exprs)]

use circuit_types::{
    order::Order,
    traits::{CircuitBaseType, SingleProverCircuit},
    transfers::ExternalTransfer,
    wallet::Wallet,
    PlonkCircuit,
};
use circuits::{
    singleprover_prove, verify_singleprover_proof,
    zk_circuits::valid_wallet_update::{
        test_helpers::construct_witness_statement, ValidWalletUpdate, ValidWalletUpdateStatement,
        ValidWalletUpdateWitness,
    },
};
use constants::{MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

/// The parameter set for the small sized circuit (MAX_BALANCES, MAX_ORDERS,
/// MERKLE_HEIGHT)
const SMALL_PARAM_SET: (usize, usize, usize) = (2, 2, 5);
/// The parameter set for the large sized circuit
const LARGE_PARAM_SET: (usize, usize, usize) = (MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT);

// -----------
// | Helpers |
// -----------

/// Construct a dummy witness and statement for the circuit
pub fn create_witness_statement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>() -> (
    ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
    ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS>,
)
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // Take a default wallet and cancel an order
    let original_wallet = Wallet::<MAX_BALANCES, MAX_ORDERS>::default();
    let mut modified_wallet = original_wallet.clone();
    modified_wallet.orders[0] = Order::default();

    construct_witness_statement(&original_wallet, &modified_wallet, 0 /* transfer_idx */, ExternalTransfer::default())
}

/// Benchmark constraint generation for the circuit
pub fn bench_apply_constraints_with_sizes<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_wallet_update");
    let benchmark_id = BenchmarkId::new(
        "constraint-generation",
        format!("({}, {}, {})", MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement, then allocate them in the proof system
        let mut cs = PlonkCircuit::new_turbo_plonk();

        let (witness, statement) =
            create_witness_statement::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>();
        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);

        b.iter(|| {
            ValidWalletUpdate::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut cs,
            )
            .unwrap();
        });
    });
}

/// Benchmark proving time for the circuit
pub fn bench_prover_with_sizes<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_wallet_update");
    let benchmark_id = BenchmarkId::new(
        "prover",
        format!("({}, {}, {})", MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement to prove on ahead of time
        let (witness, statement) =
            create_witness_statement::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>();

        b.iter(|| {
            singleprover_prove::<ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>>(
                witness.clone(),
                statement.clone(),
            )
            .unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID WALLET UPDATE`
pub fn bench_verifier<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_wallet_update");
    let benchmark_id = BenchmarkId::new(
        "verifier",
        format!("({}, {}, {})", MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT),
    );

    group.bench_function(benchmark_id, |b| {
        // First generate a proof that will be verified multiple times
        let (witness, statement) =
            create_witness_statement::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>();

        let proof =
            singleprover_prove::<ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>>(
                witness,
                statement.clone(),
            )
            .unwrap();

        b.iter(|| {
            verify_singleprover_proof::<
                ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
            >(statement.clone(), &proof)
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
    >(c);
}

/// Benchmark prover latency for the small circuit
#[allow(non_snake_case)]
pub fn bench_prover__small_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }, { SMALL_PARAM_SET.2 }>(
        c,
    );
}

/// Benchmark verifier latency for the small circuit
#[allow(non_snake_case)]
pub fn bench_verifier__small_circuit(c: &mut Criterion) {
    bench_verifier::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }, { SMALL_PARAM_SET.2 }>(c);
}

/// Benchmark constraint generation for the large circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__large_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<
        { LARGE_PARAM_SET.0 },
        { LARGE_PARAM_SET.1 },
        { LARGE_PARAM_SET.2 },
    >(c);
}

/// Benchmark prover latency for the large circuit
#[allow(non_snake_case)]
pub fn bench_prover__large_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }, { LARGE_PARAM_SET.2 }>(
        c,
    );
}

/// Benchmark verifier latency for the large circuit
#[allow(non_snake_case)]
pub fn bench_verifier__large_circuit(c: &mut Criterion) {
    bench_verifier::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }, { LARGE_PARAM_SET.2 }>(c);
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
