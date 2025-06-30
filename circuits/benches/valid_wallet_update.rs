//! Benchmarks for the `VALID WALLET UPDATE` circuit

#![allow(incomplete_features)]
#![allow(missing_docs)]
#![feature(generic_const_exprs)]

use circuit_types::{
    PlonkCircuit,
    order::Order,
    traits::{CircuitBaseType, SingleProverCircuit},
    transfers::ExternalTransfer,
    wallet::Wallet,
};
use circuits::{
    singleprover_prove, verify_singleprover_proof,
    zk_circuits::valid_wallet_update::{
        SizedValidWalletUpdate, SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
        ValidWalletUpdate, test_helpers::construct_witness_statement,
    },
};
use constants::{MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

// -----------
// | Helpers |
// -----------

/// Construct a dummy witness and statement for the circuit
pub fn create_witness_statement() -> (SizedValidWalletUpdateWitness, SizedValidWalletUpdateStatement)
{
    // Take a default wallet and cancel an order
    let original_wallet = Wallet::<MAX_BALANCES, MAX_ORDERS>::default();
    let mut modified_wallet = original_wallet.clone();
    modified_wallet.orders[0] = Order::default();

    construct_witness_statement(
        &original_wallet,
        &modified_wallet,
        0, // transfer_idx
        ExternalTransfer::default(),
    )
}

/// Benchmark constraint generation for the circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_wallet_update");
    let benchmark_id = BenchmarkId::new(
        "constraint-generation",
        format!("({}, {}, {})", MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement, then allocate them in the proof system
        let mut cs = PlonkCircuit::new_turbo_plonk();

        let (witness, statement) = create_witness_statement();
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
pub fn bench_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_wallet_update");
    let benchmark_id = BenchmarkId::new(
        "prover",
        format!("({}, {}, {})", MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement to prove on ahead of time
        let (witness, statement) = create_witness_statement();
        b.iter(|| {
            singleprover_prove::<SizedValidWalletUpdate>(witness.clone(), statement.clone())
                .unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID WALLET UPDATE`
pub fn bench_verifier(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_wallet_update");
    let benchmark_id = BenchmarkId::new(
        "verifier",
        format!("({}, {}, {})", MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT),
    );

    group.bench_function(benchmark_id, |b| {
        // First generate a proof that will be verified multiple times
        let (witness, statement) = create_witness_statement();
        let proof =
            singleprover_prove::<SizedValidWalletUpdate>(witness, statement.clone()).unwrap();

        b.iter(|| {
            verify_singleprover_proof::<
                ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
            >(statement.clone(), &proof)
            .unwrap();
        });
    });
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group!(
    name = valid_wallet_update;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints,
        bench_prover,
        bench_verifier
);
criterion_main!(valid_wallet_update);
