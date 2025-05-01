//! Tests the process of proving and verifying a `VALID OFFLINE FEE SETTLEMENT`
//! circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]
#![feature(generic_const_exprs)]

use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuit_types::PlonkCircuit;
use circuits::test_helpers::wallet_with_random_balances;
use circuits::zk_circuits::valid_offline_fee_settlement::test_helpers::create_witness_statement as create_witness_statement_helper;
use circuits::zk_circuits::valid_offline_fee_settlement::{
    SizedValidOfflineFeeSettlement, SizedValidOfflineFeeSettlementStatement,
    SizedValidOfflineFeeSettlementWitness, ValidOfflineFeeSettlement,
};
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::{MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

// -----------
// | Helpers |
// -----------

/// Create a sized witness and statement for the `VALID OFFLINE FEE SETTLEMENT`
/// circuit
pub fn create_witness_statement(
) -> (SizedValidOfflineFeeSettlementStatement, SizedValidOfflineFeeSettlementWitness) {
    let sender_wallet = wallet_with_random_balances();
    create_witness_statement_helper(&sender_wallet)
}

/// Benchmark constraint generation for the circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_offline_fee_settlement");
    let benchmark_id = BenchmarkId::new(
        "constraint-generation",
        format!("({}, {}, {})", MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement, then allocate them in the proof system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let (statement, witness) = create_witness_statement();
        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);

        b.iter(|| {
            ValidOfflineFeeSettlement::apply_constraints(
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
    let mut group = c.benchmark_group("valid_offline_fee_settlement");
    let benchmark_id = BenchmarkId::new(
        "prover",
        format!("({}, {}, {})", MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement to prove on ahead of time
        let (statement, witness) = create_witness_statement();
        b.iter(|| {
            singleprover_prove::<SizedValidOfflineFeeSettlement>(
                witness.clone(),
                statement.clone(),
            )
            .unwrap();
        });
    });
}

/// Benchmark verifying a circuit with variable sizing arguments
pub fn bench_verifier(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_offline_fee_settlement");
    let benchmark_id = BenchmarkId::new(
        "verifier",
        format!("({}, {}, {})", MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT),
    );

    group.bench_function(benchmark_id, |b| {
        // First generate a proof that will be verified multiple times
        let (statement, witness) = create_witness_statement();
        let proof =
            singleprover_prove::<SizedValidOfflineFeeSettlement>(witness, statement.clone())
                .unwrap();

        b.iter(|| {
            verify_singleprover_proof::<SizedValidOfflineFeeSettlement>(statement.clone(), &proof)
                .unwrap();
        });
    });
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group!(
    name = valid_offline_fee_settlement;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints,
        bench_prover,
        bench_verifier,
);
criterion_main!(valid_offline_fee_settlement);
