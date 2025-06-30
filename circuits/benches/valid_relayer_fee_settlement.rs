//! Tests the process of proving and verifying a `VALID RELAYER FEE SETTLEMENT`
//! circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]

use circuit_types::PlonkCircuit;
use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuits::test_helpers::wallet_with_random_balances;
use circuits::zk_circuits::valid_relayer_fee_settlement::test_helpers::create_witness_statement as create_witness_statement_helper;
use circuits::zk_circuits::valid_relayer_fee_settlement::{
    SizedValidRelayerFeeSettlement, SizedValidRelayerFeeSettlementStatement,
    SizedValidRelayerFeeSettlementWitness, ValidRelayerFeeSettlement,
};
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::{MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

// -----------
// | Helpers |
// -----------

/// Create a witness and statement for the `VALID RELAYER FEE SETTLEMENT`
/// circuit
pub fn create_witness_statement()
-> (SizedValidRelayerFeeSettlementStatement, SizedValidRelayerFeeSettlementWitness) {
    let sender_wallet = wallet_with_random_balances();
    let recipient_wallet = wallet_with_random_balances();
    create_witness_statement_helper(&sender_wallet, &recipient_wallet)
}

/// Benchmark constraint generation for the circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_relayer_fee_settlement");
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
            ValidRelayerFeeSettlement::apply_constraints(
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
    let mut group = c.benchmark_group("valid_relayer_fee_settlement");
    let benchmark_id =
        BenchmarkId::new("prover", format!("({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement to prove on ahead of time
        let (statement, witness) = create_witness_statement();
        b.iter(|| {
            singleprover_prove::<SizedValidRelayerFeeSettlement>(
                witness.clone(),
                statement.clone(),
            )
            .unwrap();
        });
    });
}

/// Benchmark verifying a circuit with variable sizing arguments
pub fn bench_verifier(c: &mut Criterion) {
    // First generate a proof that will be verified multiple times
    let (statement, witness) = create_witness_statement();
    let proof =
        singleprover_prove::<SizedValidRelayerFeeSettlement>(witness, statement.clone()).unwrap();

    // Run the benchmark
    let mut group = c.benchmark_group("valid_relayer_fee_settlement");
    let benchmark_id =
        BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"));
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            verify_singleprover_proof::<SizedValidRelayerFeeSettlement>(statement.clone(), &proof)
                .unwrap();
        });
    });
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group!(
    name = valid_relayer_fee_settlement;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints,
        bench_prover,
        bench_verifier,
);
criterion_main!(valid_relayer_fee_settlement);
