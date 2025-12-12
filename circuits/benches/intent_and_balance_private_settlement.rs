//! Tests the process of proving and verifying an `INTENT AND BALANCE PRIVATE
//! SETTLEMENT` circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]

use circuit_types::PlonkCircuit;
use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuits::zk_circuits::settlement::intent_and_balance_private_settlement::IntentAndBalancePrivateSettlementCircuit;
use circuits::zk_circuits::settlement::intent_and_balance_private_settlement::test_helpers::create_witness_statement;
use circuits::{singleprover_prove, verify_singleprover_proof};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use mpc_relation::proof_linking::LinkableCircuit;

/// Benchmark applying constraints to a circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    // Build a witness and statement
    let (witness, statement) = create_witness_statement();

    // Allocate in the constraint system
    let mut cs = PlonkCircuit::new_turbo_plonk();

    // Create link groups before allocating variables (currently empty, but handle
    // for future)
    let layout = IntentAndBalancePrivateSettlementCircuit::get_circuit_layout().unwrap();
    for (id, group_layout) in layout.group_layouts.into_iter() {
        cs.create_link_group(id, Some(group_layout));
    }

    let witness_var = witness.create_witness(&mut cs);
    let statement_var = statement.create_public_var(&mut cs);

    // Run the benchmark
    let mut group = c.benchmark_group("intent_and_balance_private_settlement");
    let benchmark_id = BenchmarkId::new("constraint-generation", "");

    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            IntentAndBalancePrivateSettlementCircuit::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut cs,
            )
            .unwrap();
        });
    });
}

/// Benchmark proving a circuit
pub fn bench_prover(c: &mut Criterion) {
    // Build a witness and statement
    let (witness, statement) = create_witness_statement();
    let mut group = c.benchmark_group("intent_and_balance_private_settlement");
    let benchmark_id = BenchmarkId::new("prover", "");
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            singleprover_prove::<IntentAndBalancePrivateSettlementCircuit>(&witness, &statement)
                .unwrap();
        });
    });
}

/// Benchmark verifying a circuit
pub fn bench_verifier(c: &mut Criterion) {
    // First generate a proof that will be verified multiple times
    let (witness, statement) = create_witness_statement();
    let proof =
        singleprover_prove::<IntentAndBalancePrivateSettlementCircuit>(&witness, &statement)
            .unwrap();

    // Run the benchmark
    let mut group = c.benchmark_group("intent_and_balance_private_settlement");
    let benchmark_id = BenchmarkId::new("verifier", "");
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            verify_singleprover_proof::<IntentAndBalancePrivateSettlementCircuit>(
                &statement, &proof,
            )
            .unwrap();
        });
    });
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group! {
    name = intent_and_balance_private_settlement;
    config = Criterion::default().sample_size(10);
    targets = bench_apply_constraints, bench_prover, bench_verifier
}
criterion_main!(intent_and_balance_private_settlement);
