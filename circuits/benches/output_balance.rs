//! Tests the process of proving and verifying an `OUTPUT BALANCE VALIDITY`
//! circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]

use circuit_types::PlonkCircuit;
use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuits::zk_circuits::validity_proofs::output_balance::SizedOutputBalanceValidityCircuit;
use circuits::zk_circuits::validity_proofs::output_balance::test_helpers::create_witness_statement;
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::MERKLE_HEIGHT;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use mpc_relation::proof_linking::LinkableCircuit;

/// Benchmark applying constraints to a circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    // Build a witness and statement
    let (witness, statement) = create_witness_statement::<MERKLE_HEIGHT>();

    // Allocate in the constraint system
    let mut cs = PlonkCircuit::new_turbo_plonk();

    // Create link groups before allocating variables
    let layout = SizedOutputBalanceValidityCircuit::get_circuit_layout().unwrap();
    for (id, group_layout) in layout.group_layouts.into_iter() {
        cs.create_link_group(id, Some(group_layout));
    }

    let witness_var = witness.create_witness(&mut cs);
    let statement_var = statement.create_public_var(&mut cs);

    // Run the benchmark
    let mut group = c.benchmark_group("output_balance_validity");
    let benchmark_id = BenchmarkId::new("constraint-generation", "");

    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            SizedOutputBalanceValidityCircuit::apply_constraints(
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
    let (witness, statement) = create_witness_statement::<MERKLE_HEIGHT>();
    let mut group = c.benchmark_group("output_balance_validity");
    let benchmark_id = BenchmarkId::new("prover", "");
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            singleprover_prove::<SizedOutputBalanceValidityCircuit>(
                witness.clone(),
                statement.clone(),
            )
            .unwrap();
        });
    });
}

/// Benchmark verifying a circuit
pub fn bench_verifier(c: &mut Criterion) {
    // First generate a proof that will be verified multiple times
    let (witness, statement) = create_witness_statement::<MERKLE_HEIGHT>();
    let proof = singleprover_prove::<SizedOutputBalanceValidityCircuit>(witness, statement.clone())
        .unwrap();

    // Run the benchmark
    let mut group = c.benchmark_group("output_balance_validity");
    let benchmark_id = BenchmarkId::new("verifier", "");
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            verify_singleprover_proof::<SizedOutputBalanceValidityCircuit>(
                statement.clone(),
                &proof,
            )
            .unwrap();
        });
    });
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group! {
    name = output_balance_validity;
    config = Criterion::default().sample_size(10);
    targets = bench_apply_constraints, bench_prover, bench_verifier
}
criterion_main!(output_balance_validity);
