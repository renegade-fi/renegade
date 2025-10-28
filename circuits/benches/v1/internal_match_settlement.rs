//! Benchmarks internal match settlement
#![allow(incomplete_features)]
#![allow(missing_docs)]

use circuit_types::PlonkCircuit;
use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuits::zk_circuits::valid_match_settle::test_helpers::dummy_witness_and_statement;
use circuits::zk_circuits::valid_match_settle::{
    SizedValidMatchSettle, SizedValidMatchSettleStatement, SizedValidMatchSettleWitness,
    ValidMatchSettle,
};
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::{MAX_BALANCES, MAX_ORDERS};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use mpc_relation::proof_linking::LinkableCircuit;

// -----------
// | Helpers |
// -----------

/// Adds sizing parameters to the `dummy_witness_and_statement` helper
pub fn create_sized_witness_statement()
-> (SizedValidMatchSettleWitness, SizedValidMatchSettleStatement) {
    dummy_witness_and_statement()
}

/// Tests the time taken to apply the constraints of `VALID MATCH SETTLE`
/// circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_match_settle");
    let benchmark_id =
        BenchmarkId::new("constraint-generation", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) = create_sized_witness_statement();
        let mut cs = PlonkCircuit::new_turbo_plonk();

        // Add proof linking groups to the circuit
        let layout = SizedValidMatchSettle::get_circuit_layout().unwrap();
        for (id, layout) in layout.group_layouts.into_iter() {
            cs.create_link_group(id, Some(layout));
        }

        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);
        b.iter(|| {
            ValidMatchSettle::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut cs,
            )
            .unwrap();
        });
    });
}

/// Tests the time taken to prove `VALID MATCH SETTLE`
pub fn bench_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_match_settle");
    let benchmark_id = BenchmarkId::new("prover", format!("({MAX_BALANCES}, {MAX_ORDERS})"));
    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) = create_sized_witness_statement();
        b.iter(|| {
            singleprover_prove::<SizedValidMatchSettle>(witness.clone(), statement.clone())
                .unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID MATCH SETTLE`
pub fn bench_verifier(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_match_settle");
    let benchmark_id = BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // First generate a proof that will be verified multiple times
        let (witness, statement) = create_sized_witness_statement();
        let proof =
            singleprover_prove::<SizedValidMatchSettle>(witness, statement.clone()).unwrap();
        b.iter(|| {
            verify_singleprover_proof::<SizedValidMatchSettle>(statement.clone(), &proof).unwrap();
        });
    });
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group! {
    name = internal_match_settle;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints,
        bench_prover,
        bench_verifier,
}
criterion_main!(internal_match_settle);
