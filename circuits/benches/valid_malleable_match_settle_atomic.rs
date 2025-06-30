//! Benchmark the `VALID MALLEABLE MATCH SETTLE ATOMIC` circuit

#![allow(incomplete_features)]
#![allow(missing_docs)]
#![feature(generic_const_exprs)]

use circuit_types::PlonkCircuit;
use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuits::zk_circuits::valid_malleable_match_settle_atomic::test_helpers::create_witness_statement as create_witness_statement_helper;
use circuits::zk_circuits::valid_malleable_match_settle_atomic::{
    SizedValidMalleableMatchSettleAtomic, SizedValidMalleableMatchSettleAtomicStatement,
    SizedValidMalleableMatchSettleAtomicWitness, ValidMalleableMatchSettleAtomic,
};
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::{MAX_BALANCES, MAX_ORDERS};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use mpc_relation::proof_linking::LinkableCircuit;

/// Create a sized witness and statement for the `VALID MATCH SETTLE ATOMIC`
pub fn create_sized_witness_statement()
-> (SizedValidMalleableMatchSettleAtomicWitness, SizedValidMalleableMatchSettleAtomicStatement)
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    create_witness_statement_helper()
}

/// Benchmarks constraint generation for the `VALID MATCH SETTLE ATOMIC` circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_malleable_match_settle_atomic");
    let benchmark_id =
        BenchmarkId::new("constraint-generation", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let (witness, statement) = create_sized_witness_statement();
        // Add proof linking groups to the circuit
        let layout = SizedValidMalleableMatchSettleAtomic::get_circuit_layout().unwrap();
        for (id, layout) in layout.group_layouts.into_iter() {
            cs.create_link_group(id, Some(layout));
        }

        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);
        b.iter(|| {
            ValidMalleableMatchSettleAtomic::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut cs,
            )
            .unwrap();
        });
    });
}

/// Benchmarks the prover for the `VALID MATCH SETTLE ATOMIC` circuit
pub fn bench_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_malleable_match_settle_atomic");
    let benchmark_id = BenchmarkId::new("prover", format!("({MAX_BALANCES}, {MAX_ORDERS})"));
    group.bench_function(benchmark_id, |b| {
        let (witness, statement) = create_sized_witness_statement();

        b.iter(|| {
            singleprover_prove::<SizedValidMalleableMatchSettleAtomic>(
                witness.clone(),
                statement.clone(),
            )
            .unwrap();
        });
    });
}

/// Benchmarks the verifier for the `VALID MATCH SETTLE ATOMIC` circuit
pub fn bench_verifier(c: &mut Criterion) {
    // Create a proof
    let (witness, statement) = create_sized_witness_statement();
    let proof =
        singleprover_prove::<SizedValidMalleableMatchSettleAtomic>(witness, statement.clone())
            .unwrap();

    let mut group = c.benchmark_group("valid_malleable_match_settle_atomic");
    let benchmark_id = BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS})"));
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            verify_singleprover_proof::<SizedValidMalleableMatchSettleAtomic>(
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

criterion_group!(
    name = valid_malleable_match_settle_atomic;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints,
        bench_prover,
        bench_verifier,
);
criterion_main!(valid_malleable_match_settle_atomic);
