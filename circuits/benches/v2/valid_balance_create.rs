//! Tests the process of proving and verifying a `VALID BALANCE CREATE` circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]

use circuit_types::PlonkCircuit;
use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuits::zk_circuits::v2::valid_balance_create::ValidBalanceCreate;
use circuits::zk_circuits::v2::valid_balance_create::test_helpers::create_witness_statement;
use circuits::{singleprover_prove, verify_singleprover_proof};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

/// Benchmark applying constraints to a circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    // Build a witness and statement
    let (witness, statement) = create_witness_statement();

    // Allocate in the constraint system
    let mut cs = PlonkCircuit::new_turbo_plonk();
    let witness_var = witness.create_witness(&mut cs);
    let statement_var = statement.create_public_var(&mut cs);

    // Run the benchmark
    let mut group = c.benchmark_group("valid_balance_create");
    let benchmark_id = BenchmarkId::new("constraint-generation", "");

    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            ValidBalanceCreate::apply_constraints(
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
    let mut group = c.benchmark_group("valid_balance_create");
    let benchmark_id = BenchmarkId::new("prover", "");
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            singleprover_prove::<ValidBalanceCreate>(witness.clone(), statement.clone()).unwrap();
        });
    });
}

/// Benchmark verifying a circuit
pub fn bench_verifier(c: &mut Criterion) {
    // First generate a proof that will be verified multiple times
    let (witness, statement) = create_witness_statement();
    let proof = singleprover_prove::<ValidBalanceCreate>(witness, statement.clone()).unwrap();

    // Run the benchmark
    let mut group = c.benchmark_group("valid_balance_create");
    let benchmark_id = BenchmarkId::new("verifier", "");
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            verify_singleprover_proof::<ValidBalanceCreate>(statement.clone(), &proof).unwrap();
        });
    });
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group! {
    name = valid_balance_create;
    config = Criterion::default().sample_size(10);
    targets = bench_apply_constraints, bench_prover, bench_verifier
}
criterion_main!(valid_balance_create);
