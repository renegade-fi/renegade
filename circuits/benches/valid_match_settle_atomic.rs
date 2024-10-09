//! Benchmarks for the `VALID MATCH SETTLE ATOMIC` circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]
#![feature(generic_const_exprs)]

use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuit_types::PlonkCircuit;
use circuits::zk_circuits::valid_match_settle_atomic::ValidMatchSettleAtomic;
use circuits::zk_circuits::valid_match_settle_atomic::{
    test_helpers::create_witness_statement, ValidMatchSettleAtomicStatement,
    ValidMatchSettleAtomicWitness,
};
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::{MAX_BALANCES, MAX_ORDERS};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

/// The small parameter set for the `VALID MATCH SETTLE ATOMIC` circuit
const SMALL_PARAM_SET: (usize, usize) = (2, 2);
/// The large parameter set for the `VALID MATCH SETTLE ATOMIC` circuit
const LARGE_PARAM_SET: (usize, usize) = (MAX_BALANCES, MAX_ORDERS);

/// Create a sized witness and statement for the `VALID MATCH SETTLE ATOMIC`
pub fn create_sized_witness_statement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>() -> (
    ValidMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>,
    ValidMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>,
)
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    create_witness_statement::<MAX_BALANCES, MAX_ORDERS>()
}

/// Benchmarks constraint generation for the `VALID MATCH SETTLE ATOMIC` circuit
pub fn bench_apply_constraints_with_sizes<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_match_settle_atomic");
    let benchmark_id =
        BenchmarkId::new("constraint-generation", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let (witness, statement) = create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS>();
        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);

        b.iter(|| {
            ValidMatchSettleAtomic::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut cs,
            )
            .unwrap();
        });
    });
}

/// Benchmarks the prover for the `VALID MATCH SETTLE ATOMIC` circuit
pub fn bench_prover_with_sizes<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_match_settle_atomic");
    let benchmark_id = BenchmarkId::new("prover", format!("({MAX_BALANCES}, {MAX_ORDERS})"));
    group.bench_function(benchmark_id, |b| {
        let (witness, statement) = create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS>();

        b.iter(|| {
            singleprover_prove::<ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>>(
                witness.clone(),
                statement.clone(),
            )
            .unwrap();
        });
    });
}

/// Benchmarks the verifier for the `VALID MATCH SETTLE ATOMIC` circuit
pub fn bench_verifier_with_sizes<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // Create a proof
    let (witness, statement) = create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS>();
    let proof = singleprover_prove::<ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>>(
        witness,
        statement.clone(),
    )
    .unwrap();

    let mut group = c.benchmark_group("valid_match_settle_atomic");
    let benchmark_id = BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS})"));
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            verify_singleprover_proof::<ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>>(
                statement.clone(),
                &proof,
            )
            .unwrap();
        });
    });
}

#[allow(non_snake_case)]
pub fn bench_apply_constraints__small_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }>(c)
}

#[allow(non_snake_case)]
pub fn bench_prover__small_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }>(c)
}

#[allow(non_snake_case)]
pub fn bench_verifier__small_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }>(c)
}

#[allow(non_snake_case)]
pub fn bench_apply_constraints__large_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }>(c)
}

#[allow(non_snake_case)]
pub fn bench_prover__large_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }>(c)
}

#[allow(non_snake_case)]
pub fn bench_verifier__large_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }>(c)
}

#[cfg(feature = "large_benchmarks")]
criterion_group!(
    name = valid_match_settle_atomic;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints__small_circuit,
        bench_prover__small_circuit,
        bench_verifier__small_circuit,
        bench_apply_constraints__large_circuit,
        bench_prover__large_circuit,
        bench_verifier__large_circuit,
);

#[cfg(not(feature = "large_benchmarks"))]
criterion_group!(
    name = valid_match_settle_atomic;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints__small_circuit,
        bench_prover__small_circuit,
        bench_verifier__small_circuit,
);

criterion_main!(valid_match_settle_atomic);
