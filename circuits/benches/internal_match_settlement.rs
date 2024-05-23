//! Benchmarks internal match settlement
#![allow(incomplete_features)]
#![allow(missing_docs)]
#![feature(generic_const_exprs)]

use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuit_types::PlonkCircuit;
use circuits::zk_circuits::valid_match_settle::test_helpers::dummy_witness_and_statement;
use circuits::zk_circuits::valid_match_settle::ValidMatchSettle;
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::{MAX_BALANCES, MAX_ORDERS};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mpc_relation::proof_linking::LinkableCircuit;

/// The parameter set for the small sized circuit (MAX_BALANCES, MAX_ORDERS,
/// MERKLE_HEIGHT)
const SMALL_PARAM_SET: (usize, usize) = (2, 2);
/// The parameter set for the large sized circuit
const LARGE_PARAM_SET: (usize, usize) = (MAX_BALANCES, MAX_ORDERS);

// -----------
// | Helpers |
// -----------

/// Tests the time taken to apply the constraints of `VALID MATCH SETTLE`
/// circuit
pub fn bench_apply_constraints_with_sizes<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_match_settle");
    let benchmark_id =
        BenchmarkId::new("constraint-generation", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) = dummy_witness_and_statement::<MAX_BALANCES, MAX_ORDERS>();
        let mut cs = PlonkCircuit::new_turbo_plonk();

        // Add proof linking groups to the circuit
        let layout = ValidMatchSettle::<MAX_BALANCES, MAX_ORDERS>::get_circuit_layout().unwrap();
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
pub fn bench_prover_with_sizes<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_match_settle");
    let benchmark_id = BenchmarkId::new("prover", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) = dummy_witness_and_statement::<MAX_BALANCES, MAX_ORDERS>();

        b.iter(|| {
            singleprover_prove::<ValidMatchSettle<MAX_BALANCES, MAX_ORDERS>>(
                witness.clone(),
                statement.clone(),
            )
            .unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID MATCH SETTLE`
pub fn bench_verifier_with_sizes<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_match_settle");
    let benchmark_id = BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // First generate a proof that will be verified multiple times
        let (witness, statement) = dummy_witness_and_statement::<MAX_BALANCES, MAX_ORDERS>();

        let proof = singleprover_prove::<ValidMatchSettle<MAX_BALANCES, MAX_ORDERS>>(
            witness,
            statement.clone(),
        )
        .unwrap();

        b.iter(|| {
            verify_singleprover_proof::<ValidMatchSettle<MAX_BALANCES, MAX_ORDERS>>(
                statement.clone(),
                &proof,
            )
            .unwrap();
        });
    });
}

// --------------
// | Benchmarks |
// --------------

/// Tests the time taken to apply the constraints of a small `VALID MATCH
/// SETTLE` circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__small_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }>(c);
}

/// Tests the time taken to prove a small `VALID MATCH SETTLE` circuit
#[allow(non_snake_case)]
pub fn bench_prover__small_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }>(c);
}

/// Tests the time taken verify a small `VALID MATCH SETTLE` circuit
#[allow(non_snake_case)]
pub fn bench_verifier__small_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }>(c);
}

/// Tests the time taken to apply the constraints of a large `VALID MATCH
/// SETTLE` circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__large_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }>(c);
}

/// Tests the time taken to prove a large `VALID MATCH SETTLE` circuit
#[allow(non_snake_case)]
pub fn bench_prover__large_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }>(c);
}

/// Tests the time taken verify a large `VALID MATCH SETTLE` circuit
#[allow(non_snake_case)]
pub fn bench_verifier__large_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }>(c);
}

// -------------------
// | Criterion Setup |
// -------------------

#[cfg(feature = "large_benchmarks")]
criterion_group! {
    name = internal_match_settle;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints__small_circuit,
        bench_prover__small_circuit,
        bench_verifier__small_circuit,
        bench_apply_constraints__large_circuit,
        bench_prover__large_circuit,
        bench_verifier__large_circuit,
}

#[cfg(not(feature = "large_benchmarks"))]
criterion_group! {
    name = internal_match_settle;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints__small_circuit,
        bench_prover__small_circuit,
        bench_verifier__small_circuit,
}

criterion_main!(internal_match_settle);
