//! Tests the process of proving and verifying a `VALID COMMITMENTS` circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]
#![feature(generic_const_exprs)]

use circuit_types::{
    traits::{CircuitBaseType, SingleProverCircuit},
    wallet::Wallet,
    PlonkCircuit,
};
use circuits::{
    singleprover_prove, verify_singleprover_proof,
    zk_circuits::{
        test_helpers::PUBLIC_KEYS,
        valid_commitments::{
            test_helpers::create_witness_and_statement, ValidCommitments,
            ValidCommitmentsStatement, ValidCommitmentsWitness,
        },
    },
};
use constants::{MAX_BALANCES, MAX_ORDERS};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

/// The parameter set for the small sized circuit (MAX_BALANCES, MAX_ORDERS)
const SMALL_PARAM_SET: (usize, usize) = (2, 2);
/// The parameter set for the large sized circuit
const LARGE_PARAM_SET: (usize, usize) = (MAX_BALANCES, MAX_ORDERS);

// -----------
// | Helpers |
// -----------

/// Create a witness and statement for `VALID COMMITMENTS` with the given sizing
/// generics
pub fn create_sized_witness_statement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
) -> (ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS>, ValidCommitmentsStatement)
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let wallet =
        Wallet::<MAX_BALANCES, MAX_ORDERS> { keys: PUBLIC_KEYS.clone(), ..Default::default() };
    create_witness_and_statement(&wallet)
}

/// Tests the time taken to apply the constraints of `VALID COMMITMENTS` circuit
pub fn bench_apply_constraints_with_sizes<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_commitments");
    let benchmark_id =
        BenchmarkId::new("constraint-generation", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) = create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS>();
        let mut cs = PlonkCircuit::new_turbo_plonk();

        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);

        b.iter(|| {
            ValidCommitments::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut cs,
            )
            .unwrap();
        });
    });
}

/// Tests the time taken to prove `VALID COMMITMENTS`
pub fn bench_prover_with_sizes<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_commitments");
    let benchmark_id = BenchmarkId::new("prover", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) = create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS>();
        b.iter(|| {
            singleprover_prove::<ValidCommitments<MAX_BALANCES, MAX_ORDERS>>(
                witness.clone(),
                statement,
            )
            .unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID COMMITMENTS`
pub fn bench_verifier_with_sizes<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_commitments");
    let benchmark_id = BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // First generate a proof that will be verified multiple times
        let (witness, statement) = create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS>();

        let proof =
            singleprover_prove::<ValidCommitments<MAX_BALANCES, MAX_ORDERS>>(witness, statement)
                .unwrap();

        b.iter(|| {
            let res = verify_singleprover_proof::<ValidCommitments<MAX_BALANCES, MAX_ORDERS>>(
                statement, &proof,
            );

            #[allow(unused_must_use)]
            {
                black_box(res)
            }
        });
    });
}

// --------------
// | Benchmarks |
// --------------

/// Benchmarks constraint generation latency on a small `VALID COMMITMENTS`
/// circuit
#[allow(non_snake_case)]
fn bench_apply_constraints__small_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }>(c);
}

/// Benchmarks prover latency on a small `VALID COMMITMENTS` circuit
#[allow(non_snake_case)]
fn bench_prover__small_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }>(c);
}

/// Benchmarks verifier latency on a small `VALID COMMITMENTS` circuit
#[allow(non_snake_case)]
fn bench_verifier__small_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }>(c);
}

/// Benchmarks constraint generation latency on a large `VALID COMMITMENTS`
/// circuit
#[allow(non_snake_case)]
fn bench_apply_constraints__large_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }>(c);
}

/// Benchmarks prover latency on a large `VALID COMMITMENTS` circuit
#[allow(non_snake_case)]
fn bench_prover__large_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }>(c);
}

/// Benchmarks verifier latency on a large `VALID COMMITMENTS` circuit
#[allow(non_snake_case)]
fn bench_verifier__large_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }>(c);
}

// -------------------
// | Criterion Setup |
// -------------------

#[cfg(feature = "large_benchmarks")]
criterion_group! {
    name = valid_commitments;
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
    name = valid_commitments;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints__small_circuit,
        bench_prover__small_circuit,
        bench_verifier__small_circuit,
}

criterion_main!(valid_commitments);
