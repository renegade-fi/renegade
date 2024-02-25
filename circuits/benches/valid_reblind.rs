//! Tests the process of proving and verifying a `VALID REBLIND` circuit
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
        valid_reblind::{
            test_helpers::construct_witness_statement, ValidReblind, ValidReblindStatement,
            ValidReblindWitness,
        },
    },
};
use constants::{MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mpc_relation::proof_linking::LinkableCircuit;

/// The parameter set for the small sized circuit (MAX_BALANCES, MAX_ORDERS,
/// MERKLE_HEIGHT)
const SMALL_PARAM_SET: (usize, usize, usize) = (2, 2, 5);
/// The parameter set for the large sized circuit
const LARGE_PARAM_SET: (usize, usize, usize) = (MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT);

// -----------
// | Helpers |
// -----------

/// Create a witness and statement with the given sizing generics
pub fn create_sized_witness_statement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>() -> (ValidReblindWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>, ValidReblindStatement)
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let wallet =
        Wallet::<MAX_BALANCES, MAX_ORDERS> { keys: PUBLIC_KEYS.clone(), ..Default::default() };
    construct_witness_statement::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>(&wallet)
}

/// Tests the time taken to apply the constraints of `VALID REBLIND` circuit
pub fn bench_apply_constraints_with_sizes<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_reblind");
    let benchmark_id = BenchmarkId::new(
        "constraint-generation",
        format!("({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) =
            create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>();
        let mut cs = PlonkCircuit::new_turbo_plonk();

        // Add proof linking groups to the circuit
        let layout =
            ValidReblind::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>::get_circuit_layout().unwrap();
        for (id, layout) in layout.group_layouts.into_iter() {
            cs.create_link_group(id, Some(layout));
        }

        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);

        b.iter(|| {
            ValidReblind::apply_constraints(witness_var.clone(), statement_var.clone(), &mut cs)
                .unwrap();
        });
    });
}

/// Tests the time taken to prove `VALID REBLIND`
pub fn bench_prover_with_sizes<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_reblind");
    let benchmark_id =
        BenchmarkId::new("prover", format!("({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) =
            create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>();

        b.iter(|| {
            singleprover_prove::<ValidReblind<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>>(
                witness.clone(),
                statement.clone(),
            )
            .unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID REBLIND`
pub fn bench_verifier_with_sizes<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_reblind");
    let benchmark_id =
        BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"));

    group.bench_function(benchmark_id, |b| {
        // First generate a proof that will be verified multiple times
        let (witness, statement) =
            create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>();

        let proof = singleprover_prove::<ValidReblind<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>>(
            witness,
            statement.clone(),
        )
        .unwrap();

        b.iter(|| {
            verify_singleprover_proof::<ValidReblind<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>>(
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

/// Tests the time taken to apply the constraints of a small `VALID REBLIND`
/// circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__small_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<
        { SMALL_PARAM_SET.0 },
        { SMALL_PARAM_SET.1 },
        { SMALL_PARAM_SET.2 },
    >(c);
}

/// Tests the time taken to prove a small `VALID REBLIND` circuit
#[allow(non_snake_case)]
pub fn bench_prover__small_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }, { SMALL_PARAM_SET.2 }>(
        c,
    );
}

/// Tests the time taken verify a small `VALID REBLIND` circuit
#[allow(non_snake_case)]
pub fn bench_verifier__small_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }, { SMALL_PARAM_SET.2 }>(
        c,
    );
}

/// Tests the time taken to apply the constraints of a large `VALID REBLIND`
/// circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__large_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<
        { LARGE_PARAM_SET.0 },
        { LARGE_PARAM_SET.1 },
        { LARGE_PARAM_SET.2 },
    >(c);
}

/// Tests the time taken to prove a large `VALID REBLIND` circuit
#[allow(non_snake_case)]
pub fn bench_prover__large_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }, { LARGE_PARAM_SET.2 }>(
        c,
    );
}

/// Tests the time taken verify a large `VALID REBLIND` circuit
#[allow(non_snake_case)]
pub fn bench_verifier__large_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }, { LARGE_PARAM_SET.2 }>(
        c,
    );
}

// -------------------
// | Criterion Setup |
// -------------------

#[cfg(feature = "large_benchmarks")]
criterion_group! {
    name = valid_reblind;
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
    name = valid_reblind;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints__small_circuit,
        bench_prover__small_circuit,
        bench_verifier__small_circuit,
}

criterion_main!(valid_reblind);
