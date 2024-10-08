//! Tests the process of proving and verifying a `VALID FEE REDEMPTION`
//! circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]
#![feature(generic_const_exprs)]

use circuit_types::elgamal::DecryptionKey;
use circuit_types::note::Note;
use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuit_types::{Address, Amount, PlonkCircuit};
use circuits::test_helpers::wallet_with_random_balances;
use circuits::zk_circuits::valid_fee_redemption::ValidFeeRedemption;
use circuits::zk_circuits::valid_fee_redemption::{
    test_helpers::create_witness_and_statement, ValidFeeRedemptionStatement,
    ValidFeeRedemptionWitness,
};
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::{Scalar, MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::thread_rng;

/// The parameter set for the small sized circuit (MAX_BALANCES, MAX_ORDERS,
/// MERKLE_HEIGHT)
const SMALL_PARAM_SET: (usize, usize, usize) = (2, 2, 5);
/// The parameter set for the large sized circuit
const LARGE_PARAM_SET: (usize, usize, usize) = (MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT);

// -----------
// | Helpers |
// -----------

/// Create a sized witness and statement for the `VALID FEE REDEMPTION`
/// circuit
pub fn create_sized_witness_statement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>() -> (
    ValidFeeRedemptionStatement<MAX_BALANCES, MAX_ORDERS>,
    ValidFeeRedemptionWitness<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
)
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut rng = thread_rng();
    let sender_wallet = wallet_with_random_balances();
    let (_, dummy_receiver) = DecryptionKey::random_pair(&mut rng);
    let note = Note {
        mint: Address::from(1u8),
        amount: Amount::from(1u8),
        receiver: dummy_receiver,
        blinder: Scalar::zero(),
    };

    create_witness_and_statement(&sender_wallet, &note)
}

/// Benchmark constraint generation for the circuit
pub fn bench_apply_constraints_with_sizes<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_fee_redemption");
    let benchmark_id = BenchmarkId::new(
        "constraint-generation",
        format!("({}, {}, {})", MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement, then allocate them in the proof system
        let mut cs = PlonkCircuit::new_turbo_plonk();

        let (statement, witness) =
            create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>();
        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);

        b.iter(|| {
            ValidFeeRedemption::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut cs,
            )
            .unwrap();
        });
    });
}

/// Benchmark proving time for the circuit
pub fn bench_prover_with_sizes<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut group = c.benchmark_group("valid_fee_redemption");
    let benchmark_id = BenchmarkId::new(
        "prover",
        format!("({}, {}, {})", MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement to prove on ahead of time
        let (statement, witness) =
            create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>();

        b.iter(|| {
            singleprover_prove::<ValidFeeRedemption<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>>(
                witness.clone(),
                statement.clone(),
            )
            .unwrap();
        });
    });
}

/// Benchmark verifying a circuit with variable sizing arguments
pub fn bench_verifier_with_sizes<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // First generate a proof that will be verified multiple times
    let (statement, witness) =
        create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>();

    let proof = singleprover_prove::<ValidFeeRedemption<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>>(
        witness,
        statement.clone(),
    )
    .unwrap();

    // Run the benchmark
    let mut group = c.benchmark_group("valid_fee_redemption");
    let benchmark_id =
        BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"));
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            verify_singleprover_proof::<
                ValidFeeRedemption<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>,
            >(statement.clone(), &proof)
            .unwrap();
        });
    });
}

// --------------
// | Benchmarks |
// --------------

/// Benchmark constraint generation for the small circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__small_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<
        { SMALL_PARAM_SET.0 },
        { SMALL_PARAM_SET.1 },
        { SMALL_PARAM_SET.2 },
    >(c)
}

/// Benchmark proving time for the small circuit
#[allow(non_snake_case)]
pub fn bench_prover__small_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }, { SMALL_PARAM_SET.2 }>(
        c,
    )
}

/// Benchmark verifying time for the small circuit
#[allow(non_snake_case)]
pub fn bench_verifier__small_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }, { SMALL_PARAM_SET.2 }>(
        c,
    )
}

/// Benchmark constraint generation for the large circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__large_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<
        { LARGE_PARAM_SET.0 },
        { LARGE_PARAM_SET.1 },
        { LARGE_PARAM_SET.2 },
    >(c);
}

/// Benchmark proving time for the large circuit
#[allow(non_snake_case)]
pub fn bench_prover__large_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }, { LARGE_PARAM_SET.2 }>(
        c,
    )
}

/// Benchmark verifying time for the large circuit
#[allow(non_snake_case)]
pub fn bench_verifier__large_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }, { LARGE_PARAM_SET.2 }>(
        c,
    )
}

#[cfg(feature = "large_benchmarks")]
criterion_group!(
    name = valid_fee_redemption;
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
    name = valid_fee_redemption;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints__small_circuit,
        bench_prover__small_circuit,
        bench_verifier__small_circuit,
);

criterion_main!(valid_fee_redemption);
