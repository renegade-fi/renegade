//! Tests the process of proving and verifying a `VALID WALLET CREATE` circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]
#![feature(generic_const_exprs)]

use circuit_types::elgamal::DecryptionKey;
use circuit_types::fixed_point::FixedPoint;
use circuit_types::native_helpers::compute_wallet_private_share_commitment;
use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuit_types::wallet::Wallet;
use circuit_types::PlonkCircuit;
use circuits::zk_circuits::test_helpers::{create_wallet_shares_with_blinder_seed, PUBLIC_KEYS};
use circuits::zk_circuits::valid_wallet_create::{
    ValidWalletCreate, ValidWalletCreateStatement, ValidWalletCreateWitness,
};
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::{Scalar, MAX_BALANCES, MAX_ORDERS};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use itertools::Itertools;
use rand::thread_rng;

/// The parameter set for the small sized circuit (MAX_BALANCES, MAX_ORDERS)
const SMALL_PARAM_SET: (usize, usize) = (2, 2);
/// The parameter set for the large sized circuit
const LARGE_PARAM_SET: (usize, usize) = (MAX_BALANCES, MAX_ORDERS);

// -----------
// | Helpers |
// -----------

/// Create a full sized witness and statement for the `VALID WALLET CREATE`
/// circuit
pub fn create_sized_witness_statement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>() -> (
    ValidWalletCreateWitness<MAX_BALANCES, MAX_ORDERS>,
    ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS>,
)
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // Create an empty wallet
    let mut rng = thread_rng();
    let (_, enc) = DecryptionKey::random_pair(&mut rng);
    let mut wallet = Wallet::<MAX_BALANCES, MAX_ORDERS> {
        balances: create_default_arr(),
        orders: create_default_arr(),
        keys: PUBLIC_KEYS.clone(),
        max_match_fee: FixedPoint::from_integer(0),
        managing_cluster: enc,
        blinder: Scalar::zero(),
    };

    let blinder_seed = Scalar::random(&mut rng);
    let (private_shares, public_shares) =
        create_wallet_shares_with_blinder_seed(&mut wallet, blinder_seed);
    let private_shares_commitment = compute_wallet_private_share_commitment(&private_shares);

    (
        ValidWalletCreateWitness { private_wallet_share: private_shares, blinder_seed },
        ValidWalletCreateStatement {
            private_shares_commitment,
            public_wallet_shares: public_shares,
        },
    )
}

pub fn create_default_arr<const N: usize, D: Default>() -> [D; N]
where
    [D; N]: Sized,
{
    (0..N)
        .map(|_| D::default())
        .collect_vec()
        .try_into()
        .map_err(|_| "Failed to create default array")
        .unwrap()
}

/// Benchmark applying constraints to a circuit with variable sizing arguments
pub fn bench_apply_constraints_with_sizes<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // Build a witness and statement
    let (witness, statement) = create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS>();

    // Allocate in the constraint system
    let mut cs = PlonkCircuit::new_turbo_plonk();
    let witness_var = witness.create_witness(&mut cs);
    let statement_var = statement.create_public_var(&mut cs);

    // Run the benchmark
    let mut group = c.benchmark_group("valid_wallet_create");
    let benchmark_id =
        BenchmarkId::new("constraint-generation", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            ValidWalletCreate::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut cs,
            )
            .unwrap();
        });
    });
}

/// Benchmark proving a circuit with variable sizing arguments
pub fn bench_prover_with_sizes<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // Build a witness and statement
    let (witness, statement) = create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS>();

    let mut group = c.benchmark_group("valid_wallet_create");
    let benchmark_id = BenchmarkId::new("prover", format!("({MAX_BALANCES}, {MAX_ORDERS})"));
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            singleprover_prove::<ValidWalletCreate<MAX_BALANCES, MAX_ORDERS>>(
                witness.clone(),
                statement.clone(),
            )
            .unwrap();
        });
    });
}

/// Benchmark verifying a circuit with variable sizing arguments
pub fn bench_verifier_with_sizes<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // First generate a proof that will be verified multiple times
    let (witness, statement) = create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS>();

    let proof = singleprover_prove::<ValidWalletCreate<MAX_BALANCES, MAX_ORDERS>>(
        witness,
        statement.clone(),
    )
    .unwrap();

    // Run the benchmark
    let mut group = c.benchmark_group("valid_wallet_create");
    let benchmark_id = BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS})"));
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            verify_singleprover_proof::<ValidWalletCreate<MAX_BALANCES, MAX_ORDERS>>(
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

/// Tests the time taken to apply the constraints of `VALID WALLET CREATE`
/// circuit on a smaller sized circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__small_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }>(c);
}

/// Tests the time taken to prove `VALID WALLET CREATE` on a smaller circuit
#[allow(non_snake_case)]
pub fn bench_prover__small_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }>(c);
}

/// Tests the time taken to verify `VALID WALLET CREATE` on a smaller circuit
#[allow(non_snake_case)]
pub fn bench_verifier__small_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }>(c);
}

/// Tests the time taken to apply the constraints of `VALID WALLET CREATE`
/// circuit on a large sized circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__large_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }>(c);
}

/// Tests the time taken to prove `VALID WALLET CREATE` on a large circuit
#[allow(non_snake_case)]
pub fn bench_prover__large_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }>(c);
}

/// Tests the time taken to verify `VALID WALLET CREATE` on a large circuit
#[allow(non_snake_case)]
pub fn bench_verifier__large_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }>(c);
}

// -------------------
// | Criterion Setup |
// -------------------

#[cfg(feature = "large_benchmarks")]
criterion_group! {
    name = valid_wallet_create;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints__small_circuit,
        bench_prover__small_circuit,
        bench_verifier__small_circuit,
        bench_apply_constraints__large_circuit,
        bench_prover__large_circuit,
        bench_verifier__large_circuit
}

#[cfg(not(feature = "large_benchmarks"))]
criterion_group! {
    name = valid_wallet_create;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints__small_circuit,
        bench_prover__small_circuit,
        bench_verifier__small_circuit,
}

criterion_main!(valid_wallet_create);
