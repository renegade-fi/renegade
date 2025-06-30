//! Tests the process of proving and verifying a `VALID WALLET CREATE` circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]
#![feature(generic_const_exprs)]

use circuit_types::PlonkCircuit;
use circuit_types::elgamal::DecryptionKey;
use circuit_types::fixed_point::FixedPoint;
use circuit_types::native_helpers::compute_wallet_share_commitment;
use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuit_types::wallet::Wallet;
use circuits::zk_circuits::test_helpers::{PUBLIC_KEYS, create_wallet_shares_with_blinder_seed};
use circuits::zk_circuits::valid_wallet_create::{
    SizedValidWalletCreate, SizedValidWalletCreateStatement, SizedValidWalletCreateWitness,
    ValidWalletCreate, ValidWalletCreateStatement, ValidWalletCreateWitness,
};
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::{MAX_BALANCES, MAX_ORDERS, Scalar};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use itertools::Itertools;
use rand::thread_rng;

// -----------
// | Helpers |
// -----------

/// Create a full sized witness and statement for the `VALID WALLET CREATE`
/// circuit
pub fn create_witness_statement() -> (SizedValidWalletCreateWitness, SizedValidWalletCreateStatement)
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
    let share_commitment = compute_wallet_share_commitment(&public_shares, &private_shares);

    (
        ValidWalletCreateWitness { private_wallet_share: private_shares, blinder_seed },
        ValidWalletCreateStatement {
            wallet_share_commitment: share_commitment,
            public_wallet_shares: public_shares,
        },
    )
}

/// Create a default array of size `N`
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
pub fn bench_apply_constraints(c: &mut Criterion) {
    // Build a witness and statement
    let (witness, statement) = create_witness_statement();

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
pub fn bench_prover(c: &mut Criterion) {
    // Build a witness and statement
    let (witness, statement) = create_witness_statement();
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
pub fn bench_verifier(c: &mut Criterion) {
    // First generate a proof that will be verified multiple times
    let (witness, statement) = create_witness_statement();
    let proof = singleprover_prove::<SizedValidWalletCreate>(witness, statement.clone()).unwrap();

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

// -------------------
// | Criterion Setup |
// -------------------

criterion_group! {
    name = valid_wallet_create;
    config = Criterion::default().sample_size(10);
    targets = bench_apply_constraints, bench_prover, bench_verifier
}
criterion_main!(valid_wallet_create);
