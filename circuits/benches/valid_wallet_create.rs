//! Tests the process of proving and verifying a `VALID WALLET CREATE` circuit
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use circuit_types::fixed_point::FixedPoint;
use circuit_types::native_helpers::compute_wallet_private_share_commitment;
use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuit_types::wallet::Wallet;
use circuits::zk_circuits::test_helpers::{create_wallet_shares, PUBLIC_KEYS};
use circuits::zk_circuits::valid_wallet_create::{
    ValidWalletCreate, ValidWalletCreateStatement, ValidWalletCreateWitness,
};
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::{MAX_BALANCES, MAX_FEES, MAX_ORDERS};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use itertools::Itertools;
use merlin::HashChainTranscript;
use mpc_bulletproof::r1cs::Prover;
use mpc_bulletproof::PedersenGens;
use mpc_stark::algebra::scalar::Scalar;
use rand::thread_rng;

/// The parameter set for the small sized circuit (MAX_BALANCES, MAX_ORDERS, MAX_FEES)
const SMALL_PARAM_SET: (usize, usize, usize) = (2, 2, 1);
/// The parameter set for the large sized circuit
const LARGE_PARAM_SET: (usize, usize, usize) = (MAX_BALANCES, MAX_ORDERS, MAX_FEES);

// -----------
// | Helpers |
// -----------

/// Create a full sized witness and statement for the `VALID WALLET CREATE` circuit
pub fn create_sized_witness_statement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>() -> (
    ValidWalletCreateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
)
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // Create an empty wallet
    let wallet = Wallet::<MAX_BALANCES, MAX_ORDERS, MAX_FEES> {
        balances: create_default_arr(),
        orders: create_default_arr(),
        keys: PUBLIC_KEYS.clone(),
        match_fee: FixedPoint::from(0.0001),
        managing_cluster: PUBLIC_KEYS.pk_root.clone(),
        blinder: Scalar::zero(),
    };

    let (private_shares, public_shares) = create_wallet_shares(wallet);
    let private_shares_commitment = compute_wallet_private_share_commitment(private_shares.clone());

    (
        ValidWalletCreateWitness {
            private_wallet_share: private_shares,
        },
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
pub fn bench_apply_constraints_with_sizes<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // Build a witness and statement
    let (witness, statement) =
        create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>();
    let mut rng = thread_rng();
    let mut transcript = HashChainTranscript::new(b"test");
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover);
    let statement_var = statement.commit_public(&mut prover);

    let mut group = c.benchmark_group("valid_wallet_create");
    let benchmark_id = BenchmarkId::new(
        "constraint-generation",
        format!("({MAX_BALANCES}, {MAX_ORDERS}, {MAX_FEES})"),
    );
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            ValidWalletCreate::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut prover,
            )
            .unwrap();
        });
    });
}

/// Benchmark proving a circuit with variable sizing arguments
pub fn bench_prover_with_sizes<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // Build a witness and statement
    let (witness, statement) =
        create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>();

    let mut group = c.benchmark_group("valid_wallet_create");
    let benchmark_id = BenchmarkId::new(
        "prover",
        format!("({MAX_BALANCES}, {MAX_ORDERS}, {MAX_FEES})"),
    );
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            singleprover_prove::<ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>>(
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
    const MAX_FEES: usize,
>(
    c: &mut Criterion,
) where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // First generate a proof that will be verified multiple times
    let (witness, statement) =
        create_sized_witness_statement::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>();

    let (commitments, proof) = singleprover_prove::<
        ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    >(witness, statement.clone())
    .unwrap();

    let mut group = c.benchmark_group("valid_wallet_create");
    let benchmark_id = BenchmarkId::new(
        "verifier",
        format!("({MAX_BALANCES}, {MAX_ORDERS}, {MAX_FEES})"),
    );
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            verify_singleprover_proof::<ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>>(
                statement.clone(),
                commitments.clone(),
                proof.clone(),
            )
            .unwrap();
        });
    });
}

// --------------
// | Benchmarks |
// --------------

/// Tests the time taken to apply the constraints of `VALID WALLET CREATE` circuit
/// on a smaller sized circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__small_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<
        { SMALL_PARAM_SET.0 },
        { SMALL_PARAM_SET.1 },
        { SMALL_PARAM_SET.2 },
    >(c);
}

/// Tests the time taken to prove `VALID WALLET CREATE` on a smaller circuit
#[allow(non_snake_case)]
pub fn bench_prover__small_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }, { SMALL_PARAM_SET.2 }>(
        c,
    );
}

/// Tests the time taken to verify `VALID WALLET CREATE` on a smaller circuit
#[allow(non_snake_case)]
pub fn bench_verifier__small_circuit(c: &mut Criterion) {
    bench_verifier_with_sizes::<{ SMALL_PARAM_SET.0 }, { SMALL_PARAM_SET.1 }, { SMALL_PARAM_SET.2 }>(
        c,
    );
}

/// Tests the time taken to apply the constraints of `VALID WALLET CREATE` circuit
/// on a large sized circuit
#[allow(non_snake_case)]
pub fn bench_apply_constraints__large_circuit(c: &mut Criterion) {
    bench_apply_constraints_with_sizes::<
        { LARGE_PARAM_SET.0 },
        { LARGE_PARAM_SET.1 },
        { LARGE_PARAM_SET.2 },
    >(c);
}

/// Tests the time taken to prove `VALID WALLET CREATE` on a large circuit
#[allow(non_snake_case)]
pub fn bench_prover__large_circuit(c: &mut Criterion) {
    bench_prover_with_sizes::<{ LARGE_PARAM_SET.0 }, { LARGE_PARAM_SET.1 }, { LARGE_PARAM_SET.2 }>(
        c,
    );
}

/// Tests the time taken to verify `VALID WALLET CREATE` on a large circuit
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
