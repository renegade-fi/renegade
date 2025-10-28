//! Tests the process of proving and verifying a `VALID FEE REDEMPTION`
//! circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]

use circuit_types::elgamal::DecryptionKey;
use circuit_types::note::Note;
use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuit_types::{Address, Amount, PlonkCircuit};
use circuits::test_helpers::wallet_with_random_balances;
use circuits::zk_circuits::valid_fee_redemption::test_helpers::create_witness_and_statement;
use circuits::zk_circuits::valid_fee_redemption::{
    SizedValidFeeRedemption, SizedValidFeeRedemptionStatement, SizedValidFeeRedemptionWitness,
    ValidFeeRedemption,
};
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::{MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT, Scalar};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::thread_rng;

// -----------
// | Helpers |
// -----------

/// Create a sized witness and statement for the `VALID FEE REDEMPTION`
/// circuit
pub fn create_sized_witness_statement()
-> (SizedValidFeeRedemptionStatement, SizedValidFeeRedemptionWitness) {
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
pub fn bench_apply_constraints(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_fee_redemption");
    let benchmark_id = BenchmarkId::new(
        "constraint-generation",
        format!("({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement, then allocate them in the proof system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let (statement, witness) = create_sized_witness_statement();
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
pub fn bench_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_fee_redemption");
    let benchmark_id =
        BenchmarkId::new("prover", format!("({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement to prove on ahead of time
        let (statement, witness) = create_sized_witness_statement();
        b.iter(|| {
            singleprover_prove::<SizedValidFeeRedemption>(witness.clone(), statement.clone())
                .unwrap();
        });
    });
}

/// Benchmark verifying a circuit with variable sizing arguments
pub fn bench_verifier(c: &mut Criterion) {
    // First generate a proof that will be verified multiple times
    let (statement, witness) = create_sized_witness_statement();
    let proof = singleprover_prove::<SizedValidFeeRedemption>(witness, statement.clone()).unwrap();

    // Run the benchmark
    let mut group = c.benchmark_group("valid_fee_redemption");
    let benchmark_id =
        BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"));
    group.bench_function(benchmark_id, |b| {
        b.iter(|| {
            verify_singleprover_proof::<SizedValidFeeRedemption>(statement.clone(), &proof)
                .unwrap();
        });
    });
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group!(
    name = valid_fee_redemption;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints,
        bench_prover,
        bench_verifier,
);
criterion_main!(valid_fee_redemption);
