//! Benchmarks for the `VALID WALLET UPDATE` circuit

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use circuit_types::{
    order::Order,
    traits::{CircuitBaseType, SingleProverCircuit},
    transfers::ExternalTransfer,
};
use circuits::zk_circuits::{
    test_helpers::INITIAL_WALLET,
    valid_wallet_update::{
        test_helpers::{construct_witness_statement, SizedStatement, SizedWitness},
        ValidWalletUpdate,
    },
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use merlin::HashChainTranscript;
use mpc_bulletproof::{r1cs::Prover, PedersenGens};
use rand::thread_rng;

/// Construct a dummy witness and statement for the circuit
pub fn create_default_witness_statement() -> (SizedWitness, SizedStatement) {
    // Take a default wallet and cancel an order
    let original_wallet = INITIAL_WALLET.clone();
    let mut modified_wallet = INITIAL_WALLET.clone();
    modified_wallet.orders[0] = Order::default();

    construct_witness_statement(
        original_wallet,
        modified_wallet,
        ExternalTransfer::default(),
    )
}

/// Benchmark constraint generation for the circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut transcript = HashChainTranscript::new(b"test");
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    let (witness, statement) = create_default_witness_statement();
    let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover);
    let statement_var = statement.commit_public(&mut prover);

    let mut group = c.benchmark_group("valid_wallet_update");
    group.bench_function(BenchmarkId::new("constraint-generation", ""), |b| {
        b.iter(|| {
            ValidWalletUpdate::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut prover,
            )
            .unwrap();
        });
    });
}

/// Benchmark proving time for the circuit
pub fn bench_prover(c: &mut Criterion) {
    // Build a witness and statement to prove on ahead of time
    let (witness, statement) = create_default_witness_statement();

    let mut group = c.benchmark_group("valid_wallet_update");
    group.bench_function(BenchmarkId::new("prover", ""), |b| {
        b.iter(|| {
            let mut transcript = HashChainTranscript::new(b"test");
            let pc_gens = PedersenGens::default();
            let prover = Prover::new(&pc_gens, &mut transcript);

            ValidWalletUpdate::prove(witness.clone(), statement.clone(), prover).unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID WALLET UPDATE`
pub fn bench_verifier(c: &mut Criterion) {
    // First generate a proof that will be verified multiple times
    let (witness, statement) = create_default_witness_statement();
    let mut transcript = HashChainTranscript::new(b"test");
    let pc_gens = PedersenGens::default();
    let prover = Prover::new(&pc_gens, &mut transcript);

    let (commitments, proof) =
        ValidWalletUpdate::prove(witness, statement.clone(), prover).unwrap();

    let mut group = c.benchmark_group("valid_wallet_update");
    group.bench_function(BenchmarkId::new("verifier", ""), |b| {
        b.iter(|| {
            let mut transcript = HashChainTranscript::new(b"test");
            let verifier = mpc_bulletproof::r1cs::Verifier::new(&pc_gens, &mut transcript);

            ValidWalletUpdate::verify(
                commitments.clone(),
                statement.clone(),
                proof.clone(),
                verifier,
            )
            .unwrap();
        });
    });
}

criterion_group!(
    name = valid_wallet_update;
    config = Criterion::default().sample_size(10);
    targets = bench_apply_constraints, bench_prover, bench_verifier
);

criterion_main!(valid_wallet_update);
