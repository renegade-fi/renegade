//! Tests the process of proving and verifying a `VALID WALLET CREATE` circuit
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuits::zk_circuits::valid_wallet_create::ValidWalletCreate;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use merlin::HashChainTranscript;
use mpc_bulletproof::r1cs::Prover;
use mpc_bulletproof::PedersenGens;
use rand::thread_rng;

use circuits::zk_circuits::valid_wallet_create::test_helpers::create_default_witness_statement;

/// Tests the time taken to apply the constraints of `VALID WALLET CREATE` circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    // Build a witness and statement
    let (witness, statement) = create_default_witness_statement();
    let mut rng = thread_rng();
    let mut transcript = HashChainTranscript::new(b"test");
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover);
    let statement_var = statement.commit_public(&mut prover);

    let mut group = c.benchmark_group("constraint-generation");
    group.bench_function(BenchmarkId::from_parameter(""), |b| {
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

/// Tests the time taken to prove `VALID WALLET CREATE`
pub fn bench_prover(c: &mut Criterion) {
    // Build a witness and statement
    let (witness, statement) = create_default_witness_statement();

    let mut group = c.benchmark_group("prover");
    group.bench_function(BenchmarkId::from_parameter(""), |b| {
        b.iter(|| {
            let mut transcript = HashChainTranscript::new(b"test");
            let pc_gens = PedersenGens::default();
            let prover = Prover::new(&pc_gens, &mut transcript);

            ValidWalletCreate::prove(witness.clone(), statement.clone(), prover).unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID WALLET CREATE`
pub fn bench_verifier(c: &mut Criterion) {
    // First generate a proof that will be verified multiple times
    let (witness, statement) = create_default_witness_statement();
    let mut transcript = HashChainTranscript::new(b"test");
    let pc_gens = PedersenGens::default();
    let prover = Prover::new(&pc_gens, &mut transcript);

    let (commitments, proof) =
        ValidWalletCreate::prove(witness, statement.clone(), prover).unwrap();

    let mut group = c.benchmark_group("verifier");
    group.bench_function(BenchmarkId::from_parameter(""), |b| {
        b.iter(|| {
            let mut transcript = HashChainTranscript::new(b"test");
            let verifier = mpc_bulletproof::r1cs::Verifier::new(&pc_gens, &mut transcript);

            ValidWalletCreate::verify(
                commitments.clone(),
                statement.clone(),
                proof.clone(),
                verifier,
            )
            .unwrap();
        });
    });
}

criterion_group! {
    name = valid_wallet_create;
    config = Criterion::default().sample_size(10);
    targets = bench_apply_constraints, bench_prover, bench_verifier
}
criterion_main!(valid_wallet_create);
