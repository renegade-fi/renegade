//! Tests the process of proving and verifying a `VALID REBLIND` circuit
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuits::zk_circuits::{
    test_helpers::INITIAL_WALLET,
    valid_reblind::{
        test_helpers::{construct_witness_statement, SizedWitness},
        ValidReblind, ValidReblindStatement,
    },
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use merlin::HashChainTranscript;
use mpc_bulletproof::{
    r1cs::{Prover, Verifier},
    PedersenGens,
};
use rand::thread_rng;

/// Create a witness and a statement for the `VALID REBLIND` circuit
pub fn create_default_witness_statement() -> (SizedWitness, ValidReblindStatement) {
    let wallet = INITIAL_WALLET.clone();
    construct_witness_statement(&wallet)
}

/// Tests the time taken to apply the constraints of `VALID REBLIND` circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    // Build a witness and statement
    let (witness, statement) = create_default_witness_statement();
    let mut rng = thread_rng();
    let mut transcript = HashChainTranscript::new(b"test");
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover);
    let statement_var = statement.commit_public(&mut prover);

    let mut group = c.benchmark_group("valid_reblind");
    group.bench_function(BenchmarkId::new("constraint-generation", ""), |b| {
        b.iter(|| {
            ValidReblind::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut prover,
            )
            .unwrap();
        });
    });
}

/// Tests the time taken to prove `VALID REBLIND`
pub fn bench_prover(c: &mut Criterion) {
    // Build a witness and statement
    let (witness, statement) = create_default_witness_statement();

    let mut group = c.benchmark_group("valid_reblind");
    group.bench_function(BenchmarkId::new("prover", ""), |b| {
        b.iter(|| {
            let mut transcript = HashChainTranscript::new(b"test");
            let pc_gens = PedersenGens::default();
            let prover = Prover::new(&pc_gens, &mut transcript);

            ValidReblind::prove(witness.clone(), statement.clone(), prover).unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID REBLIND`
pub fn bench_verifier(c: &mut Criterion) {
    // First generate a proof that will be verified multiple times
    let (witness, statement) = create_default_witness_statement();
    let mut transcript = HashChainTranscript::new(b"test");
    let pc_gens = PedersenGens::default();
    let prover = Prover::new(&pc_gens, &mut transcript);

    let (commitments, proof) = ValidReblind::prove(witness, statement.clone(), prover).unwrap();

    let mut group = c.benchmark_group("valid_reblind");
    group.bench_function(BenchmarkId::new("verifier", ""), |b| {
        b.iter(|| {
            let mut transcript = HashChainTranscript::new(b"test");
            let verifier = Verifier::new(&pc_gens, &mut transcript);

            ValidReblind::verify(
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
    name = valid_reblind;
    config = Criterion::default().sample_size(10);
    targets = bench_apply_constraints, bench_prover, bench_verifier
}
criterion_main!(valid_reblind);
