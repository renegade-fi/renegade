//! Tests the process of proving and verifying a `VALID REBLIND` circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]
#![feature(generic_const_exprs)]

use circuit_types::{
    PlonkCircuit,
    traits::{CircuitBaseType, SingleProverCircuit},
    wallet::Wallet,
};
use circuits::{
    singleprover_prove, verify_singleprover_proof,
    zk_circuits::{
        test_helpers::PUBLIC_KEYS,
        valid_reblind::{
            SizedValidReblind, SizedValidReblindWitness, ValidReblind, ValidReblindStatement,
            test_helpers::construct_witness_statement,
        },
    },
};
use constants::{MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use mpc_relation::proof_linking::LinkableCircuit;

// -----------
// | Helpers |
// -----------

/// Create a witness and statement
pub fn create_witness_statement() -> (SizedValidReblindWitness, ValidReblindStatement) {
    let wallet =
        Wallet::<MAX_BALANCES, MAX_ORDERS> { keys: PUBLIC_KEYS.clone(), ..Default::default() };
    construct_witness_statement::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>(&wallet)
}

/// Tests the time taken to apply the constraints of `VALID REBLIND` circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_reblind");
    let benchmark_id = BenchmarkId::new(
        "constraint-generation",
        format!("({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"),
    );

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) = create_witness_statement();
        let mut cs = PlonkCircuit::new_turbo_plonk();

        // Add proof linking groups to the circuit
        let layout = SizedValidReblind::get_circuit_layout().unwrap();
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
pub fn bench_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_reblind");
    let benchmark_id =
        BenchmarkId::new("prover", format!("({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) = create_witness_statement();
        b.iter(|| {
            singleprover_prove::<SizedValidReblind>(witness.clone(), statement.clone()).unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID REBLIND`
pub fn bench_verifier(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_reblind");
    let benchmark_id =
        BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS}, {MERKLE_HEIGHT})"));

    group.bench_function(benchmark_id, |b| {
        // First generate a proof that will be verified multiple times
        let (witness, statement) = create_witness_statement();
        let proof = singleprover_prove::<SizedValidReblind>(witness, statement.clone()).unwrap();
        b.iter(|| {
            verify_singleprover_proof::<SizedValidReblind>(statement.clone(), &proof).unwrap();
        });
    });
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group! {
    name = valid_reblind;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints,
        bench_prover,
        bench_verifier,
}
criterion_main!(valid_reblind);
