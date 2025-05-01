//! Tests the process of proving and verifying a `VALID COMMITMENTS` circuit
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
        valid_commitments::{
            test_helpers::create_witness_and_statement, SizedValidCommitments,
            SizedValidCommitmentsWitness, ValidCommitments, ValidCommitmentsStatement,
        },
    },
};
use constants::{MAX_BALANCES, MAX_ORDERS};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mpc_relation::proof_linking::LinkableCircuit;

// -----------
// | Helpers |
// -----------

/// Create a witness and statement for `VALID COMMITMENTS` with the given sizing
/// generics
pub fn create_sized_witness_statement() -> (SizedValidCommitmentsWitness, ValidCommitmentsStatement)
{
    let wallet =
        Wallet::<MAX_BALANCES, MAX_ORDERS> { keys: PUBLIC_KEYS.clone(), ..Default::default() };
    create_witness_and_statement(&wallet)
}

/// Tests the time taken to apply the constraints of `VALID COMMITMENTS` circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_commitments");
    let benchmark_id =
        BenchmarkId::new("constraint-generation", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) = create_sized_witness_statement();
        let mut cs = PlonkCircuit::new_turbo_plonk();

        // Add proof linking groups to the circuit
        let layout = SizedValidCommitments::get_circuit_layout().unwrap();
        for (id, layout) in layout.group_layouts.into_iter() {
            cs.create_link_group(id, Some(layout));
        }

        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);

        b.iter(|| {
            ValidCommitments::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut cs,
            )
            .unwrap();
        });
    });
}

/// Tests the time taken to prove `VALID COMMITMENTS`
pub fn bench_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_commitments");
    let benchmark_id = BenchmarkId::new("prover", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) = create_sized_witness_statement();
        b.iter(|| {
            singleprover_prove::<SizedValidCommitments>(witness.clone(), statement).unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID COMMITMENTS`
pub fn bench_verifier(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_commitments");
    let benchmark_id = BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // First generate a proof that will be verified multiple times
        let (witness, statement) = create_sized_witness_statement();
        let proof = singleprover_prove::<SizedValidCommitments>(witness, statement).unwrap();
        b.iter(|| {
            let res = verify_singleprover_proof::<SizedValidCommitments>(statement, &proof);
            #[allow(unused_must_use)]
            {
                black_box(res)
            }
        });
    });
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group! {
    name = valid_commitments;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints,
        bench_prover,
        bench_verifier,
}
criterion_main!(valid_commitments);
