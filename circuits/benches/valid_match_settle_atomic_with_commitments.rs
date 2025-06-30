//! Benchmarks the `VALID MATCH SETTLE ATOMIC WITH COMMITMENTS` circuit
#![allow(incomplete_features)]
#![allow(missing_docs)]

use circuit_types::PlonkCircuit;
use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuits::zk_circuits::valid_match_settle_atomic::ValidMatchSettleAtomicWithCommitments;
use circuits::zk_circuits::valid_match_settle_atomic::test_helpers::create_witness_statement_with_commitments;
use circuits::{singleprover_prove, verify_singleprover_proof};
use constants::{MAX_BALANCES, MAX_ORDERS};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use mpc_relation::proof_linking::LinkableCircuit;

// -----------
// | Helpers |
// -----------

/// Tests the time taken to apply the constraints of `VALID MATCH SETTLE ATOMIC
/// WITH COMMITMENTS` circuit
pub fn bench_apply_constraints(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_atomic_match_settle_with_commitments");
    let benchmark_id =
        BenchmarkId::new("constraint-generation", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) =
            create_witness_statement_with_commitments::<MAX_BALANCES, MAX_ORDERS>();
        let mut cs = PlonkCircuit::new_turbo_plonk();

        // Add proof linking groups to the circuit
        let layout =
            ValidMatchSettleAtomicWithCommitments::<MAX_BALANCES, MAX_ORDERS>::get_circuit_layout()
                .unwrap();
        for (id, layout) in layout.group_layouts.into_iter() {
            cs.create_link_group(id, Some(layout));
        }

        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);

        b.iter(|| {
            ValidMatchSettleAtomicWithCommitments::apply_constraints(
                witness_var.clone(),
                statement_var.clone(),
                &mut cs,
            )
            .unwrap();
        });
    });
}

/// Tests the time taken to prove `VALID MATCH SETTLE ATOMIC WITH COMMITMENTS`
pub fn bench_prover(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_atomic_match_settle_with_commitments");
    let benchmark_id = BenchmarkId::new("prover", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // Build a witness and statement
        let (witness, statement) =
            create_witness_statement_with_commitments::<MAX_BALANCES, MAX_ORDERS>();

        b.iter(|| {
            singleprover_prove::<ValidMatchSettleAtomicWithCommitments<MAX_BALANCES, MAX_ORDERS>>(
                witness.clone(),
                statement.clone(),
            )
            .unwrap();
        });
    });
}

/// Tests the time taken to verify `VALID MATCH SETTLE ATOMIC WITH COMMITMENTS`
pub fn bench_verifier(c: &mut Criterion) {
    let mut group = c.benchmark_group("valid_atomic_match_settle_with_commitments");
    let benchmark_id = BenchmarkId::new("verifier", format!("({MAX_BALANCES}, {MAX_ORDERS})"));

    group.bench_function(benchmark_id, |b| {
        // First generate a proof that will be verified multiple times
        let (witness, statement) =
            create_witness_statement_with_commitments::<MAX_BALANCES, MAX_ORDERS>();

        let proof = singleprover_prove::<
            ValidMatchSettleAtomicWithCommitments<MAX_BALANCES, MAX_ORDERS>,
        >(witness, statement.clone())
        .unwrap();

        b.iter(|| {
            verify_singleprover_proof::<
                ValidMatchSettleAtomicWithCommitments<MAX_BALANCES, MAX_ORDERS>,
            >(statement.clone(), &proof)
            .unwrap();
        });
    });
}

// -------------------
// | Criterion Setup |
// -------------------

criterion_group! {
    name = valid_atomic_match_settle_with_commitments;
    config = Criterion::default().sample_size(10);
    targets =
        bench_apply_constraints,
        bench_prover,
        bench_verifier,
}

criterion_main!(valid_atomic_match_settle_with_commitments);
