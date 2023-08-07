//! Groups integration tests for matching an order and proving `VALID MATCH MPC` collaboratively

//! Tests the process of proving and verifying a `VALID REBLIND` circuit
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use circuit_types::{
    fixed_point::FixedPoint,
    order::Order,
    traits::{MpcBaseType, MpcType},
};
use circuits::mpc_circuits::r#match::compute_match;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use mpc_stark::{algebra::scalar::Scalar, PARTY0, PARTY1};
use test_helpers::mpc_network::execute_mock_mpc;
use tokio::runtime::Builder as RuntimeBuilder;

/// Benchmark the time taken to run the raw `match` MPC circuits
///
/// TODO: Benchmark with various simulated latencies
pub fn bench_match_mpc(c: &mut Criterion) {
    let mut group = c.benchmark_group("match_mpc");

    group.bench_function(BenchmarkId::new("match", ""), |b| {
        // Build a Tokio runtime and spawn the benchmarks within it
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut async_bencher = b.to_async(runtime);

        async_bencher.iter(|| async {
            execute_mock_mpc(|fabric| async move {
                // Allocate the inputs in the fabric
                let o1 = Order::default().allocate(PARTY0, &fabric);
                let o2 = Order::default().allocate(PARTY1, &fabric);
                let amount1 = Scalar::one().allocate(PARTY0, &fabric);
                let amount2 = Scalar::one().allocate(PARTY1, &fabric);
                let price = FixedPoint::from_integer(1).allocate(PARTY0, &fabric);

                // Run the MPC
                let match_res = compute_match(&o1, &o2, &amount1, &amount2, &price, fabric);

                // Open the result
                let _open = match_res.open_and_authenticate().await;
            })
            .await
        });
    });
}

criterion_group! {
    name = match_mpc;
    config = Criterion::default().sample_size(10);
    targets = bench_match_mpc,
}
criterion_main!(match_mpc);
