//! Benchmarks the state interface
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
#![allow(missing_docs, clippy::missing_docs_in_private_items)]
use std::mem;

use common::types::{
    tasks::mocks::mock_task_descriptor, wallet::WalletIdentifier, wallet_mocks::mock_empty_wallet,
};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use job_types::task_driver::new_task_driver_queue;
use state::{
    State,
    test_helpers::{mock_relayer_config, mock_state_with_task_queue},
};
use tokio::runtime::Builder as RuntimeBuilder;

/// The network delays to benchmark
const BENCHMARK_DELAYS_MS: [u64; 3] = [0, 10, 100];

/// Create a mock raft with a given network delay
async fn mock_raft(network_delay_ms: u64) -> State {
    let config = mock_relayer_config();
    let (task_sender, task_recv) = new_task_driver_queue();
    mem::forget(task_recv);

    mock_state_with_task_queue(network_delay_ms, task_sender, &config).await
}

/// Benchmark updating a wallet through the raft
fn bench_update_wallet(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_interface");
    group.throughput(Throughput::Elements(1));

    for delay in BENCHMARK_DELAYS_MS {
        group.bench_function(BenchmarkId::new("update_wallet", delay), |b| {
            // Build a Tokio runtime and spawn benchmarks in it
            let runtime = RuntimeBuilder::new_multi_thread().enable_all().build().unwrap();
            let mut async_bencher = b.to_async(runtime);

            async_bencher.iter_custom(|n_iters| {
                async move {
                    // Setup the state
                    let state = mock_raft(delay).await;
                    let wallet = mock_empty_wallet();

                    // Propose a series of wallet updates
                    let mut total_time = std::time::Duration::default();
                    for _ in 0..n_iters {
                        let start = std::time::Instant::now();
                        let waiter = state.update_wallet(wallet.clone()).await.unwrap();
                        black_box(waiter.await.unwrap());

                        total_time += start.elapsed();
                    }

                    total_time
                }
            });
        });
    }
}

/// Benchmark appending a task to a wallet's task queue
fn bench_append_task(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_interface");
    group.throughput(Throughput::Elements(1));

    for delay in BENCHMARK_DELAYS_MS {
        group.bench_function(BenchmarkId::new("append_task", delay), |b| {
            // Build a Tokio runtime and spawn benchmarks in it
            let runtime = RuntimeBuilder::new_multi_thread().enable_all().build().unwrap();
            let mut async_bencher = b.to_async(runtime);

            async_bencher.iter_custom(|n_iters| {
                async move {
                    // Setup the state
                    let state = mock_raft(delay).await;

                    let mut total_time = std::time::Duration::default();
                    for _ in 0..n_iters {
                        // Create a task on a new wallet
                        let wallet_id = WalletIdentifier::new_v4();
                        let desc = mock_task_descriptor(wallet_id);

                        let start = std::time::Instant::now();
                        let (_, waiter) = state.append_task(desc).await.unwrap();
                        black_box(waiter.await.unwrap());

                        total_time += start.elapsed();
                    }

                    total_time
                }
            });
        });
    }
}

criterion_group!(
    name = storage;
    config = Criterion::default().sample_size(10);
    targets = bench_update_wallet, bench_append_task
);
criterion_main!(storage);
