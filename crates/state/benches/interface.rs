//! Benchmarks the state interface
#![allow(missing_docs, clippy::missing_docs_in_private_items)]
use std::mem;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use job_types::task_driver::new_task_driver_queue;
use state::{
    State,
    test_helpers::{mock_relayer_config, mock_state_with_task_queue},
};
use tokio::runtime::Builder as RuntimeBuilder;
use types_account::account::mocks::mock_empty_account;
use types_core::AccountId;
use types_tasks::mocks::mock_task_descriptor;

/// The network delays to benchmark
const BENCHMARK_DELAYS_MS: [u64; 3] = [0, 10, 100];

/// Create a mock raft with a given network delay
async fn mock_raft(network_delay_ms: u64) -> State {
    let config = mock_relayer_config();
    let (task_sender, task_recv) = new_task_driver_queue();
    mem::forget(task_recv);

    mock_state_with_task_queue(network_delay_ms, task_sender, &config).await
}

/// Benchmark creating an account through the raft
fn bench_create_account(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_interface");
    group.throughput(Throughput::Elements(1));

    for delay in BENCHMARK_DELAYS_MS {
        group.bench_function(BenchmarkId::new("create_account", delay), |b| {
            // Build a Tokio runtime and spawn benchmarks in it
            let runtime = RuntimeBuilder::new_multi_thread().enable_all().build().unwrap();
            let mut async_bencher = b.to_async(runtime);

            async_bencher.iter_custom(|n_iters| {
                async move {
                    // Setup the state
                    let state = mock_raft(delay).await;
                    let account = mock_empty_account();

                    // Propose a series of account updates
                    let mut total_time = std::time::Duration::default();
                    for _ in 0..n_iters {
                        let start = std::time::Instant::now();
                        let waiter = state.new_account(account.clone()).await.unwrap();
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
                        // Create a task on a new account
                        let account_id = AccountId::new_v4();
                        let desc = mock_task_descriptor(account_id);

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
    targets = bench_create_account, bench_append_task
);
criterion_main!(storage);
