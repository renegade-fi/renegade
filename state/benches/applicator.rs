//! Benchmarks the state applicator
#![allow(missing_docs, clippy::missing_docs_in_private_items)]
use std::time::{Duration, Instant};

use common::types::{
    gossip::WrappedPeerId,
    tasks::{QueuedTaskState, mocks::mock_queued_task},
    wallet_mocks::mock_empty_wallet,
};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use state::{
    StateTransition,
    applicator::{StateApplicator, test_helpers::mock_applicator},
};
use uuid::Uuid;

/// Create a mock applicator with necessary DB entries filled in
fn benchmark_applicator() -> StateApplicator {
    let applicator = mock_applicator();
    let tx = applicator.db().new_write_tx().unwrap();
    let peer_id = WrappedPeerId::random();
    tx.set_peer_id(&peer_id).unwrap();
    tx.commit().unwrap();

    applicator
}

/// Benchmark updating a wallet
fn bench_update_wallet(c: &mut Criterion) {
    let applicator = benchmark_applicator();
    let wallet = mock_empty_wallet();
    let transition = StateTransition::UpdateWallet { wallet };

    let mut group = c.benchmark_group("applicator");
    group.throughput(Throughput::Elements(1));
    group.bench_function("update_wallet", |b| {
        b.iter_custom(|n_iters| {
            let mut total_time = Duration::default();
            for _ in 0..n_iters {
                let start = Instant::now();
                applicator.handle_state_transition(Box::new(transition.clone())).unwrap();
                total_time += start.elapsed();
            }
            total_time
        });
    });
}

/// Benchmark appending a task to a task queue
fn bench_append_task(c: &mut Criterion) {
    // Create the applicator and a mock transition
    let applicator = benchmark_applicator();

    let mut group = c.benchmark_group("applicator");
    group.throughput(Throughput::Elements(1));
    group.bench_function("append_task", |b| {
        b.iter_custom(|n_iters| {
            let mut total_time = Duration::default();
            for _ in 0..n_iters {
                // Create a new mock transition
                let wallet_id = Uuid::new_v4();
                let task = mock_queued_task(wallet_id);
                let executor = WrappedPeerId::random();
                let transition = StateTransition::AppendTask { task, executor };

                // Apply the transition
                let start = Instant::now();
                applicator.handle_state_transition(Box::new(transition.clone())).unwrap();
                total_time += start.elapsed();
            }

            total_time
        });
    });
}

/// Benchmark transitioning a task
fn bench_transition_task(c: &mut Criterion) {
    let applicator = benchmark_applicator();
    let task = mock_queued_task(Uuid::new_v4());
    let executor = WrappedPeerId::random();
    applicator.append_task(&task, &executor).unwrap();

    let transition = StateTransition::TransitionTask {
        task_id: task.id,
        state: QueuedTaskState::Running { state: "dummy".to_string(), committed: false },
    };

    let mut group = c.benchmark_group("applicator");
    group.throughput(Throughput::Elements(1));
    group.bench_function("transition_task", |b| {
        b.iter(|| {
            applicator.handle_state_transition(Box::new(transition.clone())).unwrap();
        })
    });
}

/// Benchmark popping a task from a task queue
fn bench_pop_task(c: &mut Criterion) {
    let applicator = benchmark_applicator();
    let executor = WrappedPeerId::random();

    let mut group = c.benchmark_group("applicator");
    group.throughput(Throughput::Elements(1));
    group.bench_function("pop_task", |b| {
        b.iter_custom(|n_iters| {
            let mut total_time = Duration::ZERO;
            for _ in 0..n_iters {
                let task = mock_queued_task(Uuid::new_v4());
                // Append a task
                let append_transition =
                    StateTransition::AppendTask { task: task.clone(), executor };
                applicator.handle_state_transition(Box::new(append_transition)).unwrap();

                // Remove the task
                let start = Instant::now();
                let transition = StateTransition::PopTask { task_id: task.id, success: true };
                applicator.handle_state_transition(Box::new(transition.clone())).unwrap();
                total_time += start.elapsed();
            }

            total_time
        })
    });
}

criterion_group!(
    name = storage;
    config = Criterion::default();
    targets = bench_update_wallet, bench_append_task, bench_transition_task, bench_pop_task
);
criterion_main!(storage);
