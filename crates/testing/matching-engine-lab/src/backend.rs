//! Pluggable state backend for the lab.
//!
//! Abstracts how a settlement is enqueued onto the serial-preemptive task queue
//! and released, so the same strategies run against either:
//! - [`RaftBackend`] — the real raft-replicated `State`. Faithful, but the
//!   in-memory mock raft stalls past ~16 concurrent proposals.
//! - [`DirectApplicatorBackend`] — applies transitions straight to a
//!   `StateApplicator`, bypassing raft consensus. Keeps the real
//!   serial-preemption semantics (they live in the storage/applicator layer)
//!   with no consensus throughput ceiling.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use state::{
    State,
    applicator::{StateApplicator, test_helpers::mock_applicator_with_peer},
    state_transition::StateTransition,
};
use types_gossip::WrappedPeerId;
use types_tasks::{QueuedTask, TaskDescriptor, TaskIdentifier};

/// Why an enqueue did not admit.
#[derive(Debug)]
pub enum BackendError {
    /// Lost the serial-preemption race on a shared account queue.
    PreemptionConflict,
    /// Any other backend error.
    Other(String),
}

/// Classify an error as a preemption conflict vs other, by message.
fn classify<E: ToString>(e: E) -> BackendError {
    let s = e.to_string();
    if s.contains("serial preemption") {
        BackendError::PreemptionConflict
    } else {
        BackendError::Other(s)
    }
}

/// The state machine the lab drives.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Enqueue a serial preemptive settlement over the descriptor's accounts.
    async fn enqueue_preemptive(
        &self,
        descriptor: TaskDescriptor,
    ) -> Result<TaskIdentifier, BackendError>;

    /// Complete/release a previously enqueued task.
    async fn pop(&self, task_id: TaskIdentifier);

    /// Short identifier for reports.
    fn name(&self) -> &'static str;
}

/// Drives the real raft-replicated `State`. Faithful, but the in-memory mock
/// raft stalls past ~16 concurrent proposals.
pub struct RaftBackend {
    /// The state handle.
    pub state: State,
}

impl RaftBackend {
    /// Wrap a state handle.
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl Backend for RaftBackend {
    async fn enqueue_preemptive(
        &self,
        descriptor: TaskDescriptor,
    ) -> Result<TaskIdentifier, BackendError> {
        let keys = descriptor.affected_accounts();
        let (tid, waiter) = self
            .state
            .enqueue_preemptive_task(keys, descriptor, true /* serial */)
            .await
            .map_err(classify)?;
        waiter.await.map_err(classify)?;
        Ok(tid)
    }

    async fn pop(&self, task_id: TaskIdentifier) {
        if let Ok(w) = self.state.pop_task(task_id, true /* success */).await {
            let _ = w.await;
        }
    }

    fn name(&self) -> &'static str {
        "raft"
    }
}

/// Applies state transitions directly to a `StateApplicator`, bypassing raft
/// consensus. Applies serialize on a mutex (single-writer state machine); the
/// settlement hold happens outside, so many settles hold concurrently.
pub struct DirectApplicatorBackend {
    /// The applicator, behind a mutex to serialize the brief apply calls.
    applicator: Arc<Mutex<StateApplicator>>,
}

impl DirectApplicatorBackend {
    /// Build a fresh direct-applicator backend over a mock state machine.
    pub fn new() -> Self {
        Self { applicator: Arc::new(Mutex::new(mock_applicator_with_peer())) }
    }
}

impl Default for DirectApplicatorBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Backend for DirectApplicatorBackend {
    async fn enqueue_preemptive(
        &self,
        descriptor: TaskDescriptor,
    ) -> Result<TaskIdentifier, BackendError> {
        let keys = descriptor.affected_accounts();
        let task = QueuedTask::new(descriptor);
        let tid = task.id;
        let transition = StateTransition::EnqueuePreemptiveTask {
            keys,
            task,
            executor: WrappedPeerId::random(),
            serial: true,
        };
        let result = {
            let app = self.applicator.lock().unwrap();
            app.handle_state_transition(Box::new(transition))
        };
        result.map(|_| tid).map_err(classify)
    }

    async fn pop(&self, task_id: TaskIdentifier) {
        let transition = StateTransition::PopTask { task_id, success: true };
        let app = self.applicator.lock().unwrap();
        let _ = app.handle_state_transition(Box::new(transition));
    }

    fn name(&self) -> &'static str {
        "direct_applicator"
    }
}
