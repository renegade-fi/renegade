//! The swappable settlement strategy — the lab's hinge for comparing how
//! different settlement-enqueue policies behave under contention.

use async_trait::async_trait;
use types_tasks::TaskDescriptor;

use crate::backend::Backend;

/// Outcome of attempting to settle a matched pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleOutcome {
    /// The match settled (the strategy held, then released, the queue).
    Settled,
    /// Lost the serial-preemption race on a shared account queue.
    PreemptionConflict,
    /// A genuine failure (not contention).
    Failed(String),
    /// The settle did not complete within the harness's per-settle timeout
    /// (e.g. the backend stalled under concurrency). A harness safety net, not
    /// something a strategy returns itself.
    TimedOut,
}

/// A settlement-enqueue policy.
///
/// Implementations drive the **real** `state` preemptive task queue (so the
/// serial-preemption contention is faithful) but mock the settlement execution
/// (chain + proofs + raft commit time) as a tunable hold.
#[async_trait]
pub trait SettlementStrategy: Send + Sync {
    /// Attempt to settle the match described by `descriptor`.
    async fn settle(&self, backend: &dyn Backend, descriptor: TaskDescriptor) -> SettleOutcome;

    /// Short identifier for reports.
    fn name(&self) -> &'static str;
}
