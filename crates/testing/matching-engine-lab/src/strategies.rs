//! Settlement strategy implementations the lab can A/B under the same workload.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::{Semaphore, oneshot};
use types_core::AccountId;
use types_tasks::TaskDescriptor;

use crate::{
    backend::{Backend, BackendError},
    ledger::MockBalanceLedger,
    strategy::{SettleOutcome, SettlementStrategy},
};

/// Baseline strategy — models current production behavior: one **exclusive
/// serial preemption** over both affected accounts, held for the mocked
/// settlement latency, then released. A second settlement sharing either
/// account loses the race (`PreemptionConflict`) — the quoter/MM bottleneck.
pub struct SerialPerAccountMock {
    /// Mocked settlement latency — the "this takes N seconds" dial (real
    /// on-chain submit + proof gen + raft commit).
    pub hold: Duration,
    /// Accounting of settled fills, for metrics.
    pub ledger: Arc<MockBalanceLedger>,
}

impl SerialPerAccountMock {
    /// Create the baseline strategy with the given mocked settlement latency.
    pub fn new(hold: Duration, ledger: Arc<MockBalanceLedger>) -> Self {
        Self { hold, ledger }
    }
}

#[async_trait]
impl SettlementStrategy for SerialPerAccountMock {
    async fn settle(&self, backend: &dyn Backend, descriptor: TaskDescriptor) -> SettleOutcome {
        let counterparty = descriptor.affected_accounts().last().copied();

        // Enqueue onto the real serial-preemptive queue (faithful contention).
        let tid = match backend.enqueue_preemptive(descriptor).await {
            Ok(tid) => tid,
            Err(BackendError::PreemptionConflict) => return SettleOutcome::PreemptionConflict,
            Err(BackendError::Other(m)) => return SettleOutcome::Failed(m),
        };

        // Hold the line for the mocked settlement latency, then release.
        tokio::time::sleep(self.hold).await;
        if let Some(cp) = counterparty {
            self.ledger.record_settled(cp);
        }
        backend.pop(tid).await;
        SettleOutcome::Settled
    }

    fn name(&self) -> &'static str {
        "serial_per_account"
    }
}

/// Models the `a519a823` settlement-retry fix: on a preemption conflict, retry
/// the enqueue with bounded exponential backoff. Recovers conflicts the
/// baseline drops, at the cost of latency — but it still holds one account at a
/// time, so it CANNOT exceed the per-account serial throughput ceiling.
pub struct RetrySerialPerAccountMock {
    /// Mocked settlement latency.
    pub hold: Duration,
    /// Accounting of settled fills.
    pub ledger: Arc<MockBalanceLedger>,
    /// Max attempts before giving up (the `MAX_SETTLE_RETRIES` analogue).
    pub max_attempts: u32,
    /// Base backoff between attempts.
    pub base_backoff: Duration,
    /// Cap on the exponential backoff.
    pub max_backoff: Duration,
}

impl RetrySerialPerAccountMock {
    /// Create a retry strategy.
    pub fn new(
        hold: Duration,
        ledger: Arc<MockBalanceLedger>,
        max_attempts: u32,
        base_backoff: Duration,
        max_backoff: Duration,
    ) -> Self {
        Self { hold, ledger, max_attempts, base_backoff, max_backoff }
    }

    /// Deterministic exponential backoff (no jitter, for reproducibility).
    fn backoff(&self, attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX);
        self.base_backoff.saturating_mul(factor).min(self.max_backoff)
    }
}

#[async_trait]
impl SettlementStrategy for RetrySerialPerAccountMock {
    async fn settle(&self, backend: &dyn Backend, descriptor: TaskDescriptor) -> SettleOutcome {
        let counterparty = descriptor.affected_accounts().last().copied();
        for attempt in 0..self.max_attempts {
            match backend.enqueue_preemptive(descriptor.clone()).await {
                Ok(tid) => {
                    tokio::time::sleep(self.hold).await;
                    if let Some(cp) = counterparty {
                        self.ledger.record_settled(cp);
                    }
                    backend.pop(tid).await;
                    return SettleOutcome::Settled;
                },
                Err(BackendError::PreemptionConflict) => {
                    tokio::time::sleep(self.backoff(attempt)).await;
                },
                Err(BackendError::Other(m)) => return SettleOutcome::Failed(m),
            }
        }
        SettleOutcome::PreemptionConflict // exhausted retries
    }

    fn name(&self) -> &'static str {
        "retry_serial"
    }
}

/// Models batched settlement: concurrent settlements against the same
/// counterparty are coalesced into ONE preemption + ONE hold. A "leader"
/// acquires the account, holds once, and settles itself plus every "follower"
/// that arrives during the hold. Amortizes the per-settlement cost, so
/// per-counterparty throughput scales with batch size instead of `1/hold`.
pub struct BatchedPerCounterpartyMock {
    /// Mocked settlement latency (one hold per batch).
    pub hold: Duration,
    /// Accounting of settled fills.
    pub ledger: Arc<MockBalanceLedger>,
    /// Per-counterparty batch coordination.
    slots: Mutex<HashMap<AccountId, Slot>>,
}

#[derive(Default)]
struct Slot {
    /// Whether a leader currently holds this counterparty.
    leader_active: bool,
    /// Followers waiting to be settled by the current batch.
    waiters: Vec<oneshot::Sender<()>>,
}

enum Role {
    Leader,
    Follower(oneshot::Receiver<()>),
}

impl BatchedPerCounterpartyMock {
    /// Create a batched strategy.
    pub fn new(hold: Duration, ledger: Arc<MockBalanceLedger>) -> Self {
        Self { hold, ledger, slots: Mutex::new(HashMap::new()) }
    }

    /// Reopen a counterparty's slot (on the unreachable leader-conflict path),
    /// waking any followers so they re-attempt as a new leader.
    fn reopen(&self, cp: AccountId) {
        let mut slots = self.slots.lock().unwrap();
        if let Some(slot) = slots.get_mut(&cp) {
            slot.leader_active = false;
            for w in std::mem::take(&mut slot.waiters) {
                let _ = w.send(());
            }
        }
    }
}

#[async_trait]
impl SettlementStrategy for BatchedPerCounterpartyMock {
    async fn settle(&self, backend: &dyn Backend, descriptor: TaskDescriptor) -> SettleOutcome {
        let cp = match descriptor.affected_accounts().last().copied() {
            Some(c) => c,
            None => return SettleOutcome::Failed("no counterparty".to_string()),
        };

        // Claim leader or join as follower (atomic under the slots lock).
        let role = {
            let mut slots = self.slots.lock().unwrap();
            let slot = slots.entry(cp).or_default();
            if slot.leader_active {
                let (tx, rx) = oneshot::channel();
                slot.waiters.push(tx);
                Role::Follower(rx)
            } else {
                slot.leader_active = true;
                Role::Leader
            }
        };

        match role {
            // Settled as part of the leader's batch.
            Role::Follower(rx) => {
                let _ = rx.await;
                SettleOutcome::Settled
            },
            Role::Leader => {
                let tid = match backend.enqueue_preemptive(descriptor).await {
                    Ok(t) => t,
                    Err(BackendError::PreemptionConflict) => {
                        self.reopen(cp);
                        return SettleOutcome::PreemptionConflict;
                    },
                    Err(BackendError::Other(m)) => {
                        self.reopen(cp);
                        return SettleOutcome::Failed(m);
                    },
                };

                // One hold for the whole batch.
                tokio::time::sleep(self.hold).await;
                // Release the backend hold BEFORE reopening, so the next leader
                // can't collide with us on the backend queue.
                backend.pop(tid).await;

                // Drain followers that joined during the hold + reopen.
                let waiters = {
                    let mut slots = self.slots.lock().unwrap();
                    let slot = slots.get_mut(&cp).unwrap();
                    slot.leader_active = false;
                    std::mem::take(&mut slot.waiters)
                };
                let batch_size = 1 + waiters.len();
                for _ in 0..batch_size {
                    self.ledger.record_settled(cp);
                }
                for w in waiters {
                    let _ = w.send(());
                }
                SettleOutcome::Settled
            },
        }
    }

    fn name(&self) -> &'static str {
        "batched_per_cp"
    }
}

/// Fallback attempts if an enqueue still conflicts despite the per-counterparty
/// submit lock (e.g. cross-account contention). The lock makes this rare.
const PIPELINE_SUBMIT_ATTEMPTS: u32 = 16;
/// Backoff between fallback submit re-attempts.
const PIPELINE_SUBMIT_BACKOFF: Duration = Duration::from_millis(2);

/// Models pipelined / optimistic-chained settlement (NO protocol change). The
/// per-account serial hold is split in two:
///   - `submit_hold` — the local critical section (state transition + tx build +
///     submit). This is the ONLY part held on the account's serial-preemption
///     queue, so it is what serializes per counterparty.
///   - `confirm_hold` — the on-chain confirmation wait. The account is already
///     released, so confirms of successive settlements **overlap** instead of
///     each blocking the next.
///
/// Successive settlements are built against the predicted post-settlement state
/// (deterministic reblind chain), so settlement N+1 doesn't wait for N to
/// confirm. The optimistic in-flight window is bounded per counterparty by
/// `max_chain_depth` (a revert unwinds the tail, so the chain is kept shallow).
///
/// Per-counterparty throughput rises from `1/(submit+confirm)` to
/// `min(1/submit_hold, max_chain_depth/(submit+confirm))` — i.e. it stops being
/// capped by the on-chain latency, without batching's circuit change. Gas is
/// unchanged (still one tx per fill).
pub struct PipelinedOptimisticMock {
    /// Local critical section held on the account (state + build + submit).
    pub submit_hold: Duration,
    /// On-chain confirmation wait, overlapped off the account lock.
    pub confirm_hold: Duration,
    /// Accounting of settled fills.
    pub ledger: Arc<MockBalanceLedger>,
    /// Optimistic in-flight window per counterparty (chain depth bound).
    pub max_chain_depth: usize,
    /// Deterministic revert knob: revert every Nth confirm to exercise the
    /// rollback-and-resubmit cost. `None` = never (happy-path ceiling).
    pub revert_every: Option<u64>,
    /// Per-counterparty depth limiters.
    depth: Mutex<HashMap<AccountId, Arc<Semaphore>>>,
    /// Per-counterparty FIFO submit locks. The production preemptive queue orders
    /// submits per account; this models that (rather than retry-dropping), so the
    /// account-serialized part is `submit_hold` per settlement, in order.
    submit_locks: Mutex<HashMap<AccountId, Arc<tokio::sync::Mutex<()>>>>,
    /// Global settlement counter, for the deterministic revert schedule.
    seq: AtomicU64,
}

impl PipelinedOptimisticMock {
    /// Create a pipelined strategy. `submit_hold + confirm_hold` should equal the
    /// baseline's single `hold` for an apples-to-apples comparison (same total
    /// settlement latency, just pipelined).
    pub fn new(
        submit_hold: Duration,
        confirm_hold: Duration,
        ledger: Arc<MockBalanceLedger>,
        max_chain_depth: usize,
    ) -> Self {
        Self {
            submit_hold,
            confirm_hold,
            ledger,
            max_chain_depth,
            revert_every: None,
            depth: Mutex::new(HashMap::new()),
            submit_locks: Mutex::new(HashMap::new()),
            seq: AtomicU64::new(0),
        }
    }

    /// Enable a deterministic revert every `n`th confirm (rollback cost study).
    pub fn with_revert_every(mut self, n: u64) -> Self {
        self.revert_every = Some(n);
        self
    }

    /// Get (or create) the per-counterparty depth limiter.
    fn depth_sem(&self, cp: AccountId) -> Arc<Semaphore> {
        self.depth
            .lock()
            .unwrap()
            .entry(cp)
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_chain_depth)))
            .clone()
    }

    /// Get (or create) the per-counterparty FIFO submit lock.
    fn submit_lock(&self, cp: AccountId) -> Arc<tokio::sync::Mutex<()>> {
        self.submit_locks
            .lock()
            .unwrap()
            .entry(cp)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Run the submit critical section on the account: take the per-cp FIFO
    /// submit lock (ordered submits), drive the real serial preemption, hold
    /// `submit_hold`, release. Returns whether the submit landed.
    async fn submit_critical(
        &self,
        backend: &dyn Backend,
        cp: AccountId,
        descriptor: TaskDescriptor,
    ) -> bool {
        let lock = self.submit_lock(cp);
        let _ordered = lock.lock().await;
        for _ in 0..PIPELINE_SUBMIT_ATTEMPTS {
            match backend.enqueue_preemptive(descriptor.clone()).await {
                Ok(tid) => {
                    tokio::time::sleep(self.submit_hold).await;
                    backend.pop(tid).await;
                    return true;
                },
                // Rare with the per-cp lock held; brief backoff and retry.
                Err(BackendError::PreemptionConflict) => {
                    tokio::time::sleep(PIPELINE_SUBMIT_BACKOFF).await;
                },
                Err(BackendError::Other(_)) => return false,
            }
        }
        false
    }
}

#[async_trait]
impl SettlementStrategy for PipelinedOptimisticMock {
    async fn settle(&self, backend: &dyn Backend, descriptor: TaskDescriptor) -> SettleOutcome {
        let cp = match descriptor.affected_accounts().last().copied() {
            Some(c) => c,
            None => return SettleOutcome::Failed("no counterparty".to_string()),
        };

        // Bound the optimistic in-flight chain per counterparty. Held across the
        // whole submit+confirm, so at most `max_chain_depth` settlements sit in
        // the (overlapping) confirm stage at once.
        let sem = self.depth_sem(cp);
        let _permit = sem.acquire_owned().await.unwrap();

        // One rollback+resubmit on a (deterministic) revert. A real cascade would
        // also invalidate downstream optimistic settlements, so this is a LOWER
        // bound on revert cost — documented limitation, not modeled here.
        let revert_attempts = if self.revert_every.is_some() { 2 } else { 1 };
        for _ in 0..revert_attempts {
            // Submit: the only account-serialized part.
            if !self.submit_critical(backend, cp, descriptor.clone()).await {
                return SettleOutcome::PreemptionConflict;
            }

            // Confirm off the account lock — overlaps with other settlements.
            tokio::time::sleep(self.confirm_hold).await;

            let n = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
            let reverted = self.revert_every.map(|e| n % e == 0).unwrap_or(false);
            if !reverted {
                self.ledger.record_settled(cp);
                return SettleOutcome::Settled;
            }
            // Reverted: roll back and resubmit the next loop iteration.
        }
        SettleOutcome::Failed("settlement reverted past resubmit budget".to_string())
    }

    fn name(&self) -> &'static str {
        "pipelined_optimistic"
    }
}

#[cfg(test)]
mod test {
    use std::{sync::Arc, time::Duration};

    use state::test_helpers::mock_state;
    use types_core::AccountId;
    use types_tasks::mocks::mock_task_descriptor;

    use super::{PipelinedOptimisticMock, SerialPerAccountMock};
    use crate::{
        backend::RaftBackend,
        ledger::MockBalanceLedger,
        strategy::{SettleOutcome, SettlementStrategy},
    };

    /// Two settlements against the same counterparty must serialize: exactly one
    /// settles, the other hits a preemption conflict, and the ledger records the
    /// single fill. The quoter/MM hot-account bottleneck, reproduced in-process.
    #[tokio::test]
    async fn serializes_on_shared_counterparty() {
        let backend = RaftBackend::new(mock_state().await);
        let ledger = Arc::new(MockBalanceLedger::new());
        let strat = SerialPerAccountMock::new(Duration::from_millis(150), ledger.clone());

        let quoter = AccountId::new_v4();
        let d1 = mock_task_descriptor(quoter);
        let d2 = mock_task_descriptor(quoter);

        let (o1, o2) = tokio::join!(strat.settle(&backend, d1), strat.settle(&backend, d2));
        let outcomes = [o1, o2];

        let settled = outcomes.iter().filter(|o| **o == SettleOutcome::Settled).count();
        let conflicts =
            outcomes.iter().filter(|o| **o == SettleOutcome::PreemptionConflict).count();
        assert_eq!(settled, 1, "exactly one should settle; got {outcomes:?}");
        assert_eq!(conflicts, 1, "the other should hit a preemption conflict; got {outcomes:?}");
        assert_eq!(ledger.settled_count(), 1);

        // After the first releases, a fresh settlement succeeds.
        let d3 = mock_task_descriptor(quoter);
        assert_eq!(strat.settle(&backend, d3).await, SettleOutcome::Settled);
        assert_eq!(ledger.settled_count(), 2);
    }

    /// Contrast with `serializes_on_shared_counterparty`: under the SAME backend
    /// and two concurrent settlements on the SAME counterparty, pipelining lets
    /// **both** settle (the serial baseline drops one to a preemption conflict).
    /// Only the short submit serializes; the long confirms overlap, so neither is
    /// dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pipelines_same_counterparty() {
        let backend = RaftBackend::new(mock_state().await);
        let ledger = Arc::new(MockBalanceLedger::new());
        let strat = PipelinedOptimisticMock::new(
            Duration::from_millis(10),  // submit
            Duration::from_millis(120), // confirm
            ledger.clone(),
            8,
        );

        let quoter = AccountId::new_v4();
        let d1 = mock_task_descriptor(quoter);
        let d2 = mock_task_descriptor(quoter);

        let (o1, o2) = tokio::join!(strat.settle(&backend, d1), strat.settle(&backend, d2));

        assert_eq!(o1, SettleOutcome::Settled, "first should settle; got {o1:?}");
        assert_eq!(o2, SettleOutcome::Settled, "second should settle, not conflict; got {o2:?}");
        assert_eq!(ledger.settled_count(), 2, "both fills should be recorded");
    }
}
