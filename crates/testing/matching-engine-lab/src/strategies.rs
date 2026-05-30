//! Settlement strategy implementations the lab can A/B under the same workload.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::oneshot;
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

#[cfg(test)]
mod test {
    use std::{sync::Arc, time::Duration};

    use state::test_helpers::mock_state;
    use types_core::AccountId;
    use types_tasks::mocks::mock_task_descriptor;

    use super::SerialPerAccountMock;
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
}
