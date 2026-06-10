//! The interface for interacting with the task queue

use tracing::instrument;
use types_core::AccountId;
use types_gossip::WrappedPeerId;
use types_tasks::{
    HistoricalTask, QueuedTask, QueuedTaskState, RefreshAccountTaskDescriptor, TaskDescriptor,
    TaskIdentifier, TaskQueueKey,
};
use util::{get_current_time_millis, res_some, telemetry::helpers::backfill_trace_field};

use crate::{
    StateInner,
    error::StateError,
    notifications::ProposalWaiter,
    state_transition::StateTransition,
    storage::{
        error::StorageError, traits::RkyvValue,
        tx::task_queue::queue_type::ArchivedTaskQueuePreemptionState,
    },
};

/// Decide whether a wedged `SerialPreemptionQueued` head should be reaped by
/// `clear_orphaned_preempted_queues`, given its commit status, the caller's
/// age gate (`min_head_age_millis`; `0` == boot path), and the head's age
/// (`None` on the boot path, which carries no age signal).
///
/// - Boot (`gate == 0`): reap a committed head (necessarily orphaned -- no task
///   future is executing yet), but never an uncommitted one (no age signal to
///   separate a healthy just-reloaded settle from an orphan).
/// - Periodic (`gate > 0`): reap any head, committed or not, once it has aged
///   past the gate -- a healthy settle leaves `Pending` in ms and commits its
///   submit in seconds, so an older head is stuck.
fn should_reap_wedged_head(
    committed: bool,
    min_head_age_millis: u64,
    age_millis: Option<u64>,
) -> bool {
    match (committed, min_head_age_millis) {
        (true, 0) => true,
        (false, 0) => false,
        (_, gate) => matches!(age_millis, Some(age) if age >= gate),
    }
}

impl StateInner {
    // -----------
    // | Getters |
    // -----------

    /// Whether or not the task queue contains a specific task
    pub async fn contains_task(&self, task_id: &TaskIdentifier) -> Result<bool, StateError> {
        let tid = *task_id;
        self.with_read_tx(move |tx| Ok(tx.get_task(&tid)?.is_some())).await
    }

    /// Whether the queue is paused by a serial task
    pub async fn is_queue_paused_serial(&self, key: &TaskQueueKey) -> Result<bool, StateError> {
        let key = *key;
        self.with_read_tx(move |tx| {
            let queue = tx.get_task_queue(&key)?;
            let paused_serial = queue
                .map(|q| {
                    q.preemption_state == ArchivedTaskQueuePreemptionState::SerialPreemptionQueued
                })
                .unwrap_or(false);
            Ok(paused_serial)
        })
        .await
    }

    /// Self-heal task queues wedged in `SerialPreemptionQueued` by an orphaned
    /// preemptive (settle) task -- the node that was running the settle stopped
    /// driving it (worker churn, scale-down, or the seed regenerating its p2p
    /// identity on restart) without completing it, so the queue stays paused
    /// and no further settle can run (`deferred-queue full` forever). The
    /// wedged head may be COMMITTED (the settle reached its on-chain
    /// submit) or UNCOMMITTED (a settle that never advanced past `Pending`
    /// because its executor departed before stepping it even once). Clears
    /// each such queue via the raft `ClearTaskQueue` proposal and enqueues
    /// a `RefreshAccount` to re-sync wallet state. Leader-only and
    /// idempotent. Returns the number of queues cleared.
    ///
    /// Does NOT re-run the orphaned settle (re-running a committed settle could
    /// double-settle on-chain); the match is re-derived by the matcher and the
    /// wallet reconciled by the refresh. An uncommitted head took no on-chain
    /// action, so clearing it is strictly safe.
    ///
    /// `min_head_age_millis` selects the safety gate, dispatched in
    /// `should_reap_wedged_head`:
    /// - `0` (node startup): clear a COMMITTED head unconditionally (no task
    ///   future is executing yet, so a committed head is necessarily orphaned),
    ///   but NEVER an uncommitted head -- at boot there is no age signal to
    ///   tell a healthy just-reloaded settle from an orphan, and the periodic
    ///   timer catches it shortly after.
    /// - `> 0` (periodic timer): clear a head (committed or uncommitted) only
    ///   once its task was created longer ago than this threshold. A *healthy*
    ///   in-flight settle sits at committed `SubmittingTx` while it submits
    ///   (seconds) and a healthy enqueued settle leaves `Pending` in
    ///   milliseconds, so a head older than the threshold is stuck regardless
    ///   of commit state -- the executor departed or it is otherwise no longer
    ///   being driven.
    pub async fn clear_orphaned_preempted_queues(
        &self,
        min_head_age_millis: u64,
    ) -> Result<usize, StateError> {
        // Only the leader reconciles; the clear is raft-proposed so it applies
        // cluster-wide. Avoids every node racing to clear the same queues.
        if !self.is_leader() {
            return Ok(0);
        }

        let account_ids = self.get_all_account_ids().await?;
        let mut cleared = 0usize;
        for account_id in account_ids {
            let key = account_id;
            let wedged_head =
                self.with_read_tx(move |tx| Ok(tx.orphaned_preempt_head(&key)?)).await?;
            let Some((task_id, committed)) = wedged_head else { continue };

            // Compute the head's age for the periodic gate. The boot path
            // (`min_head_age_millis == 0`) has no age signal and ignores it; a
            // vanished task has nothing to clear.
            let age_millis = if min_head_age_millis > 0 {
                let created_at = self
                    .with_read_tx(move |tx| {
                        Ok(tx.get_task_deserialized(&task_id)?.map(|t| t.created_at))
                    })
                    .await?;
                match created_at {
                    Some(ts) => Some(get_current_time_millis().saturating_sub(ts)),
                    None => continue, // task vanished; nothing to clear
                }
            } else {
                None
            };

            if !should_reap_wedged_head(committed, min_head_age_millis, age_millis) {
                continue;
            }

            tracing::warn!(
                %account_id,
                %task_id,
                committed,
                "clearing orphaned SerialPreemptionQueued task queue (wedged settle head)"
            );
            self.clear_task_queue(&account_id).await?.await?;
            if let Err(e) = self.append_account_refresh_task(account_id).await {
                tracing::warn!(%account_id, error = %e, "account refresh after queue clear failed");
            }
            cleared += 1;
        }

        if cleared > 0 {
            tracing::warn!(count = cleared, "cleared orphaned preempted task queues");
        }
        Ok(cleared)
    }

    /// Whether there are any serial tasks enqueued for the given queue
    pub async fn has_active_serial_tasks(&self, key: &TaskQueueKey) -> Result<bool, StateError> {
        let serial_task_len = self.serial_tasks_queue_len(key).await?;
        Ok(serial_task_len > 0)
    }

    /// Get the length of the serial task queue
    pub async fn serial_tasks_queue_len(&self, key: &TaskQueueKey) -> Result<usize, StateError> {
        let key = *key;
        self.with_read_tx(move |tx| {
            let queue = tx.get_task_queue(&key)?;
            Ok(queue.map(|q| q.serial_tasks.len()).unwrap_or(0))
        })
        .await
    }

    /// Get the list of tasks enqueued for the given queue
    pub async fn get_queued_tasks(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Vec<QueuedTask>, StateError> {
        let key = *key;
        self.with_read_tx(move |tx| {
            let queue = tx.get_queued_tasks(&key)?;
            let queue = queue
                .into_iter()
                .map(|q| q.deserialize())
                .collect::<Result<Vec<QueuedTask>, StorageError>>()?;

            Ok(queue)
        })
        .await
    }

    /// Get the list of all tasks (running an historical) up to a truncation
    /// length
    pub async fn get_task_history(
        &self,
        len: usize,
        key: &TaskQueueKey,
    ) -> Result<Vec<HistoricalTask>, StateError> {
        let key = *key;
        self.with_read_tx(move |tx| {
            let running = tx.get_queued_tasks(&key)?;
            let remaining = len.saturating_sub(running.len());
            let historical = tx.get_truncated_task_history(remaining, &key)?;

            // Deserialize and collect all tasks
            let all_tasks = running
                .into_iter()
                .filter_map(|t| {
                    let task = t.deserialize().ok()?;
                    HistoricalTask::from_queued_task(key, task)
                })
                .chain(historical.into_iter().filter_map(|h| h.deserialize().ok()))
                .take(len)
                .collect();

            Ok(all_tasks)
        })
        .await
    }

    /// Get a task by ID
    pub async fn get_task(
        &self,
        task_id: &TaskIdentifier,
    ) -> Result<Option<QueuedTask>, StateError> {
        let tid = *task_id;
        self.with_read_tx(move |tx| {
            let task_value = res_some!(tx.get_task(&tid)?);
            let task = task_value.deserialize()?;
            Ok(Some(task))
        })
        .await
    }

    /// Get the status of a task
    pub async fn get_task_status(
        &self,
        task_id: &TaskIdentifier,
    ) -> Result<Option<QueuedTaskState>, StateError> {
        let tid = *task_id;
        self.with_read_tx(move |tx| {
            let status = res_some!(tx.get_task(&tid)?);
            let state = QueuedTaskState::from_archived(&status.state)?;
            Ok(Some(state))
        })
        .await
    }

    // -----------
    // | Setters |
    // -----------

    /// A shorthand to append an account refresh task to the queue and await the
    /// state transition
    ///
    /// Returns the task ID for the refresh
    pub async fn append_account_refresh_task(
        &self,
        account_id: AccountId,
    ) -> Result<TaskIdentifier, StateError> {
        // Fetch the account's keychain
        let keychain = self
            .get_account_keychain(&account_id)
            .await?
            .ok_or_else(|| StorageError::not_found(format!("account {account_id} not found")))?;

        // Create and append the task
        let descriptor = RefreshAccountTaskDescriptor::new(account_id, keychain);
        let (tid, waiter) = self.append_task(descriptor.into()).await?;
        waiter.await?;

        Ok(tid)
    }

    /// Append a task to the queue
    #[instrument(name = "propose_append_task", skip_all, err, fields(task_id, task = %task.display_description()))]
    pub async fn append_task(
        &self,
        task: TaskDescriptor,
    ) -> Result<(TaskIdentifier, ProposalWaiter), StateError> {
        // Build the task
        let task = QueuedTask::new(task);
        let tid = task.id;
        backfill_trace_field("task_id", tid.to_string());

        // Propose the task to the task queue
        let executor = self.get_peer_id()?;
        let proposal = StateTransition::AppendTask { task, executor };
        let waiter = self.send_proposal(proposal).await?;
        Ok((tid, waiter))
    }

    /// Pop a task from the queue
    #[instrument(name = "propose_pop_task", skip_all, err, fields(task_id = %task_id, success = %success))]
    pub async fn pop_task(
        &self,
        task_id: TaskIdentifier,
        success: bool,
    ) -> Result<ProposalWaiter, StateError> {
        // Propose the task to the task queue
        self.send_proposal(StateTransition::PopTask { task_id, success }).await
    }

    /// Transition the state of the top task in a queue
    pub async fn transition_task(
        &self,
        task_id: TaskIdentifier,
        state: QueuedTaskState,
    ) -> Result<ProposalWaiter, StateError> {
        // Propose the task to the task queue
        self.send_proposal(StateTransition::TransitionTask { task_id, state }).await
    }

    /// Clear a task queue
    pub async fn clear_task_queue(&self, key: &TaskQueueKey) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::ClearTaskQueue { queue: *key }).await
    }

    /// Enqueue a preemptive task
    ///
    /// A task marked `serial` (i.e. `serial = true`) requires exclusive access
    /// to the task queues specified by `keys`. A task marked `!serial` is a
    /// concurrent task, and is allowed to run concurrently with other
    /// concurrent tasks on the same queues.
    #[instrument(
        name = "propose_enqueue_preemptive_task", 
        skip_all, err, fields(
            queue_keys = ?keys, task_id, task = %task.display_description(), serial = %serial
        )
    )]
    pub async fn enqueue_preemptive_task(
        &self,
        keys: Vec<TaskQueueKey>,
        task: TaskDescriptor,
        serial: bool,
    ) -> Result<(TaskIdentifier, ProposalWaiter), StateError> {
        // Build the task
        let task = QueuedTask::new(task);
        let tid = task.id;
        backfill_trace_field("task_id", tid.to_string());

        // Propose the task to the task queue, with the local peer as the executor
        let executor = self.get_peer_id()?;
        let transition = StateTransition::EnqueuePreemptiveTask { keys, task, executor, serial };
        let waiter = self.send_proposal(transition).await?;
        Ok((tid, waiter))
    }

    /// Reassign the tasks from a failed peer to the local peer
    pub async fn reassign_tasks(
        &self,
        failed_peer: &WrappedPeerId,
    ) -> Result<ProposalWaiter, StateError> {
        let local_peer = self.get_peer_id()?;
        let proposal = StateTransition::ReassignTasks { from: *failed_peer, to: local_peer };
        self.send_proposal(proposal).await
    }
}

#[cfg(test)]
mod test {
    use types_account::account::mocks::mock_empty_account;
    use types_core::AccountId;
    use types_tasks::{
        QueuedTaskState, TaskIdentifier, TaskQueueKey,
        mocks::{mock_queued_task, mock_task_descriptor},
    };

    use crate::test_helpers::{mock_db, mock_state};

    /// `should_reap_wedged_head` truth table: the boot path reaps only
    /// committed heads; the periodic gate reaps any head once aged, never a
    /// fresh one.
    #[test]
    fn test_should_reap_wedged_head() {
        use super::should_reap_wedged_head as reap;
        const GATE: u64 = 120_000;

        // Boot path (gate == 0): committed orphan -> reap; uncommitted -> never
        // (no age signal to tell a healthy just-reloaded settle from an orphan).
        assert!(reap(true, 0, None));
        assert!(!reap(false, 0, None));

        // Periodic path (gate > 0): reap a head -- committed or uncommitted --
        // only once it has aged past the gate.
        assert!(!reap(true, GATE, Some(GATE - 1)));
        assert!(reap(true, GATE, Some(GATE)));
        assert!(!reap(false, GATE, Some(GATE - 1)));
        assert!(reap(false, GATE, Some(GATE + 1)));
        // No age available -> cannot reap on the periodic path.
        assert!(!reap(false, GATE, None));
        assert!(!reap(true, GATE, None));
    }

    /// Tests getter methods on an empty queue
    #[tokio::test]
    async fn test_empty_queue() {
        let state = mock_state().await;

        let key = TaskQueueKey::new_v4();
        assert_eq!(state.serial_tasks_queue_len(&key).await.unwrap(), 0);
        assert!(state.get_queued_tasks(&key).await.unwrap().is_empty());
    }

    /// Tests appending to an empty queue
    #[tokio::test]
    async fn test_append() {
        let state = mock_state().await;

        // Propose a task to the queue
        let key = TaskQueueKey::new_v4();
        let task = mock_queued_task(key).descriptor;

        let (task_id, waiter) = state.append_task(task).await.unwrap();
        waiter.await.unwrap();

        // Check that the task was added
        assert_eq!(state.serial_tasks_queue_len(&key).await.unwrap(), 1);

        let tasks = state.get_queued_tasks(&key).await.unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task_id);
        assert!(matches!(tasks[0].state, QueuedTaskState::Running { .. })); // Should be started

        assert!(state.get_task(&task_id).await.unwrap().is_some());
    }

    /// Tests popping from a queue
    #[tokio::test]
    async fn test_pop() {
        let state = mock_state().await;

        // Add an account that the task may reference
        let account = mock_empty_account();
        let account_id = account.id;
        let waiter = state.new_account(account).await.unwrap();
        waiter.await.unwrap();

        // Propose a task to the queue
        let task = mock_queued_task(account_id).descriptor;
        let (task_id, waiter) = state.append_task(task).await.unwrap();
        waiter.await.unwrap();

        // Pop the task from the queue
        let waiter = state.pop_task(task_id, true /* success */).await.unwrap();
        waiter.await.unwrap();

        // Check that the task was removed
        assert_eq!(state.serial_tasks_queue_len(&account_id).await.unwrap(), 0);
    }

    /// Seam-proof for the matching-engine concurrency lab: a serial preemptive
    /// task takes exclusive hold of all of its queue keys; a second serial
    /// preemption that shares any key is rejected until the first completes.
    /// This validates the lab's mock-executor approach (drive the real
    /// preemptive queue, hold for a latency, then `pop_task` to release).
    #[tokio::test]
    async fn test_serial_preemption_blocks_shared_key() {
        let state = mock_state().await;

        let a = TaskQueueKey::new_v4();
        let b = TaskQueueKey::new_v4();
        let c = TaskQueueKey::new_v4();

        // First serial preemptive settlement over [a, b]
        let (tid1, w1) = state
            .enqueue_preemptive_task(vec![a, b], mock_task_descriptor(a), true /* serial */)
            .await
            .unwrap();
        w1.await.unwrap();

        // A second serial preemption that shares key `b` must be rejected
        let rejected = match state
            .enqueue_preemptive_task(vec![b, c], mock_task_descriptor(b), true /* serial */)
            .await
        {
            Err(_) => true,
            Ok((_, w)) => w.await.is_err(),
        };
        assert!(rejected, "second serial preemption sharing key b should be rejected");

        // Completing the first releases the hold on both keys
        let w = state.pop_task(tid1, true /* success */).await.unwrap();
        w.await.unwrap();

        // Now the previously-rejected preemption succeeds
        let (_, w3) = state
            .enqueue_preemptive_task(vec![b, c], mock_task_descriptor(b), true /* serial */)
            .await
            .unwrap();
        w3.await.unwrap();
    }

    /// Reproduction for ticket
    /// 2026-06-02-relayer-matching-settlement-concurrency-audit:
    /// the settlement-starvation that drops market-maker internal-match fills.
    ///
    /// A market-maker wallet's serial task queue is held by a COMMITTED
    /// order-management task (a quote the MM just placed) at the instant a
    /// match against it settles. Settlement is a serial PREEMPTION over
    /// both counterparties' queues, which the state layer rejects while a
    /// committed task is at the queue head
    /// (storage::is_serial_preemption_safe). In production a single
    /// immediate attempt is made, so the fill is dropped.
    ///
    /// This test shows the rejection is TRANSIENT: once the committed task
    /// completes and clears the queue, the same preemption succeeds — so a
    /// bounded retry-with-backoff that outlasts the commit window resolves it
    /// (matching-engine-worker `manager/tasks.rs`, "Approach A"). It runs
    /// entirely in-process against the real preemptive task-queue state
    /// machine — the lab loop that replaces deploy-and-grep.
    #[tokio::test]
    async fn test_settlement_starved_by_committed_order_task() {
        // Timeout-guarded so a queue/preemption deadlock fails fast instead of
        // hanging the lab loop (mock-raft can stall; see ticket).
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let state = mock_state().await;

            // The market-maker wallet (an account so its order task can be popped).
            let mm_account = mock_empty_account();
            let mm = mm_account.id;
            state.new_account(mm_account).await.unwrap().await.unwrap();
            // The counterparty wallet; the settlement preemption spans both queues.
            let taker = TaskQueueKey::new_v4();

            // Put a COMMITTED order-management task at the head of the MM queue — past
            // its commit point, so it cannot be preempted or rolled back.
            let (order_task, w) = state.append_task(mock_task_descriptor(mm)).await.unwrap();
            w.await.unwrap();
            state
                .transition_task(
                    order_task,
                    QueuedTaskState::Running {
                        state: "placing-order".to_string(),
                        committed: true,
                    },
                )
                .await
                .unwrap()
                .await
                .unwrap();

            // 1) Today's behavior: the settle (serial preemption over both wallets) is
            //    REJECTED because the MM queue head is committed -> the fill is dropped.
            let rejected = match state
                .enqueue_preemptive_task(
                    vec![mm, taker],
                    mock_task_descriptor(mm),
                    true, // serial
                )
                .await
            {
                Ok((_, w)) => w.await.is_err(),
                Err(_) => true,
            };
            assert!(rejected, "settle must be rejected while the MM queue head is committed");

            // 2) The committed order task completes, clearing the queue.
            state.pop_task(order_task, true /* success */).await.unwrap().await.unwrap();

            // 3) The SAME preemption now succeeds — the rejection was transient, so
            //    Approach A's bounded retry lands once the commit window passes.
            let (tid, w) = state
                .enqueue_preemptive_task(vec![mm, taker], mock_task_descriptor(mm), true)
                .await
                .expect("settle enqueue should succeed after the committed task clears");
            w.await.expect("settle preemption should commit once the queue is free");
            state.pop_task(tid, true).await.unwrap().await.unwrap();
        })
        .await
        .expect("L0 lab test exceeded 15s — preemption/queue likely deadlocked");
    }

    /// L2 simulator (tx-direct, synchronous) for ticket
    /// 2026-06-02-relayer-matching-settlement-concurrency-audit.
    ///
    /// Reproduces market-maker internal-match settlement starvation under order
    /// churn and A/Bs give-up vs retry, driving the preemptive task queue
    /// DIRECTLY via a write tx — NOT mock_state/raft, which stalls and
    /// leaks threads at the volume a sim needs (the raft path is exercised
    /// by the L0 interface test). The MM is "busy" (a committed order task
    /// at its queue head) for COMMIT_TICKS, then free for GAP_TICKS;
    /// matches arrive every MATCH_EVERY ticks. Synchronous
    /// and deterministic, so it can't hang — no timeout guard needed.
    #[test]
    fn sim_settlement_starvation_ab() {
        const TICKS: usize = 120;
        const COMMIT_TICKS: usize = 4; // MM busy window (a committed order task)
        const GAP_TICKS: usize = 2; // MM idle window
        const MATCH_EVERY: usize = 3;

        // Drive the real preemptive queue under a strategy; returns (settled, dropped).
        fn run(retry: bool) -> (usize, usize) {
            let db = mock_db();
            let tx = db.new_write_tx().unwrap();
            let mm = TaskQueueKey::new_v4();
            let taker = TaskQueueKey::new_v4();

            // The MM's current committed order task (the queue head), if any.
            let mut busy: Option<TaskIdentifier> = None;
            let (mut settled, mut total, mut pending) = (0usize, 0usize, 0usize);

            for tick in 0..TICKS {
                let want_busy = (tick % (COMMIT_TICKS + GAP_TICKS)) < COMMIT_TICKS;
                // Advance MM order churn: enqueue a committed order task, or pop it.
                if want_busy && busy.is_none() {
                    let mut order = mock_queued_task(mm);
                    order.state =
                        QueuedTaskState::Running { state: "order".to_string(), committed: true };
                    tx.enqueue_serial_task(&mm, &order).unwrap();
                    busy = Some(order.id);
                } else if !want_busy && busy.is_some() {
                    tx.pop_task(&busy.take().unwrap()).unwrap();
                }

                // A new match arrives. A "settle" is a serial preemption over both
                // wallets; on success we pop it to release the hold.
                if tick % MATCH_EVERY == 0 {
                    total += 1;
                    if retry {
                        pending += 1; // Approach A queues it
                    } else {
                        let s = mock_queued_task(mm);
                        if tx.preempt_queue_with_serial(&[mm, taker], &s).is_ok() {
                            tx.pop_task(&s.id).unwrap();
                            settled += 1;
                        }
                    }
                }

                // Approach A: drain a queued match the moment the wallet is free.
                if retry && pending > 0 && busy.is_none() {
                    let s = mock_queued_task(mm);
                    if tx.preempt_queue_with_serial(&[mm, taker], &s).is_ok() {
                        tx.pop_task(&s.id).unwrap();
                        settled += 1;
                        pending -= 1;
                    }
                }
            }
            (settled, total - settled)
        }

        let (giveup_settled, giveup_dropped) = run(false);
        let (retry_settled, retry_dropped) = run(true);

        eprintln!("[sim] give-up: settled={giveup_settled} dropped={giveup_dropped}");
        eprintln!("[sim] retry  : settled={retry_settled} dropped={retry_dropped}");

        // Reproduces starvation: a give-up settle drops fills under churn ...
        assert!(
            giveup_dropped > 0,
            "give-up strategy should drop fills under MM order churn (starvation)"
        );
        // ... and Approach A (retry) recovers strictly more of them.
        assert!(
            retry_settled > giveup_settled,
            "retry strategy must settle strictly more than give-up (giveup={giveup_settled}, retry={retry_settled})"
        );
    }

    /// L4 — settlement-strategy comparison across a small churn sweep, for
    /// ticket 2026-06-02-relayer-matching-settlement-concurrency-audit.
    /// Scores candidate strategies on the SAME workload at rising MM
    /// contention. give-up + retry are MEASURED against the real preemptive
    /// queue (tx-direct); priority-preempt and separate-lane are PROJECTED
    /// (they need state-machine changes not yet built) to show whether
    /// they're worth implementing. Synchronous + deterministic.
    #[test]
    fn sim_strategy_comparison() {
        const TICKS: usize = 60;
        // (label, commit_ticks, gap_ticks, match_every): rising contention.
        let sweep = [
            ("light  busy~50% sparse", 2usize, 2usize, 3usize),
            ("heavy  busy~75% moderate", 6usize, 2usize, 3usize),
            ("saturated busy~75% dense", 6usize, 2usize, 1usize),
        ];

        fn busy_at(tick: usize, commit: usize, gap: usize) -> bool {
            (tick % (commit + gap)) < commit
        }

        // MEASURED give-up / retry against the real preemptive queue (tx-direct).
        fn run_measured(
            retry: bool,
            ticks: usize,
            commit: usize,
            gap: usize,
            me: usize,
        ) -> (usize, usize) {
            let db = mock_db();
            let tx = db.new_write_tx().unwrap();
            let mm = TaskQueueKey::new_v4();
            let taker = TaskQueueKey::new_v4();

            let mut busy: Option<TaskIdentifier> = None;
            let (mut settled, mut total, mut pending) = (0usize, 0usize, 0usize);
            for tick in 0..ticks {
                let want_busy = busy_at(tick, commit, gap);
                if want_busy && busy.is_none() {
                    let mut order = mock_queued_task(mm);
                    order.state =
                        QueuedTaskState::Running { state: "order".to_string(), committed: true };
                    tx.enqueue_serial_task(&mm, &order).unwrap();
                    busy = Some(order.id);
                } else if !want_busy && busy.is_some() {
                    tx.pop_task(&busy.take().unwrap()).unwrap();
                }
                if tick % me == 0 {
                    total += 1;
                    if retry {
                        pending += 1;
                    } else {
                        let s = mock_queued_task(mm);
                        if tx.preempt_queue_with_serial(&[mm, taker], &s).is_ok() {
                            tx.pop_task(&s.id).unwrap();
                            settled += 1;
                        }
                    }
                }
                if retry && pending > 0 && busy.is_none() {
                    let s = mock_queued_task(mm);
                    if tx.preempt_queue_with_serial(&[mm, taker], &s).is_ok() {
                        tx.pop_task(&s.id).unwrap();
                        settled += 1;
                        pending -= 1;
                    }
                }
            }
            (settled, total)
        }

        // MEASURED priority order-yield against the real preemptive queue
        // (tx-direct). Order-management tasks YIELD before committing, so the MM
        // order head is NON-committed (preemptable) for its whole busy window
        // EXCEPT the last tick (its `SubmittingTx`, modeled committed). A settle
        // preempts a non-committed head (the real queue allows it) at a rollback
        // cost; during the brief committed tick it cannot (Rule 1) and defers.
        // Returns (settled, rollbacks).
        fn run_measured_priority(
            ticks: usize,
            commit: usize,
            gap: usize,
            me: usize,
        ) -> (usize, usize) {
            let db = mock_db();
            let tx = db.new_write_tx().unwrap();
            let mm = TaskQueueKey::new_v4();
            let taker = TaskQueueKey::new_v4();
            let mut head: Option<(TaskIdentifier, bool)> = None; // (id, committed)
            let (mut settled, mut rollbacks, mut pending) = (0usize, 0usize, 0usize);
            for tick in 0..ticks {
                let want_busy = busy_at(tick, commit, gap);
                // The order commits only on the last busy tick (its SubmittingTx).
                let commit_tick = want_busy && !busy_at(tick + 1, commit, gap);
                let desired = if want_busy { Some(commit_tick) } else { None };
                if head.map(|(_, c)| c) != desired {
                    if let Some((id, _)) = head.take() {
                        tx.pop_task(&id).unwrap();
                    }
                    if let Some(committed) = desired {
                        let mut order = mock_queued_task(mm);
                        order.state =
                            QueuedTaskState::Running { state: "order".to_string(), committed };
                        tx.enqueue_serial_task(&mm, &order).unwrap();
                        head = Some((order.id, committed));
                    }
                }
                if tick % me == 0 {
                    pending += 1;
                }
                // Drain pending settles; preempt succeeds unless the head is committed.
                while pending > 0 {
                    let s = mock_queued_task(mm);
                    if tx.preempt_queue_with_serial(&[mm, taker], &s).is_ok() {
                        tx.pop_task(&s.id).unwrap();
                        settled += 1;
                        pending -= 1;
                        // Preempting a running (non-committed) order forces a re-run.
                        if matches!(head, Some((_, false))) {
                            rollbacks += 1;
                        }
                    } else {
                        break; // head committed (irreversible) -> defer to a later tick
                    }
                }
            }
            (settled, rollbacks)
        }
        // PROJECTED separate settlement lane: every match settles, no rollback.
        fn project_lane(ticks: usize, me: usize) -> usize {
            (0..ticks).filter(|t| t % me == 0).count()
        }
        // PROJECTED defer-not-reject + run-on-pop priority: a settle blocked by a
        // committed head is HELD (not rejected) and fires on the next free wallet
        // tick, ahead of new order tasks. Zero drops (every match eventually
        // settles) and zero rollbacks (it never preempts a committed task — Rule
        // 1). But because it must WAIT for committed heads to pop, it's bounded by
        // the wallet's free-window capacity: settled-within-window =
        // min(total matches, free ticks). So it does NOT exceed the single-lane
        // ceiling — it does not reach 100% under saturation. Returns
        // (settled_in_window, dropped) where dropped is always 0.
        fn project_defer(ticks: usize, commit: usize, gap: usize, me: usize) -> (usize, usize) {
            let total = (0..ticks).filter(|t| t % me == 0).count();
            let free = (0..ticks).filter(|t| !busy_at(*t, commit, gap)).count();
            (total.min(free), 0)
        }

        eprintln!("[L4] settlement strategy success (settled/total) across rising MM contention:");
        let (mut giveup_tot, mut retry_tot) = (0usize, 0usize);
        let (mut sat_retry, mut sat_defer, mut sat_priority, mut sat_total) =
            (0usize, 0usize, 0usize, 0usize);
        for (label, commit, gap, me) in sweep {
            let (g, total) = run_measured(false, TICKS, commit, gap, me);
            let (r, _) = run_measured(true, TICKS, commit, gap, me);
            let (d, _d_drop) = project_defer(TICKS, commit, gap, me);
            let (p, p_roll) = run_measured_priority(TICKS, commit, gap, me);
            let l = project_lane(TICKS, me);
            eprintln!(
                "[L4]   {label:<26}  give-up {g:>2}/{total}   retry {r:>2}/{total}   defer {d:>2}/{total} (0 rb)   priority {p:>2}/{total} (+{p_roll} rb)   sep-lane {l:>2}/{total}"
            );
            giveup_tot += g;
            retry_tot += r;
            if label.starts_with("saturated") {
                sat_retry = r;
                sat_defer = d;
                sat_priority = p;
                sat_total = total;
            }
        }

        // Findings, asserted:
        //  - retry never settles fewer than give-up, and beats it under contention;
        //  - under saturation (matches outrun free windows) retry CANNOT keep up —
        //    evidence that a busy MM needs the architectural fix (priority / lane,
        //    which settle 100% in projection), not just bot-side retry.
        assert!(retry_tot >= giveup_tot, "retry must never settle fewer than give-up");
        assert!(retry_tot > giveup_tot, "retry should beat give-up under contention");
        assert!(
            sat_retry < sat_total,
            "under saturation retry must fall short of total (only priority/lane settle all)"
        );
        // DEFER findings (these CORRECT the ticket's draft, which claimed defer
        // settles 100% under saturation):
        //  - defer captures at least as many free windows as the engine-side retry
        //    (it's deterministic / state-layer-held, can't be raced or lost), so it
        //    never settles fewer; and
        //  - defer is STILL bounded by the wallet's free-window capacity — it cannot
        //    preempt a committed head (Rule 1) — so it does NOT reach total under
        //    saturation. Only priority (order-yield, at a rollback cost) or a separate
        //    lane settle all. Defer's value is determinism and zero-drop, NOT raw
        //    saturation throughput.
        assert!(
            sat_defer >= sat_retry,
            "defer must capture at least as many windows as retry (sat_defer={sat_defer}, sat_retry={sat_retry})"
        );
        assert!(
            sat_defer < sat_total,
            "defer is free-window-bounded and must NOT reach total under saturation \
             (sat_defer={sat_defer}, sat_total={sat_total}) — refutes the 100% claim"
        );
        // PRIORITY (order-yield) — MEASURED: by yielding before commit, the settle
        // preempts the (non-committed) order, so it settles strictly more than the
        // free-window-bounded strategies (retry/defer) under saturation — at a
        // rollback cost, and short only of the brief committed SubmittingTx window.
        assert!(
            sat_priority > sat_defer,
            "priority order-yield must beat the free-window-bounded strategies under saturation \
             (sat_priority={sat_priority}, sat_defer={sat_defer})"
        );
        // ROI ranking (relaxed goal: improve rates, not strictly 100%):
        //  - retry: simplest (one-file engine retry), 0 rollback, recovers most loss at
        //    low/moderate contention; collapses to give-up only at full saturation.
        //  - defer: retry made deterministic/lossless (state-machine change); same
        //    throughput.
        //  - priority: highest single-lane rate (preempts non-committed orders) but
        //    pays rollbacks; needs order-yield-before-commit plumbing.
        //  - lane: the ceiling (no rollback) but needs the disjoint-state proof +
        //    rework.
        // => ship retry first (high ROI, low risk); escalate to priority/lane only if
        //    the saturated tail stays material.
        eprintln!(
            "[L4] ROI: retry recovers most loss cheaply at low/moderate contention; \
             priority adds the saturated tail at a rollback cost; lane is the ceiling."
        );
    }

    /// Tests transitioning the state of a task
    #[tokio::test]
    async fn test_transition() {
        let state = mock_state().await;

        // Propose a new task to the queue
        let key = TaskQueueKey::new_v4();
        let task = mock_queued_task(key).descriptor;

        let (task_id, waiter) = state.append_task(task).await.unwrap();
        waiter.await.unwrap();

        // Transition the task to a new state
        let waiter = state
            .transition_task(
                task_id,
                QueuedTaskState::Running { state: "Test".to_string(), committed: false },
            )
            .await
            .unwrap();
        waiter.await.unwrap();

        // Check that the task was transitioned
        let task = state.get_task(&task_id).await.unwrap().unwrap();
        assert_eq!(
            task.state,
            QueuedTaskState::Running { state: "Test".to_string(), committed: false }
        );
    }

    /// Tests fetching task history
    #[tokio::test]
    async fn test_task_history() {
        const N: usize = 10;
        let state = mock_state().await;
        let account_id = AccountId::new_v4();

        // Add historical tasks
        for _ in 0..N {
            // First push to the queue then pop
            let task = mock_task_descriptor(account_id);
            let (task_id, waiter) = state.append_task(task).await.unwrap();
            waiter.await.unwrap();

            let waiter = state.pop_task(task_id, true /* success */).await.unwrap();
            waiter.await.unwrap();
        }

        // Add a few running tasks
        for _ in 0..N / 2 {
            let task = mock_task_descriptor(account_id);
            let (_, waiter) = state.append_task(task).await.unwrap();
            waiter.await.unwrap();
        }

        // Fetch the task history
        let history = state.get_task_history(N, &account_id).await.unwrap();
        assert_eq!(history.len(), N);
        assert!(matches!(history[0].state, QueuedTaskState::Running { .. }));
        for task in history.iter().take(N / 2).skip(1) {
            assert_eq!(task.state, QueuedTaskState::Queued);
        }

        for task in history.iter().skip(N / 2) {
            assert!(matches!(task.state, QueuedTaskState::Completed));
        }
    }
}
