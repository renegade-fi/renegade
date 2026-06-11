//! Storage implementation for task queue operations

use libmdbx::{RW, TransactionKind};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use types_tasks::{QueuedTask, QueuedTaskState, TaskIdentifier, TaskQueueKey};
use util::res_some;

use crate::{
    TASK_QUEUE_TABLE, TASK_TO_KEY_TABLE,
    storage::{
        error::StorageError,
        traits::RkyvValue,
        tx::task_queue::queue_type::{TaskQueueValue, TaskValue},
    },
};

use super::super::StateTxn;
use super::queue_type::{TaskQueue, TaskQueuePreemptionState};

/// The error message emitted when a task is not found
const ERR_TASK_NOT_FOUND: &str = "task not found";
/// The error message emitted when a task cannot be popped from the queue
const ERR_TASK_NOT_POPPED: &str = "task not popped from queue";
/// The error message emitted when a task cannot be preempted
const ERR_CANNOT_SERIALLY_PREEMPT: &str = "serial preemption not allowed";
/// The error message emitted when a queue's deferred-preemption FIFO is at
/// capacity. Distinct from `ERR_CANNOT_SERIALLY_PREEMPT` so the two reject
/// causes are distinguishable in logs: this one means Stage 3 IS deferring but
/// per-account settlement throughput can't drain the FIFO fast enough
/// (backpressure / saturation); `ERR_CANNOT_SERIALLY_PREEMPT` surfacing from
/// `do_preempt_serial_inner` instead would indicate an apply-time recheck
/// failure (a bug), not saturation.
const ERR_PENDING_QUEUE_FULL: &str = "serial preemption deferred-queue full";
/// The error message emitted when a task cannot be preempted concurrently
const ERR_CANNOT_CONCURRENTLY_PREEMPT: &str = "concurrent preemption not allowed";

/// Feature flag gating Stage 1 "defer-not-reject" of serial preemptions.
///
/// When `false` (the default) `preempt_queue_with_serial` rejects a preemption
/// whose target queue head is committed -- identical to the pre-Stage-1
/// behavior. When `true`, the blocked settle is instead recorded as pending and
/// re-run automatically when the committing task completes.
///
/// This is an apply-path behavior change on raft-replicated state, so it ships
/// `false`: land the (additive) defer machinery with zero behavior change, then
/// flip this to `true` in a one-line follow-up commit once verified on testnet.
/// Every node MUST run the same value (a mixed-version window diverges, as with
/// any apply-path change). This `const` is not per-chain: a build with it
/// `true` enables defer on any cluster that takes the image, so mainnet is
/// gated by deploy targeting (only push the new image to sepolia-v2 until
/// proven).
#[cfg_attr(test, allow(dead_code))]
const ENABLE_SETTLE_DEFER: bool = true;

/// Whether defer-not-reject is enabled. In production this is the compile-time
/// `ENABLE_SETTLE_DEFER` const (inlined, zero cost). In test builds it reads a
/// per-thread override (default `false`) so the defer path can be exercised
/// without changing the behavior of the existing reject tests.
#[cfg(not(test))]
#[inline]
fn settle_defer_enabled() -> bool {
    ENABLE_SETTLE_DEFER
}

#[cfg(test)]
thread_local! {
    static TEST_SETTLE_DEFER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn settle_defer_enabled() -> bool {
    TEST_SETTLE_DEFER.with(|c| c.get())
}

/// Test-only: enable or disable defer-not-reject for the current thread
#[cfg(test)]
pub(crate) fn set_test_settle_defer(enabled: bool) {
    TEST_SETTLE_DEFER.with(|c| c.set(enabled));
}

/// Feature flag gating Stage 2 "order-yield": when a serial settlement
/// preemption is blocked by a COMMITTED but *yieldable* order-management head
/// (an MM requote), preempt it anyway -- the order is requeued and re-run (a
/// rollback) -- so settlement isn't starved by a perpetually-requoting wallet.
/// Bounded per queue by `MAX_CONSECUTIVE_YIELDS` so requotes aren't starved in
/// turn. Off by default: this is an apply-path behavior change (land dark, flip
/// after testnet) and also requires the task-driver to abort a yielded
/// committed order task.
#[cfg_attr(test, allow(dead_code))]
const ENABLE_ORDER_YIELD: bool = true;

/// Max consecutive settle-yields of a queue's order head before the order is
/// allowed to commit (per-queue fairness; prevents requote starvation).
const MAX_CONSECUTIVE_YIELDS: u32 = 3;

#[cfg(not(test))]
#[inline]
fn order_yield_enabled() -> bool {
    ENABLE_ORDER_YIELD
}

#[cfg(test)]
thread_local! {
    static TEST_ORDER_YIELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn order_yield_enabled() -> bool {
    TEST_ORDER_YIELD.with(|c| c.get())
}

/// Test-only: enable or disable order-yield for the current thread
#[cfg(test)]
pub(crate) fn set_test_order_yield(enabled: bool) {
    TEST_ORDER_YIELD.with(|c| c.set(enabled));
}

/// Feature flag gating Stage 4 "two-queue settle fairness".
///
/// A `SettleExternalMatch` preempts ONE queue (the taker is off-chain), while a
/// `SettleInternalMatch`/`SettlePrivateMatch` preempts TWO (both
/// counterparties, all-or-nothing). When the shared (quoter) queue is
/// momentarily free, an arriving single-queue settle takes the immediate fast
/// path and runs even though a lower-`seq` two-queue settle is already waiting
/// in that queue's pending FIFO for its OTHER queue to free -- the single-queue
/// settle keeps stealing the window, so the two-queue settle starves (observed:
/// internal + MM matches at ~100% `deferred-queue full`, 0 fills).
///
/// When enabled, an arriving serial preemption that shares a queue with any
/// already-pending (lower-`seq`) preemption must NOT take the immediate fast
/// path -- it defers into the FIFO behind the waiting entries, so the queue
/// stays free for the older two-queue settle to drain in `seq` order. No
/// liquidity fragmentation; orders stay dual-book. Requires
/// `ENABLE_SETTLE_DEFER` (the FIFO is the defer machinery). Reverse starvation
/// (a single-queue settle behind a two-queue settle whose other queue is busy)
/// is naturally bounded by the counterparty's task duration -- the two-queue
/// settle becomes runnable within one task of both queues being free; an
/// explicit cap can be added if telemetry shows external-settle regression.
///
/// Apply-path behavior change on raft-replicated state: every node MUST run the
/// same value; gated to sepolia-v2 by deploy targeting (not per-chain in code).
///
/// Disabled 2026-06-07: once the cancel-flood fixes (remove-consumed-orders +
/// idempotent/yieldable cancel + per-quoter rebalance lock) made quoter queues
/// idle, fairness WEDGED settlement. The deferred-preemption FIFO drains ONLY
/// on `pop_task`; with fairness on, a runnable settle on a FREE queue still
/// defers (FIFO non-empty), and with the queue idle nothing pops -> the drain
/// never fires -> 0 fills (see `sim_stage4_idle_queue_wedge`). Disabling
/// restores the fast path: a settle on a free queue runs immediately and its
/// completion pops, draining the FIFO. Re-enable only after the drain also
/// triggers on enqueue-when-safe (not just on pop).
#[cfg_attr(test, allow(dead_code))]
const ENABLE_SETTLE_FAIRNESS: bool = false;

#[cfg(not(test))]
#[inline]
fn fairness_enabled() -> bool {
    ENABLE_SETTLE_FAIRNESS
}

#[cfg(test)]
thread_local! {
    static TEST_SETTLE_FAIRNESS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn fairness_enabled() -> bool {
    TEST_SETTLE_FAIRNESS.with(|c| c.get())
}

/// Test-only: enable or disable two-queue settle fairness for the current
/// thread
#[cfg(test)]
pub(crate) fn set_test_settle_fairness(enabled: bool) {
    TEST_SETTLE_FAIRNESS.with(|c| c.set(enabled));
}

/// The outcome of a serial preemption attempt
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreemptOutcome {
    /// The queues were preempted; the task is enqueued and may run
    Preempted,
    /// The preemption was blocked by a committed head and has been recorded as
    /// pending; it will run automatically when the blocking task(s) complete
    Deferred,
}

/// The disposition of a queue's `SerialPreemptionQueued` head, classified by
/// `orphaned_preempt_head` so the self-heal can apply the right safety gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WedgedHeadKind {
    /// Head task exists and is committed -- a settle orphaned mid-submit.
    Committed,
    /// Head task exists but is not committed -- a settle never driven past
    /// `Pending` because its executor departed before stepping it.
    Uncommitted,
    /// Head id is present in `serial_tasks` but has NO backing task -- a
    /// dangling reference left when a multi-queue settle's task was deleted
    /// by a clear of its other counterparty queue. Unambiguously broken
    /// (the head can never pop; transitions reject `task not found`).
    Dangling,
}

/// Max deferred settle preemptions retained per queue (Stage 3 multi-pending
/// FIFO). Bounds buildup: a target queue at this depth rejects further serial
/// preemptions as backpressure rather than buffering without limit.
///
/// Raised 16 -> 64: testnet hot quoter accounts saturated the 16-deep FIFO
/// under real internal-match flow (`serial preemption deferred-queue full`
/// rejects), so absorb larger bursts. This only buys headroom; the underlying
/// limit is per-account serial settlement throughput (1/T).
const MAX_PENDING_PER_QUEUE: usize = 64;

/// A deferred (pending) serial preemption, recorded against every queue it must
/// preempt.
///
/// Entries carry a global monotonic `seq` assigned at enqueue. Because enqueues
/// apply in committed-log order, `seq` is deterministic and identical on every
/// raft node (mandatory: the completion hook runs on the apply path). A pending
/// settle runs only when it is the lowest-`seq` entry of EVERY target queue and
/// all those queues are serial-preemption-safe. The global total order means
/// the globally-lowest pending settle is always the head of all its queues, so
/// progress is guaranteed and the "two settles each waiting on the other's
/// queue" deadlock -- which the previous one-pending-per-queue rule prevented
/// -- cannot occur.
#[derive(Clone, Debug, Archive, RkyvSerialize, RkyvDeserialize)]
pub(crate) struct PendingEntry {
    /// The deferred preemptive (settle) task
    pub task: QueuedTask,
    /// The full set of queues the task must preempt (all-or-nothing)
    pub target_keys: Vec<TaskQueueKey>,
    /// Global monotonic sequence number for total ordering
    pub seq: u64,
}

/// Get the storage key for a task queue
pub fn task_queue_key(key: &TaskQueueKey) -> String {
    format!("task-queue-{}", key)
}

/// Get the storage key for a task
fn task_key(id: &TaskIdentifier) -> String {
    format!("task-{}", id)
}

/// Get the storage key for the task to queue(s) mapping
fn task_to_queue_key(id: &TaskIdentifier) -> String {
    format!("task-to-queue-{id}")
}

/// Get the storage key for a queue's ordered list of deferred preemptive
/// settles (Stage 3 multi-pending FIFO)
fn pending_preempt_list_key(key: &TaskQueueKey) -> String {
    format!("pending-preempt-list-{key}")
}

/// Get the storage key for the global pending-preemption sequence counter
fn pending_preempt_seq_key() -> String {
    "pending-preempt-seq".to_string()
}

/// Get the storage key for a queue's consecutive-yield fairness counter
fn yield_count_key(key: &TaskQueueKey) -> String {
    format!("yield-count-{key}")
}

// -----------------
// | Query Methods |
// -----------------

impl<T: TransactionKind> StateTxn<'_, T> {
    /// Check whether a task queue is empty
    pub fn is_queue_empty(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        let empty = queue.map(|q| q.is_empty()).unwrap_or(true);
        Ok(empty)
    }

    /// Check whether a task queue has any active concurrent tasks
    pub fn concurrent_tasks_active(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        let active = queue.map(|q| !q.concurrent_tasks.is_empty()).unwrap_or(false);
        Ok(active)
    }

    /// Check whether a task queue has any active serial tasks
    pub fn serial_tasks_active(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        let active = queue.map(|q| !q.serial_tasks.is_empty()).unwrap_or(false);
        Ok(active)
    }

    /// Get the task specified by the given ID
    pub fn get_task(&self, id: &TaskIdentifier) -> Result<Option<TaskValue<'_>>, StorageError> {
        let key = task_key(id);
        self.inner().read::<_, QueuedTask>(TASK_QUEUE_TABLE, &key)
    }

    /// Get the task specified by the given ID (deserialized)
    pub fn get_task_deserialized(
        &self,
        id: &TaskIdentifier,
    ) -> Result<Option<QueuedTask>, StorageError> {
        let task = self.get_task(id)?;
        task.map(|archived| archived.deserialize()).transpose()
    }

    /// Get the next serial task that can run on the given queue
    ///
    /// We do not return concurrent tasks here, as those are assumed to be
    /// started optimistically
    pub fn next_runnable_task(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Option<TaskValue<'_>>, StorageError> {
        let queue = self.get_task_queue(key)?;
        let Some(queue) = queue else {
            return Ok(None);
        };

        let tid = res_some!(queue.next_serial_task());
        self.get_task(&tid)
    }

    /// Get the queue key for a given task
    pub fn get_queue_keys_for_task(
        &self,
        id: &TaskIdentifier,
    ) -> Result<Vec<TaskQueueKey>, StorageError> {
        let key = task_to_queue_key(id);
        self.inner()
            .read::<_, Vec<TaskQueueKey>>(TASK_TO_KEY_TABLE, &key)?
            .map(|archived| archived.deserialize())
            .transpose()
            .map(|opt| opt.unwrap_or_default())
    }

    /// Check whether a given task queue is preemptable
    pub fn is_queue_preemptable(
        &self,
        key: &TaskQueueKey,
        serial: bool,
    ) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        let Some(queue) = queue else {
            // Empty queue can be preempted
            return Ok(true);
        };

        let res = if serial { queue.can_preempt_serial() } else { queue.can_preempt_concurrent() };
        Ok(res)
    }

    /// Check whether the given task can run on its queues
    ///
    /// A task may run iff it can run on all queues it is indexed into
    pub fn can_task_run(&self, id: &TaskIdentifier) -> Result<bool, StorageError> {
        let queues = self.get_queue_keys_for_task(id)?;
        for queue_key in queues.iter() {
            let queue = self.get_task_queue(queue_key)?;
            let Some(queue) = queue else {
                // Task not in queue, can't run
                return Ok(false);
            };

            if !queue.can_task_run(id) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get the queued tasks for a given key
    pub fn get_queued_tasks(&self, key: &TaskQueueKey) -> Result<Vec<TaskValue<'_>>, StorageError> {
        let queue = self.get_task_queue(key)?;
        let Some(queue) = queue else {
            return Ok(Vec::new());
        };

        let task_ids = queue.all_tasks();
        let mut tasks = Vec::with_capacity(task_ids.len());
        for task_id in task_ids.iter() {
            if let Some(task) = self.get_task(task_id)? {
                tasks.push(task);
            }
        }

        Ok(tasks)
    }

    // --- Helpers --- //

    /// Returns whether a given queue is serially preemptable
    pub(crate) fn is_serial_preemption_safe(
        &self,
        key: &TaskQueueKey,
    ) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        let Some(queue) = queue else {
            // Empty queue can be preempted
            return Ok(true);
        };

        let mut can_preempt = queue.can_preempt_serial();
        if let Some(t) = queue.serial_tasks.first() {
            let task = self.get_task(t)?.ok_or(StorageError::reject(ERR_TASK_NOT_FOUND))?;
            let state = QueuedTaskState::from_archived(&task.state)?;
            can_preempt = can_preempt && !state.is_committed();
        }

        Ok(can_preempt)
    }

    /// If this queue is wedged in `SerialPreemptionQueued`, return its head
    /// preemptive task id paired with the head's disposition, else `None`.
    ///
    /// Three orphaned-settle wedges leave a queue stuck here forever
    /// (`can_preempt_serial()` false, no further settle can run):
    /// - `Committed`: a settle preempted the queue and reached its on-chain
    ///   submit, then its worker departed (restart / new p2p id) without
    ///   completing the task.
    /// - `Uncommitted`: a settle preempted the queue but was never driven past
    ///   `Pending` -- its assigned executor departed (worker churn, seed
    ///   p2p-identity change on `-replace`) before stepping it even once, so it
    ///   never committed and never completes.
    /// - `Dangling`: the head id is present but has NO backing task -- a settle
    ///   that preempted both counterparties' queues had its task deleted by a
    ///   clear of the *other* queue, leaving this queue's head a dead reference
    ///   that can never pop and rejects every transition with `task not found`.
    ///
    /// The caller applies the right safety gate per kind (see
    /// `should_reap_wedged_head`): an uncommitted head needs an age gate to
    /// distinguish it from a healthy settle still on its way to running, while
    /// a dangling head is unambiguously broken and reaped unconditionally.
    pub(crate) fn orphaned_preempt_head(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Option<(TaskIdentifier, WedgedHeadKind)>, StorageError> {
        let queue = self.get_task_queue_deserialized(key)?;
        if queue.preemption_state != TaskQueuePreemptionState::SerialPreemptionQueued {
            return Ok(None);
        }
        let Some(head_id) = queue.serial_tasks.first().copied() else {
            return Ok(None);
        };
        let kind = match self.get_task_deserialized(&head_id)? {
            Some(task) if task.state.is_committed() => WedgedHeadKind::Committed,
            Some(_) => WedgedHeadKind::Uncommitted,
            None => WedgedHeadKind::Dangling,
        };
        Ok(Some((head_id, kind)))
    }

    /// Whether the committed head of a queue is a YIELDABLE order-management
    /// task (Stage 2 order-yield). False for an empty queue, a
    /// non-committed head, or a non-yieldable head (settlement / account
    /// op).
    pub(crate) fn head_is_yieldable(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let Some(queue) = self.get_task_queue(key)? else {
            return Ok(false);
        };
        let Some(t) = queue.serial_tasks.first() else {
            return Ok(false);
        };
        let task =
            self.get_task_deserialized(t)?.ok_or(StorageError::reject(ERR_TASK_NOT_FOUND))?;
        Ok(task.state.is_committed() && task.descriptor.is_yieldable())
    }

    /// Read a queue's consecutive-yield fairness counter (0 if unset)
    pub(crate) fn yield_count(&self, key: &TaskQueueKey) -> Result<u32, StorageError> {
        let count_key = yield_count_key(key);
        Ok(self
            .inner()
            .read::<_, u32>(TASK_QUEUE_TABLE, &count_key)?
            .map(|archived| archived.deserialize())
            .transpose()?
            .unwrap_or(0))
    }

    /// Read a queue's ordered list of deferred preemptive settles. Entries are
    /// stored in append (seq-ascending) order.
    pub(crate) fn get_pending_preempt_list(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Vec<PendingEntry>, StorageError> {
        let list_key = pending_preempt_list_key(key);
        Ok(self
            .inner()
            .read::<_, Vec<PendingEntry>>(TASK_QUEUE_TABLE, &list_key)?
            .map(|archived| archived.deserialize())
            .transpose()?
            .unwrap_or_default())
    }

    /// The lowest-`seq` (head) deferred settle on a queue, if any.
    pub(crate) fn pending_preempt_head(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Option<PendingEntry>, StorageError> {
        Ok(self.get_pending_preempt_list(key)?.into_iter().min_by_key(|e| e.seq))
    }

    /// Whether a queue has any deferred preemptive settle recorded.
    ///
    /// Test-only query helper since Stage 3 (the production defer path uses the
    /// FIFO depth, not a boolean presence check).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn has_pending_preemption(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        Ok(!self.get_pending_preempt_list(key)?.is_empty())
    }

    /// Whether `entry` is the lowest-`seq` (head) entry of the given queue.
    pub(crate) fn is_pending_head(
        &self,
        entry: &PendingEntry,
        key: &TaskQueueKey,
    ) -> Result<bool, StorageError> {
        match self.pending_preempt_head(key)? {
            Some(head) => Ok(head.seq == entry.seq),
            None => Ok(false),
        }
    }

    /// Get the task queue for a given key
    pub(crate) fn get_task_queue(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Option<TaskQueueValue<'_>>, StorageError> {
        let key = task_queue_key(key);
        self.inner().read::<_, TaskQueue>(TASK_QUEUE_TABLE, &key)
    }

    /// Get the task queue for a given key (deserialized)
    ///
    /// Helper method for mutation operations that need an owned `TaskQueue`.
    /// Returns a default `TaskQueue` if the queue doesn't exist.
    pub(crate) fn get_task_queue_deserialized(
        &self,
        key: &TaskQueueKey,
    ) -> Result<TaskQueue, StorageError> {
        Ok(self
            .get_task_queue(key)?
            .map(|archived| archived.deserialize())
            .transpose()?
            .unwrap_or_default())
    }
}

// --------------------
// | Mutation Methods |
// --------------------

impl StateTxn<'_, RW> {
    /// Add a serial task to the queue
    ///
    /// Unlike the preemptive tasks, normal serial tasks are only indexed into a
    /// single queue
    pub fn enqueue_serial_task(
        &self,
        key: &TaskQueueKey,
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        let mut queue = self.get_task_queue_deserialized(key)?;
        queue.enqueue_serial_task(task.id);

        self.write_task_queue(key, &queue)?;
        self.write_task(&task.id, vec![*key], task)
    }

    /// Preempt a set of queues with a serial task.
    ///
    /// The preemption spans all `queues` and is all-or-nothing: if any target
    /// queue head is committed, no queue is preempted. With
    /// `ENABLE_SETTLE_DEFER` off, that case is rejected (`Err`). With it
    /// on, the task is recorded as a pending preemption against every
    /// target queue and `Deferred` is returned; the completion hook re-runs
    /// it once the committing task(s) finish.
    pub fn preempt_queue_with_serial(
        &self,
        queues: &[TaskQueueKey],
        task: &QueuedTask,
    ) -> Result<PreemptOutcome, StorageError> {
        // First pass: classify queues. A queue is preemptable now if it is
        // serial-preemption-safe (free / non-committed head), or -- under Stage 2
        // order-yield -- its committed head is a yieldable order-management task
        // still within its per-queue fairness budget.
        let mut hard_blocked = false;
        for queue_key in queues.iter() {
            if self.is_serial_preemption_safe(queue_key)? {
                continue;
            }
            if order_yield_enabled()
                && self.head_is_yieldable(queue_key)?
                && self.yield_count(queue_key)? < MAX_CONSECUTIVE_YIELDS
            {
                continue; // committed yieldable head within budget -> will yield
            }
            hard_blocked = true;
            break;
        }

        // Stage 4 fairness: even when no queue is hard-blocked, do not let this
        // preemption jump the FIFO via the immediate fast path if it shares a
        // queue with an already-pending (lower-`seq`) preemption. Forcing it to
        // defer keeps the shared queue free for the older (often two-queue)
        // settle to drain in `seq` order, instead of single-queue settles
        // perpetually stealing the window. Only meaningful with the defer FIFO.
        let mut fairness_defer = false;
        if fairness_enabled() && settle_defer_enabled() {
            for queue_key in queues.iter() {
                if !self.get_pending_preempt_list(queue_key)?.is_empty() {
                    fairness_defer = true;
                    break;
                }
            }
        }

        if !hard_blocked && !fairness_defer {
            // Bump the fairness counter for every queue whose committed head we
            // are about to yield, before the requeue rewrites the head.
            if order_yield_enabled() {
                for queue_key in queues.iter() {
                    if self.head_is_yieldable(queue_key)? {
                        self.bump_yield_count(queue_key)?;
                    }
                }
            }
            self.do_preempt_serial_inner(queues, task, order_yield_enabled())?;
            return Ok(PreemptOutcome::Preempted);
        }

        // Hard-blocked. If a yield was refused only because the fairness cap was
        // hit, reset that queue's counter so its order task gets a turn to commit;
        // then fall through to defer (Stage 1).
        if order_yield_enabled() {
            for queue_key in queues.iter() {
                if self.head_is_yieldable(queue_key)?
                    && self.yield_count(queue_key)? >= MAX_CONSECUTIVE_YIELDS
                {
                    self.reset_yield_count(queue_key)?;
                }
            }
        }

        // Without defer this is the historical reject.
        if !settle_defer_enabled() {
            return Err(StorageError::reject(ERR_CANNOT_SERIALLY_PREEMPT));
        }

        // Defer (Stage 3 multi-pending FIFO). Append the settle to every target
        // queue's bounded list, ordered by a global `seq`. No queue is preempted
        // (all-or-nothing); the completion hook runs the real preemption once the
        // settle is the lowest-`seq` entry of every target queue and all are
        // safe. The total `seq` order makes multi-pending deadlock-free, so we no
        // longer reject merely because a queue already holds a pending settle.
        //
        // The only remaining reject is backpressure: a target queue already at
        // `MAX_PENDING_PER_QUEUE` bounds buildup. Checked first so the enqueue is
        // all-or-nothing (no partial append on reject).
        for queue_key in queues.iter() {
            let pending_depth = self.get_pending_preempt_list(queue_key)?.len();
            if pending_depth >= MAX_PENDING_PER_QUEUE {
                // DIAGNOSTIC: the FIFO is saturated and not draining. Dump what
                // is holding this queue -- the serial head task (type +
                // committed) and the preemption state -- so we can see WHY
                // deferred settles never run, instead of inferring it.
                let q = self.get_task_queue_deserialized(queue_key)?;
                let head = q
                    .serial_tasks
                    .first()
                    .copied()
                    .and_then(|id| self.get_task_deserialized(&id).ok().flatten());
                let (head_desc, head_committed, head_state) = match &head {
                    Some(t) => (
                        t.descriptor.display_description(),
                        t.state.is_committed(),
                        format!("{:?}", t.state),
                    ),
                    None => ("<none>".to_string(), false, "<none>".to_string()),
                };
                tracing::warn!(
                    queue = %queue_key,
                    preemption_state = ?q.preemption_state,
                    serial_len = q.serial_tasks.len(),
                    pending_fifo = pending_depth,
                    incoming = %task.descriptor.display_description(),
                    head = %head_desc,
                    head_committed,
                    head_state = %head_state,
                    "deferred-queue full: wedged queue head (FIFO saturated, not draining)"
                );
                return Err(StorageError::reject(ERR_PENDING_QUEUE_FULL));
            }
        }

        let seq = self.next_pending_seq()?;
        let entry = PendingEntry { task: task.clone(), target_keys: queues.to_vec(), seq };
        for queue_key in queues.iter() {
            self.append_pending_preemption(queue_key, &entry)?;
        }

        Ok(PreemptOutcome::Deferred)
    }

    /// Unconditionally preempt a set of queues with a serial task (no yield).
    ///
    /// Used by the Stage 1 completion hook, which only runs once every target
    /// queue is already serial-preemption-safe.
    pub(crate) fn do_preempt_serial(
        &self,
        queues: &[TaskQueueKey],
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        self.do_preempt_serial_inner(queues, task, false /* allow_yield */)
    }

    /// Preempt a set of queues with a serial task.
    ///
    /// With `allow_yield` (Stage 2), a committed head that is a yieldable
    /// order-management task is preempted anyway: it is requeued (re-run)
    /// rather than blocking. Re-checks safety defensively and rejects
    /// rather than corrupting state.
    fn do_preempt_serial_inner(
        &self,
        queues: &[TaskQueueKey],
        task: &QueuedTask,
        allow_yield: bool,
    ) -> Result<(), StorageError> {
        // Index the task into the queues
        for queue_key in queues.iter() {
            // 1. Check the queue can be preempted -- or, under order-yield, that its
            //    committed head is a yieldable order-management task.
            if !self.is_serial_preemption_safe(queue_key)?
                && !(allow_yield && self.head_is_yieldable(queue_key)?)
            {
                return Err(StorageError::reject(ERR_CANNOT_SERIALLY_PREEMPT));
            }

            // 2. Move the existing head back to the queued state (the yield, for a
            //    committed order task)
            let mut queue = self.get_task_queue_deserialized(queue_key)?;
            if let Some(t) = queue.serial_tasks.first() {
                self.requeue_task(t)?;
            }

            // 3. Preempt the queue
            if !queue.preempt_with_serial_task(task.id) {
                return Err(StorageError::reject(ERR_CANNOT_SERIALLY_PREEMPT));
            };
            self.write_task_queue(queue_key, &queue)?;
        }

        self.write_task(&task.id, queues.to_vec(), task)?;
        Ok(())
    }

    /// Add a concurrent task to the queue
    pub fn preempt_queue_with_concurrent(
        &self,
        queues: &[TaskQueueKey],
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        for queue_key in queues.iter() {
            let mut queue = self.get_task_queue_deserialized(queue_key)?;
            if !queue.preempt_with_concurrent_task(task.id) {
                return Err(StorageError::reject(ERR_CANNOT_CONCURRENTLY_PREEMPT));
            }

            self.write_task_queue(queue_key, &queue)?;
        }

        self.write_task(&task.id, queues.to_vec(), task)?;
        Ok(())
    }

    /// Pop a task from the queue
    pub fn pop_task(&self, id: &TaskIdentifier) -> Result<Option<QueuedTask>, StorageError> {
        let queue_keys = self.get_queue_keys_for_task(id)?;
        for key in queue_keys.iter() {
            // Pop the task from the queue then write back
            let mut queue = self.get_task_queue_deserialized(key)?;
            if !queue.pop_task(id) {
                return Err(StorageError::reject(ERR_TASK_NOT_POPPED));
            }

            self.write_task_queue(key, &queue)?;
        }

        let task = self.delete_task(id)?;
        Ok(task)
    }

    /// Clear a task queue, removing all tasks from it
    pub fn clear_task_queue(&self, key: &TaskQueueKey) -> Result<Vec<QueuedTask>, StorageError> {
        let queue = self.get_task_queue(key)?;
        let all_task_ids = queue.map(|q| q.all_tasks()).unwrap_or_default();
        let mut all_tasks = Vec::with_capacity(all_task_ids.len());
        for task_id in all_task_ids.iter() {
            // A serial settle preempts BOTH counterparties' queues, so a task in
            // this queue may also sit in another account's queue. Purge it from
            // every OTHER queue it spans before deleting it -- otherwise that
            // queue keeps a head id with no backing task (a `Dangling` wedge):
            // it stays `SerialPreemptionQueued` forever and rejects transitions
            // with `task not found`. `key` itself is reset to default below, so
            // skip it here. `pop_task` restores the other queue's preemption
            // state (NotPreempted) when the dead settle was its serial head.
            for other_key in self.get_queue_keys_for_task(task_id)? {
                if &other_key == key {
                    continue;
                }
                let mut other = self.get_task_queue_deserialized(&other_key)?;
                if other.pop_task(task_id) {
                    // Non-fatal write: popping the serial settle head sets
                    // `other` to NotPreempted, which violates check_invariants if
                    // B still holds a concurrent preemption alongside the serial
                    // settle (not produced in prod -- all preemptive callers are
                    // serial -- but representable). A propagated Err here would be
                    // fatal on the recovery path (recovery.rs clears every
                    // account in one tx), crash-looping the cluster. Skip the
                    // purge for that queue instead; the deleted task leaves a
                    // dangling head that the dangling-head self-heal reconciles.
                    if let Err(e) = self.write_task_queue(&other_key, &other) {
                        tracing::warn!(
                            queue = %other_key,
                            error = %e,
                            "skipped cross-queue purge of a multi-queue task (counterparty \
                             queue invariant); dangling-head self-heal will reconcile"
                        );
                    }
                }
            }
            if let Some(task) = self.delete_task(task_id)? {
                all_tasks.push(task);
            }
        }

        // Drop any deferred preemption recorded against this queue so a cleared
        // queue cannot leak a pending settle that never re-triggers.
        self.delete_pending_preemption(key)?;

        self.write_task_queue(key, &TaskQueue::default())?;
        Ok(all_tasks)
    }

    /// Transition the state of a given task
    pub fn transition_task(
        &self,
        id: &TaskIdentifier,
        new_state: QueuedTaskState,
    ) -> Result<(), StorageError> {
        let mut task = self
            .get_task_deserialized(id)?
            .ok_or_else(|| StorageError::reject(ERR_TASK_NOT_FOUND))?;

        task.state = new_state;
        self.update_task(id, &task)
    }

    // --- Helpers --- //

    /// Write the task queue to storage
    fn write_task_queue(&self, key: &TaskQueueKey, queue: &TaskQueue) -> Result<(), StorageError> {
        queue.check_invariants()?;
        let key = task_queue_key(key);
        self.inner().write(TASK_QUEUE_TABLE, &key, queue)
    }

    /// Write a task to storage
    fn write_task(
        &self,
        id: &TaskIdentifier,
        queues: Vec<TaskQueueKey>,
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        self.update_task(id, task)?;
        self.update_task_to_queues(id, queues)
    }

    /// Allocate the next global pending-preemption sequence number.
    ///
    /// Deterministic across raft nodes: enqueues apply in committed-log order,
    /// so every node assigns the same `seq` to the same settle.
    pub(crate) fn next_pending_seq(&self) -> Result<u64, StorageError> {
        let seq_key = pending_preempt_seq_key();
        let cur = self
            .inner()
            .read::<_, u64>(TASK_QUEUE_TABLE, &seq_key)?
            .map(|a| a.deserialize())
            .transpose()?
            .unwrap_or(0);
        let next = cur + 1;
        self.inner().write(TASK_QUEUE_TABLE, &seq_key, &next)?;
        Ok(next)
    }

    /// Append a deferred preemptive settle to a queue's pending list.
    pub(crate) fn append_pending_preemption(
        &self,
        key: &TaskQueueKey,
        entry: &PendingEntry,
    ) -> Result<(), StorageError> {
        let mut list = self.get_pending_preempt_list(key)?;
        list.push(entry.clone());
        let list_key = pending_preempt_list_key(key);
        self.inner().write(TASK_QUEUE_TABLE, &list_key, &list)
    }

    /// Remove a deferred preemptive settle (matched by `seq`) from every queue
    /// it targets, so no orphaned copy is left to block another queue's
    /// head.
    pub(crate) fn remove_pending_preemption_entry(
        &self,
        entry: &PendingEntry,
    ) -> Result<(), StorageError> {
        for key in entry.target_keys.iter() {
            let mut list = self.get_pending_preempt_list(key)?;
            list.retain(|e| e.seq != entry.seq);
            let list_key = pending_preempt_list_key(key);
            if list.is_empty() {
                self.inner().delete(TASK_QUEUE_TABLE, &list_key)?;
            } else {
                self.inner().write(TASK_QUEUE_TABLE, &list_key, &list)?;
            }
        }
        Ok(())
    }

    /// Drop all deferred preemptions recorded against a queue (e.g. on clear).
    ///
    /// Each entry is removed from every queue it targets so a cleared queue
    /// cannot leak a pending settle (here or in a co-targeted queue) that never
    /// re-triggers.
    pub(crate) fn delete_pending_preemption(&self, key: &TaskQueueKey) -> Result<(), StorageError> {
        let list = self.get_pending_preempt_list(key)?;
        for entry in list.iter() {
            self.remove_pending_preemption_entry(entry)?;
        }
        // Ensure this queue's own list key is gone even if an entry did not list
        // it among its targets (defensive).
        let list_key = pending_preempt_list_key(key);
        self.inner().delete(TASK_QUEUE_TABLE, &list_key)?;
        Ok(())
    }

    /// Increment a queue's consecutive-yield fairness counter
    pub(crate) fn bump_yield_count(&self, key: &TaskQueueKey) -> Result<(), StorageError> {
        let next = self.yield_count(key)? + 1;
        let count_key = yield_count_key(key);
        self.inner().write(TASK_QUEUE_TABLE, &count_key, &next)
    }

    /// Reset a queue's consecutive-yield fairness counter to zero
    pub(crate) fn reset_yield_count(&self, key: &TaskQueueKey) -> Result<(), StorageError> {
        let count_key = yield_count_key(key);
        self.inner().delete(TASK_QUEUE_TABLE, &count_key)?;
        Ok(())
    }

    /// Mark a task as queued
    fn requeue_task(&self, id: &TaskIdentifier) -> Result<(), StorageError> {
        if let Some(mut task) = self.get_task_deserialized(id)? {
            task.state = QueuedTaskState::Queued;
            self.update_task(id, &task)?;
        }

        Ok(())
    }

    /// Update a task in storage
    fn update_task(&self, id: &TaskIdentifier, task: &QueuedTask) -> Result<(), StorageError> {
        let key = task_key(id);
        self.inner().write(TASK_QUEUE_TABLE, &key, task)
    }

    /// Update the task -> queues mapping
    #[allow(clippy::needless_pass_by_value)]
    fn update_task_to_queues(
        &self,
        id: &TaskIdentifier,
        queues: Vec<TaskQueueKey>,
    ) -> Result<(), StorageError> {
        let key = task_to_queue_key(id);
        self.inner().write(TASK_TO_KEY_TABLE, &key, &queues)
    }

    /// Delete a task from storage
    ///
    /// This removes the task
    fn delete_task(&self, id: &TaskIdentifier) -> Result<Option<QueuedTask>, StorageError> {
        let key = task_key(id);
        let task_to_queues_key = task_to_queue_key(id);
        let task = self.get_task_deserialized(id)?;
        self.inner().delete(TASK_QUEUE_TABLE, &key)?;
        self.inner().delete(TASK_TO_KEY_TABLE, &task_to_queues_key)?;

        Ok(task)
    }
}

// --- Tests --- //

#[cfg(test)]
mod test {
    use types_tasks::mocks::{mock_create_order_task, mock_queued_task};

    use crate::storage::traits::RkyvValue;
    use crate::{storage::tx::task_queue::TaskQueuePreemptionState, test_helpers::mock_db};

    use super::*;

    /// Helper function to assert that an archived queue matches an expected
    /// queue
    #[allow(unsafe_code)]
    fn assert_queue_eq(archived: Option<TaskQueueValue<'_>>, expected: &TaskQueue) {
        // If the queue doesn't exist, it should match the default queue
        let archived_queue = match archived {
            Some(q) => q,
            None => {
                assert_eq!(expected, &TaskQueue::default(), "queue should be default when None");
                return;
            },
        };

        // Serialize the expected queue to compare archived types directly
        let expected_bytes = expected.rkyv_serialize().expect("failed to serialize expected queue");
        let expected_archived = unsafe { TaskQueue::rkyv_access(&expected_bytes) };

        // Compare the archived types directly using PartialEq
        assert_eq!(&*archived_queue, expected_archived, "queue mismatch");
    }

    /// Test the serial operation of the task queue (no preemption)
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_ops__basic() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Check that the queue is empty
        let empty = tx.is_queue_empty(&key)?;
        assert!(empty);

        // Add a task to the queue, and check that it is indexed
        let task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &task)?;
        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue { serial_tasks: vec![task.id], ..Default::default() };
        assert_queue_eq(task_queue, &expected_queue);

        // Check that the task is indexed
        let indexed = tx.get_task(&task.id)?.is_some();
        assert!(indexed);

        // Now pop the task and check that it is removed from the queue
        let popped_task = tx.pop_task(&task.id)?;
        let not_indexed = tx.get_task(&task.id)?.is_none();
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, task.id);
        assert!(not_indexed);

        // Check that the task queue has updated
        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue::default();
        assert_queue_eq(task_queue, &expected_queue);
        Ok(())
    }

    /// Test the serial operations of the task queue with multiple tasks
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_ops__multiple_tasks() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add two tasks to the queue, one running
        let mut task1 = mock_queued_task(key);
        task1.state = QueuedTaskState::Running { state: "running".to_string(), committed: false };
        let task2 = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &task1)?;
        tx.enqueue_serial_task(&key, &task2)?;

        // Check that the queue has the correct tasks
        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue =
            TaskQueue { serial_tasks: vec![task1.id, task2.id], ..Default::default() };
        assert_queue_eq(task_queue, &expected_queue);

        // Check that both tasks are indexed
        let indexed1 = tx.get_task(&task1.id)?.is_some();
        let indexed2 = tx.get_task(&task2.id)?.is_some();
        assert!(indexed1);
        assert!(indexed2);

        // Pop the first task from the queue
        let popped_task = tx.pop_task(&task1.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, task1.id);

        // Check that the queue has updated
        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue { serial_tasks: vec![task2.id], ..Default::default() };
        assert_queue_eq(task_queue, &expected_queue);
        Ok(())
    }

    /// Tests the `can_run` method on a basic serial task    
    #[test]
    #[allow(non_snake_case)]
    fn test_can_run__basic() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a serial task to the queue, and check that it can run
        let task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &task)?;
        let can_run = tx.can_task_run(&task.id)?;
        assert!(can_run);

        // Add another task to the same queue, and check that it cannot yet run
        let other_task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &other_task)?;
        let can_run = tx.can_task_run(&other_task.id)?;
        assert!(!can_run);

        // Pop the first task and check that the second task can run
        tx.pop_task(&task.id)?;
        let can_run = tx.can_task_run(&other_task.id)?;
        assert!(can_run);
        Ok(())
    }

    // --- Serial Preemption --- //

    /// Tests a serial preemption with only serial tasks running
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_preemption__simple() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a serial task to the queue
        let mut task = mock_queued_task(key);
        task.state = QueuedTaskState::Running { state: "running".to_string(), committed: false };
        tx.enqueue_serial_task(&key, &task)?;

        // Preempt the task queue
        let preemptive_task = mock_queued_task(key);
        tx.preempt_queue_with_serial(&[key], &preemptive_task)?;

        // Check that the task queue state is updated correctly
        let task1_info = tx.get_task(&task.id)?.expect("task1 should be present").deserialize()?;
        let preemptive_task_some = tx.get_task(&preemptive_task.id)?.is_some();
        assert_eq!(task1_info.state, QueuedTaskState::Queued);
        assert!(preemptive_task_some);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![preemptive_task.id, task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_queue_eq(task_queue, &expected_queue);

        // Pop the preemptive task and check that the queue state is updated
        let popped_task = tx.pop_task(&preemptive_task.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, preemptive_task.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue { serial_tasks: vec![task.id], ..Default::default() };
        assert_queue_eq(task_queue, &expected_queue);
        Ok(())
    }

    /// Tests a serial preemption with concurrent tasks running
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_preemption__with_concurrent() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a normal, concurrent preemptive, and serial preemptive task
        let serial_task = mock_queued_task(key);
        let concurrent_task = mock_queued_task(key);
        let preemptive_task = mock_queued_task(key);
        tx.preempt_queue_with_concurrent(&[key], &concurrent_task)?;
        tx.enqueue_serial_task(&key, &serial_task)?;
        tx.preempt_queue_with_serial(&[key], &preemptive_task)?;

        // Check that the task queue state is updated correctly
        let serial_task_some = tx.get_task(&serial_task.id)?.is_some();
        let concurrent_task_some = tx.get_task(&concurrent_task.id)?.is_some();
        let preemptive_task_some = tx.get_task(&preemptive_task.id)?.is_some();
        assert!(serial_task_some);
        assert!(concurrent_task_some);
        assert!(preemptive_task_some);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![preemptive_task.id, serial_task.id],
            concurrent_tasks: vec![concurrent_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
        };
        assert_queue_eq(task_queue, &expected_queue);

        // 1. Pop the concurrent task
        let popped_task = tx.pop_task(&concurrent_task.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, concurrent_task.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![preemptive_task.id, serial_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_queue_eq(task_queue, &expected_queue);

        // 2. Pop the serial preemptive task
        let popped_task = tx.pop_task(&preemptive_task.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, preemptive_task.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_queue_eq(task_queue, &expected_queue);
        Ok(())
    }

    /// Tests serial preemption with multiple queues
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_preemption__multiple_queues() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key1 = TaskQueueKey::new_v4();
        let key2 = TaskQueueKey::new_v4();

        // Add a serial task to one of the queues
        let task = mock_queued_task(key1);
        tx.enqueue_serial_task(&key1, &task)?;

        // Preempt both queues with a serial task
        let preemptive_task = mock_queued_task(key2);
        tx.preempt_queue_with_serial(&[key1, key2], &preemptive_task)?;

        // Check that the task -> queues mapping is updated correctly
        let task_to_queues = tx.get_queue_keys_for_task(&preemptive_task.id)?;
        assert_eq!(task_to_queues.len(), 2);
        assert!(task_to_queues.contains(&key1));
        assert!(task_to_queues.contains(&key2));

        // Check that the task queue state is updated correctly
        let task_queue1 = tx.get_task_queue(&key1)?;
        let task_queue2 = tx.get_task_queue(&key2)?;
        let expected_queue1 = TaskQueue {
            serial_tasks: vec![preemptive_task.id, task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        let expected_queue2 = TaskQueue {
            serial_tasks: vec![preemptive_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_queue_eq(task_queue1, &expected_queue1);
        assert_queue_eq(task_queue2, &expected_queue2);
        Ok(())
    }

    /// Tests the `can_run` method on a serial preemptive task    
    #[test]
    #[allow(non_snake_case)]
    fn test_can_run__serial_preemptive() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // 1. Add a concurrent preemptive task to the queue; serial task cannot run
        let concurrent_task = mock_queued_task(key);
        let serial_task = mock_queued_task(key);
        tx.preempt_queue_with_concurrent(&[key], &concurrent_task)?;
        tx.preempt_queue_with_serial(&[key], &serial_task)?;
        let can_run = tx.can_task_run(&serial_task.id)?;
        assert!(!can_run);

        // 2. Pop the concurrent task; serial task can now run
        tx.pop_task(&concurrent_task.id)?;
        let can_run = tx.can_task_run(&serial_task.id)?;
        assert!(can_run);
        Ok(())
    }

    /// Tests the `can_run` method on a serial preemptive task associated with
    /// multiple queues
    #[test]
    #[allow(non_snake_case)]
    fn test_can_run__serial_preemptive__multiple_queues() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key1 = TaskQueueKey::new_v4();
        let key2 = TaskQueueKey::new_v4();

        // Enqueue a concurrent task on one of the queues
        let dummy_key = TaskQueueKey::new_v4();
        let concurrent_task = mock_queued_task(dummy_key);
        let serial_task = mock_queued_task(dummy_key);
        tx.preempt_queue_with_concurrent(&[key1], &concurrent_task)?;
        tx.preempt_queue_with_serial(&[key1, key2], &serial_task)?;

        // Check that the serial task cannot run
        let can_run = tx.can_task_run(&serial_task.id)?;
        assert!(!can_run);

        // Pop the concurrent task; serial task can now run
        tx.pop_task(&concurrent_task.id)?;
        let can_run = tx.can_task_run(&serial_task.id)?;
        assert!(can_run);
        Ok(())
    }

    /// Tests an attempt to preempt a serial task with another -- invalid
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_serial_preemption__already_preempted() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a serial task to the queue
        let first_task = mock_queued_task(key);
        tx.preempt_queue_with_serial(&[key], &first_task)?;

        // Attempt to preempt the task with another serial task
        let second_task = mock_queued_task(key);
        let err = tx.preempt_queue_with_serial(&[key], &second_task).is_err();
        assert!(err);

        // Check that the queue was not updated
        let second_task_none = tx.get_task(&second_task.id)?.is_none();
        assert!(second_task_none);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![first_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_queue_eq(task_queue, &expected_queue);
        Ok(())
    }

    /// Tests an invalid serial preemption with multiple queues, in which one
    /// queue can be preempted and another cannot    
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_serial_preemption__multiple_queues() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key1 = TaskQueueKey::new_v4();
        let key2 = TaskQueueKey::new_v4();

        // Add a serial preemptive task to one of the queues
        let preemptive_task1 = mock_queued_task(key1);
        tx.preempt_queue_with_serial(&[key1], &preemptive_task1)?;

        // Try to preempt both queues with a new serial task
        let new_serial_task = mock_queued_task(key2);
        let err = tx.preempt_queue_with_serial(&[key1, key2], &new_serial_task).is_err();
        assert!(err);

        // Check that the queue state is updated correctly
        let task_queue1 = tx.get_task_queue(&key1)?;
        let task_queue2 = tx.get_task_queue(&key2)?;
        let expected_queue1 = TaskQueue {
            serial_tasks: vec![preemptive_task1.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        let expected_queue2 = TaskQueue::default();
        assert_queue_eq(task_queue1, &expected_queue1);
        assert_queue_eq(task_queue2, &expected_queue2);
        Ok(())
    }

    /// Tests an invalid serial preemption in the case that the running task is
    /// committed
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_serial_preemption__committed_task() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a committed task to the queue
        let mut task = mock_queued_task(key);
        task.state = QueuedTaskState::Running { state: "running".to_string(), committed: true };
        tx.enqueue_serial_task(&key, &task)?;

        // Attempt to preempt the task with another serial task
        let new_serial_task = mock_queued_task(key);
        let err = tx.preempt_queue_with_serial(&[key], &new_serial_task).is_err();
        assert!(err);

        // Check that the queue state is updated correctly
        let task_queue = tx.get_task_queue_deserialized(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);
        Ok(())
    }

    /// Tests defer-not-reject + Stage 3 multi-pending: a serial preemption
    /// blocked by a committed head is deferred (recorded pending, queue
    /// untouched); a second concurrent settle also defers (no longer rejects);
    /// and on unblock the lowest-`seq` settle runs first, leaving the rest
    /// pending in order.
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_preemption__defer_and_resume() -> Result<(), StorageError> {
        super::set_test_settle_defer(true);

        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a committed task to the queue -- not serial-preemption-safe
        let mut blocker = mock_queued_task(key);
        blocker.state = QueuedTaskState::Running { state: "running".to_string(), committed: true };
        tx.enqueue_serial_task(&key, &blocker)?;

        // Preempt with a settle: should defer rather than reject
        let settle = mock_queued_task(key);
        let outcome = tx.preempt_queue_with_serial(&[key], &settle)?;
        assert_eq!(outcome, PreemptOutcome::Deferred);

        // The settle is not enqueued; a pending record exists; the queue is
        // unchanged (still just the blocker).
        assert!(tx.get_task(&settle.id)?.is_none());
        assert!(tx.has_pending_preemption(&key)?);
        let queue = tx.get_task_queue_deserialized(&key)?;
        assert_eq!(queue.serial_tasks, vec![blocker.id]);

        // Multi-pending FIFO (Stage 3): a second settle while one is pending now
        // DEFERS too (it no longer rejects). Both are recorded, ordered by seq.
        let settle2 = mock_queued_task(key);
        let outcome2 = tx.preempt_queue_with_serial(&[key], &settle2)?;
        assert_eq!(outcome2, PreemptOutcome::Deferred);
        assert_eq!(tx.get_pending_preempt_list(&key)?.len(), 2);

        // The head (lowest seq) is the first settle.
        let head = tx.pending_preempt_head(&key)?.expect("a settle should be pending");
        assert_eq!(head.task.id, settle.id);
        assert_eq!(head.target_keys, vec![key]);

        // Complete the blocker; the queue is now safe, so the head settle (first)
        // preempts and is removed, leaving settle2 pending behind it.
        tx.pop_task(&blocker.id)?;
        assert!(tx.is_serial_preemption_safe(&key)?);
        let head = tx.pending_preempt_head(&key)?.expect("first settle still pending");
        assert_eq!(head.task.id, settle.id);
        tx.do_preempt_serial(&head.target_keys, &head.task)?;
        tx.remove_pending_preemption_entry(&head)?;

        // The first settle is now the queue head; settle2 remains pending behind it.
        let queue = tx.get_task_queue_deserialized(&key)?;
        assert_eq!(queue.serial_tasks, vec![settle.id]);
        let head2 = tx.pending_preempt_head(&key)?.expect("settle2 still pending");
        assert_eq!(head2.task.id, settle2.id);
        assert_eq!(tx.get_pending_preempt_list(&key)?.len(), 1);

        super::set_test_settle_defer(false);
        Ok(())
    }

    /// Stage 3 depth cap: once a queue holds `MAX_PENDING_PER_QUEUE` deferred
    /// settles, a further serial preemption is rejected as backpressure and is
    /// not recorded.
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_preemption__pending_depth_cap() -> Result<(), StorageError> {
        super::set_test_settle_defer(true);

        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Committed head -> every settle defers.
        let mut blocker = mock_queued_task(key);
        blocker.state = QueuedTaskState::Running { state: "running".to_string(), committed: true };
        tx.enqueue_serial_task(&key, &blocker)?;

        // Fill the queue's pending list to the cap.
        for _ in 0..super::MAX_PENDING_PER_QUEUE {
            let settle = mock_queued_task(key);
            assert_eq!(tx.preempt_queue_with_serial(&[key], &settle)?, PreemptOutcome::Deferred);
        }
        assert_eq!(tx.get_pending_preempt_list(&key)?.len(), super::MAX_PENDING_PER_QUEUE);

        // The next one is rejected (backpressure) and not recorded.
        let overflow = mock_queued_task(key);
        assert!(tx.preempt_queue_with_serial(&[key], &overflow).is_err());
        assert_eq!(tx.get_pending_preempt_list(&key)?.len(), super::MAX_PENDING_PER_QUEUE);

        super::set_test_settle_defer(false);
        Ok(())
    }

    /// Stage 3 cross-queue ordering: two settles targeting overlapping queue
    /// sets both defer and are ordered by `seq` on the shared queue, so the
    /// lower-`seq` settle is the shared queue's head and the higher one cannot
    /// run until it clears -- the total order breaks any wait cycle
    /// (deadlock-free).
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_preemption__cross_queue_ordering() -> Result<(), StorageError> {
        super::set_test_settle_defer(true);

        let db = mock_db();
        let tx = db.new_write_tx()?;
        let a = TaskQueueKey::new_v4();
        let b = TaskQueueKey::new_v4();
        let c = TaskQueueKey::new_v4();

        // Commit a head on the shared queue `b` so both settles defer.
        let mut blocker = mock_queued_task(b);
        blocker.state = QueuedTaskState::Running { state: "running".to_string(), committed: true };
        tx.enqueue_serial_task(&b, &blocker)?;

        // settle1 targets {a, b}; settle2 targets {b, c}. `b` is shared.
        let settle1 = mock_queued_task(b);
        let settle2 = mock_queued_task(b);
        assert_eq!(tx.preempt_queue_with_serial(&[a, b], &settle1)?, PreemptOutcome::Deferred);
        assert_eq!(tx.preempt_queue_with_serial(&[b, c], &settle2)?, PreemptOutcome::Deferred);

        // On the shared queue, settle1 (lower seq) is the head; both are recorded.
        let head_b = tx.pending_preempt_head(&b)?.expect("shared queue head");
        assert_eq!(head_b.task.id, settle1.id);
        assert_eq!(tx.get_pending_preempt_list(&b)?.len(), 2);

        // settle1 is the head of both of its queues; settle2 is NOT the head of
        // `b`, so it cannot run until settle1 clears.
        assert!(tx.is_pending_head(&head_b, &a)?);
        assert!(tx.is_pending_head(&head_b, &b)?);
        let entry2 = tx
            .get_pending_preempt_list(&c)?
            .into_iter()
            .find(|e| e.task.id == settle2.id)
            .expect("settle2 recorded on c");
        assert!(!tx.is_pending_head(&entry2, &b)?);

        super::set_test_settle_defer(false);
        Ok(())
    }

    /// Stage 2 order-yield: a settle blocked by a COMMITTED but yieldable
    /// (CreateOrder) head preempts (yields) it rather than deferring, and bumps
    /// the per-queue fairness counter.
    #[test]
    #[allow(non_snake_case)]
    fn test_order_yield__yields_committed_create_order() -> Result<(), StorageError> {
        super::set_test_order_yield(true);

        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Committed yieldable head: an MM CreateOrder requote past its commit point
        let mut order = mock_create_order_task(key);
        order.state = QueuedTaskState::Running { state: "creating".to_string(), committed: true };
        tx.enqueue_serial_task(&key, &order)?;
        assert!(tx.head_is_yieldable(&key)?, "committed CreateOrder head must be yieldable");

        // The settle preempts (yields) the committed order rather than deferring.
        let settle = mock_queued_task(key);
        let outcome = tx.preempt_queue_with_serial(&[key], &settle)?;
        assert_eq!(outcome, PreemptOutcome::Preempted);
        assert_eq!(tx.yield_count(&key)?, 1, "a yield bumps the fairness counter");

        // The settle is now the head; the order was requeued (to be re-run).
        let queue = tx.get_task_queue_deserialized(&key)?;
        assert_eq!(queue.serial_tasks, vec![settle.id, order.id]);

        super::set_test_order_yield(false);
        Ok(())
    }

    /// Stage 2 fairness: once the per-queue yield cap is hit, the order is NOT
    /// yielded -- the settle defers (letting the order commit) and the counter
    /// resets.
    #[test]
    #[allow(non_snake_case)]
    fn test_order_yield__fairness_cap_defers() -> Result<(), StorageError> {
        super::set_test_order_yield(true);
        super::set_test_settle_defer(true);

        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        let mut order = mock_create_order_task(key);
        order.state = QueuedTaskState::Running { state: "creating".to_string(), committed: true };
        tx.enqueue_serial_task(&key, &order)?;

        // Drive the fairness counter to the cap.
        for _ in 0..super::MAX_CONSECUTIVE_YIELDS {
            tx.bump_yield_count(&key)?;
        }

        let settle = mock_queued_task(key);
        let outcome = tx.preempt_queue_with_serial(&[key], &settle)?;
        assert_eq!(outcome, PreemptOutcome::Deferred, "at the cap the order is not yielded");
        assert_eq!(tx.yield_count(&key)?, 0, "the cap resets the counter so the order can commit");

        // The order is still the head (not preempted); the settle is pending.
        let queue = tx.get_task_queue_deserialized(&key)?;
        assert_eq!(queue.serial_tasks, vec![order.id]);
        assert!(tx.has_pending_preemption(&key)?);

        super::set_test_order_yield(false);
        super::set_test_settle_defer(false);
        Ok(())
    }

    /// A committed NON-yieldable head (e.g. NewAccount) is never yielded -- the
    /// settle defers as in Stage 1, even with order-yield on.
    #[test]
    #[allow(non_snake_case)]
    fn test_order_yield__non_yieldable_head_defers() -> Result<(), StorageError> {
        super::set_test_order_yield(true);
        super::set_test_settle_defer(true);

        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        let mut acct = mock_queued_task(key); // NewAccount -> not yieldable
        acct.state = QueuedTaskState::Running { state: "running".to_string(), committed: true };
        tx.enqueue_serial_task(&key, &acct)?;
        assert!(!tx.head_is_yieldable(&key)?);

        let settle = mock_queued_task(key);
        let outcome = tx.preempt_queue_with_serial(&[key], &settle)?;
        assert_eq!(
            outcome,
            PreemptOutcome::Deferred,
            "a non-yieldable committed head is not yielded"
        );
        assert_eq!(tx.yield_count(&key)?, 0);

        super::set_test_order_yield(false);
        super::set_test_settle_defer(false);
        Ok(())
    }

    // --- Concurrent Preemption --- //

    /// Tests the basic concurrent preemption flow with multiple tasks
    #[test]
    #[allow(non_snake_case)]
    fn test_concurrent_preemption__basic() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add two concurrent preemptive tasks
        let task1 = mock_queued_task(key);
        let task2 = mock_queued_task(key);
        tx.preempt_queue_with_concurrent(&[key], &task1)?;
        tx.preempt_queue_with_concurrent(&[key], &task2)?;

        // Check that the task queue state is updated correctly
        let task1_some = tx.get_task(&task1.id)?.is_some();
        let task2_some = tx.get_task(&task2.id)?.is_some();
        assert!(task1_some);
        assert!(task2_some);

        let task_queue = tx.get_task_queue_deserialized(&key)?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![task1.id, task2.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);

        // Pop the first task
        let popped_task = tx.pop_task(&task1.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, task1.id);

        let task_queue = tx.get_task_queue_deserialized(&key)?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![task2.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);
        Ok(())
    }

    /// Tests enqueuing a serial task behind a preempted task
    #[test]
    #[allow(non_snake_case)]
    fn test_concurrent_preemption__enqueue_serial_behind() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a concurrent preemptive task
        let concurrent_task = mock_queued_task(key);
        tx.preempt_queue_with_concurrent(&[key], &concurrent_task)?;

        // Add a serial task to the queue
        let serial_task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &serial_task)?;

        // Check that the task queue state is updated correctly
        let concurrent_task_some = tx.get_task(&concurrent_task.id)?.is_some();
        let serial_task_some = tx.get_task(&serial_task.id)?.is_some();
        assert!(concurrent_task_some);
        assert!(serial_task_some);

        let task_queue = tx.get_task_queue_deserialized(&key)?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![concurrent_task.id],
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
        };
        assert_eq!(task_queue, expected_queue);

        // Try adding another concurrent task, should fail
        let new_concurrent_task = mock_queued_task(key);
        let err = tx.preempt_queue_with_concurrent(&[key], &new_concurrent_task).is_err();
        assert!(err);

        let task_queue = tx.get_task_queue_deserialized(&key)?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![concurrent_task.id],
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
        };
        assert_eq!(task_queue, expected_queue);

        // Now pop the concurrent task and check that the queue state is updated
        let popped_task = tx.pop_task(&concurrent_task.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, concurrent_task.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_queue_eq(task_queue, &expected_queue);
        Ok(())
    }

    /// Tests enqueuing a concurrent task on multiple queues    
    #[test]
    #[allow(non_snake_case)]
    fn test_concurrent_preemption__multiple_queues() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key1 = TaskQueueKey::new_v4();
        let key2 = TaskQueueKey::new_v4();

        // Add a concurrent preemptive task to one of the queues
        let concurrent_task = mock_queued_task(key1);
        tx.preempt_queue_with_concurrent(&[key1], &concurrent_task)?;

        // Add a concurrent preemptive task to both queues
        let new_concurrent_task = mock_queued_task(key2);
        tx.preempt_queue_with_concurrent(&[key1, key2], &new_concurrent_task)?;

        // Check that the task queue state is updated correctly
        let task1_some = tx.get_task(&concurrent_task.id)?.is_some();
        let task2_some = tx.get_task(&new_concurrent_task.id)?.is_some();
        let task2_queues = tx.get_queue_keys_for_task(&new_concurrent_task.id)?;
        assert!(task1_some);
        assert!(task2_some);
        assert_eq!(task2_queues.len(), 2);
        assert!(task2_queues.contains(&key1));
        assert!(task2_queues.contains(&key2));

        let task_queue1 = tx.get_task_queue_deserialized(&key1)?;
        let task_queue2 = tx.get_task_queue_deserialized(&key2)?;
        let expected_queue1 = TaskQueue {
            concurrent_tasks: vec![concurrent_task.id, new_concurrent_task.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
            ..Default::default()
        };
        let expected_queue2 = TaskQueue {
            concurrent_tasks: vec![new_concurrent_task.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
            ..Default::default()
        };
        assert_eq!(task_queue1, expected_queue1);
        assert_eq!(task_queue2, expected_queue2);
        Ok(())
    }

    /// Tests the `can_run` method on a concurrent preemptive task    
    #[test]
    #[allow(non_snake_case)]
    fn test_can_run__concurrent_preemptive() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a concurrent preemptive task
        let task1 = mock_queued_task(key);
        let task2 = mock_queued_task(key);
        tx.preempt_queue_with_concurrent(&[key], &task1)?;
        let can_run = tx.can_task_run(&task1.id)?;
        assert!(can_run);

        // Add another task, both should be runnable
        tx.preempt_queue_with_concurrent(&[key], &task2)?;
        let can_run1 = tx.can_task_run(&task1.id)?;
        let can_run2 = tx.can_task_run(&task2.id)?;
        assert!(can_run1);
        assert!(can_run2);
        Ok(())
    }

    /// Tests enqueuing a concurrent task behind a serial task
    #[test]
    #[allow(non_snake_case)]
    fn test_concurrent_preemption__serial_already_queued() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a serial task to the queue
        let serial_task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &serial_task)?;

        // Try to add a concurrent task to the queue, should fail
        let concurrent_task = mock_queued_task(key);
        let err = tx.preempt_queue_with_concurrent(&[key], &concurrent_task).is_err();
        assert!(err);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_queue_eq(task_queue, &expected_queue);
        Ok(())
    }

    /// Tests enqueuing a concurrent task on multiple queues when one queue
    /// cannot be preempted concurrently
    #[test]
    #[allow(non_snake_case)]
    fn test_concurrent_preemption__multiple_queues__cannot_preempt() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key1 = TaskQueueKey::new_v4();
        let key2 = TaskQueueKey::new_v4();

        // Add a serial task to one of the queues
        let serial_task = mock_queued_task(key1);
        tx.enqueue_serial_task(&key1, &serial_task)?;

        // Try to add a concurrent task to both queues, should fail on the second queue
        let concurrent_task = mock_queued_task(key2);
        let err = tx.preempt_queue_with_concurrent(&[key1, key2], &concurrent_task).is_err();
        assert!(err);

        let task_queue1 = tx.get_task_queue_deserialized(&key1)?;
        let task_queue2 =
            tx.get_task_queue(&key2)?.map(|q| q.deserialize()).transpose()?.unwrap_or_default();
        let expected_queue1 = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        let expected_queue2 = TaskQueue::default();
        assert_eq!(task_queue1, expected_queue1);
        assert_eq!(task_queue2, expected_queue2);
        Ok(())
    }
}
