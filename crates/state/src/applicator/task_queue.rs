//! Task queue state transition applicator methods

use job_types::{
    event_manager::{RelayerEventType, TaskCompletionEvent, try_send_event},
    task_driver::TaskDriverJob,
};
use libmdbx::{RW, TransactionKind};
use system_bus::{SystemBusMessage, TaskStatus, task_topic};
use tracing::instrument;
use types_gossip::WrappedPeerId;
use types_tasks::{
    ArchivedQueuedTask, HistoricalTask, QueuedTask, QueuedTaskState, TaskIdentifier, TaskQueueKey,
};
use util::log_task;
use util::logging::Outcome;

use crate::logging::Task;
use crate::storage::{traits::RkyvValue, tx::StateTxn, tx::task_queue::PreemptOutcome};

use super::{
    Result, StateApplicator, error::StateApplicatorError, return_type::ApplicatorReturnType,
};

/// The pending state description
const PENDING_STATE: &str = "Pending";

/// Error emitted when a task's assignment cannot be found
const ERR_UNASSIGNED_TASK: &str = "task not assigned";
/// Error emitted when a key cannot be found for a task
const ERR_NO_KEY: &str = "key not found for task";

/// Construct an invalid task queue key error
fn invalid_task_id(key: TaskIdentifier) -> String {
    format!("invalid task id: {key}")
}

/// Construct a task not running error
fn task_not_running(task_id: TaskIdentifier) -> String {
    format!("task {task_id} is not running")
}

// -----------
// | Helpers |
// -----------

/// Construct the running state for a newly started task
fn new_running_state() -> QueuedTaskState {
    QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false }
}

/// Convert a QueuedTask to a TaskStatus for system bus messages
fn task_to_status(task: &QueuedTask) -> TaskStatus {
    let (status, description) = match &task.state {
        QueuedTaskState::Queued => ("queued".to_string(), None),
        QueuedTaskState::Preemptive => ("preemptive".to_string(), None),
        QueuedTaskState::Running { state, .. } => ("running".to_string(), Some(state.clone())),
        QueuedTaskState::Completed => ("completed".to_string(), None),
        QueuedTaskState::Failed => ("failed".to_string(), None),
    };
    TaskStatus { id: task.id, status, description }
}

impl StateApplicator {
    // ---------------------
    // | State Transitions |
    // ---------------------

    /// Apply an `AppendTask` state transition
    #[instrument(skip_all, err, fields(task_id = %task.id, task = %task.descriptor.display_description()))]
    pub fn append_task(
        &self,
        task: &QueuedTask,
        executor: &WrappedPeerId,
    ) -> Result<ApplicatorReturnType> {
        let queue_key = task.descriptor.queue_key();
        let tx = self.db().new_write_tx_with_retry("task_queue::append_task")?;

        // Index the task
        tx.enqueue_serial_task(&queue_key, task)?;
        tx.add_assigned_task(executor, &task.id)?;
        let archived_task = tx.get_task(&task.id)?.unwrap();

        // Run the task if possible
        self.maybe_run_task(&archived_task, &tx)?;
        tx.commit()?;

        self.publish_task_updates(queue_key, task);
        Ok(ApplicatorReturnType::None)
    }

    /// Apply a `PopTask` state transition
    #[instrument(skip_all, err, fields(task_id = %task_id))]
    pub fn pop_task(&self, task_id: TaskIdentifier, success: bool) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx_with_retry("task_queue::pop_task")?;
        let keys = tx.get_queue_keys_for_task(&task_id)?;
        if keys.is_empty() {
            return Err(StateApplicatorError::reject(ERR_NO_KEY));
        }

        // Pop the task from the queue, remove its assignment, and add it to history
        let (task, executor) = self
            .pop_and_record_task(&keys, &task_id, success, &tx)?
            .ok_or_else(|| StateApplicatorError::TaskQueueEmpty(keys[0]))?;

        // Process the update to each queue
        for key in keys.iter().copied() {
            // If the task failed, subsequent tasks will fail, so we clear the queue instead
            // of trying to run the next task
            if !success {
                self.clear_task_queue(key, &tx)?;
            }

            // If the queue is non-empty, start the next task
            if let Some(task) = tx.next_runnable_task(&key)? {
                self.maybe_run_task(&task, &tx)?;
            }
        }

        // Completion hook: a deferred serial preemption (Stage 1 defer-not-reject)
        // may now be unblocked by this completion. Run it after the normal
        // next-task dispatch -- the settle is not enqueued until preempted here,
        // so it is dispatched exactly once. Skipped on failure: the queue is
        // cleared above, which drops the pending record.
        if success {
            for key in keys.iter().copied() {
                self.run_unblocked_preemptions(key, &executor, &tx)?;
            }
        }

        // Commit and publish a message to the system bus
        tx.commit()?;
        self.publish_task_updates_multiple(&keys, &task);
        Ok(ApplicatorReturnType::None)
    }

    /// Transition the state of the top task on the queue
    #[instrument(skip_all, err, fields(task_id = %task_id, state = %state.display_description()))]
    pub fn transition_task_state(
        &self,
        task_id: TaskIdentifier,
        state: QueuedTaskState,
    ) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx_with_retry("task_queue::transition_task_state")?;
        let keys = tx.get_queue_keys_for_task(&task_id)?;

        // Check that the task is running
        let task = tx
            .get_task(&task_id)?
            .ok_or_else(|| StateApplicatorError::reject(invalid_task_id(task_id)))?;
        if !task.state.is_running() {
            // This can happen if the queue was preempted by another task, and the task that
            // was previously running now tries to update its state
            return Err(StateApplicatorError::reject(task_not_running(task_id)));
        }

        tx.transition_task(&task_id, state)?;
        let updated_task = tx.get_task(&task_id)?.expect("task should exist");
        let task = QueuedTask::from_archived(&updated_task)?;
        tx.commit()?;

        self.publish_task_updates_multiple(&keys, &task);
        Ok(ApplicatorReturnType::None)
    }

    /// Clear the task queue, marking all tasks as failed
    #[instrument(skip_all, err, fields(queue_key = %key))]
    pub fn clear_queue(&self, key: TaskQueueKey) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx_with_retry("task_queue::clear_queue")?;
        self.clear_task_queue(key, &tx)?;
        tx.commit()?;

        Ok(ApplicatorReturnType::None)
    }

    /// Enqueue a preemptive task onto the given task queues
    pub fn enqueue_preemptive_task(
        &self,
        keys: &[TaskQueueKey],
        task: &QueuedTask,
        executor: &WrappedPeerId,
        is_serial: bool,
    ) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx_with_retry("task_queue::enqueue_preemptive_task")?;
        // Enqueue the task on the given queues
        let outcome = self.try_preempt_queues(keys, task, is_serial, &tx)?;

        // If the preemption was deferred, the settle is blocked by a committed
        // head and has been recorded as pending; it will run automatically when
        // the blocking task(s) complete. Commit the pending record and stop --
        // the task is not enqueued, so we must not assign or run it.
        if matches!(outcome, PreemptOutcome::Deferred) {
            tx.commit()?;
            return Ok(ApplicatorReturnType::Deferred);
        }

        // Assign the task and run it if possible
        tx.add_assigned_task(executor, &task.id)?;
        let archived_task = tx.get_task(&task.id)?.unwrap();
        self.maybe_run_task(&archived_task, &tx)?;

        tx.commit()?;
        self.publish_task_updates_multiple(keys, task);
        Ok(ApplicatorReturnType::None)
    }

    /// Reassign all tasks from one peer to another
    pub fn reassign_tasks(
        &self,
        from: &WrappedPeerId,
        to: &WrappedPeerId,
    ) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx_with_retry("task_queue::reassign_tasks")?;
        let reassigned_tasks = tx.reassign_tasks(from, to)?;
        if !reassigned_tasks.is_empty() {
            log_task!(
                Task::TaskQueue,
                Outcome::Ok,
                count = reassigned_tasks.len(),
                from = %from,
                to = %to,
                "reassigning tasks"
            );
        }

        // Handle in-flight tasks that were reassigned
        for task_id in reassigned_tasks.into_iter() {
            let task = match tx.get_task(&task_id)? {
                Some(task) => task,
                None => continue,
            };

            if !task.state.is_running() {
                continue;
            }

            // TODO: If the task is committed we can be smarter and check for its most
            // recent state on-chain. This is a simpler solution for the moment, but will
            // error in the case described
            self.maybe_run_task(&task, &tx)?;
        }

        tx.commit()?;
        Ok(ApplicatorReturnType::None)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Publish task updates for a task on multiple task queues
    fn publish_task_updates_multiple(&self, keys: &[TaskQueueKey], task: &QueuedTask) {
        for key in keys.iter() {
            self.publish_task_updates(*key, task);
        }
    }

    /// Publish system bus messages indicating a task has been updated
    fn publish_task_updates(&self, _key: TaskQueueKey, task: &QueuedTask) {
        let task_id = task.id;

        // Publish a message for the individual task
        let task_topic = task_topic(&task_id);
        if self.system_bus().has_listeners(&task_topic) {
            let status = task_to_status(task);
            self.system_bus().publish(task_topic, SystemBusMessage::TaskStatusUpdate { status });
        }
    }

    /// Transition a task into the running state
    fn maybe_run_task(&self, task: &ArchivedQueuedTask, tx: &StateTxn<'_, RW>) -> Result<()> {
        if !tx.can_task_run(&task.id)? {
            return Ok(());
        }

        let running_state = new_running_state();
        tx.transition_task(&task.id, running_state)?;
        self.maybe_execute_task(task, tx)
    }

    /// Start a task if the current peer is the executor
    fn maybe_execute_task<T: TransactionKind>(
        &self,
        task: &ArchivedQueuedTask,
        tx: &StateTxn<'_, T>,
    ) -> Result<()> {
        let my_peer_id = tx.get_peer_id()?;
        let executor = tx
            .get_task_assignment(&task.id)?
            .ok_or_else(|| StateApplicatorError::MissingEntry(ERR_UNASSIGNED_TASK))?;

        if *executor == my_peer_id {
            let task = QueuedTask::from_archived(task)?;
            let job = TaskDriverJob::run(task);
            self.config.task_queue.send(job).map_err(StateApplicatorError::enqueue_task)?;
        }

        Ok(())
    }

    /// Pop the top task from all queues which contain it and add it to the
    /// historical state
    ///
    /// Returns the task and the executor to which it was assigned
    fn pop_and_record_task(
        &self,
        keys: &[TaskQueueKey],
        task_id: &TaskIdentifier,
        success: bool,
        tx: &StateTxn<'_, RW>,
    ) -> Result<Option<(QueuedTask, WrappedPeerId)>> {
        // Pop the task
        let mut task = match tx.pop_task(task_id) {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(None),
            Err(e) => return Err(StateApplicatorError::from(e)),
        };

        // Add the task to history and remove its node assignment
        task.state = if success { QueuedTaskState::Completed } else { QueuedTaskState::Failed };
        let executor = if let Some(executor) = tx.get_task_assignment(task_id)? {
            let peer_id = executor.deserialize()?;
            tx.remove_assigned_task(&peer_id, &task.id)?;
            peer_id
        } else {
            return Ok(None);
        };

        self.maybe_append_historical_task(keys, &task, executor, tx)?;
        Ok(Some((task, executor)))
    }

    /// Append a task to the task history of all queues which contained it, if
    /// it should be stored
    fn maybe_append_historical_task(
        &self,
        keys: &[TaskQueueKey],
        task: &QueuedTask,
        executor: WrappedPeerId,
        tx: &StateTxn<'_, RW>,
    ) -> Result<()> {
        let history_enabled = tx.get_historical_state_enabled()?;
        for key in keys {
            if let Some(t) = HistoricalTask::from_queued_task(*key, task.clone()) {
                if history_enabled {
                    tx.append_task_to_history(key, &t)?;
                }

                // Emit a task completion event to the event manager
                // _only if the local peer is the executor_,
                // to avoid duplicate events across the cluster
                let my_peer_id = tx.get_peer_id()?;
                if my_peer_id == executor {
                    let event = RelayerEventType::TaskCompletion(TaskCompletionEvent::new(*key, t));
                    if let Err(e) = try_send_event(event, &self.config.event_queue) {
                        log_task!(
                            Task::TaskQueue,
                            Outcome::Failed,
                            error = %e,
                            "error sending task completion event"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Clear all tasks from a task queue, recording them historically as
    /// "failed"
    fn clear_task_queue(&self, key: TaskQueueKey, tx: &StateTxn<'_, RW>) -> Result<()> {
        // Remove all tasks from queue in storage
        let cleared_tasks = tx.clear_task_queue(&key)?;

        // Mark all tasks as failed, append to history, and publish updates
        for mut task in cleared_tasks {
            task.state = QueuedTaskState::Failed;
            let executor = tx
                .get_task_assignment(&task.id)?
                .ok_or_else(|| StateApplicatorError::MissingEntry(ERR_UNASSIGNED_TASK))?;
            let executor_id = executor.deserialize()?;

            self.maybe_append_historical_task(&[key], &task, executor_id, tx)?;
            self.publish_task_updates(key, &task);

            if let Some(peer_id_value) = tx.get_task_assignment(&task.id)? {
                let peer_id = peer_id_value.deserialize()?;
                tx.remove_assigned_task(&peer_id, &task.id)?;
            }
        }

        Ok(())
    }

    /// Try preempting a set of task queues with a task, returning a transition
    /// rejection if this fails.
    ///
    /// Returns the preemption outcome: `Preempted` if the queues were taken, or
    /// `Deferred` if a committed head blocked a serial preemption and the
    /// settle was recorded as pending (only possible on the serial path).
    fn try_preempt_queues(
        &self,
        keys: &[TaskQueueKey],
        task: &QueuedTask,
        is_serial: bool,
        tx: &StateTxn<'_, RW>,
    ) -> Result<PreemptOutcome> {
        let outcome = if is_serial {
            tx.preempt_queue_with_serial(keys, task)?
        } else {
            tx.preempt_queue_with_concurrent(keys, task)?;
            PreemptOutcome::Preempted
        };

        Ok(outcome)
    }

    /// Run any deferred serial preemption recorded against a queue that has
    /// just become unblocked by a task completion.
    ///
    /// Invoked from the pop path after a task is removed from `key`. Re-checks
    /// that every queue the pending settle targets is now safe and, if so, runs
    /// the real preemption and clears the pending records. All-or-nothing:
    /// while any target queue is still committed the records are left in
    /// place to re-trigger on the next completion. Panic-free: any
    /// inconsistency results in a no-op (or a transition rejection that
    /// rolls back the tx), never a panic, since this runs on the apply path
    /// on every node.
    fn run_unblocked_preemptions(
        &self,
        key: TaskQueueKey,
        executor: &WrappedPeerId,
        tx: &StateTxn<'_, RW>,
    ) -> Result<()> {
        // Drain every deferred settle on this queue that has become runnable, in
        // `seq` order. A settle runs only when it is the lowest-`seq` (head)
        // entry of EVERY queue it targets and all those queues are
        // serial-preemption-safe. The global `seq` total order guarantees the
        // globally-lowest pending settle is the head of all its queues, so this
        // makes progress without the multi-queue deadlock the one-pending rule
        // used to prevent. If this queue's head is not yet runnable, nothing
        // behind it can run on this trigger either.
        loop {
            let Some(entry) = tx.pending_preempt_head(&key)? else {
                return Ok(());
            };

            // Self-heal: if the settle is already live (e.g. re-proposed and run
            // via the normal path), drop it from every queue and continue.
            if tx.get_task(&entry.task.id)?.is_some() {
                tx.remove_pending_preemption_entry(&entry)?;
                continue;
            }

            let mut runnable = true;
            for queue_key in entry.target_keys.iter() {
                if !tx.is_pending_head(&entry, queue_key)?
                    || !tx.is_serial_preemption_safe(queue_key)?
                {
                    runnable = false;
                    break;
                }
            }
            if !runnable {
                return Ok(());
            }

            // Run the real preemption and clear the entry from every target queue.
            tx.do_preempt_serial(&entry.target_keys, &entry.task)?;
            tx.remove_pending_preemption_entry(&entry)?;

            // Assign to the executor of the task that just completed (same node as
            // the freed queue) and run it if possible.
            tx.add_assigned_task(executor, &entry.task.id)?;
            if let Some(archived_task) = tx.get_task(&entry.task.id)? {
                self.maybe_run_task(&archived_task, tx)?;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use eyre::Result;
    use job_types::task_driver::{TaskDriverJob, TaskDriverReceiver, new_task_driver_queue};
    use types_core::AccountId;
    use types_gossip::{WrappedPeerId, mocks::mock_peer};
    use types_tasks::{
        ArchivedQueuedTaskState, HistoricalTask, QueuedTaskState, TaskIdentifier, TaskQueueKey,
        mocks::mock_queued_task,
    };
    use util::channels::TracedMessage;

    use crate::{
        applicator::{
            StateApplicator, error::StateApplicatorError,
            test_helpers::mock_applicator_with_task_queue,
        },
        storage::{
            db::DB,
            tx::task_queue::{TaskQueuePreemptionState, queue_type::TaskQueue},
        },
    };

    // -----------
    // | Helpers |
    // -----------

    /// Get a task queue, deserializing it for comparison
    fn get_queue(applicator: &StateApplicator, key: &TaskQueueKey) -> TaskQueue {
        let tx = applicator.db().new_read_tx().unwrap();
        tx.get_task_queue(key).unwrap().map(|q| q.deserialize().unwrap()).unwrap_or_default()
    }

    /// Setup a mock applicator
    fn setup_mock_applicator() -> StateApplicator {
        let (applicator, queue) = setup_mock_applicator_with_driver_queue();
        std::mem::forget(queue); // forget the queue to avoid it closing
        applicator
    }

    /// Setup a mock applicator, and return with a task driver's work queue
    fn setup_mock_applicator_with_driver_queue() -> (StateApplicator, TaskDriverReceiver) {
        let (task_queue, recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        (applicator, recv)
    }

    /// Get the local peer ID given an applicator
    fn get_local_peer_id(applicator: &StateApplicator) -> WrappedPeerId {
        let tx = applicator.db().new_read_tx().unwrap();
        tx.get_peer_id().unwrap()
    }

    /// Set the local peer ID
    fn set_local_peer_id(peer_id: &WrappedPeerId, db: &DB) {
        let tx = db.new_write_tx().unwrap();
        tx.set_peer_id(peer_id).unwrap();
        tx.commit().unwrap();
    }

    /// Add a dummy task to the given queue
    fn enqueue_dummy_task(key: TaskQueueKey, db: &DB) -> TaskIdentifier {
        let task = mock_queued_task(key);
        let tx = db.new_write_tx().unwrap();
        tx.enqueue_serial_task(&key, &task).unwrap();

        // Add an assignment
        let my_id = tx.get_peer_id().unwrap();
        tx.add_assigned_task(&my_id, &task.id).unwrap();
        tx.commit().unwrap();

        task.id
    }

    /// Check that a task driver job is a run task with the given id
    fn assert_run_task(msg: TracedMessage<TaskDriverJob>, task_id: TaskIdentifier) {
        let job = msg.into_message();
        assert!(
            matches!(job, TaskDriverJob::Run { task: queued_task, .. } if queued_task.id == task_id)
        );
    }

    // ---------------------
    // | Basic Queue Tests |
    // ---------------------

    /// Tests Stage 1 defer-not-reject end-to-end through the applicator: a
    /// preemptive settle blocked by a committed head defers, then runs
    /// automatically via the pop-time completion hook when the blocker
    /// finishes.
    #[test]
    #[allow(non_snake_case)]
    fn test_enqueue_preemptive__defer_then_resume_on_completion() -> Result<()> {
        use crate::storage::tx::task_queue::storage::set_test_settle_defer;
        set_test_settle_defer(true);

        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let peer_id = get_local_peer_id(&applicator);
        let account_id = AccountId::new_v4();

        // Append a blocker task; it starts running, then mark it committed so the
        // queue is no longer serial-preemption-safe.
        let blocker = mock_queued_task(account_id);
        applicator.append_task(&blocker, &peer_id)?;
        assert_run_task(task_recv.recv()?, blocker.id);
        applicator.transition_task_state(
            blocker.id,
            QueuedTaskState::Running { state: "submitting".to_string(), committed: true },
        )?;

        // Enqueue a preemptive serial settle: blocked by the committed head, so
        // it defers rather than rejecting.
        let settle = mock_queued_task(account_id);
        applicator.enqueue_preemptive_task(&[account_id], &settle, &peer_id, true)?;

        // The settle is not enqueued, the queue still holds only the blocker, a
        // pending record exists, and nothing was dispatched.
        let queue = get_queue(&applicator, &account_id);
        assert_eq!(queue.serial_tasks, vec![blocker.id]);
        {
            let tx = applicator.db().new_read_tx()?;
            assert!(tx.get_task(&settle.id)?.is_none());
            assert!(tx.has_pending_preemption(&account_id)?);
        }
        assert!(task_recv.is_empty());

        // Complete the blocker -> the completion hook runs the deferred settle.
        applicator.pop_task(blocker.id, true /* success */)?;

        // The settle is now the running head, the pending record is cleared, and
        // the settle was dispatched to the task driver.
        let queue = get_queue(&applicator, &account_id);
        assert_eq!(queue.serial_tasks, vec![settle.id]);
        {
            let tx = applicator.db().new_read_tx()?;
            let settle_retrieved = tx.get_task(&settle.id)?.unwrap();
            assert!(matches!(
                settle_retrieved.state,
                ArchivedQueuedTaskState::Running { committed: false, .. }
            ));
            assert!(!tx.has_pending_preemption(&account_id)?);
        }
        assert_run_task(task_recv.recv()?, settle.id);

        set_test_settle_defer(false);
        Ok(())
    }

    /// Tests Stage 1 defer-not-reject across BOTH counterparty queues -- the
    /// shape that actually occurs in settlement. Both queue heads are
    /// committed, so the settle defers. Completing one blocker must NOT run
    /// it (the other queue is still committed); completing the second runs
    /// it exactly once.
    #[test]
    #[allow(non_snake_case)]
    fn test_enqueue_preemptive__defer_two_queues_all_or_nothing() -> Result<()> {
        use crate::storage::tx::task_queue::storage::set_test_settle_defer;
        set_test_settle_defer(true);

        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let peer_id = get_local_peer_id(&applicator);
        let account_a = AccountId::new_v4();
        let account_b = AccountId::new_v4();

        // A committed blocker on each counterparty queue
        let commit_state =
            QueuedTaskState::Running { state: "submitting".to_string(), committed: true };
        let blocker_a = mock_queued_task(account_a);
        applicator.append_task(&blocker_a, &peer_id)?;
        assert_run_task(task_recv.recv()?, blocker_a.id);
        applicator.transition_task_state(blocker_a.id, commit_state.clone())?;

        let blocker_b = mock_queued_task(account_b);
        applicator.append_task(&blocker_b, &peer_id)?;
        assert_run_task(task_recv.recv()?, blocker_b.id);
        applicator.transition_task_state(blocker_b.id, commit_state)?;

        // Preemptive settle spanning both queues: both blocked -> defer
        let settle = mock_queued_task(account_a);
        applicator.enqueue_preemptive_task(&[account_a, account_b], &settle, &peer_id, true)?;
        {
            let tx = applicator.db().new_read_tx()?;
            assert!(tx.get_task(&settle.id)?.is_none());
            assert!(tx.has_pending_preemption(&account_a)?);
            assert!(tx.has_pending_preemption(&account_b)?);
        }
        assert!(task_recv.is_empty());

        // Complete blocker A only: B is still committed -> settle must NOT run.
        // The hook leaves all pending records in place (it only clears them when
        // the settle actually runs), so the settle stays tracked on both queues.
        applicator.pop_task(blocker_a.id, true)?;
        {
            let tx = applicator.db().new_read_tx()?;
            assert!(tx.get_task(&settle.id)?.is_none(), "settle ran before both queues were free");
            assert!(tx.has_pending_preemption(&account_a)?);
            assert!(tx.has_pending_preemption(&account_b)?);
        }
        assert!(task_recv.is_empty(), "settle dispatched before both queues were free");

        // Complete blocker B: both queues now free -> settle runs exactly once
        applicator.pop_task(blocker_b.id, true)?;
        let queue_a = get_queue(&applicator, &account_a);
        let queue_b = get_queue(&applicator, &account_b);
        assert_eq!(queue_a.serial_tasks, vec![settle.id]);
        assert_eq!(queue_b.serial_tasks, vec![settle.id]);
        {
            let tx = applicator.db().new_read_tx()?;
            assert!(!tx.has_pending_preemption(&account_a)?);
            assert!(!tx.has_pending_preemption(&account_b)?);
        }
        assert_run_task(task_recv.recv()?, settle.id);
        assert!(task_recv.is_empty(), "settle dispatched more than once");

        set_test_settle_defer(false);
        Ok(())
    }

    /// Stage 4 fairness: a single-queue settle must NOT take the immediate fast
    /// path past a lower-`seq` two-queue settle already pending on its queue --
    /// it defers behind it. Without fairness the single-queue settle would
    /// preempt the (free) shared queue immediately, perpetually starving the
    /// two-queue settle (the observed 100% internal-match failure).
    #[test]
    #[allow(non_snake_case)]
    fn test_fairness__single_queue_defers_behind_pending_two_queue() -> Result<()> {
        use crate::storage::tx::task_queue::storage::{
            set_test_settle_defer, set_test_settle_fairness,
        };
        set_test_settle_defer(true);
        set_test_settle_fairness(true);

        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let peer_id = get_local_peer_id(&applicator);
        let user = AccountId::new_v4(); // counterparty queue (busy)
        let quoter = AccountId::new_v4(); // shared queue (free)

        // Commit a blocker on the user queue only; the quoter queue stays free.
        let blocker = mock_queued_task(user);
        applicator.append_task(&blocker, &peer_id)?;
        assert_run_task(task_recv.recv()?, blocker.id);
        applicator.transition_task_state(
            blocker.id,
            QueuedTaskState::Running { state: "submitting".to_string(), committed: true },
        )?;

        // Two-queue settle [user, quoter]: user is committed -> defers (seq 1),
        // pending on both queues.
        let two_queue = mock_queued_task(quoter);
        applicator.enqueue_preemptive_task(&[user, quoter], &two_queue, &peer_id, true)?;
        {
            let tx = applicator.db().new_read_tx()?;
            assert!(tx.has_pending_preemption(&quoter)?);
            assert!(task_recv.is_empty());
        }

        // Single-queue settle [quoter]: the quoter queue is free, so WITHOUT
        // fairness it would preempt and run immediately. WITH fairness it must
        // defer behind the pending two-queue settle.
        let single_queue = mock_queued_task(quoter);
        applicator.enqueue_preemptive_task(&[quoter], &single_queue, &peer_id, true)?;
        {
            let tx = applicator.db().new_read_tx()?;
            assert!(
                tx.get_task(&single_queue.id)?.is_none(),
                "single-queue settle jumped the FIFO ahead of the pending two-queue settle"
            );
        }
        assert!(task_recv.is_empty(), "single-queue settle dispatched despite fairness");

        // Free the user queue -> the two-queue settle (lowest seq) runs first.
        applicator.pop_task(blocker.id, true)?;
        let queue_quoter = get_queue(&applicator, &quoter);
        assert_eq!(
            queue_quoter.serial_tasks,
            vec![two_queue.id],
            "two-queue settle should run before the single-queue settle"
        );
        assert_run_task(task_recv.recv()?, two_queue.id);

        set_test_settle_defer(false);
        set_test_settle_fairness(false);
        Ok(())
    }

    /// Stage 4 fairness: with no pending preemptions on any target queue, the
    /// immediate fast path is preserved -- a single-queue settle on a free
    /// queue still preempts and runs immediately (no latency regression in
    /// the uncontended common case).
    #[test]
    #[allow(non_snake_case)]
    fn test_fairness__uncontended_fast_path_intact() -> Result<()> {
        use crate::storage::tx::task_queue::storage::{
            set_test_settle_defer, set_test_settle_fairness,
        };
        set_test_settle_defer(true);
        set_test_settle_fairness(true);

        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let peer_id = get_local_peer_id(&applicator);
        let quoter = AccountId::new_v4();

        // No pending entries anywhere: a single-queue settle on the free queue
        // takes the immediate fast path and runs.
        let settle = mock_queued_task(quoter);
        applicator.enqueue_preemptive_task(&[quoter], &settle, &peer_id, true)?;

        let queue = get_queue(&applicator, &quoter);
        assert_eq!(queue.serial_tasks, vec![settle.id]);
        {
            let tx = applicator.db().new_read_tx()?;
            assert!(!tx.has_pending_preemption(&quoter)?);
        }
        assert_run_task(task_recv.recv()?, settle.id);

        set_test_settle_defer(false);
        set_test_settle_fairness(false);
        Ok(())
    }

    /// Stage 4 A/B (in-process, against the REAL preemptive queue + FIFO +
    /// completion-hook drain — no deploy). Deterministically constructs the
    /// production starvation shape and counts the line-cutting that Stage 4
    /// eliminates.
    ///
    /// Each round: a two-queue INTERNAL settle `[Q, U]` is enqueued while its
    /// counterparty `U` is busy (a committed order task), so it DEFERS and sits
    /// pending at the head of the hot quoter queue `Q` — ready, just waiting on
    /// `U`. Then a burst of single-queue EXTERNAL settles `[Q]` arrives.
    /// Without fairness each external takes the immediate fast path and
    /// settles AHEAD of the waiting internal (a "bypass" — exactly how
    /// external flow starves internal flow in prod). With fairness, each
    /// external instead defers behind the pending internal, so when `U`
    /// frees the internal settles first.
    ///
    /// The metric is bypasses: external settles that jumped a ready-and-waiting
    /// internal settle. Fairness must drive it to zero.
    fn run_stage4_bypass(fairness: bool) -> Result<(usize, usize, usize)> {
        use crate::storage::tx::task_queue::storage::{
            set_test_settle_defer, set_test_settle_fairness,
        };
        set_test_settle_defer(true);
        set_test_settle_fairness(fairness);

        const ROUNDS: usize = 20;
        const EXTERNALS_PER_ROUND: usize = 5;
        let committed =
            || QueuedTaskState::Running { state: "submitting".to_string(), committed: true };

        let (app, recv) = setup_mock_applicator_with_driver_queue();
        let peer = get_local_peer_id(&app);
        let quoter = AccountId::new_v4();

        // Drain the task-driver channel, returning the ids that just started.
        let drain = |recv: &TaskDriverReceiver| -> Vec<TaskIdentifier> {
            let mut ids = Vec::new();
            while !recv.is_empty() {
                if let TaskDriverJob::Run { task, .. } = recv.recv().unwrap().into_message() {
                    ids.push(task.id);
                }
            }
            ids
        };

        let (mut internal_settled, mut bypasses, mut deferred) = (0usize, 0usize, 0usize);

        for _ in 0..ROUNDS {
            // Counterparty U busy (committed order task at its queue head).
            let user = AccountId::new_v4();
            let blocker = mock_queued_task(user);
            app.append_task(&blocker, &peer)?;
            let _ = drain(&recv); // blocker started (ignored)
            app.transition_task_state(blocker.id, committed())?;

            // Internal settle [Q, U]: U committed -> defers, pending at Q's head.
            let internal = mock_queued_task(quoter);
            app.enqueue_preemptive_task(&[quoter, user], &internal, &peer, true)?;
            assert!(!drain(&recv).contains(&internal.id), "internal should defer while U is busy");

            // A burst of external settles arrives while the internal waits on U.
            for _ in 0..EXTERNALS_PER_ROUND {
                let ext = mock_queued_task(quoter);
                app.enqueue_preemptive_task(&[quoter], &ext, &peer, true)?;
                if drain(&recv).contains(&ext.id) {
                    // Ran immediately => jumped the ready-and-waiting internal.
                    bypasses += 1;
                    app.pop_task(ext.id, true)?; // release Q for the next external
                    let _ = drain(&recv); // internal still can't run (U busy)
                } else {
                    deferred += 1; // fairness forced it behind the internal
                }
            }

            // U frees -> the internal settles; then drain+pop everything (incl.
            // any externals that deferred behind it) to reset Q for next round.
            app.pop_task(blocker.id, true)?;
            let mut saw_internal = false;
            loop {
                let ids = drain(&recv);
                if ids.is_empty() {
                    break;
                }
                if ids.contains(&internal.id) {
                    saw_internal = true;
                }
                for id in ids {
                    app.pop_task(id, true)?;
                }
            }
            if saw_internal {
                internal_settled += 1;
            }
        }

        set_test_settle_defer(false);
        set_test_settle_fairness(false);
        Ok((internal_settled, bypasses, deferred))
    }

    /// Stage 4 REGRESSION: the deferred-preemption FIFO only drains on
    /// `pop_task` (via `run_unblocked_preemptions`). With fairness ON, a settle
    /// whose target queue is FREE but whose FIFO is non-empty is DEFERRED
    /// rather than run. If nothing then pops that queue (it's idle), the
    /// drain never triggers and the deferred settle is stuck forever — the
    /// production wedge observed after the cancel-flood fix made quoter
    /// queues idle (every settle defers, nothing pops, FIFO never drains ->
    /// 0 fills).
    ///
    /// Returns whether the single-queue settle on the free queue actually ran.
    fn ran_on_free_queue_with_pending(fairness: bool) -> Result<bool> {
        use crate::storage::tx::task_queue::storage::{
            set_test_settle_defer, set_test_settle_fairness,
        };
        set_test_settle_defer(true);
        set_test_settle_fairness(fairness);

        let (app, recv) = setup_mock_applicator_with_driver_queue();
        let peer = get_local_peer_id(&app);
        let quoter = AccountId::new_v4();
        let user = AccountId::new_v4();
        let committed =
            || QueuedTaskState::Running { state: "submitting".to_string(), committed: true };
        let drain = |recv: &TaskDriverReceiver| -> Vec<TaskIdentifier> {
            let mut ids = Vec::new();
            while !recv.is_empty() {
                if let TaskDriverJob::Run { task, .. } = recv.recv().unwrap().into_message() {
                    ids.push(task.id);
                }
            }
            ids
        };

        // Make the quoter FIFO non-empty while the quoter queue itself is FREE:
        // a two-queue settle [quoter, user] defers because `user` is busy.
        let blocker = mock_queued_task(user);
        app.append_task(&blocker, &peer)?;
        app.transition_task_state(blocker.id, committed())?;
        let _ = drain(&recv);
        let two_queue = mock_queued_task(quoter);
        app.enqueue_preemptive_task(&[quoter, user], &two_queue, &peer, true)?;
        let _ = drain(&recv);

        // Enqueue a single-queue settle on the (free) quoter queue. It is
        // runnable now, but fairness defers it behind the pending entry; with no
        // subsequent pop on the quoter queue there is no drain trigger.
        let one_queue = mock_queued_task(quoter);
        app.enqueue_preemptive_task(&[quoter], &one_queue, &peer, true)?;
        let started = drain(&recv);
        let ran = started.contains(&one_queue.id);

        set_test_settle_defer(false);
        set_test_settle_fairness(false);
        Ok(ran)
    }

    /// With cancels gone the quoter queues are idle; fairness then wedges a
    /// runnable settle (no pop -> no drain). Disabling fairness restores the
    /// fast path so the settle runs on the free queue.
    #[test]
    fn sim_stage4_idle_queue_wedge() -> Result<()> {
        let ran_with_fairness = ran_on_free_queue_with_pending(true)?;
        let ran_without_fairness = ran_on_free_queue_with_pending(false)?;
        eprintln!(
            "[stage4-wedge] runnable settle on free queue ran?  fairness ON={ran_with_fairness}  OFF={ran_without_fairness}"
        );
        assert!(
            !ran_with_fairness,
            "fairness ON wedges a runnable settle on a free idle queue (no pop -> no drain)"
        );
        assert!(
            ran_without_fairness,
            "fairness OFF must let the settle fast-path and run on the free queue"
        );
        Ok(())
    }

    /// Stage 4 A/B: fairness must eliminate external settles cutting ahead of a
    /// ready, waiting internal settle, while still settling every internal.
    #[test]
    fn sim_stage4_fairness_ab() -> Result<()> {
        let (off_settled, off_bypass, off_deferred) = run_stage4_bypass(false)?;
        let (on_settled, on_bypass, on_deferred) = run_stage4_bypass(true)?;

        eprintln!(
            "[stage4] fairness OFF: internal settled={off_settled:<3} external bypasses={off_bypass:<3} external deferred={off_deferred}"
        );
        eprintln!(
            "[stage4] fairness ON : internal settled={on_settled:<3} external bypasses={on_bypass:<3} external deferred={on_deferred}"
        );

        // Without fairness, externals routinely jump the waiting internal.
        assert!(off_bypass > 0, "expected external bypasses without fairness; got {off_bypass}");
        // Fairness eliminates the line-cutting entirely.
        assert_eq!(on_bypass, 0, "fairness must let no external bypass a pending internal");
        // Every internal still settles under both (correctness, not just fairness).
        assert_eq!(off_settled, on_settled, "internal settle count must be unaffected");
        assert!(on_settled > 0, "internals must settle");
        Ok(())
    }

    /// Path B detector: `orphaned_preempt_head` surfaces the head of a queue
    /// stuck in `SerialPreemptionQueued` paired with its commit status -- both
    /// an uncommitted head (a settle never driven past `Pending`) and a
    /// committed head (a settle orphaned mid-submit). A healthy
    /// `NotPreempted` queue is never flagged. The caller
    /// (`clear_orphaned_preempted_queues`) decides which to reap and when
    /// via the age gate.
    #[test]
    #[allow(non_snake_case)]
    fn test_orphaned_preempt_head__surfaces_head_and_commit_status() -> Result<()> {
        use crate::storage::tx::task_queue::WedgedHeadKind;
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let peer = get_local_peer_id(&applicator);
        let acct = AccountId::new_v4();

        // Preempt the empty queue with a serial settle -> runs immediately
        // (SerialPreemptionQueued, head not yet committed). The head is surfaced
        // as uncommitted so the caller's age gate can reap it if it never
        // advances (orphaned at `Pending`).
        let settle = mock_queued_task(acct);
        applicator.enqueue_preemptive_task(&[acct], &settle, &peer, true)?;
        assert_run_task(task_recv.recv()?, settle.id);
        {
            let tx = applicator.db().new_read_tx()?;
            assert_eq!(
                tx.orphaned_preempt_head(&acct)?,
                Some((settle.id, WedgedHeadKind::Uncommitted)),
                "uncommitted SerialPreemptionQueued head must be surfaced as Uncommitted"
            );
        }

        // Settle commits (reaches submit); its worker then "dies" (never pops).
        applicator.transition_task_state(
            settle.id,
            QueuedTaskState::Running { state: "submitting".to_string(), committed: true },
        )?;
        {
            let tx = applicator.db().new_read_tx()?;
            assert_eq!(
                tx.orphaned_preempt_head(&acct)?,
                Some((settle.id, WedgedHeadKind::Committed)),
                "committed SerialPreemptionQueued head must be surfaced as Committed"
            );
        }

        // A healthy (NotPreempted) queue with a normal task is never flagged.
        let other = AccountId::new_v4();
        let normal = mock_queued_task(other);
        applicator.append_task(&normal, &peer)?;
        {
            let tx = applicator.db().new_read_tx()?;
            assert_eq!(tx.orphaned_preempt_head(&other)?, None);
        }
        Ok(())
    }

    /// Clear-purge: clearing one queue of a multi-queue serial settle must also
    /// remove the settle from its OTHER counterparty queue. Otherwise that
    /// queue is left with a dangling head id (the settle's task is deleted)
    /// -- it stays `SerialPreemptionQueued` forever and rejects every
    /// transition with `task not found`. This is the root cause of the
    /// post-clear settle storm.
    #[test]
    #[allow(non_snake_case)]
    fn test_clear_task_queue__purges_multi_queue_settle_from_counterparty() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let peer = get_local_peer_id(&applicator);
        let a = AccountId::new_v4();
        let b = AccountId::new_v4();

        // A serial settle preempts BOTH counterparties' queues.
        let settle = mock_queued_task(a);
        applicator.enqueue_preemptive_task(&[a, b], &settle, &peer, true)?;
        assert_run_task(task_recv.recv()?, settle.id);

        // Both queues are wedged on the settle head.
        {
            let tx = applicator.db().new_read_tx()?;
            assert_eq!(tx.orphaned_preempt_head(&a)?.map(|(id, _)| id), Some(settle.id));
            assert_eq!(tx.orphaned_preempt_head(&b)?.map(|(id, _)| id), Some(settle.id));
        }

        // Clear queue A (as the orphaned-queue self-heal would). The settle's
        // task is deleted; queue B must be purged, not left dangling.
        applicator.clear_queue(a)?;
        {
            let tx = applicator.db().new_read_tx()?;
            assert!(tx.get_task(&settle.id)?.is_none(), "settle task should be deleted");
            assert_eq!(
                tx.orphaned_preempt_head(&b)?,
                None,
                "counterparty queue B must be purged (NotPreempted), not left with a dangling head"
            );
        }
        Ok(())
    }

    /// Tests appending a task to an empty queue
    #[test]
    fn test_append_empty_queue() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let peer_id = get_local_peer_id(&applicator);

        let task_queue_key = TaskQueueKey::new_v4();
        let task = mock_queued_task(task_queue_key);
        let task_id = task.id;
        applicator.append_task(&task, &peer_id)?;

        // Check the task was added to the queue
        let queue = get_queue(&applicator, &task_queue_key);
        let tx = applicator.db().new_read_tx()?;
        let task_retrieved = tx.get_task(&task_id)?.unwrap();

        let expected_queue = TaskQueue { serial_tasks: vec![task_id], ..Default::default() };
        assert_eq!(queue, expected_queue);
        assert!(matches!(
            task_retrieved.state,
            ArchivedQueuedTaskState::Running { committed: false, .. }
        )); // should be started

        // Check the task was started
        assert!(!task_recv.is_empty());
        let job = task_recv.recv()?;
        assert_run_task(job, task_id);
        Ok(())
    }

    /// Test appending to an empty queue when the local peer is not the executor
    #[test]
    fn test_append_empty_queue_not_executor() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let task_queue_key = TaskQueueKey::new_v4();
        let task = mock_queued_task(task_queue_key);
        let executor = WrappedPeerId::random();

        applicator.append_task(&task, &executor)?;

        // Check the task was not started
        let queue = get_queue(&applicator, &task_queue_key);
        let expected_queue = TaskQueue { serial_tasks: vec![task.id], ..Default::default() };
        assert_eq!(queue, expected_queue);
        assert!(task_recv.is_empty());
        Ok(())
    }

    /// Tests the case in which a task is added to a non-empty queue
    #[test]
    fn test_append_non_empty_queue() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let peer_id = get_local_peer_id(&applicator);
        let task_queue_key = TaskQueueKey::new_v4();

        // Add a task directly via the db
        let task1_id = enqueue_dummy_task(task_queue_key, applicator.db());

        // Add another task via the applicator
        let task2 = mock_queued_task(task_queue_key);
        applicator.append_task(&task2, &peer_id)?;

        // Ensure that the second task is in the db's queue, not marked as running
        let queue = get_queue(&applicator, &task_queue_key);
        let tx = applicator.db().new_read_tx()?;
        let task2_retrieved = tx.get_task(&task2.id)?.unwrap();
        let expected_queue =
            TaskQueue { serial_tasks: vec![task1_id, task2.id], ..Default::default() };
        assert_eq!(queue, expected_queue);
        assert!(matches!(task2_retrieved.state, ArchivedQueuedTaskState::Queued));

        // Ensure that the task queue is empty (no task is marked as running)
        assert!(task_recv.is_empty());
        Ok(())
    }

    /// Test popping from a task queue of length one
    #[test]
    fn test_pop_singleton_queue() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();

        // Add a wallet; when the queue empties it will trigger the matching engine,
        // which requires the wallet to be present
        let account_id = AccountId::new_v4();
        let task_id = enqueue_dummy_task(account_id, applicator.db());
        applicator.pop_task(task_id, true /* success */)?;

        // Ensure the task was removed from the queue
        let queue = get_queue(&applicator, &account_id);
        let expected_queue = TaskQueue::default();
        assert_eq!(queue, expected_queue);

        // Ensure no task was started
        assert!(task_recv.is_empty());
        Ok(())
    }

    /// Tests popping from a queue of length two in which the local peer is not
    /// the executor of the next task
    #[test]
    fn test_pop_non_executor() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let task_queue_key = TaskQueueKey::new_v4();

        // Add a task directly via the db
        let task_id = enqueue_dummy_task(task_queue_key, applicator.db());

        // Add another task via the applicator
        let task2 = mock_queued_task(task_queue_key);
        let executor = WrappedPeerId::random();
        applicator.append_task(&task2, &executor)?; // Assign different executor

        // Pop the first task
        applicator.pop_task(task_id, true /* success */)?;

        // Ensure the first task was removed from the queue
        let queue = get_queue(&applicator, &task_queue_key);
        let tx = applicator.db().new_read_tx()?;
        let task2_retrieved = tx.get_task(&task2.id)?.unwrap();
        let expected_queue = TaskQueue { serial_tasks: vec![task2.id], ..Default::default() };
        assert_eq!(queue, expected_queue);
        assert!(matches!(
            task2_retrieved.state,
            ArchivedQueuedTaskState::Running { committed: false, .. }
        )); // should be started

        // Ensure no task was started
        assert!(task_recv.is_empty());
        Ok(())
    }

    /// Tests popping from a queue of length two in which the local peer is the
    /// executor of the next task
    #[test]
    fn test_pop_executor() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let peer_id = get_local_peer_id(&applicator);
        let task_queue_key = TaskQueueKey::new_v4();

        // Add a task directly via the db
        let task_id = enqueue_dummy_task(task_queue_key, applicator.db());

        // Add another task via the applicator
        let task2 = mock_queued_task(task_queue_key);
        applicator.append_task(&task2, &peer_id)?;

        // Pop the first task
        applicator.pop_task(task_id, true /* success */)?;

        // Ensure the first task was removed from the queue
        let queue = get_queue(&applicator, &task_queue_key);
        let tx = applicator.db().new_read_tx()?;
        let task2_retrieved = tx.get_task(&task2.id)?.unwrap();
        let expected_queue = TaskQueue { serial_tasks: vec![task2.id], ..Default::default() };
        assert_eq!(queue, expected_queue);
        assert!(matches!(
            task2_retrieved.state,
            ArchivedQueuedTaskState::Running { committed: false, .. }
        )); // should be started

        // Ensure the second task was started
        assert!(!task_recv.is_empty());
        let job = task_recv.recv()?;
        assert_run_task(job, task2.id);
        Ok(())
    }

    /// Test popping from a task queue and checking task history
    #[test]
    fn test_pop_and_check_history() -> Result<()> {
        let (applicator, _task_recv) = setup_mock_applicator_with_driver_queue();
        let task_queue_key = TaskQueueKey::new_v4();

        // Add two tasks: one successful, one failed
        let task_id1 = enqueue_dummy_task(task_queue_key, applicator.db());
        let task_id2 = enqueue_dummy_task(task_queue_key, applicator.db());
        applicator.pop_task(task_id1, true /* success */)?;
        applicator.pop_task(task_id2, false /* success */)?;

        // Ensure the task was added to history
        let tx = applicator.db().new_read_tx()?;
        let history_value = tx.get_task_history(&task_queue_key)?;
        let history = history_value
            .into_iter()
            .map(|h| h.deserialize())
            .collect::<Result<Vec<HistoricalTask>, _>>()?;
        tx.commit()?;

        assert_eq!(history.len(), 2);
        assert_eq!(history[0].id, task_id2);
        assert!(matches!(history[0].state, QueuedTaskState::Failed));
        assert_eq!(history[1].id, task_id1);
        assert!(matches!(history[1].state, QueuedTaskState::Completed));

        Ok(())
    }

    /// Test popping the same task twice, this should be gracefully rejected by
    /// the applicator
    #[test]
    fn test_double_pop() -> Result<()> {
        let (applicator, _task_recv) = setup_mock_applicator_with_driver_queue();
        let task_queue_key = TaskQueueKey::new_v4();

        // Test double-popping the only task in a queue
        let task_id1 = enqueue_dummy_task(task_queue_key, applicator.db());
        applicator.pop_task(task_id1, true /* success */)?;
        let res = applicator.pop_task(task_id1, true /* success */);
        assert!(matches!(res, Err(StateApplicatorError::Rejected(_))));
        applicator.clear_queue(task_queue_key)?;

        // Test double-popping a task in a filled queue
        let task_id1 = enqueue_dummy_task(task_queue_key, applicator.db());
        enqueue_dummy_task(task_queue_key, applicator.db());
        applicator.pop_task(task_id1, true /* success */)?;
        let res = applicator.pop_task(task_id1, true /* success */);
        assert!(matches!(res, Err(StateApplicatorError::Rejected(_))));
        applicator.clear_queue(task_queue_key)?;

        // Test double-popping a failed task
        let task_id1 = enqueue_dummy_task(task_queue_key, applicator.db());
        applicator.pop_task(task_id1, false /* success */)?;
        let res = applicator.pop_task(task_id1, false /* success */);
        assert!(matches!(res, Err(StateApplicatorError::Rejected(_))));
        Ok(())
    }

    /// Test transitioning the state of the top task on the queue
    #[test]
    fn test_transition_task_state() -> Result<()> {
        let (applicator, _task_recv) = setup_mock_applicator_with_driver_queue();
        let my_peer_id = get_local_peer_id(&applicator);

        // Add a task directly via the db
        let task_queue_key = TaskQueueKey::new_v4();
        let task = mock_queued_task(task_queue_key);
        applicator.append_task(&task, &my_peer_id /* executor */)?;

        // Transition the state of the top task in the queue
        let new_state = QueuedTaskState::Running { state: "Test".to_string(), committed: false };
        applicator.transition_task_state(task.id, new_state)?;

        // Ensure the task state was updated
        let tx = applicator.db().new_read_tx()?;
        let task_info = tx.get_task(&task.id)?.unwrap().deserialize()?;
        tx.commit()?;

        assert!(matches!(
            task_info.state,
            QueuedTaskState::Running { state, committed: false } if state == "Test"
        ));
        Ok(())
    }

    /// Tests transitioning the state of a task after its queue has been
    /// preempted
    #[test]
    #[allow(non_snake_case)]
    fn test_transition_task_state_invalid__queue_preempted() -> Result<()> {
        let (applicator, _task_recv) = setup_mock_applicator_with_driver_queue();
        let my_peer_id = get_local_peer_id(&applicator);

        // Add a normal task
        let task_queue_key = TaskQueueKey::new_v4();
        let task = mock_queued_task(task_queue_key);
        applicator.append_task(&task, &my_peer_id /* executor */)?;

        // Preempt the queue
        let preemptive_task = mock_queued_task(task_queue_key);
        applicator.enqueue_preemptive_task(
            &[task_queue_key],
            &preemptive_task,
            &my_peer_id,
            true, // is_serial
        )?;

        // Try to transition the state of the task
        let new_state = QueuedTaskState::Running { state: "Test".to_string(), committed: false };
        let err = applicator.transition_task_state(task.id, new_state.clone()).unwrap_err();
        assert!(matches!(err, StateApplicatorError::Rejected(_)));
        Ok(())
    }

    /// Tests clearing an empty queue
    #[test]
    #[allow(non_snake_case)]
    fn test_clear_queue__empty() -> Result<()> {
        let applicator = setup_mock_applicator();

        // Clear the queue
        let key = TaskQueueKey::new_v4();
        applicator.clear_queue(key)?;

        // Check that the queue is still empty and unpaused
        let queue = get_queue(&applicator, &key);
        let expected_queue = TaskQueue::default();
        assert_eq!(queue, expected_queue);
        Ok(())
    }

    /// Tests clearing a non-empty queue
    #[test]
    #[allow(non_snake_case)]
    fn test_clear_queue__non_empty() -> Result<()> {
        // Add a task directly via the db
        let applicator = setup_mock_applicator();
        let task_queue_key = TaskQueueKey::new_v4();
        enqueue_dummy_task(task_queue_key, applicator.db());

        // Clear the queue
        applicator.clear_queue(task_queue_key)?;

        // Check that the queue is empty and unpaused
        let queue = get_queue(&applicator, &task_queue_key);
        let expected_queue = TaskQueue::default();
        assert_eq!(queue, expected_queue);
        Ok(())
    }

    /// Tests clearing a queue after it's been preempted
    #[test]
    #[allow(non_snake_case)]
    fn test_clear_queue__preempted() -> Result<()> {
        let applicator = setup_mock_applicator();
        let my_peer_id = get_local_peer_id(&applicator);

        // Add a normal task
        let task_queue_key = TaskQueueKey::new_v4();
        let task = mock_queued_task(task_queue_key);
        applicator.append_task(&task, &my_peer_id /* executor */)?;

        // Preempt the queue
        let preemptive_task = mock_queued_task(task_queue_key);
        applicator.enqueue_preemptive_task(
            &[task_queue_key],
            &preemptive_task,
            &my_peer_id,
            true, // is_serial
        )?;

        // Clear the queue
        applicator.clear_queue(task_queue_key)?;

        // Check the task queue
        let tx = applicator.db().new_read_tx()?;
        let task_queue = tx
            .get_task_queue(&task_queue_key)?
            .map(|q| q.deserialize())
            .transpose()?
            .unwrap_or_default();
        assert_eq!(task_queue, TaskQueue::default());
        Ok(())
    }

    // --------------------
    // | Preemption Tests |
    // --------------------

    /// Tests preempting a queue with a serial task
    #[test]
    fn test_enqueue_preemptive_serial() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let my_peer_id = get_local_peer_id(&applicator);
        let task_queue_key = TaskQueueKey::new_v4();

        // Add a serial task to the queue
        let serial_task = mock_queued_task(task_queue_key);
        applicator.append_task(&serial_task, &my_peer_id)?;
        task_recv.recv().expect("expected applicator to enqueue task for execution");

        // Preempt the queue with a new serial task
        let preemptive_task = mock_queued_task(task_queue_key);
        applicator.enqueue_preemptive_task(
            &[task_queue_key],
            &preemptive_task,
            &my_peer_id,
            true, // is_serial
        )?;

        // Ensure the task queue has updated
        let tx = applicator.db().new_read_tx()?;
        let task_queue = tx
            .get_task_queue(&task_queue_key)?
            .ok_or_else(|| StateApplicatorError::reject("queue not found"))?
            .deserialize()?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![preemptive_task.id, serial_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);

        // The existing task should be in the queued state
        let existing_task = tx.get_task(&serial_task.id)?.unwrap();
        assert!(matches!(existing_task.state, ArchivedQueuedTaskState::Queued));

        // Lastly, the applicator should have sent the task to the driver
        let job = task_recv.recv().unwrap();
        assert_run_task(job, preemptive_task.id);
        Ok(())
    }

    /// Tests enqueuing a preemptive concurrent task
    #[test]
    fn test_enqueue_preemptive_concurrent() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let my_peer_id = get_local_peer_id(&applicator);
        let task_queue_key = TaskQueueKey::new_v4();
        let task1 = mock_queued_task(task_queue_key);
        let task2 = mock_queued_task(task_queue_key);

        // Enqueue both tasks as preemptive concurrent tasks
        applicator.enqueue_preemptive_task(
            &[task_queue_key],
            &task1,
            &my_peer_id,
            false, // is_serial
        )?;
        applicator.enqueue_preemptive_task(
            &[task_queue_key],
            &task2,
            &my_peer_id,
            false, // is_serial
        )?;

        // Check that the queue has been updated correctly
        let tx = applicator.db().new_read_tx()?;
        let task_queue = tx
            .get_task_queue(&task_queue_key)?
            .ok_or_else(|| StateApplicatorError::reject("queue not found"))?
            .deserialize()?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![task1.id, task2.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);

        // The existing tasks should be in the running state
        let task1_retrieved = tx.get_task(&task1.id)?.unwrap();
        let task2_retrieved = tx.get_task(&task2.id)?.unwrap();
        assert!(matches!(task1_retrieved.state, ArchivedQueuedTaskState::Running { .. }));
        assert!(matches!(task2_retrieved.state, ArchivedQueuedTaskState::Running { .. }));

        // The applicator should have forwarded both tasks to the driver
        let job1 = task_recv.recv().unwrap();
        let job2 = task_recv.recv().unwrap();
        assert_run_task(job1, task1.id);
        assert_run_task(job2, task2.id);
        Ok(())
    }

    /// Tests popping a serial preemptive task from the queue
    #[test]
    fn test_pop_serial_preemptive() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let my_peer_id = get_local_peer_id(&applicator);
        let task_queue_key = TaskQueueKey::new_v4();

        // Add a serial task to the queue
        let serial_task = mock_queued_task(task_queue_key);
        applicator.append_task(&serial_task, &my_peer_id)?;
        task_recv.recv().expect("expected applicator to enqueue task for execution");

        // Preempt the queue with a new serial task and then pop it successfully
        let preemptive_task = mock_queued_task(task_queue_key);
        applicator.enqueue_preemptive_task(
            &[task_queue_key],
            &preemptive_task,
            &my_peer_id,
            true,
        )?;
        applicator.pop_task(preemptive_task.id, true)?;
        task_recv.recv().expect("expected applicator to forward task");

        // Ensure the task was removed from the queue
        let task_queue = get_queue(&applicator, &task_queue_key);
        let expected_queue = TaskQueue { serial_tasks: vec![serial_task.id], ..Default::default() };
        assert_eq!(task_queue, expected_queue);

        // The applicator should have forwarded the original task to the driver
        let job = task_recv.recv().unwrap();
        assert_run_task(job, serial_task.id);
        Ok(())
    }

    /// Tests popping a concurrent preemptive task from the queue
    #[test]
    fn test_pop_concurrent_preemptive() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let my_peer_id = get_local_peer_id(&applicator);
        let task_queue_key = TaskQueueKey::new_v4();

        // Add a concurrent task to the queue
        let concurrent_task = mock_queued_task(task_queue_key);
        applicator.enqueue_preemptive_task(
            &[task_queue_key],
            &concurrent_task,
            &my_peer_id,
            false, // is_serial
        )?;
        task_recv.recv().expect("expected applicator to enqueue task for execution");

        // Add a serial task to the queue through the normal path
        let serial_task = mock_queued_task(task_queue_key);
        applicator.append_task(&serial_task, &my_peer_id)?;

        // Pop the concurrent task successfully
        applicator.pop_task(concurrent_task.id, true)?;

        // Ensure the task was removed from the queue
        let task_queue = get_queue(&applicator, &task_queue_key);
        let expected_queue = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);

        // The applicator should have forwarded the original task to the driver
        let job = task_recv.recv().unwrap();
        assert_run_task(job, serial_task.id);
        Ok(())
    }

    /// Tests adding a preemptive task that affects multiple queues
    #[test]
    #[allow(non_snake_case)]
    fn test_enqueue_serial_preemptive__multiple_queues() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let my_peer_id = get_local_peer_id(&applicator);

        // Add a normal task to the first queue
        let queue_key1 = TaskQueueKey::new_v4();
        let queue_key2 = TaskQueueKey::new_v4();
        let task1 = mock_queued_task(queue_key1);
        applicator.append_task(&task1, &my_peer_id)?;
        task_recv.recv().expect("expected applicator to enqueue task for execution");

        // Add a preemptive task to both queues
        let preemptive_task = mock_queued_task(queue_key1);
        applicator.enqueue_preemptive_task(
            &[queue_key1, queue_key2],
            &preemptive_task,
            &my_peer_id,
            true, // is_serial
        )?;
        let job = task_recv.recv().expect("expected applicator to enqueue task for execution");
        assert_run_task(job, preemptive_task.id);

        // Check that the queues have been updated correctly
        let tx = applicator.db().new_read_tx()?;
        let task_queue1 = tx
            .get_task_queue(&queue_key1)?
            .ok_or_else(|| StateApplicatorError::reject("queue not found"))?
            .deserialize()?;
        let task_queue2 = tx
            .get_task_queue(&queue_key2)?
            .ok_or_else(|| StateApplicatorError::reject("queue not found"))?
            .deserialize()?;
        tx.commit()?;

        let expected_queue1 = TaskQueue {
            serial_tasks: vec![preemptive_task.id, task1.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        let expected_queue2 = TaskQueue {
            serial_tasks: vec![preemptive_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_eq!(task_queue1, expected_queue1);
        assert_eq!(task_queue2, expected_queue2);

        // Now pop the preemptive task, the applicator should forward the original task
        // on the first queue
        applicator.pop_task(preemptive_task.id, true)?;
        let job = task_recv.recv().unwrap();
        assert_run_task(job, task1.id);

        // Check the task status of the original task
        let tx = applicator.db().new_read_tx()?;
        let task1_retrieved = tx.get_task(&task1.id)?.unwrap();
        assert!(matches!(task1_retrieved.state, ArchivedQueuedTaskState::Running { .. }));
        drop(tx);

        let task_queue1 = get_queue(&applicator, &queue_key1);
        let task_queue2 = get_queue(&applicator, &queue_key2);
        let expected_queue1 = TaskQueue {
            serial_tasks: vec![task1.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_eq!(task_queue1, expected_queue1);
        assert_eq!(task_queue2, TaskQueue::default());
        Ok(())
    }

    /// Tests enqueueing a concurrent preemptive task that affects multiple
    /// queues
    #[test]
    #[allow(non_snake_case)]
    fn test_enqueue_concurrent_preemptive__multiple_queues() -> Result<()> {
        let (applicator, task_recv) = setup_mock_applicator_with_driver_queue();
        let my_peer_id = get_local_peer_id(&applicator);

        // Add a concurrent preemptive task to both queues
        let queue_key1 = TaskQueueKey::new_v4();
        let queue_key2 = TaskQueueKey::new_v4();
        let preemptive_task = mock_queued_task(queue_key1);
        applicator.enqueue_preemptive_task(
            &[queue_key1, queue_key2],
            &preemptive_task,
            &my_peer_id,
            false, // is_serial
        )?;
        let job = task_recv.recv().expect("expected applicator to enqueue task for execution");
        assert_run_task(job, preemptive_task.id);

        // Add a serial task behind the concurrent task on the second queue
        let task2 = mock_queued_task(queue_key2);
        applicator.append_task(&task2, &my_peer_id)?;

        // Pop the concurrent task successfully, check that the applicator forwarded the
        // serial task
        applicator.pop_task(preemptive_task.id, true /* success */)?;
        let job = task_recv.recv().unwrap();
        assert_run_task(job, task2.id);

        // Check the task status of the original task
        let tx = applicator.db().new_read_tx()?;
        let task2_retrieved = tx.get_task(&task2.id)?.unwrap();
        assert!(matches!(task2_retrieved.state, ArchivedQueuedTaskState::Running { .. }));

        let task_queue1 = tx.get_task_queue(&queue_key1)?.unwrap().deserialize()?;
        let task_queue2 = tx.get_task_queue(&queue_key2)?.unwrap().deserialize()?;
        let expected_queue2 = TaskQueue {
            serial_tasks: vec![task2.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_eq!(task_queue1, TaskQueue::default());
        assert_eq!(task_queue2, expected_queue2);
        Ok(())
    }

    // ----------------------
    // | Reassignment Tests |
    // ----------------------

    /// Test the case in which a task is reassigned to a non-local peer
    #[test]
    #[allow(non_snake_case)]
    fn test_reassign__non_executor() -> Result<()> {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        // Add a task
        let failed_peer = WrappedPeerId::random();
        let reassigned_peer = WrappedPeerId::random();
        let task = mock_queued_task(AccountId::new_v4());
        applicator.append_task(&task, &failed_peer)?;

        // Reassign the task
        applicator.reassign_tasks(&failed_peer, &reassigned_peer)?;

        // Ensure the task was reassigned
        let tx = applicator.db().new_read_tx()?;
        let executor = tx.get_task_assignment(&task.id)?.unwrap().deserialize()?;
        tx.commit()?;

        assert_eq!(executor, reassigned_peer);
        assert!(task_recv.is_empty());
        Ok(())
    }

    /// Tests reassigning a task to the local peer
    #[test]
    #[allow(non_snake_case)]
    fn test_reassign__local_executor() -> Result<()> {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        // Add a task
        let failed_peer = WrappedPeerId::random();
        let task = mock_queued_task(TaskQueueKey::new_v4());
        applicator.append_task(&task, &failed_peer)?;

        // Reassign the task
        applicator.reassign_tasks(&failed_peer, &peer_id)?;

        // Ensure the task was reassigned
        let tx = applicator.db().new_read_tx()?;
        let executor = tx.get_task_assignment(&task.id)?.unwrap().deserialize()?;
        tx.commit()?;
        assert_eq!(executor, peer_id);

        // Verify the task was started on the local peer
        assert!(!task_recv.is_empty());
        assert_run_task(task_recv.recv()?, task.id);
        Ok(())
    }

    /// Tests reassigning a task that was queued, i.e. not running at the time
    /// it was reassigned
    #[test]
    fn test_reassign_queued_task() -> Result<()> {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let local_peer_id = WrappedPeerId::random();
        set_local_peer_id(&local_peer_id, applicator.db());

        // Add two tasks, the second on a failed peer
        let peer2 = WrappedPeerId::random();
        let failed_peer = WrappedPeerId::random();

        let queue_key = TaskQueueKey::new_v4();
        let task1 = mock_queued_task(queue_key);
        let task2 = mock_queued_task(queue_key);
        applicator.append_task(&task1, &peer2)?;
        applicator.append_task(&task2, &failed_peer)?;

        // Reassign the task
        applicator.reassign_tasks(&failed_peer, &local_peer_id)?;

        // Ensure the first task was not reassigned and the second task was
        let tx = applicator.db().new_read_tx()?;
        let executor1 = tx.get_task_assignment(&task1.id)?.unwrap().deserialize()?;
        let executor2 = tx.get_task_assignment(&task2.id)?.unwrap().deserialize()?;
        tx.commit()?;
        assert_eq!(executor1, peer2);
        assert_eq!(executor2, local_peer_id);

        // Pop the first task
        applicator.pop_task(task1.id, true /* success */).unwrap();

        // The second task should now be started on the local peer
        assert!(!task_recv.is_empty());
        assert_run_task(task_recv.recv()?, task2.id);
        Ok(())
    }
}
