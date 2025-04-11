//! Task queue state transition applicator methods

use common::types::{
    gossip::WrappedPeerId,
    tasks::{HistoricalTask, QueuedTask, QueuedTaskState, TaskIdentifier, TaskQueueKey},
    wallet::WalletIdentifier,
};
use external_api::{
    bus_message::{task_history_topic, task_topic, SystemBusMessage},
    http::task::ApiTaskStatus,
    types::ApiHistoricalTask,
};
use job_types::{
    event_manager::{try_send_event, RelayerEvent, TaskCompletionEvent},
    handshake_manager::HandshakeManagerJob,
    task_driver::TaskDriverJob,
};
use libmdbx::{TransactionKind, RW};
use tracing::{error, info, instrument, warn};
use util::err_str;

use crate::storage::{error::StorageError, tx::StateTxn};

use super::{
    error::StateApplicatorError, return_type::ApplicatorReturnType, Result, StateApplicator,
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

/// Helper to ignore errors that come from double writes
/// TODO(@joeykraut): Remove this once we migrate to v2
fn double_write_helper<R>(res: std::result::Result<R, StorageError>) {
    if let Err(e) = res {
        warn!("error double writing: {e}");
    }
}

/// Error message emitted when a task queue is already paused
fn already_paused(id: TaskQueueKey) -> String {
    format!("task queue {id} already paused")
}

/// Error message emitted when the applicator attempts to preempt a conflicting
/// committed task
fn already_committed(id: TaskQueueKey) -> String {
    format!("cannot preempt committed task on queue: {id}")
}

/// Construct the running state for a newly started task
fn new_running_state() -> QueuedTaskState {
    QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false }
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
        let tx = self.db().new_write_tx()?;

        // Index the task
        // TODO(@joeykraut): Remove v1 implementation once we migrate
        double_write_helper(tx.add_task(&queue_key, task));
        tx.enqueue_serial_task(&queue_key, task)?;
        tx.add_assigned_task(executor, &task.id)?;

        // Run the task if possible
        self.maybe_run_task(queue_key, task, &tx)?;
        tx.commit()?;

        self.publish_task_updates(queue_key, task);
        Ok(ApplicatorReturnType::None)
    }

    /// Apply a `PopTask` state transition
    #[instrument(skip_all, err, fields(task_id = %task_id))]
    pub fn pop_task(&self, task_id: TaskIdentifier, success: bool) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;
        let keys = tx.get_queue_keys_for_task_v2(&task_id)?;
        if keys.is_empty() {
            return Err(StateApplicatorError::reject(ERR_NO_KEY));
        }

        // Pop the task from the queue, remove its assignment, and add it to history
        let (task, executor) = self
            .pop_and_record_task(&keys[0], &task_id, success, &tx)?
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
                self.maybe_run_task(key, &task, &tx)?;
            }

            if Self::should_run_matching_engine(&executor, &key, &task, &tx)? {
                // Run the matching engine on all orders that are ready
                self.run_matching_engine_on_wallet(key, &tx)?;
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
        let tx = self.db().new_write_tx()?;
        let keys = tx.get_queue_keys_for_task_v2(&task_id)?;

        // Check that the task is running
        let task = tx
            .get_task_v2(&task_id)?
            .ok_or_else(|| StateApplicatorError::reject(invalid_task_id(task_id)))?;
        if !task.state.is_running() {
            // This can happen if the queue was preempted by another task, and the task that
            // was previously running now tries to update its state
            return Err(StateApplicatorError::reject(task_not_running(task_id)));
        }

        // TODO(@joeykraut): Remove this once we migrate to v2
        double_write_helper(tx.transition_task(&keys[0], state.clone()));
        tx.transition_task_v2(&task_id, state)?;
        let updated_task = tx.get_task_v2(&task_id)?.expect("task should exist");
        tx.commit()?;

        self.publish_task_updates_multiple(&keys, &updated_task);
        Ok(ApplicatorReturnType::None)
    }

    /// Clear the task queue, marking all tasks as failed
    #[instrument(skip_all, err, fields(queue_key = %key))]
    pub fn clear_queue(&self, key: TaskQueueKey) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;
        self.clear_task_queue(key, &tx)?;

        // Resume the task queue in case it was paused
        double_write_helper(tx.resume_task_queue(&key));
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
        let tx = self.db().new_write_tx()?;
        // Enqueue the task on the given queues
        self.try_preempt_queues(keys, task, is_serial, &tx)?;

        // Assign the task and run it if possible
        tx.add_assigned_task(executor, &task.id)?;
        // TODO(@joeykraut): We don't need to pass a queue key after migration
        self.maybe_run_task(keys[0], task, &tx)?;

        // We double write to the old queue implementation to ensure consistency during
        // the migration. However, we do not add a preemptive task to the original
        // queue, as we don't want to "pause", we want the new locking logic to
        // take effect
        //
        // TODO(@joeykraut): Remove this once the migration is complete
        for key in keys.iter() {
            double_write_helper(tx.add_task_front(key, task));
        }
        tx.commit()?;

        self.publish_task_updates_multiple(keys, task);
        Ok(ApplicatorReturnType::None)
    }

    /// Preempt all queues on a given task
    ///
    /// Multiple queues may be preempted at once to give "all or none" locking
    /// semantics to the caller
    ///
    /// TODO(@joeykraut): Remove this once the migration is complete
    #[deprecated(note = "Use `EnqueuePreemptiveTask` instead")]
    pub fn preempt_task_queues(
        &self,
        keys: &[TaskQueueKey],
        task: &QueuedTask,
        executor: &WrappedPeerId,
    ) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;
        for key in keys.iter() {
            self.preempt_task_queue(*key, task, executor, &tx)?;
        }

        tx.commit()?;
        Ok(ApplicatorReturnType::None)
    }

    /// Preempt the given task queue
    #[instrument(skip_all, err, fields(queue_key = %key))]
    pub fn preempt_task_queue(
        &self,
        key: TaskQueueKey,
        task: &QueuedTask,
        executor: &WrappedPeerId,
        tx: &StateTxn<'_, RW>,
    ) -> Result<ApplicatorReturnType> {
        // Stop any running tasks if possible
        let current_running_task = tx.get_current_running_task(&key)?;
        if let Some(task) = current_running_task {
            if task.state.is_committed() {
                error!("cannot preempt committed task: {}", task.id);
                let err_msg = already_committed(key);
                return Err(StateApplicatorError::reject(err_msg));
            }

            // Otherwise transition the task to queued
            // TODO(@joeykraut): Remove the v1 implementation once we migrate
            let state = QueuedTaskState::Queued;
            double_write_helper(tx.transition_task(&key, state.clone()));
            tx.transition_task_v2(&task.id, state)?;
        }

        // If the queue is already paused, a preemptive task is already
        // running, with which we should not conflict
        if tx.is_queue_paused(&key)? {
            return Err(StateApplicatorError::reject(already_paused(key)));
        }

        // Pause the queue
        double_write_helper(tx.pause_task_queue(&key));
        tx.add_assigned_task(executor, &task.id)?;
        // TODO(@joeykraut): Remove the v1 implementation once we migrate
        double_write_helper(tx.add_task_front(&key, task));
        tx.preempt_queue_with_serial(&[key], task)?;
        self.publish_task_updates(key, task);

        Ok(ApplicatorReturnType::None)
    }

    /// Resume multiple task queues
    pub fn resume_task_queues(
        &self,
        keys: &[TaskQueueKey],
        success: bool,
    ) -> Result<ApplicatorReturnType> {
        if keys.is_empty() {
            return Ok(ApplicatorReturnType::None);
        }

        let tx = self.db().new_write_tx()?;

        // Resume each queue
        for key in keys.iter() {
            self.resume_task_queue(*key, success, &tx)?;
        }
        tx.commit()?;
        Ok(ApplicatorReturnType::None)
    }

    /// Resume a task queue
    #[instrument(skip_all, err, fields(queue_key = %key))]
    fn resume_task_queue(
        &self,
        key: TaskQueueKey,
        success: bool,
        tx: &StateTxn<'_, RW>,
    ) -> Result<ApplicatorReturnType> {
        // We don't resume an unpaused queue, nor do we execute any of the dequeuing
        // logic below, this may happen if the queue was cleared while a preemptive task
        // was running
        if !tx.is_queue_paused(&key)? {
            warn!("task queue {key} is not paused, ignoring resume");
            return Ok(ApplicatorReturnType::None);
        }

        // Resume the queue, and pop the preemptive task that was added when the queue
        // was paused
        tx.resume_task_queue(&key)?;
        // TODO(@joeykraut): Remove this once we migrate to v2
        let task_id = match tx.get_queued_tasks(&key)?.first().map(|t| t.id) {
            Some(t) => t,
            None => return Ok(ApplicatorReturnType::None),
        };

        // We ignore `None` here for the migration
        // TODO(@joeykraut): Remove this once we migrate to v2
        let (task, executor) = match self.pop_and_record_task(&key, &task_id, success, tx)? {
            Some((t, e)) => (t, e),
            None => return Ok(ApplicatorReturnType::None),
        };

        // If the task failed, clear the rest of the queue, as subsequent tasks will
        // likely have invalid state
        if !success {
            self.clear_task_queue(key, tx)?;
        }

        // Start running the first task if it exists
        // This will resume the task as if it is starting anew, regardless of whether
        // the task was previously running
        let tasks = tx.get_queued_tasks(&key)?;
        if let Some(task) = tasks.first() {
            self.maybe_run_task(key, task, tx)?;
        }

        // Possibly run the matching engine on the wallet
        if Self::should_run_matching_engine(&executor, &key, &task, tx)? {
            self.run_matching_engine_on_wallet(key, tx)?;
        }

        self.publish_task_updates(key, &task);
        Ok(ApplicatorReturnType::None)
    }

    /// Reassign all tasks from one peer to another
    pub fn reassign_tasks(
        &self,
        from: &WrappedPeerId,
        to: &WrappedPeerId,
    ) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;
        let reassigned_tasks = tx.reassign_tasks(from, to)?;
        if !reassigned_tasks.is_empty() {
            info!("Reassigning {} tasks from {from} to {to}", reassigned_tasks.len());
        }

        // Handle in-flight tasks that were reassigned
        for task_id in reassigned_tasks.into_iter() {
            let task = match tx.get_task_v2(&task_id)? {
                Some(task) => task,
                None => continue,
            };

            if !task.state.is_running() {
                continue;
            }

            // TODO: If the task is committed we can be smarter and check for its most
            // recent state on-chain. This is a simpler solution for the moment, but will
            // error in the case described
            for queue in tx.get_queue_keys_for_task_v2(&task_id)? {
                self.maybe_run_task(queue, &task, &tx)?;
            }
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
    fn publish_task_updates(&self, key: TaskQueueKey, task: &QueuedTask) {
        let task_id = task.id;

        // Publish a message for the individual task
        let task_topic = task_topic(&task_id);
        if self.system_bus().has_listeners(&task_topic) {
            let status: ApiTaskStatus = task.clone().into();
            self.system_bus().publish(task_topic, SystemBusMessage::TaskStatusUpdate { status });
        }

        // Publish a message for the key's task history
        let history_topic = task_history_topic(&key);
        if self.system_bus().has_listeners(&history_topic)
            && let Some(t) = ApiHistoricalTask::from_queued_task(key, task)
        {
            self.system_bus()
                .publish(history_topic, SystemBusMessage::TaskHistoryUpdate { task: t });
        }
    }

    /// Transition a task into the running state
    fn maybe_run_task(
        &self,
        queue_key: TaskQueueKey,
        task: &QueuedTask,
        tx: &StateTxn<'_, RW>,
    ) -> Result<()> {
        if !tx.can_task_run(&task.id)? {
            return Ok(());
        }

        // TODO(@joeykraut): Remove v1 implementation once we migrate
        let running_state = new_running_state();
        double_write_helper(tx.transition_task(&queue_key, running_state.clone()));
        tx.transition_task_v2(&task.id, running_state)?;
        self.maybe_execute_task(task, tx)
    }

    /// Start a task if the current peer is the executor
    #[instrument(skip_all, err, fields(task_id = %task.id, task = %task.descriptor.display_description()))]
    fn maybe_execute_task<T: TransactionKind>(
        &self,
        task: &QueuedTask,
        tx: &StateTxn<'_, T>,
    ) -> Result<()> {
        let my_peer_id = tx.get_peer_id()?;
        let executor = tx
            .get_task_assignment(&task.id)?
            .ok_or_else(|| StateApplicatorError::MissingEntry(ERR_UNASSIGNED_TASK))?;

        if executor == my_peer_id {
            self.config
                .task_queue
                .send(TaskDriverJob::Run(task.clone()))
                .map_err(err_str!(StateApplicatorError::EnqueueTask))?;
        }

        Ok(())
    }

    /// Given the current state of the queue and the last popped task, determine
    /// if the matching engine should be run.
    /// This should be the case if the queue is empty, the last task was a
    /// wallet task, and the current peer is the executor of the last task.
    fn should_run_matching_engine<T: TransactionKind>(
        executor: &WrappedPeerId,
        queue_key: &TaskQueueKey,
        popped_task: &QueuedTask,
        tx: &StateTxn<'_, T>,
    ) -> Result<bool> {
        let this_node = tx.get_peer_id()?;
        let queue_empty = tx.is_queue_empty_v2(queue_key)?;
        let is_executor = *executor == this_node;
        let is_wallet_task = popped_task.descriptor.is_wallet_task();
        Ok(queue_empty && is_executor && is_wallet_task)
    }

    /// Run the internal matching engine on all of a wallet's orders that are
    /// ready for matching
    fn run_matching_engine_on_wallet<T: TransactionKind>(
        &self,
        wallet_id: WalletIdentifier,
        tx: &StateTxn<'_, T>,
    ) -> Result<()> {
        let wallet = match tx.get_wallet(&wallet_id)? {
            Some(wallet) => wallet,
            // We simply skip running the matching engine if the wallet cannot be found, this may
            // happen in a failed lookup task for example. We do not want to fail the tx
            // in this case
            None => {
                warn!("wallet not found to run internal matching engine on: {wallet_id}");
                return Ok(());
            },
        };

        for order_id in wallet.orders.keys() {
            let order = match tx.get_order_info(order_id)? {
                Some(order) => order,
                None => continue,
            };

            if order.ready_for_match() {
                let job = HandshakeManagerJob::InternalMatchingEngine { order: order.id };
                if self.config.handshake_manager_queue.send(job).is_err() {
                    error!("error enqueueing internal matching engine job for order {order_id}");
                }
            }
        }

        Ok(())
    }

    /// Pop the top task on the queue and add it to the historical state    
    ///
    /// Returns the task and the executor to which it was assigned
    fn pop_and_record_task(
        &self,
        // TODO(@joeykraut): Remove this param once we migrate to v2
        key: &TaskQueueKey,
        task_id: &TaskIdentifier,
        success: bool,
        tx: &StateTxn<'_, RW>,
    ) -> Result<Option<(QueuedTask, WrappedPeerId)>> {
        // Pop the task
        // TODO(@joeykraut): Remove this once we migrate to v2
        double_write_helper(tx.pop_task(key));
        let mut task = match tx.pop_task_v2(task_id) {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(None),
            Err(StorageError::InvalidWrite(msg)) => {
                return Err(StateApplicatorError::reject(msg));
            },
            Err(e) => {
                return Err(StateApplicatorError::Storage(e));
            },
        };

        // Add the task to history and remove its node assignment
        task.state = if success { QueuedTaskState::Completed } else { QueuedTaskState::Failed };
        let executor = if let Some(executor) = tx.get_task_assignment(task_id)? {
            tx.remove_assigned_task(&executor, &task.id)?;
            executor
        } else {
            return Ok(None);
        };

        self.maybe_append_historical_task(*key, task.clone(), executor, tx)?;
        Ok(Some((task, executor)))
    }

    /// Append a task to the task history if it should be stored
    fn maybe_append_historical_task(
        &self,
        key: TaskQueueKey,
        task: QueuedTask,
        executor: WrappedPeerId,
        tx: &StateTxn<'_, RW>,
    ) -> Result<()> {
        if let Some(t) = HistoricalTask::from_queued_task(key, task) {
            if tx.get_historical_state_enabled()? {
                tx.append_task_to_history(&key, t.clone())?;
            }

            // Emit a task completion event to the event manager
            // _only if the local peer is the executor_,
            // to avoid duplicate events across the cluster
            let my_peer_id = tx.get_peer_id()?;
            if my_peer_id == executor {
                let event = RelayerEvent::TaskCompletion(TaskCompletionEvent::new(key, t));
                if let Err(e) = try_send_event(event, &self.config.event_queue) {
                    error!("error sending task completion event: {e}");
                }
            }
        }

        Ok(())
    }

    /// Clear all tasks from a task queue, recording them historically as
    /// "failed"
    fn clear_task_queue(&self, key: TaskQueueKey, tx: &StateTxn<'_, RW>) -> Result<()> {
        // Remove all tasks from queue in storage
        // TODO(@joeykraut): Remove this once we migrate to v2
        double_write_helper(tx.clear_task_queue(&key));
        let cleared_tasks = tx.clear_task_queue_v2(&key)?;

        // Mark all tasks as failed, append to history, and publish updates
        for mut task in cleared_tasks {
            task.state = QueuedTaskState::Failed;
            let executor = tx
                .get_task_assignment(&task.id)?
                .ok_or_else(|| StateApplicatorError::MissingEntry(ERR_UNASSIGNED_TASK))?;
            self.maybe_append_historical_task(key, task.clone(), executor, tx)?;
            self.publish_task_updates(key, &task);

            if let Some(peer_id) = tx.get_task_assignment(&task.id)? {
                tx.remove_assigned_task(&peer_id, &task.id)?;
            }
        }

        Ok(())
    }

    /// Try preempting a set of task queues with a task, returning a transition
    /// rejection if this fails
    fn try_preempt_queues(
        &self,
        keys: &[TaskQueueKey],
        task: &QueuedTask,
        is_serial: bool,
        tx: &StateTxn<'_, RW>,
    ) -> Result<()> {
        let res = if is_serial {
            tx.preempt_queue_with_serial(keys, task)
        } else {
            tx.preempt_queue_with_concurrent(keys, task)
        };

        match res {
            Ok(_) => Ok(()),
            Err(StorageError::InvalidWrite(msg)) => Err(StateApplicatorError::reject(msg)),
            Err(e) => Err(StateApplicatorError::Storage(e)),
        }
    }
}

#[cfg(test)]
mod test {
    use common::types::{
        gossip::{mocks::mock_peer, WrappedPeerId},
        tasks::{
            mocks::{mock_preemptive_task, mock_queued_task},
            QueuedTaskState, TaskIdentifier, TaskQueueKey,
        },
        wallet::WalletIdentifier,
        wallet_mocks::mock_empty_wallet,
    };
    use eyre::Result;
    use job_types::task_driver::{new_task_driver_queue, TaskDriverJob};
    use util::metered_channels::MeteredCrossbeamReceiver;

    use crate::{
        applicator::{
            error::StateApplicatorError, task_queue::PENDING_STATE,
            test_helpers::mock_applicator_with_task_queue, StateApplicator,
        },
        storage::{
            db::DB,
            tx::task_queuev2::{TaskQueue, TaskQueuePreemptionState},
        },
    };

    // -----------
    // | Helpers |
    // -----------

    /// Setup a mock applicator
    fn setup_mock_applicator() -> StateApplicator {
        let (applicator, queue) = setup_mock_applicator_with_driver_queue();
        std::mem::forget(queue); // forget the queue to avoid it closing
        applicator
    }

    /// Setup a mock applicator, and return with a task driver's work queue
    fn setup_mock_applicator_with_driver_queue(
    ) -> (StateApplicator, MeteredCrossbeamReceiver<TaskDriverJob>) {
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
        tx.add_task(&key, &task).unwrap();
        tx.enqueue_serial_task(&key, &task).unwrap();

        // Add an assignment
        let my_id = tx.get_peer_id().unwrap();
        tx.add_assigned_task(&my_id, &task.id).unwrap();
        tx.commit().unwrap();

        task.id
    }

    // ---------------------
    // | Basic Queue Tests |
    // ---------------------

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
        let tx = applicator.db().new_read_tx()?;
        let tasks = tx.get_queued_tasks(&task_queue_key)?;
        tx.commit()?;

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task_id);
        assert_eq!(
            tasks[0].state,
            QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false },
        ); // should be started

        // Check the task was started
        assert!(!task_recv.is_empty());
        let task = task_recv.recv()?;

        assert!(matches!(task, TaskDriverJob::Run(queued_task) if queued_task.id == task_id));
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
        let tx = applicator.db().new_read_tx()?;
        let tasks = tx.get_queued_tasks(&task_queue_key)?;
        tx.commit()?;

        assert_eq!(tasks.len(), 1);
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
        enqueue_dummy_task(task_queue_key, applicator.db());

        // Add another task via the applicator
        let task2 = mock_queued_task(task_queue_key);
        applicator.append_task(&task2, &peer_id)?;

        // Ensure that the second task is in the db's queue, not marked as running
        let tx = applicator.db().new_read_tx()?;
        let tasks = tx.get_queued_tasks(&task_queue_key)?;
        tx.commit()?;

        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[1].id, task2.id);
        assert_eq!(tasks[1].state, QueuedTaskState::Queued);

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
        let wallet_id = TaskQueueKey::new_v4();
        let mut wallet = mock_empty_wallet();
        wallet.wallet_id = wallet_id;
        applicator.add_wallet(&wallet)?;

        let task_id = enqueue_dummy_task(wallet_id, applicator.db());
        applicator.pop_task(task_id, true /* success */)?;

        // Ensure the task was removed from the queue
        let tx = applicator.db().new_read_tx()?;
        let tasks = tx.get_queued_tasks(&wallet_id)?;
        tx.commit()?;

        assert_eq!(tasks.len(), 0);

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
        let tx = applicator.db().new_read_tx()?;
        let tasks = tx.get_queued_tasks(&task_queue_key)?;
        tx.commit()?;

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task2.id);
        assert_eq!(
            tasks[0].state,
            QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false },
        ); // should be started

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
        let tx = applicator.db().new_read_tx()?;
        let tasks = tx.get_queued_tasks(&task_queue_key)?;
        tx.commit()?;

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task2.id);
        assert_eq!(
            tasks[0].state,
            QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false },
        ); // should be started

        // Ensure the second task was started
        assert!(!task_recv.is_empty());
        let task = task_recv.recv()?;

        assert!(matches!(task, TaskDriverJob::Run(queued_task) if queued_task.id == task2.id));
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
        let history = tx.get_task_history(&task_queue_key)?;
        tx.commit()?;

        assert_eq!(history.len(), 2);
        assert_eq!(history[0].id, task_id2);
        assert_eq!(history[0].state, QueuedTaskState::Failed);
        assert_eq!(history[1].id, task_id1);
        assert_eq!(history[1].state, QueuedTaskState::Completed);

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
        applicator.transition_task_state(task.id, new_state.clone())?;

        // Ensure the task state was updated
        let tx = applicator.db().new_read_tx()?;
        let task_info = tx.get_task_v2(&task.id)?.unwrap();
        tx.commit()?;

        assert_eq!(task_info.state, new_state);
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
        let (task_queue, _task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        // Clear the queue
        let key = WalletIdentifier::new_v4();
        applicator.clear_queue(key)?;

        // Check that the queue is still empty and unpaused
        let tx = applicator.db().new_read_tx()?;
        let is_paused = tx.is_queue_paused(&key)?;
        let tasks = tx.get_queued_tasks(&key)?;
        tx.commit()?;

        assert!(!is_paused);
        assert_eq!(tasks.len(), 0);
        Ok(())
    }

    /// Tests clearing a non-empty queue
    #[test]
    #[allow(non_snake_case)]
    fn test_clear_queue__non_empty() -> Result<()> {
        let (task_queue, _task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        // Add a task directly via the db
        let task_queue_key = TaskQueueKey::new_v4();
        enqueue_dummy_task(task_queue_key, applicator.db());

        // Clear the queue
        applicator.clear_queue(task_queue_key)?;

        // Check that the queue is empty and unpaused
        let tx = applicator.db().new_read_tx()?;
        let is_paused = tx.is_queue_paused(&task_queue_key)?;
        let tasks = tx.get_queued_tasks(&task_queue_key)?;
        tx.commit()?;

        assert!(!is_paused);
        assert_eq!(tasks.len(), 0);
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
        let task_queue = tx.get_task_queue(&task_queue_key)?;
        tx.commit()?;

        assert_eq!(task_queue, TaskQueue::default());
        Ok(())
    }

    /// Tests clearing a queue when it is paused
    ///
    /// TODO(@joeykraut): Remove this test once we've migrated to the new task
    /// queue
    #[test]
    #[allow(non_snake_case)]
    fn test_clear_queue__paused() -> Result<()> {
        let (task_queue, _task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        // Add a task directly via the db
        let task_queue_key = TaskQueueKey::new_v4();
        enqueue_dummy_task(task_queue_key, applicator.db());

        // Pause the queue
        let preemptive_task = mock_preemptive_task(task_queue_key);
        applicator.preempt_task_queues(&[task_queue_key], &preemptive_task, &peer_id)?;

        // Clear the queue
        applicator.clear_queue(task_queue_key)?;

        // Check that the queue is empty and unpaused
        let tx = applicator.db().new_read_tx()?;
        let is_paused = tx.is_queue_paused(&task_queue_key)?;
        let tasks = tx.get_queued_tasks(&task_queue_key)?;
        tx.commit()?;

        assert!(!is_paused);
        assert_eq!(tasks.len(), 0);
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
        let task_queue = tx.get_task_queue(&task_queue_key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![preemptive_task.id, serial_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);

        // The existing task should be in the queued state
        let existing_task = tx.get_task_v2(&serial_task.id)?.unwrap();
        assert_eq!(existing_task.state, QueuedTaskState::Queued);

        // Lastly, the applicator should have sent the task to the driver
        let task = task_recv.recv().unwrap();
        assert!(
            matches!(task, TaskDriverJob::Run(queued_task) if queued_task.id == preemptive_task.id)
        );
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
        let task_queue = tx.get_task_queue(&task_queue_key)?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![task1.id, task2.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);

        // The existing tasks should be in the queued state
        let task1_retrieved = tx.get_task_v2(&task1.id)?.unwrap();
        let task2_retrieved = tx.get_task_v2(&task2.id)?.unwrap();
        assert!(matches!(task1_retrieved.state, QueuedTaskState::Running { .. }));
        assert!(matches!(task2_retrieved.state, QueuedTaskState::Running { .. }));

        // The applicator should have forwarded both tasks to the driver
        let job1 = task_recv.recv().unwrap();
        let job2 = task_recv.recv().unwrap();
        assert!(matches!(job1, TaskDriverJob::Run(queued_task) if queued_task.id == task1.id));
        assert!(matches!(job2, TaskDriverJob::Run(queued_task) if queued_task.id == task2.id));
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
        let tx = applicator.db().new_read_tx()?;
        let task_queue = tx.get_task_queue(&task_queue_key)?;
        let expected_queue = TaskQueue { serial_tasks: vec![serial_task.id], ..Default::default() };
        assert_eq!(task_queue, expected_queue);

        // The applicator should have forwarded the original task to the driver
        let job = task_recv.recv().unwrap();
        assert!(matches!(job, TaskDriverJob::Run(queued_task) if queued_task.id == serial_task.id));
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
        let tx = applicator.db().new_read_tx()?;
        let task_queue = tx.get_task_queue(&task_queue_key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);

        // The applicator should have forwarded the original task to the driver
        let job = task_recv.recv().unwrap();
        assert!(matches!(job, TaskDriverJob::Run(queued_task) if queued_task.id == serial_task.id));
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
        assert!(
            matches!(job, TaskDriverJob::Run(queued_task) if queued_task.id == preemptive_task.id)
        );

        // Check that the queues have been updated correctly
        let tx = applicator.db().new_read_tx()?;
        let task_queue1 = tx.get_task_queue(&queue_key1)?;
        let task_queue2 = tx.get_task_queue(&queue_key2)?;
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
        assert!(matches!(job, TaskDriverJob::Run(queued_task) if queued_task.id == task1.id));

        // Check the task status of the original task
        let tx = applicator.db().new_read_tx()?;
        let task1_retrieved = tx.get_task_v2(&task1.id)?.unwrap();
        assert!(matches!(task1_retrieved.state, QueuedTaskState::Running { .. }));

        let task_queue1 = tx.get_task_queue(&queue_key1)?;
        let task_queue2 = tx.get_task_queue(&queue_key2)?;
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
        assert!(
            matches!(job, TaskDriverJob::Run(queued_task) if queued_task.id == preemptive_task.id)
        );

        // Add a serial task behind the concurrent task on the second queue
        let task2 = mock_queued_task(queue_key2);
        applicator.append_task(&task2, &my_peer_id)?;

        // Pop the concurrent task successfully, check that the applicator forwarded the
        // serial task
        applicator.pop_task(preemptive_task.id, true /* success */)?;
        let job = task_recv.recv().unwrap();
        assert!(matches!(job, TaskDriverJob::Run(queued_task) if queued_task.id == task2.id));

        // Check the task status of the original task
        let tx = applicator.db().new_read_tx()?;
        let task2_retrieved = tx.get_task_v2(&task2.id)?.unwrap();
        assert!(matches!(task2_retrieved.state, QueuedTaskState::Running { .. }));

        let task_queue1 = tx.get_task_queue(&queue_key1)?;
        let task_queue2 = tx.get_task_queue(&queue_key2)?;
        let expected_queue2 = TaskQueue {
            serial_tasks: vec![task2.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_eq!(task_queue1, TaskQueue::default());
        assert_eq!(task_queue2, expected_queue2);
        Ok(())
    }

    // TODO(@joeykraut): Remove the tests below once we've migrated to the new task
    // queue implementation

    /// Tests cases in pausing an empty queue
    #[test]
    fn test_pause_empty() -> Result<()> {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let task_queue_key = TaskQueueKey::new_v4();

        // Pause the queue
        let preemptive_task = mock_preemptive_task(task_queue_key);
        applicator.preempt_task_queues(&[task_queue_key], &preemptive_task, &peer_id)?;

        // Ensure the queue was paused
        let tx = applicator.db().new_read_tx()?;
        let is_paused = tx.is_queue_paused(&task_queue_key)?;
        tx.commit()?;

        assert!(is_paused);

        // Add a task and ensure it is not started
        let task = mock_queued_task(task_queue_key);
        let task_id = task.id;
        applicator.append_task(&task, &peer_id)?;

        let tx = applicator.db().new_read_tx()?;
        let tasks = tx.get_queued_tasks(&task_queue_key)?;
        tx.commit()?;

        assert!(task_recv.is_empty());
        assert_eq!(tasks.len(), 2); // Includes the preemptive task
        assert_eq!(tasks[0].state, QueuedTaskState::Preemptive);
        assert_eq!(tasks[1].state, QueuedTaskState::Queued);

        // Resume the queue and ensure the task is started
        applicator.resume_task_queues(&[task_queue_key], true /* success */)?;

        let tx = applicator.db().new_read_tx()?;
        let task = tx.get_current_running_task(&task_queue_key)?;
        tx.commit()?;
        assert_eq!(task.unwrap().id, task_id);

        assert!(
            matches!(task_recv.recv()?, TaskDriverJob::Run(queued_task) if queued_task.id == task_id)
        );
        Ok(())
    }

    /// Tests pausing a queue with a running task
    #[test]
    fn test_pause_with_running() -> Result<()> {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let task_queue_key = TaskQueueKey::new_v4();

        // Add a task
        let task = mock_preemptive_task(task_queue_key);
        let task_id = task.id;
        applicator.append_task(&task, &peer_id)?;

        // Start the task
        let tx = applicator.db().new_write_tx()?;
        let state = QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false };
        tx.transition_task(&task_queue_key, state)?;
        tx.commit()?;

        // Pause the queue
        let preemptive_task = mock_preemptive_task(task_queue_key);
        applicator.preempt_task_queues(&[task_queue_key], &preemptive_task, &peer_id)?;

        // Ensure the queue was paused
        let tx = applicator.db().new_read_tx()?;
        let is_paused = tx.is_queue_paused(&task_queue_key)?;
        tx.commit()?;

        assert!(is_paused);

        // Ensure the task was transitioned to queued
        let tx = applicator.db().new_read_tx()?;
        let tasks = tx.get_queued_tasks(&task_queue_key)?;
        tx.commit()?;

        assert_eq!(tasks.len(), 2); // Includes the preemptive task
        assert_eq!(tasks[0].state, QueuedTaskState::Preemptive);
        assert_eq!(tasks[1].state, QueuedTaskState::Queued);

        // Resume the queue and ensure the task is started
        applicator.resume_task_queues(&[task_queue_key], true /* success */)?;

        let tx = applicator.db().new_read_tx()?;
        let task = tx.get_current_running_task(&task_queue_key)?;
        tx.commit()?;

        assert!(task.is_some());
        assert_eq!(task.unwrap().id, task_id);

        assert!(!task_recv.is_empty());
        assert!(
            matches!(task_recv.recv()?, TaskDriverJob::Run(queued_task) if queued_task.id == task_id)
        );
        Ok(())
    }

    /// Test the case in which preempting one queue of multiple fails
    #[test]
    fn test_preempt_multiple_fail() -> Result<()> {
        let (task_queue, _task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let queue_key1 = TaskQueueKey::new_v4();
        let queue_key2 = TaskQueueKey::new_v4();

        // Add a preemptive task to the first queue
        let task = mock_preemptive_task(queue_key1);
        applicator.preempt_task_queues(&[queue_key1], &task, &peer_id)?;

        // Try to preempt both task queues
        let new_task = mock_preemptive_task(queue_key2);
        let result = applicator.preempt_task_queues(&[queue_key1, queue_key2], &new_task, &peer_id);
        assert!(matches!(result, Err(StateApplicatorError::Rejected(..))));

        // Verify that the task that _did_ have an existing preemptive task is still
        // paused
        let tx = applicator.db().new_read_tx()?;
        let is_paused1 = tx.is_queue_paused(&queue_key1)?;
        tx.commit()?;
        assert!(is_paused1);

        // Verify that the task queue that did not originally have a preemptive task in
        // it remains unpaused
        let tx = applicator.db().new_read_tx()?;
        let is_paused2 = tx.is_queue_paused(&queue_key2)?;
        tx.commit()?;
        assert!(!is_paused2);
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
        let task = mock_queued_task(WalletIdentifier::new_v4());
        applicator.append_task(&task, &failed_peer)?;

        // Reassign the task
        applicator.reassign_tasks(&failed_peer, &reassigned_peer)?;

        // Ensure the task was reassigned
        let tx = applicator.db().new_read_tx()?;
        let executor = tx.get_task_assignment(&task.id)?.unwrap();
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
        let task = mock_queued_task(WalletIdentifier::new_v4());
        applicator.append_task(&task, &failed_peer)?;

        // Reassign the task
        applicator.reassign_tasks(&failed_peer, &peer_id)?;

        // Ensure the task was reassigned
        let tx = applicator.db().new_read_tx()?;
        let executor = tx.get_task_assignment(&task.id)?.unwrap();
        tx.commit()?;
        assert_eq!(executor, peer_id);

        // Verify the task was started on the local peer
        assert!(!task_recv.is_empty());
        assert!(
            matches!(task_recv.recv()?, TaskDriverJob::Run(queued_task) if queued_task.id == task.id)
        );
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

        let wallet_id = WalletIdentifier::new_v4();
        let task1 = mock_queued_task(wallet_id);
        let task2 = mock_queued_task(wallet_id);
        applicator.append_task(&task1, &peer2)?;
        applicator.append_task(&task2, &failed_peer)?;

        // Reassign the task
        applicator.reassign_tasks(&failed_peer, &local_peer_id)?;

        // Ensure the first task was not reassigned and the second task was
        let tx = applicator.db().new_read_tx()?;
        let executor1 = tx.get_task_assignment(&task1.id)?.unwrap();
        let executor2 = tx.get_task_assignment(&task2.id)?.unwrap();
        tx.commit()?;
        assert_eq!(executor1, peer2);
        assert_eq!(executor2, local_peer_id);

        // Pop the first task
        applicator.pop_task(task1.id, true /* success */).unwrap();

        // The second task should now be started on the local peer
        assert!(!task_recv.is_empty());
        assert!(
            matches!(task_recv.recv()?, TaskDriverJob::Run(queued_task) if queued_task.id == task2.id)
        );
        Ok(())
    }

    // TODO(@joeykraut): Remove double write tests once migration is complete

    // ---------------------------------
    // | Task Queue Double Write Tests |
    // ---------------------------------

    /// Tests that an added task is double-written correctly
    #[test]
    #[allow(non_snake_case)]
    fn test_add_and_pop_task__double_write() -> Result<()> {
        let applicator = setup_mock_applicator();

        // Add a task
        let executor = mock_peer().peer_id;
        let task = mock_queued_task(WalletIdentifier::new_v4());
        let queue_key = task.descriptor.queue_key();
        applicator.append_task(&task, &executor)?;

        // Check the task queue v2 storage for the task
        let tx = applicator.db().new_read_tx()?;
        let task_info_some = tx.get_task_v2(&task.id)?.is_some();
        assert!(task_info_some);

        let is_empty = tx.is_queue_empty_v2(&queue_key)?;
        let task_queue = tx.get_task_queue(&queue_key)?;
        tx.commit()?;
        assert!(!is_empty);

        // Check the task queue for the wallet
        let expected_queue = TaskQueue {
            serial_tasks: vec![task.id],
            concurrent_tasks: vec![],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
        };
        assert_eq!(task_queue, expected_queue);

        // Pop the task
        applicator.pop_task(task.id, true /* success */)?;

        // Check that the task queue v2 storage is updated
        let tx = applicator.db().new_read_tx()?;
        let task_info_none = tx.get_task_v2(&task.id)?.is_none();
        assert!(task_info_none);

        let is_empty = tx.is_queue_empty_v2(&queue_key)?;
        let task_queue = tx.get_task_queue(&queue_key)?;
        assert!(is_empty);
        assert_eq!(task_queue, TaskQueue::default());
        Ok(())
    }

    /// Checks double write behavior when multiple tasks are added to the queue
    #[test]
    #[allow(non_snake_case)]
    fn test_add_multiple_tasks__double_write() -> Result<()> {
        let applicator = setup_mock_applicator();

        // Add two tasks
        let executor = mock_peer().peer_id;
        let queue_key = WalletIdentifier::new_v4();
        let task1 = mock_queued_task(queue_key);
        let task2 = mock_queued_task(queue_key);
        applicator.append_task(&task1, &executor)?;
        applicator.append_task(&task2, &executor)?;

        // Check the task queue v2 storage for the tasks
        let tx = applicator.db().new_read_tx()?;
        let task1_info_some = tx.get_task_v2(&task1.id)?.is_some();
        let task2_info_some = tx.get_task_v2(&task2.id)?.is_some();
        assert!(task1_info_some);
        assert!(task2_info_some);

        let task_queue = tx.get_task_queue(&queue_key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![task1.id, task2.id],
            concurrent_tasks: vec![],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
        };

        assert_eq!(task_queue, expected_queue);
        tx.commit()?;
        Ok(())
    }

    /// Tests the double write behavior when a queue is paused and subsequently
    /// resumed
    #[test]
    #[allow(non_snake_case)]
    fn test_pause_and_resume_queue__double_write() -> Result<()> {
        let applicator = setup_mock_applicator();

        // Add a task
        let executor = mock_peer().peer_id;
        let queue_key = WalletIdentifier::new_v4();
        let task = mock_queued_task(queue_key);
        applicator.append_task(&task, &executor)?;

        // Pause the queue
        let preemptive_task = mock_preemptive_task(queue_key);
        applicator.preempt_task_queues(&[queue_key], &preemptive_task, &executor)?;

        // Check the task queue v2 storage for the task
        let tx = applicator.db().new_read_tx().unwrap();
        let task_info_some = tx.get_task_v2(&task.id)?.is_some();
        let preemptive_task_info_some = tx.get_task_v2(&preemptive_task.id)?.is_some();
        assert!(task_info_some);
        assert!(preemptive_task_info_some);
        let task_queue = tx.get_task_queue(&queue_key)?;
        tx.commit()?;

        // Check the task queue for the wallet
        let expected_queue = TaskQueue {
            serial_tasks: vec![preemptive_task.id, task.id],
            concurrent_tasks: vec![],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
        };
        assert_eq!(task_queue, expected_queue);

        // Resume the queue, then check the task queue v2 storage for the task
        applicator.resume_task_queues(&[queue_key], true /* success */)?;
        let tx = applicator.db().new_read_tx()?;
        let task_info_some = tx.get_task_v2(&task.id)?.is_some();
        let preemptive_task_info_none = tx.get_task_v2(&preemptive_task.id)?.is_none();
        let task_queue = tx.get_task_queue(&queue_key)?;
        assert!(task_info_some);
        assert!(preemptive_task_info_none);
        tx.commit()?;

        // Check the task queue for the wallet
        let expected_queue = TaskQueue {
            serial_tasks: vec![task.id],
            concurrent_tasks: vec![],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
        };
        assert_eq!(task_queue, expected_queue);
        Ok(())
    }
}
