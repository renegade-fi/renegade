//! Task queue state transition applicator methods

use common::types::{
    tasks::{HistoricalTask, QueuedTask, QueuedTaskState, TaskIdentifier, TaskQueueKey},
    wallet::WalletIdentifier,
};
use external_api::{
    bus_message::{task_history_topic, task_topic, SystemBusMessage},
    http::task::ApiTaskStatus,
    types::ApiHistoricalTask,
};
use job_types::{handshake_manager::HandshakeExecutionJob, task_driver::TaskDriverJob};
use libmdbx::{TransactionKind, RW};
use tracing::{error, instrument, warn};
use util::err_str;

use crate::storage::tx::StateTxn;

use super::{
    error::StateApplicatorError, return_type::ApplicatorReturnType, Result, StateApplicator,
};

/// The pending state description
const PENDING_STATE: &str = "Pending";
/// Error emitted when a key cannot be found for a task
const ERR_NO_KEY: &str = "key not found for task";
/// Metric describing the number of tasks in a task queue
const TASK_QUEUE_LENGTH_METRIC: &str = "task_queue_length";
/// Metric tag for the key of a task queue
const QUEUE_KEY_METRIC_TAG: &str = "queue_key";

// -----------
// | Helpers |
// -----------

/// Error message emitted when a task queue is already paused
fn already_paused(id: TaskQueueKey) -> String {
    format!("task queue {id} already paused")
}

/// Error message emitted when a task id is missing
fn missing_task_key(id: TaskIdentifier) -> String {
    format!("task id {id} not found")
}

/// Error message emitted when the applicator attempts to preempt a conflicting
/// committed task
fn already_committed(id: TaskQueueKey) -> String {
    format!("cannot preempt committed task on queue: {id}")
}

/// Error message emitted when a task queue is paused
fn queue_paused(id: TaskQueueKey) -> String {
    format!("task queue {id} is paused")
}

/// Construct the running state for a newly started task
fn new_running_state() -> QueuedTaskState {
    QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false }
}

/// Record the length of a task queue
#[inline]
fn record_task_queue_length<T: TransactionKind>(key: &TaskQueueKey, tx: &StateTxn<'_, T>) {
    #[cfg(feature = "task-queue-len")]
    {
        let task_queue_length = match tx.get_queued_tasks(key) {
            Ok(tasks) => tasks.len(),
            Err(e) => {
                error!("Error getting task queue length: {}", e);
                return;
            },
        };

        metrics::gauge!(TASK_QUEUE_LENGTH_METRIC, QUEUE_KEY_METRIC_TAG => key.to_string())
            .set(task_queue_length as f64);
    }
}

impl StateApplicator {
    // ---------------------
    // | State Transitions |
    // ---------------------

    /// Apply an `AppendTask` state transition
    #[instrument(skip_all, err, fields(task_id = %task.id, task = %task.descriptor.display_description()))]
    pub fn append_task(&self, task: &QueuedTask) -> Result<ApplicatorReturnType> {
        let queue_key = task.descriptor.queue_key();
        let tx = self.db().new_write_tx()?;

        // Index the task
        let previously_empty = tx.is_queue_empty(&queue_key)?;
        tx.add_task(&queue_key, task)?;

        // If the task queue was empty, transition the task to in progress and start it
        if previously_empty && !tx.is_queue_paused(&queue_key)? {
            // Start the task
            tx.transition_task(&queue_key, new_running_state())?;
            self.maybe_start_task(task, &tx)?;
        }

        record_task_queue_length(&queue_key, &tx);

        tx.commit()?;
        self.publish_task_updates(queue_key, task);
        Ok(ApplicatorReturnType::None)
    }

    /// Apply a `PopTask` state transition
    #[instrument(skip_all, err, fields(task_id = %task_id))]
    pub fn pop_task(&self, task_id: TaskIdentifier, success: bool) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;
        let key = tx
            .get_queue_key_for_task(&task_id)?
            .ok_or_else(|| StateApplicatorError::MissingEntry(ERR_NO_KEY))?;

        if tx.is_queue_paused(&key)? {
            return Err(StateApplicatorError::Rejected(queue_paused(key)));
        }

        // Pop the task from the queue and add it to history
        let mut task =
            tx.pop_task(&key)?.ok_or_else(|| StateApplicatorError::TaskQueueEmpty(key))?;
        task.state = if success { QueuedTaskState::Completed } else { QueuedTaskState::Failed };
        Self::maybe_append_historical_task(key, task.clone(), &tx)?;

        // If the task failed, clear the rest of the queue, as subsequent tasks will
        // likely have invalid state
        if !success {
            self.clear_task_queue(key, &tx)?;
        }

        // If the queue is non-empty, start the next task
        let remaining_tasks = tx.get_queued_tasks(&key)?;
        if let Some(task) = remaining_tasks.first() {
            tx.transition_task(&key, new_running_state())?;
            self.maybe_start_task(task, &tx)?;
        }

        if Self::should_run_matching_engine(&remaining_tasks, &task, &tx)? {
            // Run the matching engine on all orders that are ready
            self.run_matching_engine_on_wallet(key, &tx)?;
        }

        record_task_queue_length(&key, &tx);

        tx.commit()?;

        // Publish a completed message to the system bus
        self.publish_task_updates(key, &task);
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
        let key = tx
            .get_queue_key_for_task(&task_id)?
            .ok_or_else(|| StateApplicatorError::Rejected(missing_task_key(task_id)))?;

        if tx.is_queue_paused(&key)? {
            return Err(StateApplicatorError::Rejected(already_paused(key)));
        }

        tx.transition_task(&key, state)?;
        let task = tx.get_task(&task_id)?;
        tx.commit()?;

        if let Some(t) = task {
            self.publish_task_updates(key, &t);
        }
        Ok(ApplicatorReturnType::None)
    }

    /// Preempt all queues on a given task
    ///
    /// Multiple queues may be preempted at once to give "all or none" locking
    /// semantics to the caller
    pub fn preempt_task_queues(
        &self,
        keys: &[TaskQueueKey],
        task: &QueuedTask,
    ) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;
        for key in keys.iter() {
            self.preempt_task_queue(*key, task, &tx)?;
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
        tx: &StateTxn<'_, RW>,
    ) -> Result<ApplicatorReturnType> {
        // Stop any running tasks if possible
        let current_running_task = tx.get_current_running_task(&key)?;
        if let Some(task) = current_running_task {
            if task.state.is_committed() {
                error!("cannot preempt committed task: {}", task.id);
                let err_msg = already_committed(key);
                return Err(StateApplicatorError::Rejected(err_msg));
            }

            // Otherwise transition the task to queued
            let state = QueuedTaskState::Queued;
            tx.transition_task(&key, state)?;
        }

        // If the queue is already paused, a preemptive task is already
        // running, with which we should not conflict
        if tx.is_queue_paused(&key)? {
            return Err(StateApplicatorError::Rejected(already_paused(key)));
        }

        // Pause the queue
        tx.pause_task_queue(&key)?;
        tx.add_task_front(&key, task)?;
        self.publish_task_updates(key, task);
        record_task_queue_length(&key, tx);
        Ok(ApplicatorReturnType::None)
    }

    /// Resume multiple task queues
    pub fn resume_task_queues(
        &self,
        keys: &[TaskQueueKey],
        success: bool,
    ) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;
        for key in keys.iter() {
            self.resume_task_queue(*key, success, &tx)?;
        }
        tx.commit()?;
        Ok(ApplicatorReturnType::None)
    }

    /// Resume a task queue
    #[instrument(skip_all, err, fields(queue_key = %key))]
    pub fn resume_task_queue(
        &self,
        key: TaskQueueKey,
        success: bool,
        tx: &StateTxn<'_, RW>,
    ) -> Result<ApplicatorReturnType> {
        // Resume the queue, and pop the preemptive task that was added when the queue
        // was paused
        tx.resume_task_queue(&key)?;
        let mut task = tx.pop_task(&key)?.expect("expected preemptive task");
        task.state = if success { QueuedTaskState::Completed } else { QueuedTaskState::Failed };
        Self::maybe_append_historical_task(key, task.clone(), tx)?;

        // If the task failed, clear the rest of the queue, as subsequent tasks will
        // likely have invalid state
        if !success {
            self.clear_task_queue(key, tx)?;
        }

        // Start running the first task if it exists
        let tasks = tx.get_queued_tasks(&key)?;
        if let Some(task) = tasks.first() {
            // Mark the task as pending in the db
            let state = new_running_state();
            tx.transition_task(&key, state)?;

            // This will resume the task as if it is starting anew, regardless of whether
            // the task was previously running
            self.maybe_start_task(task, tx)?;
        }

        // Possibly run the matching engine on the wallet
        if Self::should_run_matching_engine(&tasks, &task, tx)? {
            self.run_matching_engine_on_wallet(key, tx)?;
        }

        self.publish_task_updates(key, &task);
        record_task_queue_length(&key, tx);
        Ok(ApplicatorReturnType::None)
    }

    // -----------
    // | Helpers |
    // -----------

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

    /// Start a task if the current peer is the executor
    #[instrument(skip_all, err, fields(task_id = %task.id, task = %task.descriptor.display_description()))]
    fn maybe_start_task<T: TransactionKind>(
        &self,
        task: &QueuedTask,
        tx: &StateTxn<'_, T>,
    ) -> Result<()> {
        let my_peer_id = tx.get_peer_id()?;
        if task.executor == my_peer_id {
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
        queued_tasks: &[QueuedTask],
        popped_task: &QueuedTask,
        tx: &StateTxn<'_, T>,
    ) -> Result<bool> {
        let my_peer_id = tx.get_peer_id()?;
        Ok(queued_tasks.is_empty()
            && popped_task.descriptor.is_wallet_task()
            && popped_task.executor == my_peer_id)
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
                let job = HandshakeExecutionJob::InternalMatchingEngine { order: order.id };
                if self.config.handshake_manager_queue.send(job).is_err() {
                    error!("error enqueueing internal matching engine job for order {order_id}");
                }
            }
        }

        Ok(())
    }

    /// Append a task to the task history if it should be stored
    fn maybe_append_historical_task(
        key: TaskQueueKey,
        task: QueuedTask,
        tx: &StateTxn<'_, RW>,
    ) -> Result<()> {
        if let Some(t) = HistoricalTask::from_queued_task(key, task) {
            tx.append_task_to_history(&key, t)?;
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
            Self::maybe_append_historical_task(key, task.clone(), tx)?;
            self.publish_task_updates(key, &task);
        }

        Ok(())
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
        wallet_mocks::mock_empty_wallet,
    };
    use job_types::task_driver::{new_task_driver_queue, TaskDriverJob};

    use crate::{
        applicator::{
            error::StateApplicatorError, task_queue::PENDING_STATE,
            test_helpers::mock_applicator_with_task_queue,
        },
        storage::db::DB,
    };

    // -----------
    // | Helpers |
    // -----------

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
        tx.commit().unwrap();

        task.id
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests appending a task to an empty queue
    #[test]
    fn test_append_empty_queue() {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let task_queue_key = TaskQueueKey::new_v4();
        let mut task = mock_queued_task(task_queue_key);
        task.executor = peer_id;
        let task_id = task.id;

        applicator.append_task(&task).expect("Failed to append task");

        // Check the task was added to the queue
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task_id);
        assert_eq!(
            tasks[0].state,
            QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false },
        ); // should be started

        // Check the task was started
        assert!(!task_recv.is_empty());
        let task = task_recv.recv().unwrap();

        if let TaskDriverJob::Run(queued_task) = task {
            assert_eq!(queued_task.id, task_id);
        } else {
            panic!("Expected a Run task job");
        }
    }

    /// Test appending to an empty queue when the local peer is not the executor
    #[test]
    fn test_append_empty_queue_not_executor() {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let task_queue_key = TaskQueueKey::new_v4();
        let mut task = mock_queued_task(task_queue_key);
        task.executor = WrappedPeerId::random(); // Assign a different executor

        applicator.append_task(&task).expect("Failed to append task");

        // Check the task was not started
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert_eq!(tasks.len(), 1);
        assert!(task_recv.is_empty());
    }

    /// Tests the case in which a task is added to a non-empty queue
    #[test]
    fn test_append_non_empty_queue() {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let task_queue_key = TaskQueueKey::new_v4();

        // Add a task directly via the db
        enqueue_dummy_task(task_queue_key, applicator.db());

        // Add another task via the applicator
        let mut task2 = mock_queued_task(task_queue_key);
        task2.executor = peer_id; // Assign the local executor
        applicator.append_task(&task2).expect("Failed to append task");

        // Ensure that the second task is in the db's queue, not marked as running
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[1].id, task2.id);
        assert_eq!(tasks[1].state, QueuedTaskState::Queued);

        // Ensure that the task queue is empty (no task is marked as running)
        assert!(task_recv.is_empty());
    }

    /// Test popping from a task queue of length one
    #[test]
    fn test_pop_singleton_queue() {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        // Add a wallet; when the queue empties it will trigger the matching engine,
        // which requires the wallet to be present
        let wallet_id = TaskQueueKey::new_v4();
        let mut wallet = mock_empty_wallet();
        wallet.wallet_id = wallet_id;
        applicator.add_wallet(&wallet).unwrap();

        let task_id = enqueue_dummy_task(wallet_id, applicator.db());

        applicator.pop_task(task_id, true /* success */).expect("Failed to pop task");

        // Ensure the task was removed from the queue
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&wallet_id).unwrap();
        tx.commit().unwrap();

        assert_eq!(tasks.len(), 0);

        // Ensure no task was started
        assert!(task_recv.is_empty());
    }

    /// Tests popping from a queue of length two in which the local peer is not
    /// the executor of the next task
    #[test]
    fn test_pop_non_executor() {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let task_queue_key = TaskQueueKey::new_v4();

        // Add a task directly via the db
        let task_id = enqueue_dummy_task(task_queue_key, applicator.db());

        // Add another task via the applicator
        let mut task2 = mock_queued_task(task_queue_key);
        task2.executor = WrappedPeerId::random(); // Assign a different executor
        applicator.append_task(&task2).unwrap();

        // Pop the first task
        applicator.pop_task(task_id, true /* success */).unwrap();

        // Ensure the first task was removed from the queue
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task2.id);
        assert_eq!(
            tasks[0].state,
            QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false },
        ); // should be started

        // Ensure no task was started
        assert!(task_recv.is_empty());
    }

    /// Tests popping from a queue of length two in which the local peer is the
    /// executor of the next task
    #[test]
    fn test_pop_executor() {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let task_queue_key = TaskQueueKey::new_v4();

        // Add a task directly via the db
        let task_id = enqueue_dummy_task(task_queue_key, applicator.db());

        // Add another task via the applicator
        let mut task2 = mock_queued_task(task_queue_key);
        task2.executor = peer_id; // Assign the local executor
        applicator.append_task(&task2).unwrap();

        // Pop the first task
        applicator.pop_task(task_id, true /* success */).unwrap();

        // Ensure the first task was removed from the queue
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task2.id);
        assert_eq!(
            tasks[0].state,
            QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false },
        ); // should be started

        // Ensure the second task was started
        assert!(!task_recv.is_empty());
        let task = task_recv.recv().unwrap();

        if let TaskDriverJob::Run(queued_task) = task {
            assert_eq!(queued_task.id, task2.id);
        } else {
            panic!("Expected a Run task job");
        }
    }

    /// Test popping from a task queue and checking task history
    #[test]
    fn test_pop_and_check_history() {
        let (task_queue, _task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        // Set the local peer ID
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let task_queue_key = TaskQueueKey::new_v4();

        // Add two tasks: one successful, one failed
        let task_id1 = enqueue_dummy_task(task_queue_key, applicator.db());
        let task_id2 = enqueue_dummy_task(task_queue_key, applicator.db());
        applicator.pop_task(task_id1, true /* success */).unwrap();
        applicator.pop_task(task_id2, false /* success */).unwrap();

        // Ensure the task was added to history
        let tx = applicator.db().new_read_tx().unwrap();
        let history = tx.get_task_history(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert_eq!(history.len(), 2);
        assert_eq!(history[0].id, task_id2);
        assert_eq!(history[0].state, QueuedTaskState::Failed);
        assert_eq!(history[1].id, task_id1);
        assert_eq!(history[1].state, QueuedTaskState::Completed);
    }

    /// Test transitioning the state of the top task on the queue
    #[test]
    fn test_transition_task_state() {
        let (task_queue, _task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);

        let task_queue_key = TaskQueueKey::new_v4();

        // Add a task directly via the db
        let task_id = enqueue_dummy_task(task_queue_key, applicator.db());

        // Transition the state of the top task in the queue
        let new_state = QueuedTaskState::Running { state: "Test".to_string(), committed: false };
        applicator.transition_task_state(task_id, new_state.clone()).unwrap();

        // Ensure the task state was updated
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].state, new_state); // should be updated
    }

    /// Tests cases in pausing an empty queue
    #[test]
    fn test_pause_empty() {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let task_queue_key = TaskQueueKey::new_v4();

        // Pause the queue
        let preemptive_task = mock_preemptive_task(task_queue_key);
        applicator.preempt_task_queues(&[task_queue_key], &preemptive_task).unwrap();

        // Ensure the queue was paused
        let tx = applicator.db().new_read_tx().unwrap();
        let is_paused = tx.is_queue_paused(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert!(is_paused);

        // Add a task and ensure it is not started
        let mut task = mock_queued_task(task_queue_key);
        task.executor = peer_id;
        let task_id = task.id;
        applicator.append_task(&task).unwrap();

        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert!(task_recv.is_empty());
        assert_eq!(tasks.len(), 2); // Includes the preemptive task
        assert_eq!(tasks[0].state, QueuedTaskState::Preemptive);
        assert_eq!(tasks[1].state, QueuedTaskState::Queued);

        // Resume the queue and ensure the task is started
        applicator.resume_task_queues(&[task_queue_key], true /* success */).unwrap();

        let tx = applicator.db().new_read_tx().unwrap();
        let task = tx.get_current_running_task(&task_queue_key).unwrap();
        tx.commit().unwrap();
        assert_eq!(task.unwrap().id, task_id);

        assert!(!task_recv.is_empty());

        let task = task_recv.recv().unwrap();
        if let TaskDriverJob::Run(queued_task) = task {
            assert_eq!(queued_task.id, task_id);
        } else {
            panic!("Expected a Run task job");
        }
    }

    /// Tests pausing a queue with a running task
    #[test]
    fn test_pause_with_running() {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let task_queue_key = TaskQueueKey::new_v4();

        // Add a task
        let mut task = mock_preemptive_task(task_queue_key);
        task.executor = peer_id;
        let task_id = task.id;
        applicator.append_task(&task).unwrap();

        // Start the task
        let tx = applicator.db().new_write_tx().unwrap();
        let state = QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false };
        tx.transition_task(&task_queue_key, state).unwrap();
        tx.commit().unwrap();

        // Pause the queue
        let preemptive_task = mock_preemptive_task(task_queue_key);
        applicator.preempt_task_queues(&[task_queue_key], &preemptive_task).unwrap();

        // Ensure the queue was paused
        let tx = applicator.db().new_read_tx().unwrap();
        let is_paused = tx.is_queue_paused(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert!(is_paused);

        // Ensure the task was transitioned to queued
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert_eq!(tasks.len(), 2); // Includes the preemptive task
        assert_eq!(tasks[0].state, QueuedTaskState::Preemptive);
        assert_eq!(tasks[1].state, QueuedTaskState::Queued);

        // Resume the queue and ensure the task is started
        applicator.resume_task_queues(&[task_queue_key], true /* success */).unwrap();

        let tx = applicator.db().new_read_tx().unwrap();
        let task = tx.get_current_running_task(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert!(task.is_some());
        assert_eq!(task.unwrap().id, task_id);

        assert!(!task_recv.is_empty());
        let job = task_recv.recv().unwrap();
        if let TaskDriverJob::Run(queued_task) = job {
            assert_eq!(queued_task.id, task_id);
        } else {
            panic!("Expected a Run task job");
        }
    }

    /// Tests preempting and resuming multiple task queues successfully
    #[test]
    fn test_preempt_resume_multiple() {
        let (task_queue, task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let queue_key1 = TaskQueueKey::new_v4();
        let queue_key2 = TaskQueueKey::new_v4();

        // Add a task to the second queue and begin running it
        let mut task = mock_preemptive_task(queue_key2);
        task.executor = peer_id;
        let task_id = task.id;
        applicator.append_task(&task).unwrap();

        // Start the task
        let tx = applicator.db().new_write_tx().unwrap();
        let state = QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false };
        tx.transition_task(&queue_key2, state).unwrap();
        tx.commit().unwrap();

        // Preempt both queues
        let preemptive_task = mock_preemptive_task(queue_key1);
        applicator.preempt_task_queues(&[queue_key1, queue_key2], &preemptive_task).unwrap();

        // Ensure both queues are paused
        let tx = applicator.db().new_read_tx().unwrap();
        let is_paused1 = tx.is_queue_paused(&queue_key1).unwrap();
        let is_paused2 = tx.is_queue_paused(&queue_key2).unwrap();
        tx.commit().unwrap();

        assert!(is_paused1);
        assert!(is_paused2);

        // Ensure the existing task was transitioned to queued
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&queue_key2).unwrap();
        tx.commit().unwrap();

        assert_eq!(tasks.len(), 2); // Includes the preemptive task
        assert_eq!(tasks[0].state, QueuedTaskState::Preemptive);
        assert_eq!(tasks[1].state, QueuedTaskState::Queued);

        // Resume both queues
        applicator.resume_task_queues(&[queue_key1, queue_key2], true /* success */).unwrap();

        let tx = applicator.db().new_read_tx().unwrap();
        let task = tx.get_current_running_task(&queue_key2).unwrap();
        tx.commit().unwrap();

        assert!(task.is_some());
        assert_eq!(task.unwrap().id, task_id);

        assert!(!task_recv.is_empty());
        let job = task_recv.recv().unwrap();
        if let TaskDriverJob::Run(queued_task) = job {
            assert_eq!(queued_task.id, task_id);
        } else {
            panic!("Expected a Run task job");
        }
    }

    /// Test the case in which preempting one queue of multiple fails
    #[test]
    fn test_preempt_multiple_fail() {
        let (task_queue, _task_recv) = new_task_driver_queue();
        let applicator = mock_applicator_with_task_queue(task_queue);
        let peer_id = mock_peer().peer_id;
        set_local_peer_id(&peer_id, applicator.db());

        let queue_key1 = TaskQueueKey::new_v4();
        let queue_key2 = TaskQueueKey::new_v4();

        // Add a preemptive task to the first queue
        let task = mock_preemptive_task(queue_key1);
        applicator.preempt_task_queues(&[queue_key1], &task).unwrap();

        // Try to preempt both task queues
        let new_task = mock_preemptive_task(queue_key2);
        let result = applicator.preempt_task_queues(&[queue_key1, queue_key2], &new_task);
        assert!(matches!(result, Err(StateApplicatorError::Rejected(..))));

        // Verify that the task that _did_ have an existing preemptive task is still
        // paused
        let tx = applicator.db().new_read_tx().unwrap();
        let is_paused1 = tx.is_queue_paused(&queue_key1).unwrap();
        tx.commit().unwrap();
        assert!(is_paused1);

        // Verify that the task queue that did not originally have a preemptive task in
        // it remains unpaused
        let tx = applicator.db().new_read_tx().unwrap();
        let is_paused2 = tx.is_queue_paused(&queue_key2).unwrap();
        tx.commit().unwrap();
        assert!(!is_paused2);
    }
}
