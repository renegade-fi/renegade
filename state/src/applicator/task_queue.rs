//! Task queue state transition applicator methods

use common::types::{
    tasks::{QueuedTask, QueuedTaskState, TaskIdentifier, TaskQueueKey},
    wallet::WalletIdentifier,
};
use job_types::{handshake_manager::HandshakeExecutionJob, task_driver::TaskDriverJob};
use libmdbx::TransactionKind;
use tracing::{error, warn};
use util::err_str;

use crate::storage::tx::StateTxn;

use super::{error::StateApplicatorError, Result, StateApplicator};

/// The pending state description
const PENDING_STATE: &str = "Pending";
/// Error emitted when a key cannot be found for a task
const ERR_NO_KEY: &str = "key not found for task";

/// Construct the running state for a newly started task
fn new_running_state() -> QueuedTaskState {
    QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false }
}

impl StateApplicator {
    // ---------------------
    // | State Transitions |
    // ---------------------

    /// Apply an `AppendTask` state transition
    pub fn append_task(&self, task: &QueuedTask) -> Result<()> {
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

        Ok(tx.commit()?)
    }

    /// Apply a `PopTask` state transition
    pub fn pop_task(&self, task_id: TaskIdentifier) -> Result<()> {
        let tx = self.db().new_write_tx()?;
        let key = tx
            .get_queue_key_for_task(&task_id)?
            .ok_or_else(|| StateApplicatorError::MissingEntry(ERR_NO_KEY.to_string()))?;

        if tx.is_queue_paused(&key)? {
            return Err(StateApplicatorError::QueuePaused(key));
        }

        // Pop the task from the queue
        let task = tx.pop_task(&key)?.ok_or_else(|| StateApplicatorError::TaskQueueEmpty(key))?;

        // If the queue is non-empty, start the next task
        let tasks = tx.get_queued_tasks(&key)?;
        if let Some(task) = tasks.first() {
            tx.transition_task(&key, new_running_state())?;
            self.maybe_start_task(task, &tx)?;
        }

        // If the queue is empty and the task was a wallet task, run the matching engine
        // on all orders that are ready
        // TODO: We should only have one node execute the internal matching engine,
        // though this is okay for the moment
        if tasks.is_empty() && task.descriptor.is_wallet_task() {
            self.run_matching_engine_on_wallet(key, &tx)?;
        }

        Ok(tx.commit()?)
    }

    /// Transition the state of the top task on the queue
    pub fn transition_task_state(
        &self,
        task_id: TaskIdentifier,
        state: QueuedTaskState,
    ) -> Result<()> {
        let tx = self.db().new_write_tx()?;
        let key = tx
            .get_queue_key_for_task(&task_id)?
            .ok_or_else(|| StateApplicatorError::MissingEntry(ERR_NO_KEY.to_string()))?;

        if tx.is_queue_paused(&key)? {
            return Err(StateApplicatorError::QueuePaused(key));
        }

        tx.transition_task(&key, state)?;
        Ok(tx.commit()?)
    }

    /// Preempt the given task queue
    pub fn preempt_task_queue(&self, key: TaskQueueKey) -> Result<()> {
        let tx = self.db().new_write_tx()?;

        // Stop any running tasks if possible
        let current_running_task = tx.get_current_running_task(&key)?;
        if let Some(task) = current_running_task {
            if task.state.is_committed() {
                error!("cannot preempt committed task: {}", task.id);
                return Err(StateApplicatorError::Preemption);
            }

            // Otherwise transition the task to queued
            let state = QueuedTaskState::Queued;
            tx.transition_task(&key, state)?;
        }

        // Pause the queue
        tx.pause_task_queue(&key)?;
        Ok(tx.commit()?)
    }

    /// Resume a task queue
    pub fn resume_task_queue(&self, key: TaskQueueKey) -> Result<()> {
        let tx = self.db().new_write_tx()?;

        // Resume the queue
        tx.resume_task_queue(&key)?;

        // Start running the first task if it exists
        let tasks = tx.get_queued_tasks(&key)?;
        if let Some(task) = tasks.first() {
            // Mark the task as pending in the db
            let state = new_running_state();
            tx.transition_task(&key, state)?;

            // This will resume the task as if it is starting anew, regardless of whether
            // the task was previously running
            self.maybe_start_task(task, &tx)?;
        }

        Ok(tx.commit()?)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Start a task if the current peer is the executor
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
}

#[cfg(test)]
mod test {
    use common::types::{
        gossip::{mocks::mock_peer, WrappedPeerId},
        tasks::{mocks::mock_queued_task, QueuedTaskState, TaskIdentifier, TaskQueueKey},
        wallet_mocks::mock_empty_wallet,
    };
    use job_types::task_driver::{new_task_driver_queue, TaskDriverJob};

    use crate::{
        applicator::{task_queue::PENDING_STATE, test_helpers::mock_applicator_with_task_queue},
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

        applicator.pop_task(task_id).expect("Failed to pop task");

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
        applicator.pop_task(task_id).unwrap();

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
        applicator.pop_task(task_id).unwrap();

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
        applicator.preempt_task_queue(task_queue_key).unwrap();

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
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].state, QueuedTaskState::Queued);

        // Resume the queue and ensure the task is started
        applicator.resume_task_queue(task_queue_key).unwrap();

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
        let mut task = mock_queued_task(task_queue_key);
        task.executor = peer_id;
        let task_id = task.id;
        applicator.append_task(&task).unwrap();

        // Start the task
        let tx = applicator.db().new_write_tx().unwrap();
        let state = QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false };
        tx.transition_task(&task_queue_key, state).unwrap();
        tx.commit().unwrap();

        // Pause the queue
        applicator.preempt_task_queue(task_queue_key).unwrap();

        // Ensure the queue was paused
        let tx = applicator.db().new_read_tx().unwrap();
        let is_paused = tx.is_queue_paused(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert!(is_paused);

        // Ensure the task was transitioned to queued
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&task_queue_key).unwrap();
        tx.commit().unwrap();

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].state, QueuedTaskState::Queued);

        // Resume the queue and ensure the task is started
        applicator.resume_task_queue(task_queue_key).unwrap();

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
}
