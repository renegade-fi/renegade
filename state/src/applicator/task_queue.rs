//! Task queue state transition applicator methods

use common::types::{
    tasks::{QueuedTask, QueuedTaskState},
    wallet::WalletIdentifier,
};
use job_types::task_driver::TaskDriverJob;
use libmdbx::TransactionKind;
use tracing::log;
use util::err_str;

use crate::storage::tx::StateTxn;

use super::{error::StateApplicatorError, Result, StateApplicator};

/// The pending state description
const PENDING_STATE: &str = "Pending";

/// Construct the running state for a newly started task
fn new_running_state() -> QueuedTaskState {
    QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false }
}

impl StateApplicator {
    // ---------------------
    // | State Transitions |
    // ---------------------

    /// Apply an `AppendWalletTask` state transition
    pub fn append_wallet_task(
        &self,
        wallet_id: WalletIdentifier,
        mut task: QueuedTask,
    ) -> Result<()> {
        let tx = self.db().new_write_tx()?;

        // If the task queue is empty for the wallet, transition the task to in progress
        // and start it
        if tx.is_wallet_queue_empty(&wallet_id)? && !tx.is_task_queue_paused(&wallet_id)? {
            // Start the task
            task.state = new_running_state();
            self.maybe_start_task(&task, &tx)?;
        }

        tx.add_wallet_task(&wallet_id, &task)?;
        Ok(tx.commit()?)
    }

    /// Apply a `PopWalletTask` state transition
    pub fn pop_wallet_task(&self, wallet_id: WalletIdentifier) -> Result<()> {
        let tx = self.db().new_write_tx()?;
        if tx.is_task_queue_paused(&wallet_id)? {
            return Err(StateApplicatorError::QueuePaused(wallet_id));
        }

        // Pop the task from the queue
        tx.pop_wallet_task(&wallet_id)?;

        // If the queue is non-empty, start the next task
        let tasks = tx.get_wallet_tasks(&wallet_id)?;
        if let Some(task) = tasks.first() {
            let state = new_running_state();
            tx.transition_wallet_task(&wallet_id, state)?;
            self.maybe_start_task(task, &tx)?;
        }

        Ok(tx.commit()?)
    }

    /// Transition the state of the top task on the queue
    pub fn transition_task_state(
        &self,
        wallet_id: WalletIdentifier,
        state: QueuedTaskState,
    ) -> Result<()> {
        let tx = self.db().new_write_tx()?;
        if tx.is_task_queue_paused(&wallet_id)? {
            return Err(StateApplicatorError::QueuePaused(wallet_id));
        }

        tx.transition_wallet_task(&wallet_id, state)?;
        Ok(tx.commit()?)
    }

    /// Preempt the task queue on a given wallet
    pub fn preempt_task_queue(&self, wallet_id: WalletIdentifier) -> Result<()> {
        let tx = self.db().new_write_tx()?;

        // Stop any running tasks if possible
        let current_running_task = tx.get_current_running_task(&wallet_id)?;
        if let Some(task) = current_running_task {
            if task.state.is_committed() {
                log::error!("cannot preempt committed task: {}", task.id);
                return Err(StateApplicatorError::Preemption);
            }

            // Otherwise transition the task to queued
            let state = QueuedTaskState::Queued;
            tx.transition_wallet_task(&wallet_id, state)?;
        }

        // Pause the queue
        tx.pause_task_queue(&wallet_id)?;
        Ok(tx.commit()?)
    }

    /// Resume a task queue on a given wallet
    pub fn resume_task_queue(&self, wallet_id: WalletIdentifier) -> Result<()> {
        let tx = self.db().new_write_tx()?;

        // Resume the queue
        tx.resume_task_queue(&wallet_id)?;

        // Start running the first task if it exists
        let tasks = tx.get_wallet_tasks(&wallet_id)?;
        if let Some(task) = tasks.first() {
            // Mark the task as pending in the db
            let state = new_running_state();
            tx.transition_wallet_task(&wallet_id, state)?;

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
}

#[cfg(test)]
mod test {
    use common::types::{
        gossip::{mocks::mock_peer, WrappedPeerId},
        tasks::{mocks::mock_queued_task, QueuedTaskState},
        wallet::WalletIdentifier,
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

    /// Add a dummy task to the given wallet's queue
    fn enqueue_dummy_task(wallet_id: &WalletIdentifier, db: &DB) {
        let task = mock_queued_task();
        let tx = db.new_write_tx().unwrap();
        tx.add_wallet_task(wallet_id, &task).unwrap();
        tx.commit().unwrap();
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

        let wallet_id = WalletIdentifier::new_v4();
        let mut task = mock_queued_task();
        task.executor = peer_id;
        let task_id = task.id;

        applicator.append_wallet_task(wallet_id, task.clone()).expect("Failed to append task");

        // Check the task was added to the queue
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
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

        let wallet_id = WalletIdentifier::new_v4();
        let mut task = mock_queued_task();
        task.executor = WrappedPeerId::random(); // Assign a different executor

        applicator.append_wallet_task(wallet_id, task.clone()).expect("Failed to append task");

        // Check the task was not started
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
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

        let wallet_id = WalletIdentifier::new_v4();

        // Add a task directly via the db
        enqueue_dummy_task(&wallet_id, applicator.db());

        // Add another task via the applicator
        let mut task2 = mock_queued_task();
        task2.executor = peer_id; // Assign the local executor
        applicator.append_wallet_task(wallet_id, task2.clone()).expect("Failed to append task");

        // Ensure that the second task is in the db's queue, not marked as running
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
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

        let wallet_id = WalletIdentifier::new_v4();
        enqueue_dummy_task(&wallet_id, applicator.db());

        applicator.pop_wallet_task(wallet_id).expect("Failed to pop task");

        // Ensure the task was removed from the queue
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
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

        let wallet_id = WalletIdentifier::new_v4();

        // Add a task directly via the db
        enqueue_dummy_task(&wallet_id, applicator.db());

        // Add another task via the applicator
        let mut task2 = mock_queued_task();
        task2.executor = WrappedPeerId::random(); // Assign a different executor
        applicator.append_wallet_task(wallet_id, task2.clone()).unwrap();

        // Pop the first task
        applicator.pop_wallet_task(wallet_id).unwrap();

        // Ensure the first task was removed from the queue
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
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

        let wallet_id = WalletIdentifier::new_v4();

        // Add a task directly via the db
        enqueue_dummy_task(&wallet_id, applicator.db());

        // Add another task via the applicator
        let mut task2 = mock_queued_task();
        task2.executor = peer_id; // Assign the local executor
        applicator.append_wallet_task(wallet_id, task2.clone()).unwrap();

        // Pop the first task
        applicator.pop_wallet_task(wallet_id).unwrap();

        // Ensure the first task was removed from the queue
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
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

        let wallet_id = WalletIdentifier::new_v4();

        // Add a task directly via the db
        enqueue_dummy_task(&wallet_id, applicator.db());

        // Transition the state of the top task in the queue
        let new_state = QueuedTaskState::Running { state: "Test".to_string(), committed: false };
        applicator.transition_task_state(wallet_id, new_state.clone()).unwrap();

        // Ensure the task state was updated
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
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

        let wallet_id = WalletIdentifier::new_v4();

        // Pause the queue
        applicator.preempt_task_queue(wallet_id).unwrap();

        // Ensure the queue was paused
        let tx = applicator.db().new_read_tx().unwrap();
        let is_paused = tx.is_task_queue_paused(&wallet_id).unwrap();
        tx.commit().unwrap();

        assert!(is_paused);

        // Add a task and ensure it is not started
        let mut task = mock_queued_task();
        task.executor = peer_id;
        let task_id = task.id;
        applicator.append_wallet_task(wallet_id, task.clone()).unwrap();

        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
        tx.commit().unwrap();

        assert!(task_recv.is_empty());
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].state, QueuedTaskState::Queued);

        // Resume the queue and ensure the task is started
        applicator.resume_task_queue(wallet_id).unwrap();

        let tx = applicator.db().new_read_tx().unwrap();
        let task = tx.get_current_running_task(&wallet_id).unwrap();
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

        let wallet_id = WalletIdentifier::new_v4();

        // Add a task
        let mut task = mock_queued_task();
        task.executor = peer_id;
        let task_id = task.id;
        applicator.append_wallet_task(wallet_id, task.clone()).unwrap();

        // Start the task
        let tx = applicator.db().new_write_tx().unwrap();
        let state = QueuedTaskState::Running { state: PENDING_STATE.to_string(), committed: false };
        tx.transition_wallet_task(&wallet_id, state).unwrap();
        tx.commit().unwrap();

        // Pause the queue
        applicator.preempt_task_queue(wallet_id).unwrap();

        // Ensure the queue was paused
        let tx = applicator.db().new_read_tx().unwrap();
        let is_paused = tx.is_task_queue_paused(&wallet_id).unwrap();
        tx.commit().unwrap();

        assert!(is_paused);

        // Ensure the task was transitioned to queued
        let tx = applicator.db().new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
        tx.commit().unwrap();

        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].state, QueuedTaskState::Queued);

        // Resume the queue and ensure the task is started
        applicator.resume_task_queue(wallet_id).unwrap();

        let tx = applicator.db().new_read_tx().unwrap();
        let task = tx.get_current_running_task(&wallet_id).unwrap();
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
