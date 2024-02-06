//! Task queue state transition applicator methods

use common::types::{
    task_descriptors::{QueuedTask, QueuedTaskState},
    wallet::WalletIdentifier,
};
use job_types::task_driver::TaskDriverJob;
use libmdbx::TransactionKind;
use util::err_str;

use crate::storage::tx::StateTxn;

use super::{error::StateApplicatorError, Result, StateApplicator};

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
        if tx.is_wallet_queue_empty(&wallet_id)? {
            // Start the task
            task.state = QueuedTaskState::Running;
            self.maybe_start_task(&task, &tx)?;
        }

        tx.add_wallet_task(&wallet_id, &task)?;
        Ok(tx.commit()?)
    }

    /// Apply a `PopWalletTask` state transition
    pub fn pop_wallet_task(&self, wallet_id: WalletIdentifier) -> Result<()> {
        let tx = self.db().new_write_tx()?;

        // Pop the task from the queue
        tx.pop_wallet_task(&wallet_id)?;

        // If the queue is non-empty, start the next task
        let tasks = tx.get_wallet_tasks(&wallet_id)?;
        if let Some(task) = tasks.first() {
            tx.transition_wallet_task(&wallet_id, QueuedTaskState::Running)?;
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
        task_descriptors::{mocks::mock_queued_task, QueuedTaskState},
        wallet::WalletIdentifier,
    };
    use job_types::task_driver::{new_task_driver_queue, TaskDriverJob};

    use crate::{applicator::test_helpers::mock_applicator_with_task_queue, storage::db::DB};

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
        assert_eq!(tasks[0].state, QueuedTaskState::Running); // should be started

        // Check the task was started
        assert!(!task_recv.is_empty());
        let task = task_recv.recv().unwrap();

        let TaskDriverJob::Run(queued_task) = task;
        assert_eq!(queued_task.id, task_id);
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
        assert_eq!(tasks[0].state, QueuedTaskState::Running); // should be started

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
        assert_eq!(tasks[0].state, QueuedTaskState::Running); // should be started

        // Ensure the second task was started
        assert!(!task_recv.is_empty());
        let task = task_recv.recv().unwrap();

        let TaskDriverJob::Run(queued_task) = task;
        assert_eq!(queued_task.id, task2.id);
    }
}
