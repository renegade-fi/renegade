//! Defines storage primitives for the task queue
//!
//! Tasks are indexed in queues identified by the shared resource they occupy.
//! For now this is only wallets (i.e. wallet_id).

use common::types::{
    tasks::TaskIdentifier,
    tasks::{QueuedTask, QueuedTaskState},
    wallet::WalletIdentifier,
};
use libmdbx::{TransactionKind, RW};

use crate::{storage::error::StorageError, TASK_QUEUE_TABLE, TASK_TO_WALLET_TABLE};

use super::StateTxn;

// -----------
// | Getters |
// -----------

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Check whether the current task queue is empty
    pub fn is_wallet_queue_empty(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<bool, StorageError> {
        let tasks = self.get_wallet_tasks(wallet_id)?;
        Ok(tasks.is_empty())
    }

    /// Get the tasks for a given wallet
    pub fn get_wallet_tasks(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<Vec<QueuedTask>, StorageError> {
        self.read_queue(TASK_QUEUE_TABLE, wallet_id)
    }

    /// Get the wallet that a given task is associated with
    pub fn get_task_wallet(
        &self,
        task_id: &TaskIdentifier,
    ) -> Result<Option<WalletIdentifier>, StorageError> {
        self.inner().read(TASK_TO_WALLET_TABLE, task_id)
    }

    /// Get the task for a given wallet and task id
    pub fn get_wallet_task_by_id(
        &self,
        wallet_id: &WalletIdentifier,
        task_id: &TaskIdentifier,
    ) -> Result<Option<QueuedTask>, StorageError> {
        let tasks = self.get_wallet_tasks(wallet_id)?;
        Ok(tasks.into_iter().find(|x| &x.id == task_id))
    }

    /// Get the currently running task for a wallet, or `None` if there is no
    /// running task
    pub fn get_current_running_task(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<Option<QueuedTask>, StorageError> {
        let tasks = self.get_wallet_tasks(wallet_id)?;

        Ok(tasks.first().cloned().filter(|task| task.state.is_running()))
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    /// Add a task to the queue
    pub fn add_wallet_task(
        &self,
        wallet_id: &WalletIdentifier,
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        self.push_to_queue(TASK_QUEUE_TABLE, wallet_id, task)?;

        // Add a mapping from the task to the wallet
        self.inner().write(TASK_TO_WALLET_TABLE, &task.id, wallet_id)
    }

    /// Pop a task from the queue
    pub fn pop_wallet_task(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<Option<QueuedTask>, StorageError> {
        let res: Option<QueuedTask> = self.pop_from_queue(TASK_QUEUE_TABLE, wallet_id)?;

        if let Some(ref task) = res {
            // Remove the mapping from the task to the wallet
            self.inner().delete(TASK_TO_WALLET_TABLE, &task.id)?;
        }

        Ok(res)
    }

    /// Transition the state of the top task in the queue
    pub fn transition_wallet_task(
        &self,
        wallet_id: &WalletIdentifier,
        new_state: QueuedTaskState,
    ) -> Result<(), StorageError> {
        let mut tasks = self.get_wallet_tasks(wallet_id)?;
        tasks[0].state = new_state;

        self.write_queue(TASK_QUEUE_TABLE, wallet_id, &tasks)
    }
}

#[cfg(test)]
mod test {
    use common::types::{
        tasks::{mocks::mock_queued_task, QueuedTaskState},
        wallet::WalletIdentifier,
    };

    use crate::{test_helpers::mock_db, TASK_QUEUE_TABLE, TASK_TO_WALLET_TABLE};

    /// Tests getting the tasks for a wallet
    #[test]
    fn test_append_and_get() {
        // Setup the mock
        let db = mock_db();
        db.create_table(TASK_QUEUE_TABLE).unwrap();

        // Get the tasks for a wallet, should be empty
        let wallet_id = WalletIdentifier::new_v4();
        let tx = db.new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
        tx.commit().unwrap();
        assert_eq!(tasks.len(), 0);

        // Add a task to the wallet
        let task = mock_queued_task();
        let tx = db.new_write_tx().unwrap();
        tx.add_wallet_task(&wallet_id, &task).unwrap();
        tx.commit().unwrap();

        // Read the task back
        let tx = db.new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
        tx.commit().unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task.id);

        // Read the task back by ID
        let tx = db.new_read_tx().unwrap();
        let task = tx.get_wallet_task_by_id(&wallet_id, &tasks[0].id).unwrap();
        tx.commit().unwrap();
        assert_eq!(task.unwrap().id, tasks[0].id);
    }

    /// Tests getting the current running task
    #[test]
    fn test_current_running_task() {
        let db = mock_db();
        let wallet_id = WalletIdentifier::new_v4();

        // Test on an empty queue
        let tx = db.new_read_tx().unwrap();
        let task = tx.get_current_running_task(&wallet_id).unwrap();
        tx.commit().unwrap();

        assert!(task.is_none());

        // Add a task, not running and test again
        let task = mock_queued_task();
        let tx = db.new_write_tx().unwrap();
        tx.add_wallet_task(&wallet_id, &task).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        let no_task = tx.get_current_running_task(&wallet_id).unwrap();
        tx.commit().unwrap();
        assert!(no_task.is_none());

        // Transition the task to running and test again
        let tx = db.new_write_tx().unwrap();
        let state = QueuedTaskState::Running { state: "Running".to_string(), committed: false };
        tx.transition_wallet_task(&wallet_id, state).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        let found_task = tx.get_current_running_task(&wallet_id).unwrap();
        tx.commit().unwrap();
        assert!(found_task.is_some());
        assert_eq!(found_task.unwrap().id, task.id);
    }

    /// Tests popping a task from the queue
    #[test]
    fn test_pop() {
        // Setup the mock
        let db = mock_db();
        db.create_table(TASK_QUEUE_TABLE).unwrap();

        // Add a task to the wallet
        let wallet_id = WalletIdentifier::new_v4();
        let task = mock_queued_task();
        let tx = db.new_write_tx().unwrap();
        tx.add_wallet_task(&wallet_id, &task).unwrap();
        tx.commit().unwrap();

        // Pop the task from the wallet
        let tx = db.new_write_tx().unwrap();
        let popped_task = tx.pop_wallet_task(&wallet_id).unwrap();
        tx.commit().unwrap();
        assert_eq!(popped_task.unwrap().id, task.id);

        // Check the queue is empty
        let tx = db.new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
        tx.commit().unwrap();
        assert_eq!(tasks.len(), 0);
    }

    /// Tests updating the state of the top task in the queue
    #[test]
    fn test_transition() {
        // Setup the mock
        let db = mock_db();
        db.create_table(TASK_QUEUE_TABLE).unwrap();

        // Add a task to the wallet
        let wallet_id = WalletIdentifier::new_v4();
        let task = mock_queued_task();
        let tx = db.new_write_tx().unwrap();
        tx.add_wallet_task(&wallet_id, &task).unwrap();
        tx.commit().unwrap();

        // Transition the state of the task
        let tx = db.new_write_tx().unwrap();
        tx.transition_wallet_task(
            &wallet_id,
            QueuedTaskState::Running { state: "Running".to_string(), committed: false },
        )
        .unwrap();
        tx.commit().unwrap();

        // Read the task back
        let tx = db.new_read_tx().unwrap();
        let tasks = tx.get_wallet_tasks(&wallet_id).unwrap();
        tx.commit().unwrap();
        assert_eq!(tasks.len(), 1);
        assert!(matches!(tasks[0].state, QueuedTaskState::Running { .. }));
    }

    /// Test the task to wallet map
    #[test]
    fn test_task_to_wallet_map() {
        // Setup the mock
        let db = mock_db();
        db.create_table(TASK_TO_WALLET_TABLE).unwrap();

        // Add a task to the wallet
        let wallet_id = WalletIdentifier::new_v4();
        let task = mock_queued_task();
        let tx = db.new_write_tx().unwrap();
        tx.add_wallet_task(&wallet_id, &task).unwrap();
        tx.commit().unwrap();

        // Check the task is associated with the wallet
        let tx = db.new_read_tx().unwrap();
        let task_wallet = tx.get_task_wallet(&task.id).unwrap();
        tx.commit().unwrap();
        assert_eq!(task_wallet, Some(wallet_id));

        // Remove the task from the wallet
        let tx = db.new_write_tx().unwrap();
        tx.pop_wallet_task(&wallet_id).unwrap();
        tx.commit().unwrap();

        // Validate that the task is no longer associated with the wallet
        let tx = db.new_read_tx().unwrap();
        let task_wallet = tx.get_task_wallet(&task.id).unwrap();
        tx.commit().unwrap();
        assert_eq!(task_wallet, None);
    }
}
