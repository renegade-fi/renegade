//! Defines storage primitives for the task queue
//!
//! Tasks are indexed in queues identified by the shared resource they occupy.
//! For now this is only wallets (i.e. wallet_id).

use std::collections::VecDeque;

use common::types::tasks::{
    QueuedTask, QueuedTaskState, TaskIdentifier, TaskQueueKey, TaskQueuePauseState,
};
use libmdbx::{TransactionKind, RW};
use util::res_some;

use crate::{storage::error::StorageError, TASK_QUEUE_TABLE, TASK_TO_KEY_TABLE};

use super::StateTxn;

/// The error message emitted when a task queue is empty
const ERR_NO_TASKS: &str = "No tasks in the queue";

/// Create the key for a "task queue state" entry from a queue key
fn queue_lock_state_key(key: &TaskQueueKey) -> String {
    format!("{key}-queue-state")
}

// -----------
// | Getters |
// -----------

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Check whether the current task queue is empty
    pub fn is_queue_empty(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let tasks = self.get_queued_tasks(key)?;
        Ok(tasks.is_empty())
    }

    /// Whether or not the task queue is paused
    ///
    /// This is true for _any_ of the pause states
    pub fn is_queue_paused(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let state = self.get_queue_pause_state(key)?;
        Ok(matches!(state, TaskQueuePauseState::Paused | TaskQueuePauseState::PausedShared))
    }

    /// Whether or not the task queue is paused-shared
    pub fn is_queue_paused_shared(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let state = self.get_queue_pause_state(key)?;
        Ok(matches!(state, TaskQueuePauseState::PausedShared))
    }

    /// Get the tasks for a given queue
    pub fn get_queued_tasks(&self, key: &TaskQueueKey) -> Result<Vec<QueuedTask>, StorageError> {
        self.read_task_deque(key).map(|x| x.into())
    }

    /// Get the task queue that a given task is associated with
    pub fn get_queue_key_for_task(
        &self,
        task_id: &TaskIdentifier,
    ) -> Result<Option<TaskQueueKey>, StorageError> {
        self.inner().read(TASK_TO_KEY_TABLE, task_id)
    }

    /// Get the task by ID
    pub fn get_task(&self, task_id: &TaskIdentifier) -> Result<Option<QueuedTask>, StorageError> {
        // Get the key for the task
        let key = res_some!(self.get_queue_key_for_task(task_id)?);
        let tasks = self.get_queued_tasks(&key)?;

        Ok(tasks.into_iter().find(|x| &x.id == task_id))
    }

    /// Get the currently running task for a queue, or `None` if there is no
    /// running task
    pub fn get_current_running_task(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Option<QueuedTask>, StorageError> {
        let tasks = self.get_queued_tasks(key)?;
        Ok(tasks.first().cloned().filter(|task| task.state.is_running()))
    }

    // --- Helpers --- //

    /// Internal helper to read the queued tasks as a `VecDeque`
    fn read_task_deque(&self, key: &TaskQueueKey) -> Result<VecDeque<QueuedTask>, StorageError> {
        self.read_queue(TASK_QUEUE_TABLE, key)
    }

    /// Get the lock state for a given queue
    fn get_queue_pause_state(
        &self,
        key: &TaskQueueKey,
    ) -> Result<TaskQueuePauseState, StorageError> {
        let key = queue_lock_state_key(key);
        let state = self.inner().read(TASK_QUEUE_TABLE, &key)?;

        Ok(state.unwrap_or(TaskQueuePauseState::Active))
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    /// Add a task to the queue
    pub fn add_task(&self, key: &TaskQueueKey, task: &QueuedTask) -> Result<(), StorageError> {
        self.push_to_queue(TASK_QUEUE_TABLE, key, task)?;

        // Add a mapping from the task to the queue key
        self.inner().write(TASK_TO_KEY_TABLE, &task.id, key)
    }

    /// Add a task to the front of the queue
    pub fn add_task_front(
        &self,
        key: &TaskQueueKey,
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        self.push_to_queue_front(TASK_QUEUE_TABLE, key, task)?;

        // Add a mapping from the task to the queue key
        self.inner().write(TASK_TO_KEY_TABLE, &task.id, key)
    }

    /// Pop a task from the queue
    pub fn pop_task(&self, key: &TaskQueueKey) -> Result<Option<QueuedTask>, StorageError> {
        let res: Option<QueuedTask> = self.pop_from_queue(TASK_QUEUE_TABLE, key)?;

        if let Some(ref task) = res {
            // Remove the mapping from the task to the queue key
            self.inner().delete(TASK_TO_KEY_TABLE, &task.id)?;
        }

        Ok(res)
    }

    /// Clear the task queue, returning the tasks that were in it
    pub fn clear_task_queue(&self, key: &TaskQueueKey) -> Result<Vec<QueuedTask>, StorageError> {
        let tasks: Vec<QueuedTask> = self.read_task_deque(key)?.into();
        for task in &tasks {
            // Remove the mapping from the task to the queue key
            self.inner().delete(TASK_TO_KEY_TABLE, &task.id)?;
        }

        // Remove all the tasks from the queue
        self.clear_queue::<_, QueuedTask>(TASK_QUEUE_TABLE, key)?;

        Ok(tasks)
    }

    /// Transition the state of the top task in the queue
    pub fn transition_task(
        &self,
        key: &TaskQueueKey,
        new_state: QueuedTaskState,
    ) -> Result<(), StorageError> {
        let mut tasks = self.read_task_deque(key)?;
        if tasks.is_empty() {
            return Err(StorageError::NotFound(ERR_NO_TASKS.to_string()));
        }

        tasks.get_mut(0).unwrap().state = new_state;
        self.write_queue(TASK_QUEUE_TABLE, key, &tasks)
    }

    /// Mark the given task queue as paused
    pub fn pause_task_queue(&self, key: &TaskQueueKey) -> Result<(), StorageError> {
        self.set_queue_pause_state(key, TaskQueuePauseState::Paused)
    }

    /// Mark the given task queue as paused-shared
    pub fn pause_task_queue_shared(&self, key: &TaskQueueKey) -> Result<(), StorageError> {
        self.set_queue_pause_state(key, TaskQueuePauseState::PausedShared)
    }

    /// Resume the given task queue
    ///
    /// We simply delete the pause state entry for the given queue and let it
    /// default into the setter
    pub fn resume_task_queue(&self, key: &TaskQueueKey) -> Result<(), StorageError> {
        self.set_queue_pause_state(key, TaskQueuePauseState::Active)
    }

    // --- Helpers --- //

    /// Set the pause state for a given task queue
    fn set_queue_pause_state(
        &self,
        key: &TaskQueueKey,
        state: TaskQueuePauseState,
    ) -> Result<(), StorageError> {
        let key = queue_lock_state_key(key);
        self.inner().write(TASK_QUEUE_TABLE, &key, &state)
    }
}

#[cfg(test)]
mod test {
    use common::types::tasks::{
        mocks::mock_queued_task, QueuedTask, QueuedTaskState, TaskQueueKey,
    };

    use crate::{test_helpers::mock_db, TASK_QUEUE_TABLE, TASK_TO_KEY_TABLE};

    /// Tests getting the tasks for a key
    #[test]
    fn test_append_and_get() {
        // Setup the mock
        let db = mock_db();
        db.create_table(TASK_QUEUE_TABLE).unwrap();

        // Get the tasks for a key, should be empty
        let key = TaskQueueKey::new_v4();
        let tx = db.new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&key).unwrap();
        tx.commit().unwrap();
        assert_eq!(tasks.len(), 0);

        // Add a task to the key
        let task = mock_queued_task(key);
        let tx = db.new_write_tx().unwrap();
        tx.add_task(&key, &task).unwrap();
        tx.commit().unwrap();

        // Read the task back
        let tx = db.new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&key).unwrap();
        tx.commit().unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task.id);

        // Read the task back by ID
        let tx = db.new_read_tx().unwrap();
        let task = tx.get_task(&tasks[0].id).unwrap();
        tx.commit().unwrap();
        assert_eq!(task.unwrap().id, tasks[0].id);
    }

    /// Tests getting the current running task
    #[test]
    fn test_current_running_task() {
        let db = mock_db();
        let key = TaskQueueKey::new_v4();

        // Test on an empty queue
        let tx = db.new_read_tx().unwrap();
        let task = tx.get_current_running_task(&key).unwrap();
        tx.commit().unwrap();

        assert!(task.is_none());

        // Add a task, not running and test again
        let task = mock_queued_task(key);
        let tx = db.new_write_tx().unwrap();
        tx.add_task(&key, &task).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        let no_task = tx.get_current_running_task(&key).unwrap();
        tx.commit().unwrap();
        assert!(no_task.is_none());

        // Transition the task to running and test again
        let tx = db.new_write_tx().unwrap();
        let state = QueuedTaskState::Running { state: "Running".to_string(), committed: false };
        tx.transition_task(&key, state).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        let found_task = tx.get_current_running_task(&key).unwrap();
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

        // Add a task to the key
        let key = TaskQueueKey::new_v4();
        let task = mock_queued_task(key);
        let tx = db.new_write_tx().unwrap();
        tx.add_task(&key, &task).unwrap();
        tx.commit().unwrap();

        // Pop the task from the key
        let tx = db.new_write_tx().unwrap();
        let popped_task = tx.pop_task(&key).unwrap();
        tx.commit().unwrap();
        assert_eq!(popped_task.unwrap().id, task.id);

        // Check the queue is empty
        let tx = db.new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&key).unwrap();
        tx.commit().unwrap();
        assert_eq!(tasks.len(), 0);
    }

    /// Tests updating the state of the top task in the queue
    #[test]
    fn test_transition() {
        // Setup the mock
        let db = mock_db();
        db.create_table(TASK_QUEUE_TABLE).unwrap();

        // Add a task to the key
        let key = TaskQueueKey::new_v4();
        let task = mock_queued_task(key);
        let tx = db.new_write_tx().unwrap();
        tx.add_task(&key, &task).unwrap();
        tx.commit().unwrap();

        // Transition the state of the task
        let tx = db.new_write_tx().unwrap();
        tx.transition_task(
            &key,
            QueuedTaskState::Running { state: "Running".to_string(), committed: false },
        )
        .unwrap();
        tx.commit().unwrap();

        // Read the task back
        let tx = db.new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&key).unwrap();
        tx.commit().unwrap();
        assert_eq!(tasks.len(), 1);
        assert!(matches!(tasks[0].state, QueuedTaskState::Running { .. }));
    }

    /// Test the task to key map
    #[test]
    fn test_task_to_key_map() {
        // Setup the mock
        let db = mock_db();
        db.create_table(TASK_TO_KEY_TABLE).unwrap();

        // Add a task to the key
        let key = TaskQueueKey::new_v4();
        let task = mock_queued_task(key);
        let tx = db.new_write_tx().unwrap();
        tx.add_task(&key, &task).unwrap();
        tx.commit().unwrap();

        // Check the task is associated with the key
        let tx = db.new_read_tx().unwrap();
        let task_key = tx.get_queue_key_for_task(&task.id).unwrap();
        tx.commit().unwrap();
        assert_eq!(task_key, Some(key));

        // Remove the task from the key
        let tx = db.new_write_tx().unwrap();
        tx.pop_task(&key).unwrap();
        tx.commit().unwrap();

        // Validate that the task is no longer associated with the key
        let tx = db.new_read_tx().unwrap();
        let task_key = tx.get_queue_key_for_task(&task.id).unwrap();
        tx.commit().unwrap();
        assert_eq!(task_key, None);
    }

    /// Tests pausing and resuming the task queue
    #[test]
    fn test_pause_resume() {
        // Setup the mock
        let db = mock_db();
        db.create_table(TASK_QUEUE_TABLE).unwrap();
        let key = TaskQueueKey::new_v4();

        let tx = db.new_read_tx().unwrap();
        let paused = tx.is_queue_paused(&key).unwrap();
        tx.commit().unwrap();
        assert!(!paused);

        // Pause the task queue
        let tx = db.new_write_tx().unwrap();
        tx.pause_task_queue(&key).unwrap();
        tx.commit().unwrap();

        // Check the task queue is paused
        let tx = db.new_read_tx().unwrap();
        let paused = tx.is_queue_paused(&key).unwrap();
        tx.commit().unwrap();
        assert!(paused);

        // Resume the task queue
        let tx = db.new_write_tx().unwrap();
        tx.resume_task_queue(&key).unwrap();
        tx.commit().unwrap();

        // Check the task queue is resumed
        let tx = db.new_read_tx().unwrap();
        let paused = tx.is_queue_paused(&key).unwrap();
        tx.commit().unwrap();
        assert!(!paused);
    }

    /// Tests pausing (shared) and resuming a task queue
    #[test]
    fn test_pause_resume_shared() {
        // Setup the mock
        let db = mock_db();
        db.create_table(TASK_QUEUE_TABLE).unwrap();
        let key = TaskQueueKey::new_v4();

        let tx = db.new_read_tx().unwrap();
        let paused = tx.is_queue_paused(&key).unwrap();
        let pause_shared = tx.is_queue_paused_shared(&key).unwrap();
        tx.commit().unwrap();
        assert!(!paused);
        assert!(!pause_shared);

        // Pause the task queue with shared state
        let tx = db.new_write_tx().unwrap();
        tx.pause_task_queue_shared(&key).unwrap();
        tx.commit().unwrap();

        // Check the task queue is paused
        let tx = db.new_read_tx().unwrap();
        let pause_shared = tx.is_queue_paused_shared(&key).unwrap();
        let paused = tx.is_queue_paused(&key).unwrap();
        tx.commit().unwrap();
        assert!(pause_shared);
        assert!(paused);

        // Resume the task queue
        let tx = db.new_write_tx().unwrap();
        tx.resume_task_queue(&key).unwrap();
        tx.commit().unwrap();

        // Check the task queue is resumed
        let tx = db.new_read_tx().unwrap();
        let pause_shared = tx.is_queue_paused_shared(&key).unwrap();
        let paused = tx.is_queue_paused(&key).unwrap();
        tx.commit().unwrap();
        assert!(!pause_shared);
        assert!(!paused);
    }

    /// Tests clearing the task queue
    #[test]
    fn test_clear_queue() {
        // Setup the mock
        let db = mock_db();
        db.create_table(TASK_QUEUE_TABLE).unwrap();

        // Add a few tasks to the queue
        let key = TaskQueueKey::new_v4();
        let n = 10;

        let tasks: Vec<QueuedTask> = (0..n).map(|_| mock_queued_task(key)).collect();

        let tx = db.new_write_tx().unwrap();
        for task in &tasks {
            tx.add_task(&key, task).unwrap();
        }
        tx.commit().unwrap();

        // Clear the task queue
        let tx = db.new_write_tx().unwrap();
        let cleared_tasks = tx.clear_task_queue(&key).unwrap();
        tx.commit().unwrap();

        // Check that the right tasks were cleared,
        // and that their states are "failed"
        assert_eq!(cleared_tasks.len(), n);
        for (task, cleared_task) in tasks.iter().zip(cleared_tasks.iter()) {
            assert_eq!(task.id, cleared_task.id);
        }

        // Check the queue is empty
        let tx = db.new_read_tx().unwrap();
        let tasks = tx.get_queued_tasks(&key).unwrap();
        tx.commit().unwrap();
        assert_eq!(tasks.len(), 0);
    }
}
