//! Defines storage primitives for the task queue
//!
//! Tasks are indexed in queues identified by a queue key which specifies the
//! resource they contend for. Currently, this is a wallet ID.
//!
//! The layout of the queue is as follows:
//! - Each queue key maps to a `TaskQueue` containing lists of task IDs
//!   segmented by their access class (exclusive or shared).
//! - Each task ID maps to a `QueuedTask` containing the task's description and
//!   metadata.

// TODO(@joeykraut): Rename this to `task_queue` after migration completes

use common::types::tasks::{QueuedTask, QueuedTaskState, TaskIdentifier, TaskQueueKey};
use libmdbx::{TransactionKind, RW};
use serde::{Deserialize, Serialize};

use crate::{storage::error::StorageError, TASK_QUEUE_TABLE, TASK_TO_KEY_TABLE};

use super::StateTxn;

/// The error message emitted when a task is not found
const ERR_TASK_NOT_FOUND: &str = "task not found";
/// The error message emitted when a task queue is at max concurrency
const ERR_MAX_CONCURRENCY: &str = "max concurrency reached for task queue";

/// The maximum number of tasks that can be concurrently running for a queue
const MAX_CONCURRENT_TASKS: usize = 20;

// --------------------
// | Task Queue Types |
// --------------------

/// Get the storage key for a task queue
fn task_queue_key(key: &TaskQueueKey) -> String {
    format!("task-queue-{}", key)
}

/// Get the storage key for a task
fn task_key(id: &TaskIdentifier) -> String {
    format!("task-{}", id)
}

/// The task queue type, containing the list of tasks that are queued for
/// execution
///
/// We express a "write preference" in the queue by enforcing that the
/// `serial_tasks` list be empty before a task is added to the
/// `concurrent_tasks` list.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct TaskQueue {
    /// The list of tasks that are queued for execution
    concurrent_tasks: Vec<TaskIdentifier>,
    /// The list of tasks that are queued for execution
    serial_tasks: Vec<TaskIdentifier>,
    /// The list of running tasks
    running_tasks: Vec<TaskIdentifier>,
}

impl TaskQueue {
    /// Check whether the task queue is in a valid state
    pub fn check(&self) -> Result<(), StorageError> {
        if self.concurrent_tasks.len() > MAX_CONCURRENT_TASKS {
            return Err(StorageError::other(ERR_MAX_CONCURRENCY));
        }
        Ok(())
    }

    /// Check whether the task queue is empty
    pub fn is_empty(&self) -> bool {
        self.concurrent_tasks.is_empty() && self.serial_tasks.is_empty()
    }

    /// Check whether the given task is running
    #[cfg(test)]
    pub fn is_running(&self, id: &TaskIdentifier) -> bool {
        self.running_tasks.contains(id)
    }

    /// Get all tasks in the queue
    pub fn all_tasks(&self) -> Vec<TaskIdentifier> {
        self.concurrent_tasks.clone().into_iter().chain(self.serial_tasks.clone()).collect()
    }

    /// Add a serial task to the queue
    pub fn add_serial_task(&mut self, task: TaskIdentifier) {
        self.serial_tasks.push(task);
    }

    /// Add a serial task to the front of the queue
    pub fn add_serial_task_front(&mut self, task: TaskIdentifier) {
        self.serial_tasks.insert(0, task);
    }

    /// Add a concurrent task to the queue
    pub fn add_concurrent_task(&mut self, task: TaskIdentifier) {
        self.concurrent_tasks.push(task);
    }

    /// Pop a task from the queue
    pub fn pop_task(&mut self, id: &TaskIdentifier) -> Option<TaskIdentifier> {
        self.remove_running_task(id);
        if let Some(serial_idx) = self.serial_tasks.iter().position(|t| t == id) {
            self.serial_tasks.remove(serial_idx);
        } else if let Some(concurrent_idx) = self.concurrent_tasks.iter().position(|t| t == id) {
            self.concurrent_tasks.remove(concurrent_idx);
        } else {
            return None;
        }

        Some(*id)
    }

    /// Mark a task as running
    pub fn mark_running(&mut self, task: TaskIdentifier) {
        self.running_tasks.push(task);
    }

    /// Remove a task from the running list
    pub fn remove_running_task(&mut self, id: &TaskIdentifier) -> Option<TaskIdentifier> {
        let idx = self.running_tasks.iter().position(|t| t == id)?;
        Some(self.running_tasks.remove(idx))
    }
}

// --------------------------
// | Storage Implementation |
// --------------------------

// --- Getters --- //

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Check whether a task queue is empty
    /// TODO(@joeykraut): Rename this method after migration completes
    pub fn is_queue_empty_v2(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        Ok(queue.is_empty())
    }

    /// Check whether a task queue has any active concurrent tasks
    pub fn concurrent_tasks_active(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        Ok(!queue.concurrent_tasks.is_empty())
    }

    /// Check whether a task queue has any active serial tasks
    pub fn serial_tasks_active(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        Ok(!queue.serial_tasks.is_empty())
    }

    /// Get the task specified by the given ID
    /// TODO(@joeykraut): Rename this method after migration completes
    pub fn get_task_v2(&self, id: &TaskIdentifier) -> Result<Option<QueuedTask>, StorageError> {
        let key = task_key(id);
        let task = self.inner().read(TASK_QUEUE_TABLE, &key)?;
        Ok(task)
    }

    /// Get the currently running task for a queue
    /// TODO(@joeykraut): Rename this method after migration completes
    pub fn get_current_running_tasks_v2(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Vec<TaskIdentifier>, StorageError> {
        let queue = self.get_task_queue(key)?;
        Ok(queue.running_tasks)
    }

    /// Get the queue key for a given task
    /// TODO(@joeykraut): Rename this method after migration completes
    pub fn get_queue_key_for_task_v2(
        &self,
        id: &TaskIdentifier,
    ) -> Result<Option<TaskQueueKey>, StorageError> {
        self.inner().read(TASK_TO_KEY_TABLE, id)
    }

    // --- Helpers --- //

    /// Get the task queue for a given key
    pub(crate) fn get_task_queue(&self, key: &TaskQueueKey) -> Result<TaskQueue, StorageError> {
        let key = task_queue_key(key);
        let queue = self.inner().read(TASK_QUEUE_TABLE, &key)?;

        Ok(queue.unwrap_or_default())
    }
}

// --- Setters --- //

impl<'db> StateTxn<'db, RW> {
    /// Add a serial task to the queue
    pub fn add_serial_task(
        &self,
        key: &TaskQueueKey,
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        let mut queue = self.get_task_queue(key)?;
        queue.add_serial_task(task.id);

        self.write_task_queue(key, &queue)?;
        self.write_task(&task.id, key, task)
    }

    /// Add a serial task to the front of the queue
    pub fn add_serial_task_front(
        &self,
        key: &TaskQueueKey,
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        let mut queue = self.get_task_queue(key)?;
        queue.add_serial_task_front(task.id);

        self.write_task_queue(key, &queue)?;
        self.write_task(&task.id, key, task)
    }

    /// Add a concurrent task to the queue
    pub fn add_concurrent_task(
        &self,
        key: &TaskQueueKey,
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        let mut queue = self.get_task_queue(key)?;
        queue.add_concurrent_task(task.id);

        self.write_task_queue(key, &queue)?;
        self.write_task(&task.id, key, task)
    }

    /// Pop a task from the queue
    pub fn pop_task_v2(
        &self,
        key: &TaskQueueKey,
        id: &TaskIdentifier,
    ) -> Result<Option<QueuedTask>, StorageError> {
        let mut queue = self.get_task_queue(key)?;
        queue.pop_task(id);
        self.write_task_queue(key, &queue)?;

        let task = self.delete_task(id)?;
        Ok(task)
    }

    /// Clear a task queue, removing all tasks from it
    /// TODO(@joeykraut): Rename this method after migration completes
    pub fn clear_task_queue_v2(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Vec<TaskIdentifier>, StorageError> {
        let queue = self.get_task_queue(key)?;
        let all_tasks = queue.all_tasks();
        for task_id in all_tasks.iter() {
            self.delete_task(task_id)?;
        }

        self.write_task_queue(key, &TaskQueue::default())?;
        Ok(all_tasks)
    }

    /// Transition the state of a given task
    /// TODO(@joeykraut): Rename this method after migration completes
    pub fn transition_task_v2(
        &self,
        id: &TaskIdentifier,
        key: &TaskQueueKey,
        new_state: QueuedTaskState,
    ) -> Result<(), StorageError> {
        let mut task = match self.get_task_v2(id)? {
            Some(t) => t,
            None => return Err(StorageError::not_found(ERR_TASK_NOT_FOUND)),
        };

        // Mark the task as running if the new state is running
        if new_state.is_running() {
            self.mark_task_running(id, key)?;
        }
        task.state = new_state;
        self.update_task(id, &task)
    }

    // --- Helpers --- //

    /// Mark a task as running in the queue
    fn mark_task_running(
        &self,
        id: &TaskIdentifier,
        key: &TaskQueueKey,
    ) -> Result<(), StorageError> {
        let mut queue = self.get_task_queue(key)?;
        queue.mark_running(*id);
        self.write_task_queue(key, &queue)
    }

    /// Write the task queue to storage
    fn write_task_queue(&self, key: &TaskQueueKey, queue: &TaskQueue) -> Result<(), StorageError> {
        queue.check()?;
        let key = task_queue_key(key);
        self.inner().write(TASK_QUEUE_TABLE, &key, queue)
    }

    /// Write a task to storage
    fn write_task(
        &self,
        id: &TaskIdentifier,
        queue: &TaskQueueKey,
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        self.update_task(id, task)?;
        self.inner().write(TASK_TO_KEY_TABLE, id, queue)
    }

    /// Update a task in storage
    fn update_task(&self, id: &TaskIdentifier, task: &QueuedTask) -> Result<(), StorageError> {
        let key = task_key(id);
        self.inner().write(TASK_QUEUE_TABLE, &key, task)
    }

    /// Delete a task from storage
    ///
    /// This removes the task
    fn delete_task(&self, id: &TaskIdentifier) -> Result<Option<QueuedTask>, StorageError> {
        let key = task_key(id);
        let task = self.inner().read(TASK_QUEUE_TABLE, &key)?;
        self.inner().delete(TASK_QUEUE_TABLE, &key)?;
        self.inner().delete(TASK_TO_KEY_TABLE, id)?;

        Ok(task)
    }
}

// --- Tests --- //

#[cfg(test)]
mod test {
    use common::types::tasks::mocks::mock_queued_task;

    use crate::test_helpers::mock_db;

    use super::*;

    /// Tests adding a task to the queue and retrieving it
    #[test]
    fn test_append_and_get() {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx().unwrap();

        // Check the queue before any tasks are added
        let key = TaskQueueKey::new_v4();
        let queued_tasks = tx.get_task_queue(&key).unwrap();
        assert!(queued_tasks.is_empty());

        // Add a serial task to the queue
        let serial_task = mock_queued_task(key);
        tx.add_serial_task(&key, &serial_task).unwrap();
        let queued_tasks = tx.get_task_queue(&key).unwrap();
        assert_eq!(queued_tasks.serial_tasks.len(), 1);
        assert_eq!(queued_tasks.serial_tasks[0], serial_task.id);
        assert_eq!(queued_tasks.concurrent_tasks.len(), 0);

        // Add a concurrent task to the queue
        let concurrent_task = mock_queued_task(key);
        tx.add_concurrent_task(&key, &concurrent_task).unwrap();
        let queued_tasks = tx.get_task_queue(&key).unwrap();
        assert_eq!(queued_tasks.serial_tasks.len(), 1);
        assert_eq!(queued_tasks.concurrent_tasks.len(), 1);
        assert_eq!(queued_tasks.concurrent_tasks[0], concurrent_task.id);

        // Get the tasks and their queue mappings individually
        let serial_id = serial_task.id;
        let concurrent_id = concurrent_task.id;
        let serial_task_retrieved = tx.get_task_v2(&serial_id).unwrap().is_some();
        let concurrent_task_retrieved = tx.get_task_v2(&concurrent_id).unwrap().is_some();
        let serial_queue_key = tx.get_queue_key_for_task_v2(&serial_id).unwrap().unwrap();
        let concurrent_queue_key = tx.get_queue_key_for_task_v2(&concurrent_id).unwrap().unwrap();
        assert!(serial_task_retrieved);
        assert!(concurrent_task_retrieved);
        assert_eq!(serial_queue_key, key);
        assert_eq!(concurrent_queue_key, key);
    }

    /// Tests popping a task from the queue
    #[test]
    fn test_pop() {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx().unwrap();
        let key = TaskQueueKey::new_v4();
        let serial_task = mock_queued_task(key);
        let concurrent_task = mock_queued_task(key);

        // First pop when the queue is empty
        let maybe_task = tx.pop_task_v2(&key, &serial_task.id).unwrap();
        assert!(maybe_task.is_none());
        let maybe_task = tx.pop_task_v2(&key, &concurrent_task.id).unwrap();
        assert!(maybe_task.is_none());

        // Add tasks to the queue
        tx.add_serial_task(&key, &serial_task).unwrap();
        tx.add_concurrent_task(&key, &concurrent_task).unwrap();

        // Pop the serial task
        let popped_task = tx.pop_task_v2(&key, &serial_task.id).unwrap();
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, serial_task.id);

        // Pop the concurrent task
        let popped_task = tx.pop_task_v2(&key, &concurrent_task.id).unwrap();
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, concurrent_task.id);

        // Check the queue is empty
        let queued_tasks = tx.get_task_queue(&key).unwrap();
        assert!(queued_tasks.is_empty());

        // Check that both tasks are deleted
        let serial_task_none = tx.get_task_v2(&serial_task.id).unwrap().is_none();
        let concurrent_task_none = tx.get_task_v2(&concurrent_task.id).unwrap().is_none();
        assert!(serial_task_none);
        assert!(concurrent_task_none);
    }

    /// Tests updating the state of a task
    #[test]
    fn test_transition() {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx().unwrap();

        // Add a task to the queue
        let key = TaskQueueKey::new_v4();
        let task = mock_queued_task(key);
        tx.add_serial_task(&key, &task).unwrap();

        // Transition the state of the task
        let state = QueuedTaskState::Running { state: "Running".to_string(), committed: false };
        tx.transition_task_v2(&task.id, &key, state.clone()).unwrap();

        // Check the task is running
        let task_queue = tx.get_task_queue(&key).unwrap();
        assert!(task_queue.is_running(&task.id));

        // Fetch the task directly
        let task = tx.get_task_v2(&task.id).unwrap().unwrap();
        assert_eq!(task.state, state);

        // Now delete the task and check the running map
        tx.pop_task_v2(&key, &task.id).unwrap();
        let task_queue = tx.get_task_queue(&key).unwrap();
        let task_none = tx.get_task_v2(&task.id).unwrap().is_none();
        assert!(!task_queue.is_running(&task.id));
        assert!(task_none);
    }

    /// Test clearing a task queue
    #[test]
    fn test_clear_queue() {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx().unwrap();
        let key = TaskQueueKey::new_v4();

        // Add three tasks to the queue
        let task1 = mock_queued_task(key);
        let task2 = mock_queued_task(key);
        let task3 = mock_queued_task(key);
        tx.add_serial_task(&key, &task1).unwrap();
        tx.add_serial_task(&key, &task2).unwrap();
        tx.add_concurrent_task(&key, &task3).unwrap();

        // Clear the queue
        tx.clear_task_queue_v2(&key).unwrap();
        let queue = tx.get_task_queue(&key).unwrap();
        assert!(queue.is_empty());
        assert!(queue.running_tasks.is_empty());
    }

    /// Tests adding tasks up to the max concurrency limit
    #[test]
    #[should_panic(expected = "max concurrency reached for task queue")]
    fn test_max_concurrency() {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx().unwrap();
        let key = TaskQueueKey::new_v4();

        for _ in 0..MAX_CONCURRENT_TASKS {
            let task = mock_queued_task(key);
            tx.add_concurrent_task(&key, &task).unwrap();
        }

        // Check that the queue is at max concurrency
        let queue = tx.get_task_queue(&key).unwrap();
        assert_eq!(queue.concurrent_tasks.len(), MAX_CONCURRENT_TASKS);

        // Add one more and check that it errors
        let task = mock_queued_task(key);
        tx.add_concurrent_task(&key, &task).unwrap();
    }
}
