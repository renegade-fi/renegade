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
/// The error message emitted when a task queue has an invalid preemption state
const ERR_INVALID_PREEMPTION_STATE: &str = "invalid preemption state for task queue";

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

/// The preemption state of a task queue
#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskQueuePreemptionState {
    /// The queue has a serial preemption in progress
    SerialPreemptionQueued,
    /// The queue has a concurrent preemption in progress
    ConcurrentPreemptionsQueued,
    /// The queue is not currently preempted by any task
    #[default]
    NotPreempted,
}

/// The task queue type, containing the list of tasks that are queued for
/// execution
///
/// We express a "write preference" in the queue by enforcing that the
/// `serial_tasks` list be empty before a task is added to the
/// `concurrent_tasks` list.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct TaskQueue {
    /// The list of tasks that are queued for execution
    ///
    /// These are assumed to be preemptive tasks
    pub(crate) concurrent_tasks: Vec<TaskIdentifier>,
    /// The list of tasks that are queued for execution
    pub(crate) serial_tasks: Vec<TaskIdentifier>,
    /// The list of running tasks
    pub(crate) running_tasks: Vec<TaskIdentifier>,
    /// The preemption state of the queue
    pub(crate) preemption_state: TaskQueuePreemptionState,
}

impl TaskQueue {
    // --- Getters --- //

    /// Check whether the task queue is in a valid state
    pub fn check(&self) -> Result<(), StorageError> {
        if self.concurrent_tasks.len() > MAX_CONCURRENT_TASKS {
            return Err(StorageError::other(ERR_MAX_CONCURRENCY));
        }

        if !self.check_preemption_state() {
            return Err(StorageError::other(ERR_INVALID_PREEMPTION_STATE));
        }

        Ok(())
    }

    /// Validate the preemption state
    ///
    /// This does not catch all invalid states, but ensures that the `TaskQueue`
    /// struct is at least self consistent
    fn check_preemption_state(&self) -> bool {
        match self.preemption_state {
            TaskQueuePreemptionState::NotPreempted => self.concurrent_tasks.is_empty(),
            TaskQueuePreemptionState::ConcurrentPreemptionsQueued => {
                !self.concurrent_tasks.is_empty()
            },
            // No invalid state can be caught here for a `SerialPreemptionQueued`
            TaskQueuePreemptionState::SerialPreemptionQueued => true,
        }
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

    /// Returns `true` if the queue may be preempted serially
    ///
    /// A queue may be serially preempted iff it is not already preempted by
    /// another serial task
    pub fn can_preempt_serial(&self) -> bool {
        self.preemption_state != TaskQueuePreemptionState::SerialPreemptionQueued
    }

    /// Returns `true` if the queue may be preempted concurrently
    ///
    /// A queue may be concurrently preempted iff it has no queued serial tasks
    pub fn can_preempt_concurrent(&self) -> bool {
        self.serial_tasks.is_empty()
    }

    // --- Setters --- //

    /// Add a serial task to the queue
    ///
    /// A serial task may always be enqueued, regardless of preemption state
    pub fn enqueue_serial_task(&mut self, task: TaskIdentifier) {
        self.serial_tasks.push(task);
    }

    /// Add a serial task to the front of the queue
    ///
    /// Returns `true` if the queue can be preempted serially, `false`
    /// otherwise. In the case that the method returns false, no modifications
    /// will be made to the queue.
    ///
    /// A serial task may preempt a queue iff the queue is not already preempted
    /// by another serial task
    ///
    /// Inserts the preemptive task at the front of the queue
    pub fn preempt_with_serial_task(&mut self, task: TaskIdentifier) -> bool {
        if !self.can_preempt_serial() {
            return false;
        }

        // Insert the preemptive task at the front of the queue
        self.serial_tasks.insert(0, task);
        self.preemption_state = TaskQueuePreemptionState::SerialPreemptionQueued;
        true
    }

    /// Add a concurrent task to the queue
    ///
    /// Returns `true` if the queue can be preempted concurrently, `false`
    /// otherwise. In the case that the method returns false, no modifications
    /// will be made to the queue.
    ///
    /// A concurrent task may preempt the queue iff the queue has no queued
    /// serial tasks. In this way, the queue expressed a preference for serial
    /// (write or exclusive) tasks
    pub fn preempt_with_concurrent_task(&mut self, task: TaskIdentifier) -> bool {
        if !self.can_preempt_concurrent() {
            return false;
        }

        self.concurrent_tasks.push(task);
        self.preemption_state = TaskQueuePreemptionState::ConcurrentPreemptionsQueued;
        true
    }

    /// Pop a task from the queue
    pub fn pop_task(&mut self, id: &TaskIdentifier) -> bool {
        if let Some(_idx) = self.serial_tasks.iter().position(|t| t == id) {
            self.pop_serial_task();
        } else if let Some(concurrent_idx) = self.concurrent_tasks.iter().position(|t| t == id) {
            self.pop_concurrent_task(concurrent_idx);
        } else {
            return false;
        }

        // Remove the task from the running list
        self.remove_running_task(id);
        true
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

    // --- Helpers --- //

    /// Pop the first serial task from the queue
    ///
    /// Updates the preemption state after the pop
    fn pop_serial_task(&mut self) {
        self.serial_tasks.remove(0);
        match self.preemption_state {
            TaskQueuePreemptionState::SerialPreemptionQueued => {
                // If this was the serially preemptive task, the queue is no longer preempted
                self.preemption_state = TaskQueuePreemptionState::NotPreempted;
            },
            TaskQueuePreemptionState::ConcurrentPreemptionsQueued => {
                unreachable!("Serial tasks cannot pop when concurrently preempted");
            },
            TaskQueuePreemptionState::NotPreempted => {
                // Do nothing, no preemption existed before
            },
        }
    }

    /// Pop a task from the concurrent tasks list at the given index
    ///
    /// Updates the preemption state after the pop
    fn pop_concurrent_task(&mut self, idx: usize) {
        self.concurrent_tasks.remove(idx);
        match self.preemption_state {
            TaskQueuePreemptionState::SerialPreemptionQueued => {
                // Noop, the queue waits for the serial preemption to commit
            },
            TaskQueuePreemptionState::ConcurrentPreemptionsQueued => {
                // Only update if this is the last concurrent task active
                if self.concurrent_tasks.is_empty() {
                    self.preemption_state = TaskQueuePreemptionState::NotPreempted;
                }
            },
            TaskQueuePreemptionState::NotPreempted => {
                unreachable!("Task queue must be preempted to pop concurrent tasks");
            },
        };
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

    /// Check whether a given task queue is preemptable
    pub fn is_preemptable(&self, key: &TaskQueueKey, serial: bool) -> Result<bool, StorageError> {
        if serial {
            self.is_serially_preemptable(key)
        } else {
            self.is_concurrently_preemptable(key)
        }
    }

    // --- Helpers --- //

    /// Get the task queue for a given key
    pub(crate) fn get_task_queue(&self, key: &TaskQueueKey) -> Result<TaskQueue, StorageError> {
        let key = task_queue_key(key);
        let queue = self.inner().read(TASK_QUEUE_TABLE, &key)?;

        Ok(queue.unwrap_or_default())
    }

    /// Check whether a given task queue is preemptable by a serial preemptive
    /// task
    ///
    /// This is true iff the queue has no existing preemptive serial tasks
    fn is_serially_preemptable(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        Ok(queue.can_preempt_serial())
    }

    /// Check whether a given task queue is preemptable by a concurrent
    /// preemptive task
    fn is_concurrently_preemptable(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        Ok(queue.can_preempt_concurrent())
    }
}

// --- Setters --- //

impl<'db> StateTxn<'db, RW> {
    /// Add a serial task to the queue
    pub fn enqueue_serial_task(
        &self,
        key: &TaskQueueKey,
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        let mut queue = self.get_task_queue(key)?;
        queue.enqueue_serial_task(task.id);

        self.write_task_queue(key, &queue)?;
        self.write_task(&task.id, key, task)
    }

    /// Preempt a queue with a serial task
    pub fn preempt_queue_with_serial(
        &self,
        key: &TaskQueueKey,
        task: &QueuedTask,
    ) -> Result<bool, StorageError> {
        // Index the task into the queue
        let mut queue = self.get_task_queue(key)?;
        if !queue.preempt_with_serial_task(task.id) {
            return Ok(false);
        };

        // If we add to the front of the queue, we must check if the task has
        // been added in the running state
        if task.state.is_running() {
            queue.mark_running(task.id);
        }
        self.write_task_queue(key, &queue)?;
        self.write_task(&task.id, key, task)?;
        Ok(true)
    }

    /// Add a concurrent task to the queue
    pub fn preempt_queue_with_concurrent(
        &self,
        key: &TaskQueueKey,
        task: &QueuedTask,
    ) -> Result<bool, StorageError> {
        let mut queue = self.get_task_queue(key)?;
        if !queue.preempt_with_concurrent_task(task.id) {
            return Ok(false);
        };

        self.write_task_queue(key, &queue)?;
        self.write_task(&task.id, key, task)?;
        Ok(true)
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

        // Update the running status of the task
        if new_state.is_running() {
            self.mark_task_running(id, key)?;
        } else {
            self.mark_task_not_running(id, key)?;
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

    /// Mark a task as _not_ running in the queue
    fn mark_task_not_running(
        &self,
        id: &TaskIdentifier,
        key: &TaskQueueKey,
    ) -> Result<(), StorageError> {
        let mut queue = self.get_task_queue(key)?;
        queue.remove_running_task(id);
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

        // Add a concurrent task to the queue
        let concurrent_task = mock_queued_task(key);
        tx.preempt_queue_with_concurrent(&key, &concurrent_task).unwrap();
        let queued_tasks = tx.get_task_queue(&key).unwrap();
        assert_eq!(queued_tasks.serial_tasks.len(), 0);
        assert_eq!(queued_tasks.concurrent_tasks.len(), 1);
        assert_eq!(queued_tasks.concurrent_tasks[0], concurrent_task.id);

        // Add a serial task to the queue
        let serial_task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &serial_task).unwrap();
        let queued_tasks = tx.get_task_queue(&key).unwrap();
        assert_eq!(queued_tasks.serial_tasks.len(), 1);
        assert_eq!(queued_tasks.serial_tasks[0], serial_task.id);
        assert_eq!(queued_tasks.concurrent_tasks.len(), 1);

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
        tx.preempt_queue_with_concurrent(&key, &concurrent_task).unwrap();
        tx.enqueue_serial_task(&key, &serial_task).unwrap();

        // Pop the concurrent task
        let popped_task = tx.pop_task_v2(&key, &concurrent_task.id).unwrap();
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, concurrent_task.id);

        // Pop the serial task
        let popped_task = tx.pop_task_v2(&key, &serial_task.id).unwrap();
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, serial_task.id);

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
        tx.enqueue_serial_task(&key, &task).unwrap();

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
        tx.enqueue_serial_task(&key, &task1).unwrap();
        tx.enqueue_serial_task(&key, &task2).unwrap();
        tx.preempt_queue_with_concurrent(&key, &task3).unwrap();

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
            tx.preempt_queue_with_concurrent(&key, &task).unwrap();
        }

        // Check that the queue is at max concurrency
        let queue = tx.get_task_queue(&key).unwrap();
        assert_eq!(queue.concurrent_tasks.len(), MAX_CONCURRENT_TASKS);

        // Add one more and check that it errors
        let task = mock_queued_task(key);
        tx.preempt_queue_with_concurrent(&key, &task).unwrap();
    }
}
