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
    /// The queue contains a serial preemptive task
    SerialPreemptionQueued,
    /// The queue contains one or more concurrent preemptive tasks
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

        true
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

    /// Get the queue key for a given task
    /// TODO(@joeykraut): Rename this method after migration completes
    pub fn get_queue_key_for_task_v2(
        &self,
        id: &TaskIdentifier,
    ) -> Result<Option<TaskQueueKey>, StorageError> {
        self.inner().read(TASK_TO_KEY_TABLE, id)
    }

    /// Check whether a given task queue is preemptable
    pub fn is_queue_preemptable(
        &self,
        key: &TaskQueueKey,
        serial: bool,
    ) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        let res = if serial { queue.can_preempt_serial() } else { queue.can_preempt_concurrent() };
        Ok(res)
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
        new_state: QueuedTaskState,
    ) -> Result<(), StorageError> {
        let mut task = match self.get_task_v2(id)? {
            Some(t) => t,
            None => return Err(StorageError::not_found(ERR_TASK_NOT_FOUND)),
        };

        task.state = new_state;
        self.update_task(id, &task)
    }

    // --- Helpers --- //

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

    /// Test the serial operation of the task queue (no preemption)
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_ops__basic() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Check that the queue is empty
        let empty = tx.is_queue_empty_v2(&key)?;
        assert!(empty);

        // Add a task to the queue, and check that it is indexed
        let task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &task)?;
        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue { serial_tasks: vec![task.id], ..Default::default() };
        assert_eq!(task_queue, expected_queue);

        // Check that the task is indexed
        let indexed = tx.get_task_v2(&task.id)?.is_some();
        assert!(indexed);

        // Now pop the task and check that it is removed from the queue
        let popped_task = tx.pop_task_v2(&key, &task.id)?;
        let not_indexed = tx.get_task_v2(&task.id)?.is_none();
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, task.id);
        assert!(not_indexed);

        // Check that the task queue has updated
        let task_queue = tx.get_task_queue(&key).unwrap();
        let expected_queue = TaskQueue::default();
        assert_eq!(task_queue, expected_queue);
        Ok(())
    }

    /// Test the serial operations of the task queue with multiple tasks
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_ops__multiple_tasks() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add two tasks to the queue, one running
        let mut task1 = mock_queued_task(key);
        task1.state = QueuedTaskState::Running { state: "running".to_string(), committed: false };
        let task2 = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &task1)?;
        tx.enqueue_serial_task(&key, &task2)?;

        // Check that the queue has the correct tasks
        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue =
            TaskQueue { serial_tasks: vec![task1.id, task2.id], ..Default::default() };
        assert_eq!(task_queue, expected_queue);

        // Check that both tasks are indexed
        let indexed1 = tx.get_task_v2(&task1.id)?.is_some();
        let indexed2 = tx.get_task_v2(&task2.id)?.is_some();
        assert!(indexed1);
        assert!(indexed2);

        // Pop the first task from the queue
        let popped_task = tx.pop_task_v2(&key, &task1.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, task1.id);

        // Check that the queue has updated
        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue { serial_tasks: vec![task2.id], ..Default::default() };
        assert_eq!(task_queue, expected_queue);
        Ok(())
    }

    /// Tests a serial preemption with only serial tasks running
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_preemption__simple() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a serial task to the queue
        let task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &task)?;

        // Preempt the task queue
        let preemptive_task = mock_queued_task(key);
        tx.preempt_queue_with_serial(&key, &preemptive_task)?;

        // Check that the task queue state is updated correctly
        let task1_some = tx.get_task_v2(&task.id)?.is_some();
        let preemptive_task_some = tx.get_task_v2(&preemptive_task.id)?.is_some();
        assert!(task1_some);
        assert!(preemptive_task_some);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![preemptive_task.id, task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);

        // Pop the preemptive task and check that the queue state is updated
        let popped_task = tx.pop_task_v2(&key, &preemptive_task.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, preemptive_task.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue { serial_tasks: vec![task.id], ..Default::default() };
        assert_eq!(task_queue, expected_queue);
        Ok(())
    }

    /// Tests a serial preemption with concurrent tasks running
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_preemption__with_concurrent() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a normal, concurrent preemptive, and serial preemptive task
        let serial_task = mock_queued_task(key);
        let concurrent_task = mock_queued_task(key);
        let preemptive_task = mock_queued_task(key);
        tx.preempt_queue_with_concurrent(&key, &concurrent_task)?;
        tx.enqueue_serial_task(&key, &serial_task)?;
        tx.preempt_queue_with_serial(&key, &preemptive_task)?;

        // Check that the task queue state is updated correctly
        let serial_task_some = tx.get_task_v2(&serial_task.id)?.is_some();
        let concurrent_task_some = tx.get_task_v2(&concurrent_task.id)?.is_some();
        let preemptive_task_some = tx.get_task_v2(&preemptive_task.id)?.is_some();
        assert!(serial_task_some);
        assert!(concurrent_task_some);
        assert!(preemptive_task_some);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![preemptive_task.id, serial_task.id],
            concurrent_tasks: vec![concurrent_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
        };
        assert_eq!(task_queue, expected_queue);

        // 1. Pop the concurrent task
        let popped_task = tx.pop_task_v2(&key, &concurrent_task.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, concurrent_task.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![preemptive_task.id, serial_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);

        // 2. Pop the serial preemptive task
        let popped_task = tx.pop_task_v2(&key, &preemptive_task.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, preemptive_task.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);
        Ok(())
    }

    /// Tests an attempt to preempt a serial task with another -- invalid
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_serial_preemption__already_preempted() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a serial task to the queue
        let first_task = mock_queued_task(key);
        tx.preempt_queue_with_serial(&key, &first_task)?;

        // Attempt to preempt the task with another serial task
        let second_task = mock_queued_task(key);
        let success = tx.preempt_queue_with_serial(&key, &second_task)?;
        assert!(!success);

        // Check that the queue was not updated
        let second_task_none = tx.get_task_v2(&second_task.id)?.is_none();
        assert!(second_task_none);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![first_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);
        Ok(())
    }

    /// Tests the basic concurrent preemption flow with multiple tasks
    #[test]
    #[allow(non_snake_case)]
    fn test_concurrent_preemption__basic() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add two concurrent preemptive tasks
        let task1 = mock_queued_task(key);
        let task2 = mock_queued_task(key);
        tx.preempt_queue_with_concurrent(&key, &task1)?;
        tx.preempt_queue_with_concurrent(&key, &task2)?;

        // Check that the task queue state is updated correctly
        let task1_some = tx.get_task_v2(&task1.id)?.is_some();
        let task2_some = tx.get_task_v2(&task2.id)?.is_some();
        assert!(task1_some);
        assert!(task2_some);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![task1.id, task2.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);

        // Pop the first task
        let popped_task = tx.pop_task_v2(&key, &task1.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, task1.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![task2.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);
        Ok(())
    }

    /// Tests enqueuing a serial task behind a preempted task
    #[test]
    #[allow(non_snake_case)]
    fn test_concurrent_preemption__enqueue_serial_behind() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a concurrent preemptive task
        let concurrent_task = mock_queued_task(key);
        tx.preempt_queue_with_concurrent(&key, &concurrent_task)?;

        // Add a serial task to the queue
        let serial_task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &serial_task)?;

        // Check that the task queue state is updated correctly
        let concurrent_task_some = tx.get_task_v2(&concurrent_task.id)?.is_some();
        let serial_task_some = tx.get_task_v2(&serial_task.id)?.is_some();
        assert!(concurrent_task_some);
        assert!(serial_task_some);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![concurrent_task.id],
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
        };
        assert_eq!(task_queue, expected_queue);

        // Try adding another concurrent task, should fail
        let new_concurrent_task = mock_queued_task(key);
        let success = tx.preempt_queue_with_concurrent(&key, &new_concurrent_task)?;
        assert!(!success);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![concurrent_task.id],
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
        };
        assert_eq!(task_queue, expected_queue);

        // Now pop the concurrent task and check that the queue state is updated
        let popped_task = tx.pop_task_v2(&key, &concurrent_task.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, concurrent_task.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);
        Ok(())
    }

    /// Tests enqueuing a concurrent task behind a serial task
    #[test]
    #[allow(non_snake_case)]
    fn test_concurrent_preemption__serial_already_queued() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a serial task to the queue
        let serial_task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &serial_task)?;

        // Try to add a concurrent task to the queue, should fail
        let concurrent_task = mock_queued_task(key);
        let success = tx.preempt_queue_with_concurrent(&key, &concurrent_task)?;
        assert!(!success);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);
        Ok(())
    }
}
