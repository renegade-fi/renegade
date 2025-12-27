//! Storage implementation for task queue operations

use libmdbx::{RW, TransactionKind};
use types_tasks::{QueuedTask, QueuedTaskState, TaskIdentifier, TaskQueueKey};
use util::res_some;

use crate::{
    TASK_QUEUE_TABLE, TASK_TO_KEY_TABLE,
    storage::{
        error::StorageError,
        traits::RkyvValue,
        tx::task_queue::queue_type::{TaskQueueValue, TaskValue},
    },
};

use super::super::StateTxn;
use super::queue_type::TaskQueue;

/// The error message emitted when a task is not found
const ERR_TASK_NOT_FOUND: &str = "task not found";
/// The error message emitted when a task cannot be popped from the queue
const ERR_TASK_NOT_POPPED: &str = "task not popped from queue";
/// The error message emitted when a task cannot be preempted
const ERR_CANNOT_SERIALLY_PREEMPT: &str = "serial preemption not allowed";
/// The error message emitted when a task cannot be preempted concurrently
const ERR_CANNOT_CONCURRENTLY_PREEMPT: &str = "concurrent preemption not allowed";

/// Get the storage key for a task queue
pub fn task_queue_key(key: &TaskQueueKey) -> String {
    format!("task-queue-{}", key)
}

/// Get the storage key for a task
fn task_key(id: &TaskIdentifier) -> String {
    format!("task-{}", id)
}

/// Get the storage key for the task to queue(s) mapping
fn task_to_queue_key(id: &TaskIdentifier) -> String {
    format!("task-to-queue-{id}")
}

// -----------------
// | Query Methods |
// -----------------

impl<T: TransactionKind> StateTxn<'_, T> {
    /// Check whether a task queue is empty
    pub fn is_queue_empty(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        let empty = queue.map(|q| q.is_empty()).unwrap_or(true);
        Ok(empty)
    }

    /// Check whether a task queue has any active concurrent tasks
    pub fn concurrent_tasks_active(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        let active = queue.map(|q| !q.concurrent_tasks.is_empty()).unwrap_or(false);
        Ok(active)
    }

    /// Check whether a task queue has any active serial tasks
    pub fn serial_tasks_active(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        let active = queue.map(|q| !q.serial_tasks.is_empty()).unwrap_or(false);
        Ok(active)
    }

    /// Get the task specified by the given ID
    pub fn get_task(&self, id: &TaskIdentifier) -> Result<Option<TaskValue<'_>>, StorageError> {
        let key = task_key(id);
        self.inner().read::<_, QueuedTask>(TASK_QUEUE_TABLE, &key)
    }

    /// Get the task specified by the given ID (deserialized)
    pub fn get_task_deserialized(
        &self,
        id: &TaskIdentifier,
    ) -> Result<Option<QueuedTask>, StorageError> {
        let task = self.get_task(id)?;
        task.map(|archived| archived.deserialize()).transpose()
    }

    /// Get the next serial task that can run on the given queue
    ///
    /// We do not return concurrent tasks here, as those are assumed to be
    /// started optimistically
    pub fn next_runnable_task(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Option<TaskValue<'_>>, StorageError> {
        let queue = self.get_task_queue(key)?;
        let Some(queue) = queue else {
            return Ok(None);
        };

        let tid = res_some!(queue.next_serial_task());
        self.get_task(&tid)
    }

    /// Get the queue key for a given task
    pub fn get_queue_keys_for_task(
        &self,
        id: &TaskIdentifier,
    ) -> Result<Vec<TaskQueueKey>, StorageError> {
        let key = task_to_queue_key(id);
        self.inner()
            .read::<_, Vec<TaskQueueKey>>(TASK_TO_KEY_TABLE, &key)?
            .map(|archived| archived.deserialize())
            .transpose()
            .map(|opt| opt.unwrap_or_default())
    }

    /// Check whether a given task queue is preemptable
    pub fn is_queue_preemptable(
        &self,
        key: &TaskQueueKey,
        serial: bool,
    ) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        let Some(queue) = queue else {
            // Empty queue can be preempted
            return Ok(true);
        };

        let res = if serial { queue.can_preempt_serial() } else { queue.can_preempt_concurrent() };
        Ok(res)
    }

    /// Check whether the given task can run on its queues
    ///
    /// A task may run iff it can run on all queues it is indexed into
    pub fn can_task_run(&self, id: &TaskIdentifier) -> Result<bool, StorageError> {
        let queues = self.get_queue_keys_for_task(id)?;
        for queue_key in queues.iter() {
            let queue = self.get_task_queue(queue_key)?;
            let Some(queue) = queue else {
                // Task not in queue, can't run
                return Ok(false);
            };

            if !queue.can_task_run(id) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get the queued tasks for a given key
    pub fn get_queued_tasks(&self, key: &TaskQueueKey) -> Result<Vec<TaskValue<'_>>, StorageError> {
        let queue = self.get_task_queue(key)?;
        let Some(queue) = queue else {
            return Ok(Vec::new());
        };

        let task_ids = queue.all_tasks();
        let mut tasks = Vec::with_capacity(task_ids.len());
        for task_id in task_ids.iter() {
            if let Some(task) = self.get_task(task_id)? {
                tasks.push(task);
            }
        }

        Ok(tasks)
    }

    // --- Helpers --- //

    /// Returns whether a given queue is serially preemptable
    fn is_serial_preemption_safe(&self, key: &TaskQueueKey) -> Result<bool, StorageError> {
        let queue = self.get_task_queue(key)?;
        let Some(queue) = queue else {
            // Empty queue can be preempted
            return Ok(true);
        };

        let mut can_preempt = queue.can_preempt_serial();
        if let Some(t) = queue.serial_tasks.first() {
            let task = self.get_task(t)?.ok_or(StorageError::reject(ERR_TASK_NOT_FOUND))?;
            let state = QueuedTaskState::rkyv_deserialize(&task.state)?;
            can_preempt = can_preempt && !state.is_committed();
        }

        Ok(can_preempt)
    }

    /// Get the task queue for a given key
    pub(crate) fn get_task_queue(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Option<TaskQueueValue<'_>>, StorageError> {
        let key = task_queue_key(key);
        self.inner().read::<_, TaskQueue>(TASK_QUEUE_TABLE, &key)
    }

    /// Get the task queue for a given key (deserialized)
    ///
    /// Helper method for mutation operations that need an owned `TaskQueue`.
    /// Returns a default `TaskQueue` if the queue doesn't exist.
    pub(crate) fn get_task_queue_deserialized(
        &self,
        key: &TaskQueueKey,
    ) -> Result<TaskQueue, StorageError> {
        Ok(self
            .get_task_queue(key)?
            .map(|archived| archived.deserialize())
            .transpose()?
            .unwrap_or_default())
    }
}

// --------------------
// | Mutation Methods |
// --------------------

impl StateTxn<'_, RW> {
    /// Add a serial task to the queue
    ///
    /// Unlike the preemptive tasks, normal serial tasks are only indexed into a
    /// single queue
    pub fn enqueue_serial_task(
        &self,
        key: &TaskQueueKey,
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        let mut queue = self.get_task_queue_deserialized(key)?;
        queue.enqueue_serial_task(task.id);

        self.write_task_queue(key, &queue)?;
        self.write_task(&task.id, vec![*key], task)
    }

    /// Preempt a queue with a serial task
    pub fn preempt_queue_with_serial(
        &self,
        queues: &[TaskQueueKey],
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        // Index the task into the queues
        for queue_key in queues.iter() {
            // 1. Check that the queue can be preempted
            if !self.is_serial_preemption_safe(queue_key)? {
                return Err(StorageError::reject(ERR_CANNOT_SERIALLY_PREEMPT));
            }

            // 2. Move the existing task back to the queued state
            let mut queue = self.get_task_queue_deserialized(queue_key)?;
            if let Some(t) = queue.serial_tasks.first() {
                self.requeue_task(t)?;
            }

            // 3. Preempt the queue
            if !queue.preempt_with_serial_task(task.id) {
                return Err(StorageError::reject(ERR_CANNOT_SERIALLY_PREEMPT));
            };
            self.write_task_queue(queue_key, &queue)?;
        }

        self.write_task(&task.id, queues.to_vec(), task)?;
        Ok(())
    }

    /// Add a concurrent task to the queue
    pub fn preempt_queue_with_concurrent(
        &self,
        queues: &[TaskQueueKey],
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        for queue_key in queues.iter() {
            let mut queue = self.get_task_queue_deserialized(queue_key)?;
            if !queue.preempt_with_concurrent_task(task.id) {
                return Err(StorageError::reject(ERR_CANNOT_CONCURRENTLY_PREEMPT));
            }

            self.write_task_queue(queue_key, &queue)?;
        }

        self.write_task(&task.id, queues.to_vec(), task)?;
        Ok(())
    }

    /// Pop a task from the queue
    pub fn pop_task(&self, id: &TaskIdentifier) -> Result<Option<QueuedTask>, StorageError> {
        let queue_keys = self.get_queue_keys_for_task(id)?;
        for key in queue_keys.iter() {
            // Pop the task from the queue then write back
            let mut queue = self.get_task_queue_deserialized(key)?;
            if !queue.pop_task(id) {
                return Err(StorageError::reject(ERR_TASK_NOT_POPPED));
            }

            self.write_task_queue(key, &queue)?;
        }

        let task = self.delete_task(id)?;
        Ok(task)
    }

    /// Clear a task queue, removing all tasks from it
    pub fn clear_task_queue(&self, key: &TaskQueueKey) -> Result<Vec<QueuedTask>, StorageError> {
        let queue = self.get_task_queue(key)?;
        let all_task_ids = queue.map(|q| q.all_tasks()).unwrap_or_default();
        let mut all_tasks = Vec::with_capacity(all_task_ids.len());
        for task_id in all_task_ids.iter() {
            if let Some(task) = self.delete_task(task_id)? {
                all_tasks.push(task);
            }
        }

        self.write_task_queue(key, &TaskQueue::default())?;
        Ok(all_tasks)
    }

    /// Transition the state of a given task
    pub fn transition_task(
        &self,
        id: &TaskIdentifier,
        new_state: QueuedTaskState,
    ) -> Result<(), StorageError> {
        let mut task = self
            .get_task_deserialized(id)?
            .ok_or_else(|| StorageError::reject(ERR_TASK_NOT_FOUND))?;

        task.state = new_state;
        self.update_task(id, &task)
    }

    // --- Helpers --- //

    /// Write the task queue to storage
    fn write_task_queue(&self, key: &TaskQueueKey, queue: &TaskQueue) -> Result<(), StorageError> {
        queue.check_invariants()?;
        let key = task_queue_key(key);
        self.inner().write(TASK_QUEUE_TABLE, &key, queue)
    }

    /// Write a task to storage
    fn write_task(
        &self,
        id: &TaskIdentifier,
        queues: Vec<TaskQueueKey>,
        task: &QueuedTask,
    ) -> Result<(), StorageError> {
        self.update_task(id, task)?;
        self.update_task_to_queues(id, queues)
    }

    /// Mark a task as queued
    fn requeue_task(&self, id: &TaskIdentifier) -> Result<(), StorageError> {
        if let Some(mut task) = self.get_task_deserialized(id)? {
            task.state = QueuedTaskState::Queued;
            self.update_task(id, &task)?;
        }

        Ok(())
    }

    /// Update a task in storage
    fn update_task(&self, id: &TaskIdentifier, task: &QueuedTask) -> Result<(), StorageError> {
        let key = task_key(id);
        self.inner().write(TASK_QUEUE_TABLE, &key, task)
    }

    /// Update the task -> queues mapping
    #[allow(clippy::needless_pass_by_value)]
    fn update_task_to_queues(
        &self,
        id: &TaskIdentifier,
        queues: Vec<TaskQueueKey>,
    ) -> Result<(), StorageError> {
        let key = task_to_queue_key(id);
        self.inner().write(TASK_TO_KEY_TABLE, &key, &queues)
    }

    /// Delete a task from storage
    ///
    /// This removes the task
    fn delete_task(&self, id: &TaskIdentifier) -> Result<Option<QueuedTask>, StorageError> {
        let key = task_key(id);
        let task_to_queues_key = task_to_queue_key(id);
        let task = self.get_task_deserialized(id)?;
        self.inner().delete(TASK_QUEUE_TABLE, &key)?;
        self.inner().delete(TASK_TO_KEY_TABLE, &task_to_queues_key)?;

        Ok(task)
    }
}

// --- Tests --- //

#[cfg(test)]
mod test {
    use types_tasks::mocks::mock_queued_task;

    use crate::storage::traits::RkyvValue;
    use crate::{storage::tx::task_queue::TaskQueuePreemptionState, test_helpers::mock_db};

    use super::*;

    /// Helper function to assert that an archived queue matches an expected
    /// queue
    #[allow(unsafe_code)]
    fn assert_queue_eq(archived: Option<TaskQueueValue<'_>>, expected: &TaskQueue) {
        // If the queue doesn't exist, it should match the default queue
        let archived_queue = match archived {
            Some(q) => q,
            None => {
                assert_eq!(expected, &TaskQueue::default(), "queue should be default when None");
                return;
            },
        };

        // Serialize the expected queue to compare archived types directly
        let expected_bytes = expected.rkyv_serialize().expect("failed to serialize expected queue");
        let expected_archived = unsafe { TaskQueue::rkyv_access(&expected_bytes) };

        // Compare the archived types directly using PartialEq
        assert_eq!(&*archived_queue, expected_archived, "queue mismatch");
    }

    /// Test the serial operation of the task queue (no preemption)
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_ops__basic() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Check that the queue is empty
        let empty = tx.is_queue_empty(&key)?;
        assert!(empty);

        // Add a task to the queue, and check that it is indexed
        let task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &task)?;
        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue { serial_tasks: vec![task.id], ..Default::default() };
        assert_queue_eq(task_queue, &expected_queue);

        // Check that the task is indexed
        let indexed = tx.get_task(&task.id)?.is_some();
        assert!(indexed);

        // Now pop the task and check that it is removed from the queue
        let popped_task = tx.pop_task(&task.id)?;
        let not_indexed = tx.get_task(&task.id)?.is_none();
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, task.id);
        assert!(not_indexed);

        // Check that the task queue has updated
        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue::default();
        assert_queue_eq(task_queue, &expected_queue);
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
        assert_queue_eq(task_queue, &expected_queue);

        // Check that both tasks are indexed
        let indexed1 = tx.get_task(&task1.id)?.is_some();
        let indexed2 = tx.get_task(&task2.id)?.is_some();
        assert!(indexed1);
        assert!(indexed2);

        // Pop the first task from the queue
        let popped_task = tx.pop_task(&task1.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, task1.id);

        // Check that the queue has updated
        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue { serial_tasks: vec![task2.id], ..Default::default() };
        assert_queue_eq(task_queue, &expected_queue);
        Ok(())
    }

    /// Tests the `can_run` method on a basic serial task    
    #[test]
    #[allow(non_snake_case)]
    fn test_can_run__basic() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a serial task to the queue, and check that it can run
        let task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &task)?;
        let can_run = tx.can_task_run(&task.id)?;
        assert!(can_run);

        // Add another task to the same queue, and check that it cannot yet run
        let other_task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &other_task)?;
        let can_run = tx.can_task_run(&other_task.id)?;
        assert!(!can_run);

        // Pop the first task and check that the second task can run
        tx.pop_task(&task.id)?;
        let can_run = tx.can_task_run(&other_task.id)?;
        assert!(can_run);
        Ok(())
    }

    // --- Serial Preemption --- //

    /// Tests a serial preemption with only serial tasks running
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_preemption__simple() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a serial task to the queue
        let mut task = mock_queued_task(key);
        task.state = QueuedTaskState::Running { state: "running".to_string(), committed: false };
        tx.enqueue_serial_task(&key, &task)?;

        // Preempt the task queue
        let preemptive_task = mock_queued_task(key);
        tx.preempt_queue_with_serial(&[key], &preemptive_task)?;

        // Check that the task queue state is updated correctly
        let task1_info = tx.get_task(&task.id)?.expect("task1 should be present").deserialize()?;
        let preemptive_task_some = tx.get_task(&preemptive_task.id)?.is_some();
        assert_eq!(task1_info.state, QueuedTaskState::Queued);
        assert!(preemptive_task_some);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![preemptive_task.id, task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_queue_eq(task_queue, &expected_queue);

        // Pop the preemptive task and check that the queue state is updated
        let popped_task = tx.pop_task(&preemptive_task.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, preemptive_task.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue { serial_tasks: vec![task.id], ..Default::default() };
        assert_queue_eq(task_queue, &expected_queue);
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
        tx.preempt_queue_with_concurrent(&[key], &concurrent_task)?;
        tx.enqueue_serial_task(&key, &serial_task)?;
        tx.preempt_queue_with_serial(&[key], &preemptive_task)?;

        // Check that the task queue state is updated correctly
        let serial_task_some = tx.get_task(&serial_task.id)?.is_some();
        let concurrent_task_some = tx.get_task(&concurrent_task.id)?.is_some();
        let preemptive_task_some = tx.get_task(&preemptive_task.id)?.is_some();
        assert!(serial_task_some);
        assert!(concurrent_task_some);
        assert!(preemptive_task_some);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![preemptive_task.id, serial_task.id],
            concurrent_tasks: vec![concurrent_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
        };
        assert_queue_eq(task_queue, &expected_queue);

        // 1. Pop the concurrent task
        let popped_task = tx.pop_task(&concurrent_task.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, concurrent_task.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![preemptive_task.id, serial_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_queue_eq(task_queue, &expected_queue);

        // 2. Pop the serial preemptive task
        let popped_task = tx.pop_task(&preemptive_task.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, preemptive_task.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_queue_eq(task_queue, &expected_queue);
        Ok(())
    }

    /// Tests serial preemption with multiple queues
    #[test]
    #[allow(non_snake_case)]
    fn test_serial_preemption__multiple_queues() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key1 = TaskQueueKey::new_v4();
        let key2 = TaskQueueKey::new_v4();

        // Add a serial task to one of the queues
        let task = mock_queued_task(key1);
        tx.enqueue_serial_task(&key1, &task)?;

        // Preempt both queues with a serial task
        let preemptive_task = mock_queued_task(key2);
        tx.preempt_queue_with_serial(&[key1, key2], &preemptive_task)?;

        // Check that the task -> queues mapping is updated correctly
        let task_to_queues = tx.get_queue_keys_for_task(&preemptive_task.id)?;
        assert_eq!(task_to_queues.len(), 2);
        assert!(task_to_queues.contains(&key1));
        assert!(task_to_queues.contains(&key2));

        // Check that the task queue state is updated correctly
        let task_queue1 = tx.get_task_queue(&key1)?;
        let task_queue2 = tx.get_task_queue(&key2)?;
        let expected_queue1 = TaskQueue {
            serial_tasks: vec![preemptive_task.id, task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        let expected_queue2 = TaskQueue {
            serial_tasks: vec![preemptive_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_queue_eq(task_queue1, &expected_queue1);
        assert_queue_eq(task_queue2, &expected_queue2);
        Ok(())
    }

    /// Tests the `can_run` method on a serial preemptive task    
    #[test]
    #[allow(non_snake_case)]
    fn test_can_run__serial_preemptive() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // 1. Add a concurrent preemptive task to the queue; serial task cannot run
        let concurrent_task = mock_queued_task(key);
        let serial_task = mock_queued_task(key);
        tx.preempt_queue_with_concurrent(&[key], &concurrent_task)?;
        tx.preempt_queue_with_serial(&[key], &serial_task)?;
        let can_run = tx.can_task_run(&serial_task.id)?;
        assert!(!can_run);

        // 2. Pop the concurrent task; serial task can now run
        tx.pop_task(&concurrent_task.id)?;
        let can_run = tx.can_task_run(&serial_task.id)?;
        assert!(can_run);
        Ok(())
    }

    /// Tests the `can_run` method on a serial preemptive task associated with
    /// multiple queues
    #[test]
    #[allow(non_snake_case)]
    fn test_can_run__serial_preemptive__multiple_queues() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key1 = TaskQueueKey::new_v4();
        let key2 = TaskQueueKey::new_v4();

        // Enqueue a concurrent task on one of the queues
        let dummy_key = TaskQueueKey::new_v4();
        let concurrent_task = mock_queued_task(dummy_key);
        let serial_task = mock_queued_task(dummy_key);
        tx.preempt_queue_with_concurrent(&[key1], &concurrent_task)?;
        tx.preempt_queue_with_serial(&[key1, key2], &serial_task)?;

        // Check that the serial task cannot run
        let can_run = tx.can_task_run(&serial_task.id)?;
        assert!(!can_run);

        // Pop the concurrent task; serial task can now run
        tx.pop_task(&concurrent_task.id)?;
        let can_run = tx.can_task_run(&serial_task.id)?;
        assert!(can_run);
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
        tx.preempt_queue_with_serial(&[key], &first_task)?;

        // Attempt to preempt the task with another serial task
        let second_task = mock_queued_task(key);
        let err = tx.preempt_queue_with_serial(&[key], &second_task).is_err();
        assert!(err);

        // Check that the queue was not updated
        let second_task_none = tx.get_task(&second_task.id)?.is_none();
        assert!(second_task_none);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![first_task.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        assert_queue_eq(task_queue, &expected_queue);
        Ok(())
    }

    /// Tests an invalid serial preemption with multiple queues, in which one
    /// queue can be preempted and another cannot    
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_serial_preemption__multiple_queues() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key1 = TaskQueueKey::new_v4();
        let key2 = TaskQueueKey::new_v4();

        // Add a serial preemptive task to one of the queues
        let preemptive_task1 = mock_queued_task(key1);
        tx.preempt_queue_with_serial(&[key1], &preemptive_task1)?;

        // Try to preempt both queues with a new serial task
        let new_serial_task = mock_queued_task(key2);
        let err = tx.preempt_queue_with_serial(&[key1, key2], &new_serial_task).is_err();
        assert!(err);

        // Check that the queue state is updated correctly
        let task_queue1 = tx.get_task_queue(&key1)?;
        let task_queue2 = tx.get_task_queue(&key2)?;
        let expected_queue1 = TaskQueue {
            serial_tasks: vec![preemptive_task1.id],
            preemption_state: TaskQueuePreemptionState::SerialPreemptionQueued,
            ..Default::default()
        };
        let expected_queue2 = TaskQueue::default();
        assert_queue_eq(task_queue1, &expected_queue1);
        assert_queue_eq(task_queue2, &expected_queue2);
        Ok(())
    }

    /// Tests an invalid serial preemption in the case that the running task is
    /// committed
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_serial_preemption__committed_task() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a committed task to the queue
        let mut task = mock_queued_task(key);
        task.state = QueuedTaskState::Running { state: "running".to_string(), committed: true };
        tx.enqueue_serial_task(&key, &task)?;

        // Attempt to preempt the task with another serial task
        let new_serial_task = mock_queued_task(key);
        let err = tx.preempt_queue_with_serial(&[key], &new_serial_task).is_err();
        assert!(err);

        // Check that the queue state is updated correctly
        let task_queue = tx.get_task_queue_deserialized(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);
        Ok(())
    }

    // --- Concurrent Preemption --- //

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
        tx.preempt_queue_with_concurrent(&[key], &task1)?;
        tx.preempt_queue_with_concurrent(&[key], &task2)?;

        // Check that the task queue state is updated correctly
        let task1_some = tx.get_task(&task1.id)?.is_some();
        let task2_some = tx.get_task(&task2.id)?.is_some();
        assert!(task1_some);
        assert!(task2_some);

        let task_queue = tx.get_task_queue_deserialized(&key)?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![task1.id, task2.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
            ..Default::default()
        };
        assert_eq!(task_queue, expected_queue);

        // Pop the first task
        let popped_task = tx.pop_task(&task1.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, task1.id);

        let task_queue = tx.get_task_queue_deserialized(&key)?;
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
        tx.preempt_queue_with_concurrent(&[key], &concurrent_task)?;

        // Add a serial task to the queue
        let serial_task = mock_queued_task(key);
        tx.enqueue_serial_task(&key, &serial_task)?;

        // Check that the task queue state is updated correctly
        let concurrent_task_some = tx.get_task(&concurrent_task.id)?.is_some();
        let serial_task_some = tx.get_task(&serial_task.id)?.is_some();
        assert!(concurrent_task_some);
        assert!(serial_task_some);

        let task_queue = tx.get_task_queue_deserialized(&key)?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![concurrent_task.id],
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
        };
        assert_eq!(task_queue, expected_queue);

        // Try adding another concurrent task, should fail
        let new_concurrent_task = mock_queued_task(key);
        let err = tx.preempt_queue_with_concurrent(&[key], &new_concurrent_task).is_err();
        assert!(err);

        let task_queue = tx.get_task_queue_deserialized(&key)?;
        let expected_queue = TaskQueue {
            concurrent_tasks: vec![concurrent_task.id],
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
        };
        assert_eq!(task_queue, expected_queue);

        // Now pop the concurrent task and check that the queue state is updated
        let popped_task = tx.pop_task(&concurrent_task.id)?;
        assert!(popped_task.is_some());
        assert_eq!(popped_task.unwrap().id, concurrent_task.id);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_queue_eq(task_queue, &expected_queue);
        Ok(())
    }

    /// Tests enqueuing a concurrent task on multiple queues    
    #[test]
    #[allow(non_snake_case)]
    fn test_concurrent_preemption__multiple_queues() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key1 = TaskQueueKey::new_v4();
        let key2 = TaskQueueKey::new_v4();

        // Add a concurrent preemptive task to one of the queues
        let concurrent_task = mock_queued_task(key1);
        tx.preempt_queue_with_concurrent(&[key1], &concurrent_task)?;

        // Add a concurrent preemptive task to both queues
        let new_concurrent_task = mock_queued_task(key2);
        tx.preempt_queue_with_concurrent(&[key1, key2], &new_concurrent_task)?;

        // Check that the task queue state is updated correctly
        let task1_some = tx.get_task(&concurrent_task.id)?.is_some();
        let task2_some = tx.get_task(&new_concurrent_task.id)?.is_some();
        let task2_queues = tx.get_queue_keys_for_task(&new_concurrent_task.id)?;
        assert!(task1_some);
        assert!(task2_some);
        assert_eq!(task2_queues.len(), 2);
        assert!(task2_queues.contains(&key1));
        assert!(task2_queues.contains(&key2));

        let task_queue1 = tx.get_task_queue_deserialized(&key1)?;
        let task_queue2 = tx.get_task_queue_deserialized(&key2)?;
        let expected_queue1 = TaskQueue {
            concurrent_tasks: vec![concurrent_task.id, new_concurrent_task.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
            ..Default::default()
        };
        let expected_queue2 = TaskQueue {
            concurrent_tasks: vec![new_concurrent_task.id],
            preemption_state: TaskQueuePreemptionState::ConcurrentPreemptionsQueued,
            ..Default::default()
        };
        assert_eq!(task_queue1, expected_queue1);
        assert_eq!(task_queue2, expected_queue2);
        Ok(())
    }

    /// Tests the `can_run` method on a concurrent preemptive task    
    #[test]
    #[allow(non_snake_case)]
    fn test_can_run__concurrent_preemptive() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key = TaskQueueKey::new_v4();

        // Add a concurrent preemptive task
        let task1 = mock_queued_task(key);
        let task2 = mock_queued_task(key);
        tx.preempt_queue_with_concurrent(&[key], &task1)?;
        let can_run = tx.can_task_run(&task1.id)?;
        assert!(can_run);

        // Add another task, both should be runnable
        tx.preempt_queue_with_concurrent(&[key], &task2)?;
        let can_run1 = tx.can_task_run(&task1.id)?;
        let can_run2 = tx.can_task_run(&task2.id)?;
        assert!(can_run1);
        assert!(can_run2);
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
        let err = tx.preempt_queue_with_concurrent(&[key], &concurrent_task).is_err();
        assert!(err);

        let task_queue = tx.get_task_queue(&key)?;
        let expected_queue = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        assert_queue_eq(task_queue, &expected_queue);
        Ok(())
    }

    /// Tests enqueuing a concurrent task on multiple queues when one queue
    /// cannot be preempted concurrently
    #[test]
    #[allow(non_snake_case)]
    fn test_concurrent_preemption__multiple_queues__cannot_preempt() -> Result<(), StorageError> {
        // Setup the mock
        let db = mock_db();
        let tx = db.new_write_tx()?;
        let key1 = TaskQueueKey::new_v4();
        let key2 = TaskQueueKey::new_v4();

        // Add a serial task to one of the queues
        let serial_task = mock_queued_task(key1);
        tx.enqueue_serial_task(&key1, &serial_task)?;

        // Try to add a concurrent task to both queues, should fail on the second queue
        let concurrent_task = mock_queued_task(key2);
        let err = tx.preempt_queue_with_concurrent(&[key1, key2], &concurrent_task).is_err();
        assert!(err);

        let task_queue1 = tx.get_task_queue_deserialized(&key1)?;
        let task_queue2 =
            tx.get_task_queue(&key2)?.map(|q| q.deserialize()).transpose()?.unwrap_or_default();
        let expected_queue1 = TaskQueue {
            serial_tasks: vec![serial_task.id],
            preemption_state: TaskQueuePreemptionState::NotPreempted,
            ..Default::default()
        };
        let expected_queue2 = TaskQueue::default();
        assert_eq!(task_queue1, expected_queue1);
        assert_eq!(task_queue2, expected_queue2);
        Ok(())
    }
}
