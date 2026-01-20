//! Task queue type definitions and implementations

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use types_tasks::{QueuedTask, TaskIdentifier};

use crate::storage::{ArchivedValue, error::StorageError};

/// The error message emitted when a task queue is at max concurrency
const ERR_MAX_CONCURRENCY: &str = "max concurrency reached for task queue";
/// The error message emitted when a task queue has an invalid preemption state
const ERR_INVALID_PREEMPTION_STATE: &str = "invalid preemption state for task queue";

/// The maximum number of tasks that can be concurrently running for a queue
const MAX_CONCURRENT_TASKS: usize = 20;

/// A type alias for an archived task queue value
pub(crate) type TaskQueueValue<'a> = ArchivedValue<'a, TaskQueue>;
/// A type alias for an archived task
pub(crate) type TaskValue<'a> = ArchivedValue<'a, QueuedTask>;

/// The preemption state of a task queue
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
pub enum TaskQueuePreemptionState {
    /// The queue is not currently preempted by any task
    #[default]
    NotPreempted,
    /// The queue contains a serial preemptive task
    SerialPreemptionQueued,
    /// The queue contains one or more concurrent preemptive tasks
    ConcurrentPreemptionsQueued,
}

/// The task queue type, containing the list of tasks that are queued for
/// execution
///
/// We express a "write preference" in the queue by enforcing that the
/// `serial_tasks` list be empty before a task is added to the
/// `concurrent_tasks` list.
#[derive(
    Debug, Default, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
#[rkyv(derive(Debug, PartialEq, Eq))]
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
    pub fn check_invariants(&self) -> Result<(), StorageError> {
        if self.concurrent_tasks.len() > MAX_CONCURRENT_TASKS {
            return Err(StorageError::reject(ERR_MAX_CONCURRENCY));
        }

        if !self.check_preemption_state() {
            return Err(StorageError::reject(ERR_INVALID_PREEMPTION_STATE));
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
        // Only the first serial task may be popped
        if self.serial_tasks.first() == Some(id) {
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

// -------------------------
// | ArchivedValue Methods |
// -------------------------

impl ArchivedValue<'_, TaskQueue> {
    /// Check whether the task queue is empty
    pub fn is_empty(&self) -> bool {
        self.concurrent_tasks.is_empty() && self.serial_tasks.is_empty()
    }

    /// Get all tasks in the queue
    pub fn all_tasks(&self) -> Vec<TaskIdentifier> {
        self.concurrent_tasks.iter().copied().chain(self.serial_tasks.iter().copied()).collect()
    }

    /// Get the next task to run
    pub fn next_serial_task(&self) -> Option<TaskIdentifier> {
        if let Some(task) = self.serial_tasks.first()
            && self.can_task_run(task)
        {
            return Some(*task);
        }

        None
    }

    /// Returns `true` if the queue may be preempted serially
    ///
    /// A queue may be serially preempted iff it is not already preempted by
    /// another serial task
    pub fn can_preempt_serial(&self) -> bool {
        !matches!(self.preemption_state, ArchivedTaskQueuePreemptionState::SerialPreemptionQueued)
    }

    /// Returns `true` if the queue may be preempted concurrently
    ///
    /// A queue may be concurrently preempted iff it has no queued serial tasks
    pub fn can_preempt_concurrent(&self) -> bool {
        self.serial_tasks.is_empty()
    }

    /// Whether the given task can run on the queue
    pub fn can_task_run(&self, task: &TaskIdentifier) -> bool {
        let is_first_serial = !self.serial_tasks.is_empty()
            && self.serial_tasks.first().map(|t| *t == *task).unwrap_or(false);
        if is_first_serial && self.concurrent_tasks.is_empty() {
            // Only the first serial task may run, if no concurrent tasks are queued
            return true;
        } else if self.concurrent_tasks.contains(task) {
            // A concurrent task may run iff it is in the queue
            return true;
        }

        false
    }

    /// Validate the preemption state
    ///
    /// This does not catch all invalid states, but ensures that the `TaskQueue`
    /// struct is at least self consistent
    fn check_preemption_state(&self) -> bool {
        match self.preemption_state {
            ArchivedTaskQueuePreemptionState::NotPreempted => self.concurrent_tasks.is_empty(),
            ArchivedTaskQueuePreemptionState::ConcurrentPreemptionsQueued => {
                !self.concurrent_tasks.is_empty()
            },
            // No invalid state can be caught here for a `SerialPreemptionQueued`
            ArchivedTaskQueuePreemptionState::SerialPreemptionQueued => true,
        }
    }

    /// Check whether the task queue is in a valid state
    pub fn check_invariants(&self) -> Result<(), StorageError> {
        if self.concurrent_tasks.len() > MAX_CONCURRENT_TASKS {
            return Err(StorageError::reject(ERR_MAX_CONCURRENCY));
        }

        if !self.check_preemption_state() {
            return Err(StorageError::reject(ERR_INVALID_PREEMPTION_STATE));
        }

        Ok(())
    }
}
