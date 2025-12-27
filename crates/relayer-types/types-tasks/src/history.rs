//! Types for task history storage

#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::descriptors::{
    QueuedTask, QueuedTaskState, TaskDescriptor, TaskIdentifier, TaskQueueKey,
};

/// A historical task executed by the task driver
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct HistoricalTask {
    /// The ID of the task
    pub id: TaskIdentifier,
    /// The state of the task
    pub state: QueuedTaskState,
    /// The time the task was created
    pub created_at: u64,
    /// The auxiliary information from the task descriptor that we keep in the
    /// history
    pub task_info: HistoricalTaskDescription,
}

impl HistoricalTask {
    /// Create a new historical task from a `QueuedTask`
    ///
    /// Returns `None` for tasks that should not be stored in history
    pub fn from_queued_task(key: TaskQueueKey, task: QueuedTask) -> Option<Self> {
        let desc = task.descriptor.clone();
        let task_info = HistoricalTaskDescription::from_task_descriptor(key, &desc)?;
        Some(Self { id: task.id, state: task.state, created_at: task.created_at, task_info })
    }
}

/// A historical description of a task
///
/// Separated out from the task descriptors as the descriptors may contain
/// runtime information irrelevant for storage
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub enum HistoricalTaskDescription {
    /// A new account was created
    NewAccount,
}

impl HistoricalTaskDescription {
    /// Create a historical task description from a task descriptor
    pub fn from_task_descriptor(_key: TaskQueueKey, desc: &TaskDescriptor) -> Option<Self> {
        match desc {
            TaskDescriptor::NewAccount(_) => Some(Self::NewAccount),
        }
    }
}
