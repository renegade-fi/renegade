//! Defines storage primitives for the task queue
//!
//! Tasks are indexed in queues identified by a queue key which specifies the
//! resource they contend for. Currently, this is an account ID.
//!
//! The layout of the queue is as follows:
//! - Each queue key maps to a `TaskQueue` containing lists of task IDs
//!   segmented by their access class (exclusive or shared).
//! - Each task ID maps to a `QueuedTask` containing the task's description and
//!   metadata.

pub mod queue_type;
pub mod storage;

pub use queue_type::TaskQueuePreemptionState;
pub use storage::task_queue_key;
