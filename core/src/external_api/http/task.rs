//! Defines API types for task status introspection

use serde::Serialize;

use crate::tasks::driver::StateWrapper as TaskStatus;

/// The response type for a request to fetch task status
#[derive(Clone, Debug, Serialize)]
pub struct GetTaskStatusResponse {
    /// The status of the requested task
    pub status: TaskStatus,
}
