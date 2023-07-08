//! Defines API types for task status introspection

use serde::Serialize;

/// The response type for a request to fetch task status
#[derive(Clone, Debug, Serialize)]
pub struct GetTaskStatusResponse {
    /// The status of the requested task
    pub status: String,
}
