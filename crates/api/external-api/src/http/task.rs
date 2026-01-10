//! HTTP route definitions and request/response types for task operations

use serde::{Deserialize, Serialize};

use crate::types::ApiTask;

// ---------------
// | HTTP Routes |
// ---------------

/// Route to get tasks for an account
pub const GET_TASKS_ROUTE: &str = "/v2/account/:account_id/tasks";
/// Route to get a task by ID
pub const GET_TASK_BY_ID_ROUTE: &str = "/v2/account/:account_id/tasks/:task_id";

// -------------------
// | Request/Response |
// -------------------

/// Response for get tasks
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetTasksResponse {
    /// The tasks
    pub tasks: Vec<ApiTask>,
    /// The next page token for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<i64>,
}

/// Response for get task by ID
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetTaskByIdResponse {
    /// The task
    pub task: ApiTask,
}
