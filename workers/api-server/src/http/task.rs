//! Groups API definitions relevant to task interaction

// ---------------
// | Http Routes |
// ---------------

use async_trait::async_trait;
use external_api::{
    http::task::{GetTaskStatusResponse, TaskQueueListResponse, TaskStatus},
    EmptyRequestResponse,
};
use hyper::HeaderMap;
use state::State;
use util::err_str;

use crate::{
    error::{internal_error, not_found, ApiServerError},
    router::{TypedHandler, UrlParams},
};

use super::{parse_task_id_from_params, parse_wallet_id_from_params};

// ------------------
// | Error Messages |
// ------------------

/// Error message displayed when a given task cannot be found
const ERR_TASK_NOT_FOUND: &str = "task not found";

/// -----------------------
/// | Task Route Handlers |
/// -----------------------

/// Handler for the GET /task/:id route
pub struct GetTaskStatusHandler {
    /// A reference to the global state
    state: State,
}

impl GetTaskStatusHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for GetTaskStatusHandler {
    type Request = EmptyRequestResponse;
    type Response = GetTaskStatusResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Lookup the task status in the task driver's state
        let task_id = parse_task_id_from_params(&params)?;
        let task_status = self.state.get_task_status(&task_id)?;

        if let Some(status) = task_status {
            let status = serde_json::to_string(&status).map_err(err_str!(internal_error))?;
            Ok(GetTaskStatusResponse { status: status.to_string() })
        } else {
            Err(not_found(ERR_TASK_NOT_FOUND.to_string()))
        }
    }
}

/// Handler for the GET /task_queue/:wallet_id route
pub struct GetTaskQueueHandler {
    /// A reference to the global state
    state: State,
}

impl GetTaskQueueHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for GetTaskQueueHandler {
    type Request = EmptyRequestResponse;
    type Response = TaskQueueListResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;

        // Lookup all tasks from global state
        let tasks = self.state.get_queued_tasks(&wallet_id)?;
        let api_tasks: Vec<TaskStatus> = tasks.into_iter().map(|t| t.into()).collect();

        Ok(TaskQueueListResponse { tasks: api_tasks })
    }
}
