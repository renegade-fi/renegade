//! Groups API definitions relevant to task interaction

// ---------------
// | Http Routes |
// ---------------

use async_trait::async_trait;
use external_api::{http::task::GetTaskStatusResponse, EmptyRequestResponse};
use hyper::{HeaderMap, StatusCode};
use task_driver::driver::TaskDriver;

use crate::{
    error::ApiServerError,
    router::{TypedHandler, UrlParams},
};

use super::parse_task_id_from_params;

/// Get the status of a task
pub(super) const GET_TASK_STATUS_ROUTE: &str = "/v0/tasks/:task_id";

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
    /// A reference to the task driver that holds global task info
    task_driver: TaskDriver,
}

impl GetTaskStatusHandler {
    /// Constructor
    pub fn new(task_driver: TaskDriver) -> Self {
        Self { task_driver }
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
        if let Some(status) = self.task_driver.get_task_state(&task_id).await {
            Ok(GetTaskStatusResponse { status: status.to_string() })
        } else {
            Err(ApiServerError::HttpStatusCode(
                StatusCode::NOT_FOUND,
                ERR_TASK_NOT_FOUND.to_string(),
            ))
        }
    }
}
