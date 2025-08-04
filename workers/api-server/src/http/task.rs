//! Groups API definitions relevant to task interaction

// ---------------
// | Http Routes |
// ---------------

use async_trait::async_trait;
use external_api::{
    EmptyRequestResponse,
    http::{
        task::{
            ApiTaskStatus, GetTaskStatusResponse, TaskQueueListResponse, TaskQueuePausedResponse,
        },
        task_history::GetTaskHistoryResponse,
    },
    types::ApiHistoricalTask,
};
use hyper::HeaderMap;
use state::State;

use crate::{
    error::{ApiServerError, bad_request, not_found},
    router::{QueryParams, TypedHandler, UrlParams},
};

use super::{parse_task_id_from_params, parse_wallet_id_from_params};

// -------------
// | Constants |
// -------------

/// The name of the URL query param for task history length
const TASK_HISTORY_LEN_PARAM: &str = "task_history_len";
/// The default length of the task history to return
const DEFAULT_TASK_HISTORY_LEN: usize = 50;

/// Error message displayed when a given task cannot be found
const ERR_TASK_NOT_FOUND: &str = "task not found";
/// Error message emitted when historical state is disabled
const ERR_HISTORICAL_STATE_DISABLED: &str = "historical state is disabled";

// -----------------------
// | Task Route Handlers |
// -----------------------

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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Lookup the task status in the task driver's state
        let task_id = parse_task_id_from_params(&params)?;
        let task_status = self.state.get_task(&task_id).await?;

        if let Some(status) = task_status {
            let status: ApiTaskStatus = status.into();
            Ok(GetTaskStatusResponse { status })
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
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;

        // Lookup all tasks from global state
        let tasks = self.state.get_queued_tasks(&wallet_id).await?;
        let api_tasks: Vec<ApiTaskStatus> = tasks.into_iter().map(|t| t.into()).collect();

        Ok(TaskQueueListResponse { tasks: api_tasks })
    }
}

/// Handler for the GET /task_queue/:wallet_id/is_paused route
pub struct GetTaskQueuePausedHandler {
    /// A reference to the global state
    state: State,
}

impl GetTaskQueuePausedHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for GetTaskQueuePausedHandler {
    type Request = EmptyRequestResponse;
    type Response = TaskQueuePausedResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let wallet_id = parse_wallet_id_from_params(&params)?;

        // Check if the queue is paused
        let is_paused = self.state.is_queue_paused_serial(&wallet_id).await?;

        Ok(TaskQueuePausedResponse { is_paused })
    }
}

/// Handler for the `/wallet/:wallet_id/task-history` route
#[derive(Clone)]
pub struct GetTaskHistoryHandler {
    /// A reference to the global state
    state: State,
}

impl GetTaskHistoryHandler {
    /// Constructor
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

#[async_trait]
impl TypedHandler for GetTaskHistoryHandler {
    type Request = EmptyRequestResponse;
    type Response = GetTaskHistoryResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        mut query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        if !self.state.historical_state_enabled()? {
            return Err(bad_request(ERR_HISTORICAL_STATE_DISABLED));
        }

        // Lookup the task status in the task driver's state
        let wallet_id = parse_wallet_id_from_params(&params)?;
        let len = query_params
            .remove(TASK_HISTORY_LEN_PARAM)
            .map(|x| x.parse::<usize>())
            .transpose()
            .map_err(bad_request)?
            .unwrap_or(DEFAULT_TASK_HISTORY_LEN);

        // Get the historical and running tasks for a wallet
        let tasks = self.state.get_task_history(len, &wallet_id).await?;
        let api_tasks: Vec<ApiHistoricalTask> = tasks.into_iter().map(|t| t.into()).collect();

        Ok(GetTaskHistoryResponse { tasks: api_tasks, pagination_token: None })
    }
}
