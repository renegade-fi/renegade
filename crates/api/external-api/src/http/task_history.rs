//! Task history API definitions and routes

// ---------------
// | HTTP Routes |
// ---------------

use serde::{Deserialize, Serialize};

use crate::types::ApiHistoricalTask;

/// The route to fetch task history for a wallet
pub const TASK_HISTORY_ROUTE: &str = "/v0/wallet/:wallet_id/task-history";

// ------------------------------
// | Api Request Response Types |
// ------------------------------

/// The response type to a request for task history
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetTaskHistoryResponse {
    /// A list of historical tasks
    pub tasks: Vec<ApiHistoricalTask>,
    /// A token to use for pagination in subsequent requests
    pub pagination_token: Option<String>,
}
