//! Request/response types for the admin api

// ---------------
// | HTTP Routes |
// ---------------

use serde::{Deserialize, Serialize};

/// Check whether the target node is a raft leader
pub const IS_LEADER_ROUTE: &str = "/v0/admin/is-leader";

/// The response to an "is leader" request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsLeaderResponse {
    /// Whether the target node is a raft leader
    pub leader: bool,
}
