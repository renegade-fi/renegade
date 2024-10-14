//! API handlers for external matches
//!
//! External matches are those brokered by the darkpool between an "internal"
//! party (one with state committed into the protocol), and an external party,
//! one whose trade obligations are fulfilled directly through erc20 transfers;
//! and importantly do not commit state into the protocol
//!
//! Endpoints here allow permissioned solvers, searchers, etc to "ping the pool"
//! for consenting liquidity on a given token pair.

// ------------------
// | Error Messages |
// ------------------

// ------------------
// | Route Handlers |
// ------------------

use async_trait::async_trait;
use external_api::http::external_match::{ExternalMatchRequest, ExternalMatchResponse};
use hyper::HeaderMap;
use job_types::handshake_manager::HandshakeManagerQueue;
use state::State;

use crate::{
    error::ApiServerError,
    router::{QueryParams, TypedHandler, UrlParams},
};

/// The handler for the `POST /external-match/request` route
pub struct RequestExternalMatchHandler {
    /// The relayer-global state
    state: State,
    /// The handshake manager's queue
    handshake_queue: HandshakeManagerQueue,
}

impl RequestExternalMatchHandler {
    /// Create a new handler
    pub fn new(state: State, handshake_queue: HandshakeManagerQueue) -> Self {
        Self { state, handshake_queue }
    }
}

#[async_trait]
impl TypedHandler for RequestExternalMatchHandler {
    type Request = ExternalMatchRequest;
    type Response = ExternalMatchResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        Ok(ExternalMatchResponse {})
    }
}
