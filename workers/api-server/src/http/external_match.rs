//! API handlers for external matches
//!
//! External matches are those brokered by the darkpool between an "internal"
//! party (one with state committed into the protocol), and an external party,
//! one whose trade obligations are fulfilled directly through erc20 transfers;
//! and importantly do not commit state into the protocol
//!
//! Endpoints here allow permissioned solvers, searchers, etc to "ping the pool"
//! for consenting liquidity on a given token pair.

use async_trait::async_trait;
use common::types::wallet::Order;
use external_api::http::external_match::{ExternalMatchRequest, ExternalMatchResponse};
use hyper::HeaderMap;
use job_types::handshake_manager::{HandshakeManagerJob, HandshakeManagerQueue};

use crate::{
    error::{internal_error, ApiServerError},
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

/// The error message returned when the relayer fails to process an external
/// match request
const ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH: &str = "failed to process external match request";

// ------------------
// | Route Handlers |
// ------------------

/// The handler for the `POST /external-match/request` route
pub struct RequestExternalMatchHandler {
    /// The handshake manager's queue
    handshake_queue: HandshakeManagerQueue,
}

impl RequestExternalMatchHandler {
    /// Create a new handler
    pub fn new(handshake_queue: HandshakeManagerQueue) -> Self {
        Self { handshake_queue }
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
        let order: Order = req.external_order.into();
        let (job, rx) = HandshakeManagerJob::new_external_matching_job(order);
        self.handshake_queue
            .send(job)
            .map_err(|_| internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH))?;
        let _ = rx.await.map_err(|_| internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH))?;
        Ok(ExternalMatchResponse {})
    }
}
