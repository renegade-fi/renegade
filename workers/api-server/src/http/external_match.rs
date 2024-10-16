//! API handlers for external matches
//!
//! External matches are those brokered by the darkpool between an "internal"
//! party (one with state committed into the protocol), and an external party,
//! one whose trade obligations are fulfilled directly through erc20 transfers;
//! and importantly do not commit state into the protocol
//!
//! Endpoints here allow permissioned solvers, searchers, etc to "ping the pool"
//! for consenting liquidity on a given token pair.

use std::time::Duration;

use async_trait::async_trait;
use common::types::wallet::Order;
use external_api::{
    bus_message::SystemBusMessage,
    http::external_match::{AtomicMatchApiBundle, ExternalMatchRequest, ExternalMatchResponse},
};
use hyper::HeaderMap;
use job_types::handshake_manager::{HandshakeManagerJob, HandshakeManagerQueue};
use state::State;
use system_bus::SystemBus;

use crate::{
    error::{bad_request, internal_error, no_content, ApiServerError},
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

/// The timeout waiting for an external match to be generated
const EXTERNAL_MATCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The error message returned when atomic matches are disabled
const ERR_ATOMIC_MATCHES_DISABLED: &str = "atomic matches are disabled";
/// The error message returned when the relayer fails to process an external
/// match request
const ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH: &str = "failed to process external match request";
/// The message returned when no atomic match is found
const NO_ATOMIC_MATCH_FOUND: &str = "no atomic match found";
/// The error message returned when the external matching engine times out
const ERR_EXTERNAL_MATCH_TIMEOUT: &str = "external match request timed out";

// -----------
// | Helpers |
// -----------

/// Await a response from the external matching engine
async fn await_external_match_response(
    response_topic: String,
    bus: &SystemBus<SystemBusMessage>,
) -> Result<Option<AtomicMatchApiBundle>, ApiServerError> {
    let mut rx = bus.subscribe(response_topic);
    let msg = tokio::time::timeout(EXTERNAL_MATCH_TIMEOUT, rx.next_message())
        .await
        .map_err(|_| internal_error(ERR_EXTERNAL_MATCH_TIMEOUT))?;

    match msg {
        SystemBusMessage::AtomicMatchFound { match_bundle } => Ok(Some(match_bundle)),
        SystemBusMessage::NoAtomicMatchFound => Ok(None),
        _ => Err(internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH)),
    }
}

// ------------------
// | Route Handlers |
// ------------------

/// The handler for the `POST /external-match/request` route
pub struct RequestExternalMatchHandler {
    /// The handshake manager's queue
    handshake_queue: HandshakeManagerQueue,
    /// A handle on the system bus
    bus: SystemBus<SystemBusMessage>,
    /// A handle on the relayer state
    state: State,
}

impl RequestExternalMatchHandler {
    /// Create a new handler
    pub fn new(
        handshake_queue: HandshakeManagerQueue,
        bus: SystemBus<SystemBusMessage>,
        state: State,
    ) -> Self {
        Self { handshake_queue, bus, state }
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
        // Check that atomic matches are enabled
        let enabled = self.state.get_atomic_matches_enabled().await?;
        if !enabled {
            return Err(bad_request(ERR_ATOMIC_MATCHES_DISABLED));
        }

        // Forward a request to the handshake manager for an external match
        let order: Order = req.external_order.into();
        let (job, response_topic) = HandshakeManagerJob::new_external_matching_job(order);
        self.handshake_queue
            .send(job)
            .map_err(|_| internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH))?;

        let match_bundle = await_external_match_response(response_topic, &self.bus)
            .await?
            .ok_or_else(|| no_content(NO_ATOMIC_MATCH_FOUND))?;
        Ok(ExternalMatchResponse { match_bundle })
    }
}
