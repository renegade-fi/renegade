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
use common::types::{token::Token, wallet::Order};
use external_api::{
    bus_message::SystemBusMessage,
    http::external_match::{
        AtomicMatchApiBundle, ExternalMatchRequest, ExternalMatchResponse, ExternalOrder,
    },
};
use hyper::HeaderMap;
use job_types::{
    handshake_manager::{HandshakeManagerJob, HandshakeManagerQueue},
    price_reporter::PriceReporterQueue,
};
use num_traits::Zero;
use state::State;
use system_bus::SystemBus;

use crate::{
    error::{bad_request, internal_error, no_content, ApiServerError},
    router::{QueryParams, TypedHandler, UrlParams},
};

use super::wallet::get_usdc_denominated_value;

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
/// The error message emitted when an external order specifies zero size
const ERR_EXTERNAL_ORDER_ZERO_SIZE: &str = "external order has zero size";
/// The error message emitted when an external order specifies both the quote
/// and base size
const ERR_EXTERNAL_ORDER_BOTH_SIZE: &str = "external order specifies both quote and base size";

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

/// Check the USDC denominated value of an external order and assert that it is
/// greater than the configured minimum size
async fn check_external_order_size(
    o: &Order,
    min_order_size: f64,
    price_queue: &PriceReporterQueue,
) -> Result<(), ApiServerError> {
    let usdc_value = get_usdc_denominated_value(&o.base_mint, o.amount, price_queue).await?;

    // If we cannot fetch a price, do not block the order
    if let Some(usdc_value) = usdc_value {
        if usdc_value < min_order_size {
            let msg = format!("order value too small, ${usdc_value} < ${min_order_size}");
            return Err(bad_request(msg));
        }
    }

    Ok(())
}

/// Convert an external order to an internal order
async fn external_order_to_internal_order(
    o: &ExternalOrder,
    price_queue: &PriceReporterQueue,
) -> Result<Order, ApiServerError> {
    // External order must specify non-zero size
    let quote_zero = o.quote_amount.is_zero();
    let base_zero = o.base_amount.is_zero();
    if quote_zero && base_zero {
        return Err(bad_request(ERR_EXTERNAL_ORDER_ZERO_SIZE));
    }

    // Only one of quote or base should specify the size
    if !quote_zero && !base_zero {
        return Err(bad_request(ERR_EXTERNAL_ORDER_BOTH_SIZE));
    }

    let base = Token::from_addr_biguint(&o.base_mint);
    let quote = Token::from_addr_biguint(&o.quote_mint);

    let ts_price =
        price_queue.peek_price(base.clone(), quote.clone()).await.map_err(internal_error)?;
    let decimal_corrected_price =
        ts_price.get_decimal_corrected_price(&base, &quote).map_err(internal_error)?;
    let order = o.to_order_with_price(decimal_corrected_price.as_fixed_point());
    Ok(order)
}

// ------------------
// | Route Handlers |
// ------------------

/// The handler for the `POST /external-match/request` route
pub struct RequestExternalMatchHandler {
    /// The minimum usdc denominated order size
    min_order_size: f64,
    /// The handshake manager's queue
    handshake_queue: HandshakeManagerQueue,
    /// A handle on the system bus
    bus: SystemBus<SystemBusMessage>,
    /// A handle on the relayer state
    state: State,
    /// The price reporter queue
    price_queue: PriceReporterQueue,
}

impl RequestExternalMatchHandler {
    /// Create a new handler
    pub fn new(
        min_order_size: f64,
        handshake_queue: HandshakeManagerQueue,
        bus: SystemBus<SystemBusMessage>,
        state: State,
        price_queue: PriceReporterQueue,
    ) -> Self {
        Self { min_order_size, handshake_queue, bus, state, price_queue }
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

        // Check that the external order is large enough
        let price_queue = &self.price_queue;
        let order = external_order_to_internal_order(&req.external_order, price_queue).await?;
        check_external_order_size(&order, self.min_order_size, price_queue).await?;

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
