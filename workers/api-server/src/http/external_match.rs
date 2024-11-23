//! API handlers for external matches
//!
//! External matches are those brokered by the darkpool between an "internal"
//! party (one with state committed into the protocol), and an external party,
//! one whose trade obligations are fulfilled directly through erc20 transfers;
//! and importantly do not commit state into the protocol
//!
//! Endpoints here allow permissioned solvers, searchers, etc to "ping the pool"
//! for consenting liquidity on a given token pair.

use std::{sync::Arc, time::Duration};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use circuit_types::r#match::ExternalMatchResult;
use common::types::{
    proof_bundles::{AtomicMatchSettleBundle, OrderValidityProofBundle},
    token::Token,
    wallet::Order,
};
use constants::{NATIVE_ASSET_ADDRESS, NATIVE_ASSET_WRAPPER_TICKER};
use ethers::{
    middleware::Middleware,
    types::{transaction::eip2718::TypedTransaction, U256},
};
use external_api::{
    bus_message::SystemBusMessage,
    http::external_match::{
        AtomicMatchApiBundle, ExternalMatchRequest, ExternalMatchResponse, ExternalOrder,
        ExternalQuoteRequest, ExternalQuoteResponse,
    },
};
use hyper::HeaderMap;
use job_types::{
    handshake_manager::{HandshakeManagerJob, HandshakeManagerQueue},
    price_reporter::PriceReporterQueue,
};
use num_bigint::BigUint;
use num_traits::Zero;
use state::State;
use system_bus::SystemBus;
use tracing::warn;
use util::hex::biguint_from_hex_string;

use crate::{
    error::{bad_request, internal_error, no_content, ApiServerError},
    router::{QueryParams, TypedHandler, UrlParams},
};

use super::wallet::get_usdc_denominated_value;

/// The gas estimation to use if fetching a gas estimation fails
const DEFAULT_GAS_ESTIMATION: u64 = 4_000_000; // 4m
/// The timeout waiting for an external match to be generated
const EXTERNAL_MATCH_TIMEOUT: Duration = Duration::from_secs(30);

// ------------------
// | Error Messages |
// ------------------

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
    mut o: ExternalOrder,
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

    let base = if o.trades_native_asset() {
        let native_wrapper = get_native_asset_wrapper_token();
        o.base_mint = biguint_from_hex_string(&native_wrapper.get_addr()).unwrap();
        native_wrapper
    } else {
        Token::from_addr_biguint(&o.base_mint)
    };
    let quote = Token::from_addr_biguint(&o.quote_mint);

    let ts_price =
        price_queue.peek_price(base.clone(), quote.clone()).await.map_err(internal_error)?;
    let decimal_corrected_price =
        ts_price.get_decimal_corrected_price(&base, &quote).map_err(internal_error)?;
    let order = o.to_order_with_price(decimal_corrected_price.as_fixed_point());
    Ok(order)
}

/// Get the token representing a wrapper on the native asset
fn get_native_asset_wrapper_token() -> Token {
    Token::from_ticker(NATIVE_ASSET_WRAPPER_TICKER)
}

/// Get the native asset address as a `BigUint`
fn get_native_asset_address() -> BigUint {
    biguint_from_hex_string(NATIVE_ASSET_ADDRESS).unwrap()
}

// ------------------
// | Route Handlers |
// ------------------

/// The handler for the `GET /external-match/quote` route
pub struct RequestExternalQuoteHandler {
    /// The minimum usdc denominated order size
    min_order_size: f64,
    /// The handshake manager's queue
    handshake_queue: HandshakeManagerQueue,
    /// The price reporter queue
    price_queue: PriceReporterQueue,
    /// A handle on the relayer state
    state: State,
    /// The system bus
    bus: SystemBus<SystemBusMessage>,
}

impl RequestExternalQuoteHandler {
    /// Create a new handler
    pub fn new(
        min_order_size: f64,
        handshake_queue: HandshakeManagerQueue,
        price_queue: PriceReporterQueue,
        state: State,
        bus: SystemBus<SystemBusMessage>,
    ) -> Self {
        Self { min_order_size, handshake_queue, price_queue, state, bus }
    }

    /// Await a quote response from the external matching engine
    async fn await_quote_response(
        &self,
        response_topic: String,
    ) -> Result<Option<ExternalMatchResult>, ApiServerError> {
        let mut rx = self.bus.subscribe(response_topic);
        let msg = tokio::time::timeout(EXTERNAL_MATCH_TIMEOUT, rx.next_message())
            .await
            .map_err(|_| internal_error(ERR_EXTERNAL_MATCH_TIMEOUT))?;

        match msg {
            SystemBusMessage::ExternalOrderQuote { quote } => Ok(Some(quote)),
            SystemBusMessage::NoAtomicMatchFound => Ok(None),
            _ => Err(internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH)),
        }
    }
}

#[async_trait]
impl TypedHandler for RequestExternalQuoteHandler {
    type Request = ExternalQuoteRequest;
    type Response = ExternalQuoteResponse;

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

        let order = external_order_to_internal_order(req.external_order, &self.price_queue).await?;
        check_external_order_size(&order, self.min_order_size, &self.price_queue).await?;

        let (job, response_topic) = HandshakeManagerJob::get_external_quote(order);
        self.handshake_queue
            .send(job)
            .map_err(|_| internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH))?;

        // Await a quote response from the external matching engine
        let quote = self
            .await_quote_response(response_topic)
            .await?
            .ok_or_else(|| no_content(NO_ATOMIC_MATCH_FOUND))?;
        Ok(ExternalQuoteResponse { match_result: quote.into() })
    }
}

/// The handler for the `POST /external-match/request` route
pub struct RequestExternalMatchHandler {
    /// The minimum usdc denominated order size
    min_order_size: f64,
    /// The handshake manager's queue
    handshake_queue: HandshakeManagerQueue,
    /// A handle on the Arbitrum RPC client
    arbitrum_client: ArbitrumClient,
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
        arbitrum_client: ArbitrumClient,
        bus: SystemBus<SystemBusMessage>,
        state: State,
        price_queue: PriceReporterQueue,
    ) -> Self {
        Self { min_order_size, handshake_queue, arbitrum_client, bus, state, price_queue }
    }

    /// Estimate the gas for a given external match transaction
    pub(super) async fn estimate_gas(
        &self,
        mut tx: TypedTransaction,
    ) -> Result<U256, ApiServerError> {
        // To estimate gas without reverts, we would need to approve the ERC20 transfers
        // due in the transaction before estimating. This is infeasible, so we mock the
        // sender as the _darkpool itself_, which will automatically have an approval
        // for itself. This can still fail if a transfer exceeds the darkpool's balance,
        // in which case we fall back to the default gas estimation below
        let darkpool_addr = self.arbitrum_client.get_darkpool_client().address();
        tx.set_from(darkpool_addr);

        let client = self.arbitrum_client.client();
        match client.estimate_gas(&tx, None /* block */).await {
            Ok(gas) => Ok(gas),
            Err(e) => {
                warn!("gas estimation failed for external match: {e}");
                Ok(DEFAULT_GAS_ESTIMATION.into())
            },
        }
    }

    /// Await a response from the external matching engine and build a
    /// settlement transaction from the response
    async fn await_external_match_response(
        &self,
        response_topic: String,
        do_gas_estimation: bool,
        order: &ExternalOrder,
    ) -> Result<Option<AtomicMatchApiBundle>, ApiServerError> {
        // Await a response from the external matching engine
        let mut rx = self.bus.subscribe(response_topic);
        let msg = tokio::time::timeout(EXTERNAL_MATCH_TIMEOUT, rx.next_message())
            .await
            .map_err(|_| internal_error(ERR_EXTERNAL_MATCH_TIMEOUT))?;
        let (match_bundle, validity_proofs) = match msg {
            SystemBusMessage::AtomicMatchFound { match_bundle, validity_proofs } => {
                (match_bundle, validity_proofs)
            },
            SystemBusMessage::NoAtomicMatchFound => return Ok(None),
            _ => return Err(internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH)),
        };

        // Build an API bundle
        let res =
            self.build_api_bundle(do_gas_estimation, order, match_bundle, validity_proofs).await?;
        Ok(Some(res))
    }

    /// Build an API bundle from an atomic match bundle and internal party
    /// validity proofs
    async fn build_api_bundle(
        &self,
        do_gas_estimation: bool,
        order: &ExternalOrder,
        mut match_bundle: AtomicMatchSettleBundle,
        validity_proofs: OrderValidityProofBundle,
    ) -> Result<AtomicMatchApiBundle, ApiServerError> {
        // If the order trades the native asset, replace WETH with ETH
        let is_native = order.trades_native_asset();
        let bundle = Arc::make_mut(&mut match_bundle.atomic_match_proof);
        if is_native {
            bundle.statement.match_result.base_mint = get_native_asset_address();
        }

        // Build a settlement transaction for the match
        let mut settlement_tx = self
            .arbitrum_client
            .gen_atomic_match_settle_calldata(&validity_proofs, &match_bundle)
            .map_err(internal_error)?;

        // If the order _sells_ the native asset, the value of the transaction should
        // match the base amount sold by the external party
        if is_native && order.side.is_sell() {
            let base_amount = match_bundle.atomic_match_proof.statement.match_result.base_amount;
            settlement_tx.set_value(base_amount);
        }

        // Estimate gas for the settlement tx if requested
        if do_gas_estimation {
            let gas = self.estimate_gas(settlement_tx.clone()).await?;
            settlement_tx.set_gas(gas);
        }

        let match_result = match_bundle.atomic_match_proof.statement.match_result.clone().into();
        Ok(AtomicMatchApiBundle { match_result, settlement_tx })
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
        let external_order = &req.external_order;
        let order = external_order_to_internal_order(external_order.clone(), price_queue).await?;
        check_external_order_size(&order, self.min_order_size, price_queue).await?;

        let (job, response_topic) = HandshakeManagerJob::get_external_match_bundle(order);
        self.handshake_queue
            .send(job)
            .map_err(|_| internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH))?;

        let match_bundle = self
            .await_external_match_response(response_topic, req.do_gas_estimation, external_order)
            .await?
            .ok_or_else(|| no_content(NO_ATOMIC_MATCH_FOUND))?;
        Ok(ExternalMatchResponse { match_bundle })
    }
}
