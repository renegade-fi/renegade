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
use circuit_types::{
    fixed_point::FixedPoint,
    r#match::{ExternalMatchResult, FeeTake},
};
use common::types::{
    hmac::HmacKey,
    proof_bundles::{AtomicMatchSettleBundle, OrderValidityProofBundle},
    token::Token,
    wallet::Order,
    TimestampedPrice,
};
use constants::{
    Scalar, EXTERNAL_MATCH_RELAYER_FEE, NATIVE_ASSET_ADDRESS, NATIVE_ASSET_WRAPPER_TICKER,
};
use ethers::{
    middleware::Middleware,
    types::{transaction::eip2718::TypedTransaction, Address, U256},
};
use external_api::{
    bus_message::SystemBusMessage,
    http::external_match::{
        ApiExternalQuote, AssembleExternalMatchRequest, AtomicMatchApiBundle, ExternalMatchRequest,
        ExternalMatchResponse, ExternalOrder, ExternalQuoteRequest, ExternalQuoteResponse,
        SignedExternalQuote,
    },
};
use hyper::HeaderMap;
use job_types::{
    handshake_manager::{
        ExternalMatchingEngineOptions, HandshakeManagerJob, HandshakeManagerQueue,
    },
    price_reporter::PriceReporterQueue,
};
use num_bigint::BigUint;
use renegade_crypto::fields::scalar_to_u128;
use state::State;
use system_bus::SystemBus;
use tracing::warn;
use util::{
    arbitrum::get_external_match_fee,
    get_current_time_millis,
    hex::{biguint_from_hex_string, bytes_from_hex_string, bytes_to_hex_string},
};

use crate::{
    error::{bad_request, internal_error, no_content, ApiServerError},
    router::{QueryParams, TypedHandler, UrlParams},
};

use super::wallet::get_usdc_denominated_value;

/// The gas estimation to use if fetching a gas estimation fails
const DEFAULT_GAS_ESTIMATION: u64 = 4_000_000; // 4m
/// The timeout waiting for an external match to be generated
const EXTERNAL_MATCH_TIMEOUT: Duration = Duration::from_secs(30);
/// The maximum age of a quote before it is considered expired
const MAX_QUOTE_AGE: u64 = 10_000; // 10 seconds
/// The validity duration for a match bundle in the assemble flow
const ASSEMBLE_BUNDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// The validity duration for a match bundle in the direct match flow
const DIRECT_MATCH_BUNDLE_TIMEOUT: Duration = Duration::from_secs(0);

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
/// The error message emitted when a quote is expired
const ERR_QUOTE_EXPIRED: &str = "quote expired";
/// The error message emitted when a quote signature is invalid
const ERR_INVALID_QUOTE_SIGNATURE: &str = "invalid quote signature";
/// The error message emitted when an order update changes the pair
const ERR_PAIR_CHANGED: &str = "order update must not change the token pair";
/// The error message emitted when an order update changes the side
const ERR_SIDE_CHANGED: &str = "order update must not change the side";

// -----------
// | Helpers |
// -----------

/// Get the token representing a wrapper on the native asset
fn get_native_asset_wrapper_token() -> Token {
    Token::from_ticker(NATIVE_ASSET_WRAPPER_TICKER)
}

/// Get the native asset address as a `BigUint`
fn get_native_asset_address() -> BigUint {
    biguint_from_hex_string(NATIVE_ASSET_ADDRESS).unwrap()
}

/// Parse a receiver address from an optional string
fn parse_receiver_address(receiver: Option<String>) -> Result<Option<Address>, ApiServerError> {
    receiver.map(|r| r.parse::<Address>()).transpose().map_err(bad_request)
}

// ----------------------------
// | External Match Processor |
// ----------------------------

/// The `ExternalMatchProcessor` is responsible for processing external matches
/// originating from the api layer
///
/// It is responsible for fetching prices, interacting with the handshake
/// manager, gas estimation, etc
#[derive(Clone)]
pub struct ExternalMatchProcessor {
    /// The minimum usdc denominated order size
    min_order_size: f64,
    /// The handshake manager's queue
    handshake_queue: HandshakeManagerQueue,
    /// A handle on the Arbitrum RPC client
    arbitrum_client: ArbitrumClient,
    /// A handle on the system bus
    bus: SystemBus<SystemBusMessage>,
    /// The price reporter queue
    price_queue: PriceReporterQueue,
}

impl ExternalMatchProcessor {
    /// Create a new processor
    pub fn new(
        min_order_size: f64,
        handshake_queue: HandshakeManagerQueue,
        arbitrum_client: ArbitrumClient,
        bus: SystemBus<SystemBusMessage>,
        price_queue: PriceReporterQueue,
    ) -> Self {
        Self { min_order_size, handshake_queue, arbitrum_client, bus, price_queue }
    }

    /// Await the next bus message on a topic
    async fn await_bus_message(&self, topic: String) -> Result<SystemBusMessage, ApiServerError> {
        let mut rx = self.bus.subscribe(topic);
        tokio::time::timeout(EXTERNAL_MATCH_TIMEOUT, rx.next_message())
            .await
            .map_err(|_| internal_error(ERR_EXTERNAL_MATCH_TIMEOUT))
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

    // --- Order Validation & Conversion --- //

    /// Get an internal order from an external order given a price
    async fn external_order_to_internal_order_with_options(
        &self,
        mut o: ExternalOrder,
        mut options: ExternalMatchingEngineOptions,
    ) -> Result<(Order, ExternalMatchingEngineOptions), ApiServerError> {
        // Get the tokens being traded, swapping WETH for ETH if necessary
        let base = if o.trades_native_asset() {
            let native_wrapper = get_native_asset_wrapper_token();
            o.base_mint = biguint_from_hex_string(&native_wrapper.get_addr()).unwrap();
            native_wrapper
        } else {
            Token::from_addr_biguint(&o.base_mint)
        };
        let quote = Token::from_addr_biguint(&o.quote_mint);

        // Fetch a price for the pair
        let decimal_corrected_price = self
            .price_queue
            .peek_price(base.clone(), quote.clone())
            .await
            .and_then(|p| p.get_decimal_corrected_price(&base, &quote))
            .map(|p| p.as_fixed_point())
            .map_err(internal_error)?;

        // TODO: Currently we set the relayer fee to zero, remove this
        let relayer_fee = FixedPoint::from_f64_round_down(EXTERNAL_MATCH_RELAYER_FEE);
        let order = o.to_internal_order(decimal_corrected_price, relayer_fee);

        // Enforce an exact quote amount if specified
        if o.exact_quote_output != 0 {
            let quote_amount = o.get_quote_amount(decimal_corrected_price, relayer_fee);
            options = options.with_exact_quote_amount(quote_amount);
        }

        self.check_external_order_size(&order).await?;
        Ok((order, options))
    }

    /// Check the USDC denominated value of an external order and assert that it
    /// is greater than the configured minimum size
    async fn check_external_order_size(&self, o: &Order) -> Result<(), ApiServerError> {
        let usdc_value =
            get_usdc_denominated_value(&o.base_mint, o.amount, &self.price_queue).await?;

        // If we cannot fetch a price, do not block the order
        let min_size = self.min_order_size;
        if let Some(usdc_value) = usdc_value {
            if usdc_value < min_size {
                let msg = format!("order value too small, ${usdc_value} < ${min_size}");
                return Err(bad_request(msg));
            }
        }

        Ok(())
    }

    // --- Handshake Manager Interactions --- //

    /// Request a quote from the external matching engine
    async fn request_external_quote(
        &self,
        external_order: ExternalOrder,
    ) -> Result<ExternalMatchResult, ApiServerError> {
        let opt = ExternalMatchingEngineOptions::only_quote();
        let resp = self.request_handshake_manager(external_order, opt).await?;

        match resp {
            SystemBusMessage::NoAtomicMatchFound => Err(no_content(NO_ATOMIC_MATCH_FOUND)),
            SystemBusMessage::ExternalOrderQuote { quote } => Ok(quote),
            _ => Err(internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH)),
        }
    }

    /// Assemble an external match quote into a settlement bundle
    async fn assemble_external_match(
        &self,
        gas_estimation: bool,
        receiver: Option<Address>,
        price: TimestampedPrice,
        order: ExternalOrder,
    ) -> Result<AtomicMatchApiBundle, ApiServerError> {
        let opt = ExternalMatchingEngineOptions::new()
            .with_bundle_duration(ASSEMBLE_BUNDLE_TIMEOUT)
            .with_price(price);
        let resp = self.request_handshake_manager(order.clone(), opt).await?;

        match resp {
            SystemBusMessage::NoAtomicMatchFound => Err(no_content(NO_ATOMIC_MATCH_FOUND)),
            SystemBusMessage::AtomicMatchFound { match_bundle, validity_proofs } => {
                self.build_api_bundle(
                    gas_estimation,
                    receiver,
                    &order,
                    match_bundle,
                    validity_proofs,
                )
                .await
            },
            _ => Err(internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH)),
        }
    }

    /// Request an external match for a given order
    async fn request_match_bundle(
        &self,
        gas_estimation: bool,
        receiver: Option<Address>,
        external_order: ExternalOrder,
    ) -> Result<AtomicMatchApiBundle, ApiServerError> {
        let opt =
            ExternalMatchingEngineOptions::new().with_bundle_duration(DIRECT_MATCH_BUNDLE_TIMEOUT);
        let resp = self.request_handshake_manager(external_order.clone(), opt).await?;

        match resp {
            SystemBusMessage::NoAtomicMatchFound => Err(no_content(NO_ATOMIC_MATCH_FOUND)),
            SystemBusMessage::AtomicMatchFound { match_bundle, validity_proofs } => {
                self.build_api_bundle(
                    gas_estimation,
                    receiver,
                    &external_order,
                    match_bundle,
                    validity_proofs,
                )
                .await
            },
            _ => Err(internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH)),
        }
    }

    /// Request a quote from the external matching engine
    ///
    /// Returns the bus message that was sent by the handshake manager
    async fn request_handshake_manager(
        &self,
        order: ExternalOrder,
        options: ExternalMatchingEngineOptions,
    ) -> Result<SystemBusMessage, ApiServerError> {
        let (order, options) =
            self.external_order_to_internal_order_with_options(order, options).await?;
        self.check_external_order_size(&order).await?;

        let (job, response_topic) = HandshakeManagerJob::new_external_match_job(order, options);
        self.handshake_queue
            .send(job)
            .map_err(|_| internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH))?;

        self.await_bus_message(response_topic).await
    }

    /// Build an API bundle from an atomic match bundle and internal party
    /// validity proofs
    async fn build_api_bundle(
        &self,
        do_gas_estimation: bool,
        receiver: Option<Address>,
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
            .gen_atomic_match_settle_calldata(receiver, &validity_proofs, &match_bundle)
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

        Ok(AtomicMatchApiBundle::new(&match_bundle, settlement_tx))
    }
}

// ------------------
// | Route Handlers |
// ------------------

/// The handler for the `GET /external-match/quote` route
pub struct RequestExternalQuoteHandler {
    /// The admin key, used to sign quotes
    admin_key: HmacKey,
    /// The external match processor
    processor: ExternalMatchProcessor,
    /// A handle on the relayer state
    state: State,
}

impl RequestExternalQuoteHandler {
    /// Create a new handler
    pub fn new(admin_key: HmacKey, processor: ExternalMatchProcessor, state: State) -> Self {
        Self { admin_key, processor, state }
    }

    /// Sign an external quote
    fn sign_external_quote(
        &self,
        order: ExternalOrder,
        match_res: &ExternalMatchResult,
    ) -> Result<SignedExternalQuote, ApiServerError> {
        // Estimate the fees for the match
        let fees = self.estimate_fee_take(match_res);
        let quote = ApiExternalQuote::new(order, match_res, fees);
        let quote_bytes = serde_json::to_vec(&quote).map_err(internal_error)?;
        let signature = self.admin_key.compute_mac(&quote_bytes);
        let signature_hex = bytes_to_hex_string(&signature);

        Ok(SignedExternalQuote { quote, signature: signature_hex })
    }

    /// Estimate the fee take for a given match
    fn estimate_fee_take(&self, match_res: &ExternalMatchResult) -> FeeTake {
        let protocol_fee = get_external_match_fee(&match_res.base_mint);
        let (_, receive_amount) = match_res.external_party_receive();
        let receive_amount_scalar = Scalar::from(receive_amount);
        let protocol_fee = (protocol_fee * receive_amount_scalar).floor();

        FeeTake { relayer_fee: 0, protocol_fee: scalar_to_u128(&protocol_fee) }
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

        let order = req.external_order;
        order.validate().map_err(bad_request)?;
        let mut match_res = self.processor.request_external_quote(order.clone()).await?;

        if order.trades_native_asset() {
            match_res.base_mint = get_native_asset_address();
        }
        let signed_quote = self.sign_external_quote(order, &match_res)?;
        Ok(ExternalQuoteResponse { signed_quote })
    }
}

/// The handler for the `POST /external-match/assemble` route
pub struct AssembleExternalMatchHandler {
    /// The admin key, used to verify signatures
    admin_key: HmacKey,
    /// The external match processor
    processor: ExternalMatchProcessor,
    /// A handle on the relayer state
    state: State,
}

impl AssembleExternalMatchHandler {
    /// Create a new handler
    pub fn new(admin_key: HmacKey, processor: ExternalMatchProcessor, state: State) -> Self {
        Self { admin_key, processor, state }
    }

    /// Validate a quote
    fn validate_quote(&self, signed_quote: &SignedExternalQuote) -> Result<(), ApiServerError> {
        // Check that quote has not expired
        let current_time = get_current_time_millis();
        let quote = &signed_quote.quote;
        let quote_age = current_time.saturating_sub(quote.timestamp);
        if quote_age > MAX_QUOTE_AGE {
            return Err(bad_request(ERR_QUOTE_EXPIRED));
        }

        // Check the quote signature
        let quote_bytes = serde_json::to_vec(&quote).map_err(internal_error)?;
        let mac_bytes = bytes_from_hex_string(&signed_quote.signature).map_err(internal_error)?;
        if !self.admin_key.verify_mac(&quote_bytes, &mac_bytes) {
            return Err(bad_request(ERR_INVALID_QUOTE_SIGNATURE));
        }

        Ok(())
    }

    /// Validate an order update
    ///
    /// Amounts are allowed to change, as is `min_fill_size`, but the order side
    /// and pair is not
    fn validate_order_update(
        &self,
        new_order: &ExternalOrder,
        old_order: &ExternalOrder,
    ) -> Result<(), ApiServerError> {
        // Validate the new order
        new_order.validate().map_err(bad_request)?;

        // Check that the mints are the same
        let base_mint_changed = new_order.base_mint != old_order.base_mint;
        let quote_mint_changed = new_order.quote_mint != old_order.quote_mint;
        if base_mint_changed || quote_mint_changed {
            return Err(bad_request(ERR_PAIR_CHANGED));
        }

        // Check that the side is the same
        let side_changed = new_order.side != old_order.side;
        if side_changed {
            return Err(bad_request(ERR_SIDE_CHANGED));
        }

        Ok(())
    }
}

#[async_trait]
impl TypedHandler for AssembleExternalMatchHandler {
    type Request = AssembleExternalMatchRequest;
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

        // Validate the order update if one is present
        let old_order = req.signed_quote.quote.order.clone();
        let order = if let Some(updated_order) = req.updated_order {
            self.validate_order_update(&updated_order, &old_order)?;
            updated_order
        } else {
            old_order
        };

        // Validate the quote then execute it
        self.validate_quote(&req.signed_quote)?;
        let receiver = parse_receiver_address(req.receiver_address)?;
        let price = TimestampedPrice::from(req.signed_quote.quote.price);
        let match_bundle = self
            .processor
            .assemble_external_match(req.do_gas_estimation, receiver, price, order)
            .await?;
        Ok(ExternalMatchResponse { match_bundle })
    }
}

/// The handler for the `POST /external-match/request` route
pub struct RequestExternalMatchHandler {
    /// The external match processor
    processor: ExternalMatchProcessor,
    /// A handle on the relayer state
    state: State,
}

impl RequestExternalMatchHandler {
    /// Create a new handler
    pub fn new(processor: ExternalMatchProcessor, state: State) -> Self {
        Self { processor, state }
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

        // Validate the order then request a match bundle
        let order = req.external_order;
        order.validate().map_err(bad_request)?;

        let receiver = parse_receiver_address(req.receiver_address)?;
        let match_bundle =
            self.processor.request_match_bundle(req.do_gas_estimation, receiver, order).await?;
        Ok(ExternalMatchResponse { match_bundle })
    }
}
