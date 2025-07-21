//! The external match processor

use std::{sync::Arc, time::Duration};

use alloy::{
    primitives::{Address, U256},
    rpc::types::TransactionRequest,
};
use circuit_types::{fixed_point::FixedPoint, r#match::ExternalMatchResult};
use common::types::{
    MatchingPoolName,
    hmac::HmacKey,
    price::TimestampedPrice,
    proof_bundles::{
        AtomicMatchSettleBundle, MalleableAtomicMatchSettleBundle, OrderValidityProofBundle,
    },
    token::Token,
    wallet::Order,
};
use constants::{NATIVE_ASSET_ADDRESS, NATIVE_ASSET_WRAPPER_TICKER};
use darkpool_client::DarkpoolClient;
use external_api::{
    bus_message::SystemBusMessage,
    http::external_match::{
        AtomicMatchApiBundle, ExternalOrder, MalleableAtomicMatchApiBundle, SignedExternalQuote,
    },
};
use job_types::{
    handshake_manager::{
        ExternalMatchingEngineOptions, HandshakeManagerJob, HandshakeManagerQueue,
    },
    price_reporter::PriceReporterQueue,
};
use num_bigint::BigUint;
use system_bus::SystemBus;
use util::{
    get_current_time_millis,
    hex::{biguint_from_hex_string, bytes_from_hex_string},
};

use crate::{
    error::{ApiServerError, bad_request, internal_error, no_content},
    http::wallet::{ERR_FAILED_TO_FETCH_PRICE, get_usdc_denominated_value},
};

// -------------
// | Constants |
// -------------

/// The gas estimation to use if fetching a gas estimation fails
const DEFAULT_GAS_ESTIMATION: u64 = 4_000_000; // 4m
/// The timeout waiting for an external match to be generated
const EXTERNAL_MATCH_TIMEOUT: Duration = Duration::from_secs(30);
/// The maximum age of a quote before it is considered expired
const MAX_QUOTE_AGE: u64 = 10_000; // 10 seconds
/// The validity duration for a match bundle in the assemble flow
/// TODO(@joeykraut): Use a non-zero timeout
const ASSEMBLE_BUNDLE_TIMEOUT: Duration = Duration::from_secs(0);
/// The validity duration for a match bundle in the direct match flow
const DIRECT_MATCH_BUNDLE_TIMEOUT: Duration = Duration::from_secs(0);

// ------------------
// | Error Messages |
// ------------------

/// The error message returned when the quote token is not USDC
const ERR_QUOTE_TOKEN_NOT_USDC: &str = "quote token must be USDC";
/// The error message returned when the pair is not supported
const ERR_UNSUPPORTED_PAIR: &str = "unsupported pair";

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
pub(crate) fn get_native_asset_address() -> BigUint {
    biguint_from_hex_string(NATIVE_ASSET_ADDRESS).unwrap()
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
    /// The admin key, used to sign and validate quotes
    admin_key: HmacKey,
    /// The handshake manager's queue
    handshake_queue: HandshakeManagerQueue,
    /// A handle on the darkpool RPC client
    darkpool_client: DarkpoolClient,
    /// A handle on the system bus
    bus: SystemBus<SystemBusMessage>,
    /// The price reporter queue
    price_queue: PriceReporterQueue,
}

impl ExternalMatchProcessor {
    /// Create a new processor
    pub fn new(
        min_order_size: f64,
        admin_key: HmacKey,
        handshake_queue: HandshakeManagerQueue,
        darkpool_client: DarkpoolClient,
        bus: SystemBus<SystemBusMessage>,
        price_queue: PriceReporterQueue,
    ) -> Self {
        Self { min_order_size, admin_key, handshake_queue, darkpool_client, bus, price_queue }
    }

    /// Await the next bus message on a topic
    async fn await_bus_message(&self, topic: String) -> Result<SystemBusMessage, ApiServerError> {
        let mut rx = self.bus.subscribe(topic);
        tokio::time::timeout(EXTERNAL_MATCH_TIMEOUT, rx.next_message())
            .await
            .map_err(|_| internal_error(ERR_EXTERNAL_MATCH_TIMEOUT))
    }

    // -------------
    // | Interface |
    // -------------

    /// Request a quote from the external matching engine
    pub(crate) async fn request_external_quote(
        &self,
        external_order: ExternalOrder,
        matching_pool: Option<MatchingPoolName>,
    ) -> Result<ExternalMatchResult, ApiServerError> {
        let opt = ExternalMatchingEngineOptions::only_quote().with_matching_pool(matching_pool);
        let resp = self.request_handshake_manager(external_order, opt).await?;

        match resp {
            SystemBusMessage::NoAtomicMatchFound => Err(no_content(NO_ATOMIC_MATCH_FOUND)),
            SystemBusMessage::ExternalOrderQuote { quote } => Ok(quote),
            _ => Err(internal_error(ERR_FAILED_TO_PROCESS_EXTERNAL_MATCH)),
        }
    }

    /// Assemble an external match quote into a settlement bundle
    pub(crate) async fn assemble_external_match(
        &self,
        gas_estimation: bool,
        allow_shared: bool,
        receiver: Option<Address>,
        price: TimestampedPrice,
        matching_pool: Option<MatchingPoolName>,
        order: ExternalOrder,
    ) -> Result<AtomicMatchApiBundle, ApiServerError> {
        let opt = ExternalMatchingEngineOptions::new()
            .with_bundle_duration(ASSEMBLE_BUNDLE_TIMEOUT)
            .with_allow_shared(allow_shared)
            .with_price(price)
            .with_matching_pool(matching_pool);
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

    /// Assemble a malleable external match quote into a settlement bundle
    pub(crate) async fn assemble_malleable_external_match(
        &self,
        gas_estimation: bool,
        allow_shared: bool,
        receiver: Option<Address>,
        price: TimestampedPrice,
        matching_pool: Option<MatchingPoolName>,
        order: ExternalOrder,
    ) -> Result<MalleableAtomicMatchApiBundle, ApiServerError> {
        let opt = ExternalMatchingEngineOptions::new()
            .with_bundle_duration(ASSEMBLE_BUNDLE_TIMEOUT)
            .with_allow_shared(allow_shared)
            .with_bounded_match(true)
            .with_price(price)
            .with_matching_pool(matching_pool);
        let resp = self.request_handshake_manager(order.clone(), opt).await?;

        match resp {
            SystemBusMessage::NoAtomicMatchFound => Err(no_content(NO_ATOMIC_MATCH_FOUND)),
            SystemBusMessage::MalleableAtomicMatchFound { match_bundle, validity_proofs } => {
                self.build_malleable_api_bundle(
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
    pub(crate) async fn request_match_bundle(
        &self,
        gas_estimation: bool,
        receiver: Option<Address>,
        matching_pool: Option<MatchingPoolName>,
        external_order: ExternalOrder,
    ) -> Result<AtomicMatchApiBundle, ApiServerError> {
        let opt = ExternalMatchingEngineOptions::new()
            .with_allow_shared(true)
            .with_bundle_duration(DIRECT_MATCH_BUNDLE_TIMEOUT)
            .with_matching_pool(matching_pool);
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

    /// Estimate the gas for a given external match transaction
    ///
    /// TODO: Properly implement gas estimation for external matches
    #[allow(clippy::unused_async)]
    pub(super) async fn estimate_gas(
        &self,
        _tx: TransactionRequest,
    ) -> Result<u64, ApiServerError> {
        Ok(DEFAULT_GAS_ESTIMATION)
    }

    // ---------------------------------
    // | Order Validation & Conversion |
    // ---------------------------------

    /// Validate a quote
    pub(crate) fn validate_quote(
        &self,
        signed_quote: &SignedExternalQuote,
    ) -> Result<(), ApiServerError> {
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
    pub(crate) fn validate_order_update(
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

    /// Get an internal order from an external order given a price
    async fn external_order_to_internal_order_with_options(
        &self,
        mut o: ExternalOrder,
        mut options: ExternalMatchingEngineOptions,
    ) -> Result<(Order, ExternalMatchingEngineOptions), ApiServerError> {
        // Validate the pair
        self.check_supported_pair(&o)?;
        let (base, quote) = self.setup_order_tokens(&mut o)?;
        let price = self.get_external_match_price(base, quote).await?;

        let relayer_fee = options.relayer_fee_rate;
        let order = o.to_internal_order(price, relayer_fee);

        // Enforce an exact quote amount if specified
        if self.requires_exact_quote_amount(&o, price) {
            let quote_amount = o.get_quote_amount(price, relayer_fee);
            options = options.with_exact_quote_amount(quote_amount);
        }

        // If the order is quote denominated and a min fill size is specified, we should
        // require the matching engine match at least this amount
        let min_fill_quote = o.get_min_fill_quote();
        options = options.with_min_quote_amount(min_fill_quote);

        // Check that the order size is at least the min fill size
        self.check_external_order_size(&order).await?;
        Ok((order, options))
    }

    /// Check that the pair on an external order is supported
    fn check_supported_pair(&self, o: &ExternalOrder) -> Result<(), ApiServerError> {
        let base = Token::from_addr_biguint(&o.base_mint);
        let quote = Token::from_addr_biguint(&o.quote_mint);

        // Currently, we only support USDC quoted pairs
        let usdc = Token::usdc();
        if quote != usdc {
            return Err(bad_request(ERR_QUOTE_TOKEN_NOT_USDC));
        }

        // The base token cannot be another stablecoin
        if base == Token::usdt() {
            return Err(bad_request(ERR_UNSUPPORTED_PAIR));
        }

        // Check that the base token is in the token configuration -- i.e. if it is
        // named or the native asset
        if !(base.is_named() || base.is_native_asset()) {
            return Err(bad_request(ERR_UNSUPPORTED_PAIR));
        }

        Ok(())
    }

    /// Set the tokens for an external order, converting WETH to ETH if
    /// necessary
    ///
    /// Returns the base and quote tokens
    fn setup_order_tokens(&self, o: &mut ExternalOrder) -> Result<(Token, Token), ApiServerError> {
        // Get the tokens being traded, swapping WETH for ETH if necessary
        let quote = Token::from_addr_biguint(&o.quote_mint);
        let base = if o.trades_native_asset() {
            let native_wrapper = get_native_asset_wrapper_token();
            o.base_mint = biguint_from_hex_string(&native_wrapper.get_addr()).unwrap();
            native_wrapper
        } else {
            Token::from_addr_biguint(&o.base_mint)
        };

        Ok((base, quote))
    }

    /// Determine whether an external order requires an exact quote amount
    ///
    /// Some orders may require exact quote amounts even when the order
    /// originally did not specify one.
    ///
    /// Specifically, suppose an order is sent to the API with `quote_amount`
    /// set and `min_fill_size` set to a non-zero value. The valid matched quote
    /// amounts are then all values in `[min_fill_size, quote_amount]`. However,
    /// if `quote_amount - min_fill_size < price` it may be the case that no
    /// value in the range is representable with a whole number base amount.
    ///
    /// For example, suppose `min_fill_size = 3`, `quote_amount = 4`, and `price
    /// = 5`. Trading one base token gives 5 quote tokens, which outside the
    /// range, and trading 0 base tokens gives 0 quote tokens, which is also
    /// invalid.
    ///
    /// In this case, we use the `exact_quote_output` feature to select a quote
    /// amount. The matching engine will fuzz the price to find a valid match in
    /// this range.
    pub fn requires_exact_quote_amount(&self, order: &ExternalOrder, price: FixedPoint) -> bool {
        if !order.is_quote_denominated() {
            return false;
        } else if order.is_exact_output_configured() {
            return true;
        }

        // Compute the minimum and maximum base amounts implied by the order
        let min_fill_size = order.get_min_fill_quote();
        let relayer_fee = FixedPoint::zero();
        let quote_amount = order.get_quote_amount(price, relayer_fee);
        let min_base = price.floor_div_int(min_fill_size);
        let max_base = price.floor_div_int(quote_amount);

        // If the min and max base amounts are the same, the situation described in the
        // doc comment applies, so we choose the largest quote amount allowable
        if min_base >= max_base {
            return true;
        }

        false
    }

    // ----------------------------------
    // | Handshake Manager Interactions |
    // ----------------------------------

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
            .darkpool_client
            .gen_atomic_match_settle_calldata(receiver, &validity_proofs, &match_bundle)
            .map_err(internal_error)?;

        // If the order _sells_ the native asset, the value of the transaction should
        // match the base amount sold by the external party
        if is_native && order.side.is_sell() {
            let base_amount = match_bundle.atomic_match_proof.statement.match_result.base_amount;
            settlement_tx.value.replace(U256::from(base_amount));
        }

        // Estimate gas for the settlement tx if requested
        if do_gas_estimation {
            let gas = self.estimate_gas(settlement_tx.clone()).await?;
            settlement_tx = settlement_tx.gas_limit(gas);
        }

        Ok(AtomicMatchApiBundle::new(&match_bundle, settlement_tx))
    }

    /// Build a malleable API bundle from a malleable match bundle and internal
    /// party validity proofs
    async fn build_malleable_api_bundle(
        &self,
        do_gas_estimation: bool,
        receiver: Option<Address>,
        order: &ExternalOrder,
        mut match_bundle: MalleableAtomicMatchSettleBundle,
        validity_proofs: OrderValidityProofBundle,
    ) -> Result<MalleableAtomicMatchApiBundle, ApiServerError> {
        // If the order trades the native asset, replace WETH with ETH
        let is_native = order.trades_native_asset();
        let bundle = Arc::make_mut(&mut match_bundle.atomic_match_proof);
        if is_native {
            bundle.statement.bounded_match_result.base_mint = get_native_asset_address();
        }

        // Build a settlement transaction for the match
        let mut settlement_tx = self
            .darkpool_client
            .gen_malleable_atomic_match_settle_calldata(receiver, &validity_proofs, &match_bundle)
            .map_err(internal_error)?;

        // Estimate gas for the settlement tx if requested
        if do_gas_estimation {
            let gas = self.estimate_gas(settlement_tx.clone()).await?;
            settlement_tx = settlement_tx.gas_limit(gas);
        }

        Ok(MalleableAtomicMatchApiBundle::new(&match_bundle, settlement_tx))
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get the external match compatible price for a given token pair
    ///
    /// Handles decimal correction for the pair
    async fn get_external_match_price(
        &self,
        base: Token,
        quote: Token,
    ) -> Result<FixedPoint, ApiServerError> {
        self.price_queue
            .peek_price(base.clone(), quote.clone())
            .await
            .and_then(|p| p.get_decimal_corrected_price(&base, &quote))
            .map(|p| p.as_fixed_point())
            .map_err(|_| internal_error(ERR_FAILED_TO_FETCH_PRICE))
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
}
