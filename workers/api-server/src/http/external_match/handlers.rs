//! API handlers for external matches
//!
//! External matches are those brokered by the darkpool between an "internal"
//! party (one with state committed into the protocol), and an external party,
//! one whose trade obligations are fulfilled directly through erc20 transfers;
//! and importantly do not commit state into the protocol
//!
//! Endpoints here allow permissioned solvers, searchers, etc to "ping the pool"
//! for consenting liquidity on a given token pair.

use alloy::primitives::Address;
use async_trait::async_trait;
use circuit_types::{fees::FeeTake, r#match::ExternalMatchResult};
use common::types::{hmac::HmacKey, TimestampedPrice};
use constants::Scalar;
use external_api::http::external_match::{
    ApiExternalQuote, AssembleExternalMatchRequest, ExternalMatchRequest, ExternalMatchResponse,
    ExternalOrder, ExternalQuoteRequest, ExternalQuoteResponse, MalleableExternalMatchResponse,
    SignedExternalQuote,
};
use hyper::HeaderMap;
use renegade_crypto::fields::scalar_to_u128;
use state::State;
use util::{hex::bytes_to_hex_string, on_chain::get_external_match_fee};

use crate::{
    error::{bad_request, internal_error, ApiServerError},
    http::external_match::{get_native_asset_address, ExternalMatchProcessor},
    router::{QueryParams, TypedHandler, UrlParams},
};

// ------------------
// | Error Messages |
// ------------------

/// The error message returned when atomic matches are disabled
const ERR_ATOMIC_MATCHES_DISABLED: &str = "atomic matches are disabled";

// -----------
// | Helpers |
// -----------

/// Parse a receiver address from an optional string
fn parse_receiver_address(receiver: Option<String>) -> Result<Option<Address>, ApiServerError> {
    receiver.map(|r| r.parse::<Address>()).transpose().map_err(bad_request)
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
    /// The external match processor
    processor: ExternalMatchProcessor,
    /// A handle on the relayer state
    state: State,
}

impl AssembleExternalMatchHandler {
    /// Create a new handler
    pub fn new(processor: ExternalMatchProcessor, state: State) -> Self {
        Self { processor, state }
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
            self.processor.validate_order_update(&updated_order, &old_order)?;
            updated_order
        } else {
            old_order
        };

        // Validate the quote then execute it
        self.processor.validate_quote(&req.signed_quote)?;
        let receiver = parse_receiver_address(req.receiver_address)?;
        let price = TimestampedPrice::from(req.signed_quote.quote.price);
        let match_bundle = self
            .processor
            .assemble_external_match(
                req.do_gas_estimation,
                req.allow_shared,
                receiver,
                price,
                order,
            )
            .await?;
        Ok(ExternalMatchResponse { match_bundle })
    }
}

/// The handler for the `POST /external-match/assemble-malleable` route
pub struct AssembleMalleableExternalMatchHandler {
    /// The external match processor
    processor: ExternalMatchProcessor,
}

impl AssembleMalleableExternalMatchHandler {
    /// Create a new handler
    pub fn new(processor: ExternalMatchProcessor) -> Self {
        Self { processor }
    }
}

#[async_trait]
impl TypedHandler for AssembleMalleableExternalMatchHandler {
    type Request = AssembleExternalMatchRequest;
    type Response = MalleableExternalMatchResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        // Validate the order update if one is present
        let old_order = req.signed_quote.quote.order.clone();
        let order = if let Some(updated_order) = req.updated_order {
            self.processor.validate_order_update(&updated_order, &old_order)?;
            updated_order
        } else {
            old_order
        };

        // Validate the quote then execute it
        self.processor.validate_quote(&req.signed_quote)?;
        let receiver = parse_receiver_address(req.receiver_address)?;
        let price = TimestampedPrice::from(req.signed_quote.quote.price);
        let match_bundle = self
            .processor
            .assemble_malleable_external_match(
                req.do_gas_estimation,
                req.allow_shared,
                receiver,
                price,
                order,
            )
            .await?;

        Ok(MalleableExternalMatchResponse { match_bundle })
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
