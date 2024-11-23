//! API types for external matches
//!
//! External matches are those brokered by the darkpool between an "internal"
//! party (one with state committed into the protocol), and an external party,
//! one whose trade obligations are fulfilled directly through erc20 transfers;
//! and importantly do not commit state into the protocol
//!
//! Endpoints here allow permissioned solvers, searchers, etc to "ping the pool"
//! for consenting liquidity on a given token pair.

use circuit_types::{
    fixed_point::FixedPoint, order::OrderSide, r#match::ExternalMatchResult, Amount,
};
use common::types::wallet::Order;
use constants::NATIVE_ASSET_ADDRESS;
use ethers::types::transaction::eip2718::TypedTransaction;
use num_bigint::BigUint;
use renegade_crypto::fields::scalar_to_u128;
use serde::{Deserialize, Serialize};
use util::{
    get_current_time_millis,
    hex::{biguint_from_hex_string, biguint_to_hex_string},
};

use crate::{deserialize_biguint_from_hex_string, serialize_biguint_to_hex_addr};

// ---------------
// | HTTP Routes |
// ---------------

/// The route for requesting a quote on an external match
pub const REQUEST_EXTERNAL_QUOTE_ROUTE: &str = "/v0/matching-engine/quote";
/// The route for requesting an atomic match
pub const REQUEST_EXTERNAL_MATCH_ROUTE: &str = "/v0/matching-engine/request-external-match";

// -------------------------------
// | HTTP Requests and Responses |
// -------------------------------

/// The request type for requesting an external match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalMatchRequest {
    /// Whether or not to include gas estimation in the response
    #[serde(default)]
    pub do_gas_estimation: bool,
    /// The external order
    pub external_order: ExternalOrder,
}

/// The response type for requesting an external match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalMatchResponse {
    /// The match bundle
    pub match_bundle: AtomicMatchApiBundle,
}

/// The request type for a quote on an external order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalQuoteRequest {
    /// The external order
    pub external_order: ExternalOrder,
}

/// The response type for a quote on an external order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalQuoteResponse {
    /// The signed quote
    pub signed_quote: SignedExternalQuote,
}

// ------------------
// | Api Data Types |
// ------------------

/// An external order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalOrder {
    /// The mint (erc20 address) of the quote token
    #[serde(
        serialize_with = "serialize_biguint_to_hex_addr",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub quote_mint: BigUint,
    /// The mint (erc20 address) of the base token
    #[serde(
        serialize_with = "serialize_biguint_to_hex_addr",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub base_mint: BigUint,
    /// The side of the market this order is on
    pub side: OrderSide,
    /// The base amount of the order
    #[serde(default, alias = "amount")]
    pub base_amount: Amount,
    /// The quote amount of the order
    #[serde(default)]
    pub quote_amount: Amount,
    /// The minimum fill size for the order
    #[serde(default)]
    pub min_fill_size: Amount,
}

impl ExternalOrder {
    /// Returns whether the order is for the chain-native asset
    pub fn trades_native_asset(&self) -> bool {
        let native_mint = biguint_from_hex_string(NATIVE_ASSET_ADDRESS).unwrap();
        self.base_mint == native_mint
    }

    /// Convert the external order to the standard `Order` type used throughout
    /// the relayer
    ///
    /// We need the price here to convert a quote denominated order into a base
    /// denominated order
    pub fn to_order_with_price(&self, price: FixedPoint) -> Order {
        let base_amount = self.get_base_amount(price);
        Order {
            quote_mint: self.quote_mint.clone(),
            base_mint: self.base_mint.clone(),
            side: self.side,
            amount: base_amount,
            min_fill_size: self.min_fill_size,
            worst_case_price: price,
            allow_external_matches: true,
        }
    }

    /// Get the base amount of the order implied by the external order
    ///
    /// The price here is expected to be decimal corrected; i.e. multiplied by
    /// the decimal diff for the two tokens
    fn get_base_amount(&self, price: FixedPoint) -> Amount {
        if self.base_amount != 0 {
            return self.base_amount;
        }

        let implied_base_amount = FixedPoint::floor_div_int(self.quote_amount, price);
        scalar_to_u128(&implied_base_amount)
    }
}

/// An atomic match settlement bundle, sent to the client so that they may
/// settle the match on-chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicMatchApiBundle {
    /// The match result
    pub match_result: ApiExternalMatchResult,
    /// The transaction which settles the match on-chain
    pub settlement_tx: TypedTransaction,
}

/// An API server external match result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiExternalMatchResult {
    /// The mint of the quote token in the matched asset pair
    pub quote_mint: String,
    /// The mint of the base token in the matched asset pair
    pub base_mint: String,
    /// The amount of the quote token exchanged by the match
    pub quote_amount: Amount,
    /// The amount of the base token exchanged by the match
    pub base_amount: Amount,
    /// The direction of the match
    pub direction: OrderSide,
}

impl From<ExternalMatchResult> for ApiExternalMatchResult {
    fn from(result: ExternalMatchResult) -> Self {
        let quote_mint = biguint_to_hex_string(&result.quote_mint);
        let base_mint = biguint_to_hex_string(&result.base_mint);
        // Convert the match direction to the side of the external party
        let direction = if result.direction { OrderSide::Buy } else { OrderSide::Sell };

        Self {
            quote_mint,
            base_mint,
            quote_amount: result.quote_amount,
            base_amount: result.base_amount,
            direction,
        }
    }
}

/// A signed quote for an external order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedExternalQuote {
    /// The quote
    pub quote: ApiExternalQuote,
    /// The signature
    pub signature: String,
}

/// A quote for an external order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiExternalQuote {
    /// The mint of the quote token in the matched asset pair
    pub quote_mint: String,
    /// The mint of the base token in the matched asset pair
    pub base_mint: String,
    /// The amount of the quote token exchanged by the match
    pub quote_amount: Amount,
    /// The amount of the base token exchanged by the match
    pub base_amount: Amount,
    /// The direction of the match
    pub direction: OrderSide,
    /// The price of the match
    pub price: f64,
    /// The timestamp of the quote
    pub timestamp: u64,
}

impl From<ExternalMatchResult> for ApiExternalQuote {
    fn from(result: ExternalMatchResult) -> Self {
        let quote_mint = biguint_to_hex_string(&result.quote_mint);
        let base_mint = biguint_to_hex_string(&result.base_mint);
        let direction = if result.direction { OrderSide::Buy } else { OrderSide::Sell };

        // Calculate implied price as quote_amount / base_amount
        let base_amt_f64 = result.base_amount as f64;
        let quote_amt_f64 = result.quote_amount as f64;
        let price = quote_amt_f64 / base_amt_f64;
        let timestamp = get_current_time_millis();

        Self {
            quote_mint,
            base_mint,
            quote_amount: result.quote_amount,
            base_amount: result.base_amount,
            direction,
            price,
            timestamp,
        }
    }
}
