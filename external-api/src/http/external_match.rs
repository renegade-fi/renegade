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
    fixed_point::FixedPoint, max_price, order::OrderSide, r#match::ExternalMatchResult, Amount,
};
use common::types::wallet::Order;
use ethers::types::transaction::eip2718::TypedTransaction;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use util::hex::biguint_to_hex_string;

use crate::{deserialize_biguint_from_hex_string, serialize_biguint_to_hex_addr};

// ---------------
// | HTTP Routes |
// ---------------

/// The route for requesting an atomic match
pub const REQUEST_EXTERNAL_MATCH_ROUTE: &str = "/v0/matching-engine/request-external-match";

// -------------------------------
// | HTTP Requests and Responses |
// -------------------------------

/// The request type for requesting an external match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalMatchRequest {
    /// The external order
    pub external_order: ExternalOrder,
}

/// The response type for requesting an external match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalMatchResponse {
    /// The match bundle
    pub match_bundle: AtomicMatchApiBundle,
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
    /// The amount of the order
    pub amount: Amount,
    /// The minimum fill size for the order
    #[serde(default)]
    pub min_fill_size: Amount,
}

impl From<ExternalOrder> for Order {
    fn from(order: ExternalOrder) -> Self {
        let worst_case_price =
            if order.side == OrderSide::Buy { max_price() } else { FixedPoint::from_integer(0) };

        Order {
            quote_mint: order.quote_mint,
            base_mint: order.base_mint,
            side: order.side,
            amount: order.amount,
            min_fill_size: order.min_fill_size,
            worst_case_price,
            allow_external_matches: true,
        }
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
