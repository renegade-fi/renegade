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
        }
    }
}

/// An atomic match settlement bundle, sent to the client so that they may
/// settle the match on-chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicMatchApiBundle {
    /// The match result
    pub match_result: ExternalMatchResult,
    /// The transaction which settles the match on-chain
    pub settlement_tx: TypedTransaction,
}
