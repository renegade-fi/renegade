//! API types for admin requests

use circuit_types::Amount;
use common::types::{
    wallet::{order_metadata::OrderMetadata, WalletIdentifier},
    Price,
};
use serde::{Deserialize, Serialize};

/// An order's metadata, augmented with the containing
/// wallet's ID, and optionally the fillable amount
/// of the order and the price used to calculate it
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminOrderMetadata {
    /// The order metadata
    pub order: OrderMetadata,
    /// The ID of the wallet containing the order
    pub wallet_id: WalletIdentifier,
    /// The fillable amount of the order, if calculated
    pub fillable: Option<Amount>,
    /// The price used to calculate the fillable amount
    pub price: Option<Price>,
}

/// A summary of the aggregate matchable amount for a given side of the market
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MidpointMatchableAmount {
    /// The matchable amount at the midpoint price, in units of the base token
    pub total_quantity: Amount,
    /// The matchable amount at the midpoint price, in USD
    pub total_quantity_usd: f64,
}

impl MidpointMatchableAmount {
    /// Constructor
    pub fn new(matchable_amount: Amount, price: Price) -> Self {
        let total_quantity_usd = matchable_amount as f64 * price;

        Self { total_quantity: matchable_amount, total_quantity_usd }
    }
}
