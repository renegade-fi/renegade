//! API types for admin requests

use circuit_types::Amount;
use common::types::{
    wallet::{order_metadata::OrderMetadata, OrderIdentifier, WalletIdentifier},
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

/// An opaque message type for the admin wallet updates
/// websocket route, indicating wallet updates without
/// leaking unnecessary information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AdminWalletUpdate {
    /// Any update to a wallet
    WalletUpdate {
        /// The ID of the wallet that was updated
        wallet_id: WalletIdentifier,
    },
    /// An order placement
    OrderPlacement {
        /// The ID of the wallet containing the order
        wallet_id: WalletIdentifier,
        /// The ID of the order that was placed
        order_id: OrderIdentifier,
    },
    /// An order cancellation
    OrderCancellation {
        /// The ID of the wallet containing the order
        wallet_id: WalletIdentifier,
        /// The ID of the order that was cancelled
        order_id: OrderIdentifier,
    },
}
