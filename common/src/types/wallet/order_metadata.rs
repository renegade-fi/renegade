//! Order metadata for a wallet's orders

use circuit_types::Amount;
use serde::{Deserialize, Serialize};

use super::OrderIdentifier;

/// The state of an order in the wallet
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OrderState {
    /// The order has been created, but validity proofs are not yet proven
    Created,
    /// The order is ready to match, and is being shopped around the network
    Matching,
    /// A match has been found and is being settled
    SettlingMatch,
    /// The order has been entirely filled
    Filled,
    /// The order was canceled before it could be filled
    Cancelled,
}

/// Metadata for an order in a wallet, possibly historical
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrderMetadata {
    /// The order ID
    pub id: OrderIdentifier,
    /// The order state
    pub state: OrderState,
    /// The amount that has been filled
    pub filled: Amount,
    /// The unix timestamp in milliseconds since the order was created
    pub created: u64,
}
