//! Order metadata for a wallet's orders

use circuit_types::{order::Order, Amount};
use serde::{Deserialize, Serialize};
use util::get_current_time_millis;

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

impl OrderState {
    /// Whether the order state is terminal, i.e. it is either filled or
    /// cancelled
    pub fn is_terminal(self) -> bool {
        self == OrderState::Filled || self == OrderState::Cancelled
    }
}

/// Metadata for an order in a wallet, possibly historical
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderMetadata {
    /// The order ID
    pub id: OrderIdentifier,
    /// The data of the order
    pub data: Order,
    /// The order state
    pub state: OrderState,
    /// The amount that has been filled
    pub filled: Amount,
    /// The unix timestamp in milliseconds since the order was created
    pub created: u64,
}

impl OrderMetadata {
    /// Create a new order metadata instance, defaults to `Created` state
    pub fn new(id: OrderIdentifier, order: Order) -> Self {
        let created = get_current_time_millis();
        Self { id, data: order, state: OrderState::Created, filled: 0, created }
    }
}
