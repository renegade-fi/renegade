//! Order metadata for a wallet's orders

use circuit_types::{fixed_point::FixedPoint, order::Order, Amount};
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OrderMetadata {
    /// The order ID
    pub id: OrderIdentifier,
    /// The data of the order
    pub data: Order,
    /// The order state
    pub state: OrderState,
    /// The amount that has been filled
    pub fills: Vec<PartialOrderFill>,
    /// The unix timestamp in milliseconds since the order was created
    pub created: u64,
}

impl OrderMetadata {
    /// Create a new order metadata instance, defaults to `Created` state
    pub fn new(id: OrderIdentifier, order: Order) -> Self {
        let created = get_current_time_millis();
        Self { id, data: order, state: OrderState::Created, fills: vec![], created }
    }

    /// The total amount filled
    pub fn total_filled(&self) -> Amount {
        self.fills.iter().map(|f| f.amount).sum()
    }

    /// Add a fill to the order metadata
    pub fn record_partial_fill(&mut self, amount: Amount, price: FixedPoint) {
        let fill = PartialOrderFill::new(amount, price);
        self.fills.push(fill);
    }
}

/// A partial fill of an order, recording the information parameterizing a match
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PartialOrderFill {
    /// The amount filled by the partial fill
    pub amount: Amount,
    /// The price at which the fill executed
    pub price: f64,
    /// The time at which the fill executed, in milliseconds since the epoch
    pub timestamp: u64,
}

impl PartialOrderFill {
    /// Constructor
    pub fn new(amount: Amount, price: FixedPoint) -> Self {
        let timestamp = get_current_time_millis();
        let price = price.to_f64();
        Self { amount, price, timestamp }
    }
}
