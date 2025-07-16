//! Order metadata for a wallet's orders

use circuit_types::Amount;
use serde::{Deserialize, Serialize};
use util::get_current_time_millis;

use crate::types::price::TimestampedPrice;

use super::{Order, OrderIdentifier};

/// The maximum number of recent fills to retain for an order
const MAX_RECENT_FILLS: usize = 2; // 1 aggregate + 1 most-recent fill kept

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
    pub fn record_partial_fill(&mut self, amount: Amount, price: TimestampedPrice) {
        let fill = PartialOrderFill::new(amount, price);
        self.fills.push(fill);
    }

    /// Roll up older fills into a single aggregate fill so that the number of
    /// retained fill entries never exceeds `MAX_RECENT_FILLS`.
    ///
    /// This is a lossy compression that preserves the *total* filled amount
    /// while bounding per-order storage growth. The newest fill (or newest
    /// `MAX_RECENT_FILLS - 1` fills) is always preserved verbatim so that
    /// downstream consumers can detect the latest execution.
    pub fn roll_up_fills(&mut self) {
        // Only run if the vector exceeds the cap
        if self.fills.len() <= MAX_RECENT_FILLS {
            return;
        }

        // Keep the newest `MAX_RECENT_FILLS - 1` fills
        let keep = MAX_RECENT_FILLS - 1;
        let newest: Vec<_> = self.fills.split_off(self.fills.len() - keep);

        // Aggregate the amounts of all older fills
        let rolled_amount: Amount = self.fills.iter().map(|f| f.amount).sum();

        // Use the price of the newest fill being aggregated as the representative price
        // for the aggregate entry. Downstream consumers generally ignore this
        // price for aggregates, but we must supply *some* value.
        let representative_price = self.fills.last().unwrap().price;
        let aggregate_fill = PartialOrderFill::new(rolled_amount, representative_price);

        // Rebuild the fills vector: [aggregate, newest...]
        self.fills = iter::once(aggregate_fill).chain(newest).collect();
    }
}

/// A partial fill of an order, recording the information parameterizing a match
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PartialOrderFill {
    /// The amount filled by the partial fill
    pub amount: Amount,
    /// The timestamped price at which the fill executed
    pub price: TimestampedPrice,
}

impl PartialOrderFill {
    /// Constructor
    pub fn new(amount: Amount, price: TimestampedPrice) -> Self {
        Self { amount, price }
    }
}
