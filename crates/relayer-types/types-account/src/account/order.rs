//! The order type for an account
//!
//! This type wraps an intent and adds metadata to the order that doesn't appear
//! in the circuits (and thereby the intent) directly.

use alloy::primitives::Address;
use circuit_types::{Amount, fixed_point::FixedPoint};
use darkpool_types::intent::Intent;
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::{OrderId, pair::Pair};

/// The order type for an account
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct Order {
    /// The id of the order
    pub id: OrderId,
    /// The intent
    pub intent: Intent,
    /// The metadata for the order
    pub metadata: OrderMetadata,
}

/// The metadata for an order
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct OrderMetadata {
    /// The minimum fill size for the order
    pub min_fill_size: Amount,
    /// Whether or not to allow external matches
    pub allow_external_matches: bool,
}

impl Order {
    /// Create a new order from the given intent and metadata
    pub fn new(intent: Intent, metadata: OrderMetadata) -> Self {
        let id = OrderId::new_v4();
        Self { id, intent, metadata }
    }

    /// Get a reference to the intent
    pub fn intent(&self) -> &Intent {
        &self.intent
    }

    /// Get a reference to the metadata
    pub fn metadata(&self) -> &OrderMetadata {
        &self.metadata
    }

    /// The input token for the order
    pub fn input_token(&self) -> Address {
        self.intent.in_token
    }

    /// The output token for the order
    pub fn output_token(&self) -> Address {
        self.intent.out_token
    }

    /// Whether the order is zero'd out
    ///
    /// This can happen without an order being removed from an account because
    /// the order shares are directly updated on-chain
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.intent.amount_in == 0
    }

    /// Get the pair for the order
    pub fn pair(&self) -> Pair {
        Pair::new(self.intent.in_token, self.intent.out_token)
    }

    /// Get the min fill size for the order
    pub fn min_fill_size(&self) -> Amount {
        self.metadata.min_fill_size
    }

    /// Whether the order has external matches enabled
    pub fn allow_external_matches(&self) -> bool {
        self.metadata.allow_external_matches
    }

    /// Validate a match's price against the order's bounds
    pub fn validate_match_price(&self, input_amount: Amount, output_amount: Amount) -> bool {
        // Check the worst case price
        let implied_price = FixedPoint::from_integer_ratio(output_amount, input_amount);
        implied_price >= self.intent.min_price
    }
}

impl OrderMetadata {
    /// Create a new order metadata from the given min fill size and allow
    /// external matches
    pub fn new(min_fill_size: Amount, allow_external_matches: bool) -> Self {
        Self { min_fill_size, allow_external_matches }
    }
}

impl From<Order> for Intent {
    fn from(order: Order) -> Self {
        order.intent
    }
}

impl From<Intent> for Order {
    fn from(intent: Intent) -> Self {
        Self::new(intent, OrderMetadata::default())
    }
}

impl Default for OrderMetadata {
    fn default() -> Self {
        Self { min_fill_size: 0, allow_external_matches: true }
    }
}

#[cfg(feature = "mocks")]
/// Mock types for order testing
pub mod mocks {
    use super::{Order, OrderMetadata};
    use crate::{account::mocks::mock_intent, pair::Pair};

    /// Create a mock order for testing
    pub fn mock_order() -> Order {
        let intent = mock_intent();
        Order::new(intent, OrderMetadata::default())
    }

    /// Create a mock order with the given pair
    pub fn mock_order_with_pair(pair: Pair) -> Order {
        let mut intent = mock_intent();
        intent.in_token = pair.in_token;
        intent.out_token = pair.out_token;
        Order::new(intent, OrderMetadata::default())
    }
}
