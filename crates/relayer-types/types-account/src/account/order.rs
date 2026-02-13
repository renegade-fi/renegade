//! The order type for an account
//!
//! This type wraps an intent and adds metadata to the order that doesn't appear
//! in the circuits (and thereby the intent) directly.

use alloy::primitives::Address;
use circuit_types::{Amount, fixed_point::FixedPoint};
use constants::Scalar;
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::ArchivedAddress;
use darkpool_types::{intent::Intent, state_wrapper::StateWrapper};
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

#[cfg(feature = "rkyv")]
use crate::balance::ArchivedBalanceLocation;
use crate::{
    MatchingPoolName, OrderId, balance::BalanceLocation, order_auth::OrderAuth, pair::Pair,
};

/// The order type for an account
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct Order {
    /// The id of the order
    pub id: OrderId,
    /// The intent
    pub intent: StateWrapper<Intent>,
    /// The privacy ring in which the intent is allocated
    pub ring: PrivacyRing,
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
    /// Whether the order has received at least one fill
    pub has_been_filled: bool,
}

impl Order {
    /// Create a new order from the given intent and metadata
    pub fn new(intent: StateWrapper<Intent>, metadata: OrderMetadata) -> Self {
        let id = OrderId::new_v4();
        Self::new_with_ring(id, intent, metadata, PrivacyRing::default())
    }

    /// Create a new order from the given intent, metadata, and privacy ring
    pub fn new_with_ring(
        id: OrderId,
        intent: StateWrapper<Intent>,
        metadata: OrderMetadata,
        ring: PrivacyRing,
    ) -> Self {
        Self { id, intent, metadata, ring }
    }

    /// Get a reference to the intent
    pub fn intent(&self) -> &Intent {
        self.intent.as_ref()
    }

    /// Get a reference to the metadata
    pub fn metadata(&self) -> &OrderMetadata {
        &self.metadata
    }

    /// The input token for the order
    pub fn input_token(&self) -> Address {
        self.intent.inner.in_token
    }

    /// The output token for the order
    pub fn output_token(&self) -> Address {
        self.intent.inner.out_token
    }

    /// The input amount for the order
    pub fn amount_in(&self) -> Amount {
        self.intent.inner.amount_in
    }

    /// Decrement the amount remaining for the order
    pub fn decrement_amount_in(&mut self, amount: Amount) {
        let new_amount = self
            .intent
            .inner
            .amount_in
            .checked_sub(amount)
            .expect("underflow when decrementing amount_in");

        self.intent.inner.amount_in = new_amount;
        self.intent.public_share.amount_in -= Scalar::from(amount);
    }

    /// Whether the order is zero'd out
    ///
    /// This can happen without an order being removed from an account because
    /// the order shares are directly updated on-chain
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.intent.inner.amount_in == 0
    }

    /// Get the pair for the order
    pub fn pair(&self) -> Pair {
        Pair::new(self.intent.inner.in_token, self.intent.inner.out_token)
    }

    /// Get the min fill size for the order
    pub fn min_fill_size(&self) -> Amount {
        self.metadata.min_fill_size
    }

    /// The min price for the order
    pub fn min_price(&self) -> FixedPoint {
        self.intent.inner.min_price
    }

    /// Whether the order has external matches enabled
    pub fn allow_external_matches(&self) -> bool {
        self.metadata.allow_external_matches
    }

    /// Validate a match's price against the order's bounds
    pub fn validate_match_price(&self, input_amount: Amount, output_amount: Amount) -> bool {
        // Check the worst case price
        let implied_price = FixedPoint::from_integer_ratio(output_amount, input_amount);
        implied_price >= self.intent.inner.min_price
    }
}

#[cfg(feature = "rkyv")]
impl ArchivedOrder {
    /// Get the input token for the order
    pub fn input_token(&self) -> &ArchivedAddress {
        &self.intent.inner.in_token
    }

    /// Get the amount in for the order
    pub fn amount_in(&self) -> Amount {
        self.intent.inner.amount_in.to_native()
    }
}

impl OrderMetadata {
    /// Create a new order metadata from the given min fill size and allow
    /// external matches
    pub fn new(min_fill_size: Amount, allow_external_matches: bool) -> Self {
        Self { min_fill_size, allow_external_matches, has_been_filled: false }
    }

    /// Mark the order as having received its first fill
    pub fn mark_filled(&mut self) {
        self.has_been_filled = true;
    }
}

impl From<Order> for Intent {
    fn from(order: Order) -> Self {
        order.intent.inner
    }
}

impl From<StateWrapper<Intent>> for Order {
    fn from(intent: StateWrapper<Intent>) -> Self {
        Self::new(intent, OrderMetadata::default())
    }
}

impl Default for OrderMetadata {
    fn default() -> Self {
        Self { min_fill_size: 0, allow_external_matches: true, has_been_filled: false }
    }
}

/// The privacy ring in which the intent is allocated
///
/// Renegade allows users to configure the level or privacy applied to the
/// intent. This allows users to tradeoff privacy versus latency in a very
/// direct way. We expose 4 privacy rings:
///
/// - Ring 0: Public intent, public balance. Intents are allocated in the clear
///   on-chain and the balances that capitalize them are assumed to be EOA ERC20
///   balances.
/// - Ring 1: Private intent, public balance. Intents in ring 1 are Merklized to
///   hide their contents, but the capitalizing balances are still ERC20
///   balances. This hides the total size of the intent, but not the individual
///   fills.
/// - Ring 2: Private intent, private balance (public fill). In this ring, both
///   intents and balances are Merklized to hide their contents. This allows for
///   private fills, in which full post-trade privacy is guaranteed. However,
///   opting into ring 2 also allows an intent to cross with intents from other
///   rings, effectively _allowing_ public fills.
/// - Ring 3: Private intent, private balance (private fill). In this ring, both
///   intents and balances are Merklized to hide their contents. This is similar
///   to ring 2, except public fills are explicitly disabled. Ring 3 intents may
///   only cross with other ring 2 and ring 3 intents, where private fills are
///   possible.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
#[serde(rename_all = "lowercase")]
pub enum PrivacyRing {
    /// Ring 0: Public intent, public balance
    #[default]
    Ring0,
    /// Ring 1: Private intent, public balance
    Ring1,
    /// Ring 2: Private intent, private balance (public fill)
    Ring2,
    /// Ring 3: Private intent, private balance (private fill)
    Ring3,
}

impl PrivacyRing {
    /// Get the minimum counterparty ring this ring is allowed to cross with.
    ///
    /// Rings <= 2 accept counterparties from any ring, whereas Ring 3 only
    /// accepts Ring 2/3 counterparties. Note that `can_cross_with` enforces
    /// this bidirectionally, so Ring 0/1 cannot match with Ring 3.
    pub fn min_counterparty_ring(&self) -> Self {
        match self {
            Self::Ring0 | Self::Ring1 | Self::Ring2 => Self::Ring0,
            Self::Ring3 => Self::Ring2,
        }
    }

    /// Get an ordinal rank for the ring.
    fn rank(&self) -> u8 {
        match self {
            Self::Ring0 => 0,
            Self::Ring1 => 1,
            Self::Ring2 => 2,
            Self::Ring3 => 3,
        }
    }

    /// Whether this ring can cross with the given counterparty ring.
    ///
    /// This enforces compatibility in both directions:
    /// - The counterparty must satisfy this ring's minimum counterparty ring.
    /// - This ring must satisfy the counterparty's minimum counterparty ring.
    pub fn can_cross_with(&self, counterparty: PrivacyRing) -> bool {
        counterparty.rank() >= self.min_counterparty_ring().rank()
            && self.rank() >= counterparty.min_counterparty_ring().rank()
    }

    /// Whether or not two orders support private settlement
    pub fn supports_private_settlement(order0_ring: PrivacyRing, order1_ring: PrivacyRing) -> bool {
        let order0_supports = matches!(order0_ring, PrivacyRing::Ring2 | PrivacyRing::Ring3);
        let order1_supports = matches!(order1_ring, PrivacyRing::Ring2 | PrivacyRing::Ring3);
        order0_supports && order1_supports
    }

    /// Get the balance location from which an order in the privacy ring is
    /// capitalized
    pub fn balance_location(&self) -> BalanceLocation {
        match self {
            PrivacyRing::Ring0 | PrivacyRing::Ring1 => BalanceLocation::EOA,
            PrivacyRing::Ring2 | PrivacyRing::Ring3 => BalanceLocation::Darkpool,
        }
    }
}

#[cfg(feature = "rkyv")]
impl ArchivedPrivacyRing {
    /// Get the balance location from which an order in the privacy ring is
    /// capitalized
    pub fn balance_location(&self) -> ArchivedBalanceLocation {
        match self {
            ArchivedPrivacyRing::Ring0 | ArchivedPrivacyRing::Ring1 => ArchivedBalanceLocation::EOA,
            ArchivedPrivacyRing::Ring2 | ArchivedPrivacyRing::Ring3 => {
                ArchivedBalanceLocation::Darkpool
            },
        }
    }
}

/// Data for refreshing an order in an account
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct OrderRefreshData {
    /// The order
    pub order: Order,
    /// The matching pool assignment
    pub matching_pool: MatchingPoolName,
    /// The order authorization
    pub auth: OrderAuth,
}

#[cfg(feature = "mocks")]
/// Mock types for order testing
pub mod mocks {
    use super::{Order, OrderMetadata};
    use crate::{account::mocks::mock_intent, pair::Pair};
    use constants::Scalar;
    use darkpool_types::state_wrapper::StateWrapper;
    use rand::thread_rng;

    /// Create a mock order for testing
    pub fn mock_order() -> Order {
        let intent = mock_intent();
        let mut rng = thread_rng();
        let share_stream_seed = Scalar::random(&mut rng);
        let recovery_stream_seed = Scalar::random(&mut rng);
        let state_wrapper = StateWrapper::new(intent, share_stream_seed, recovery_stream_seed);
        Order::new(state_wrapper, OrderMetadata::default())
    }

    /// Create a mock order with the given pair
    pub fn mock_order_with_pair(pair: Pair) -> Order {
        let mut intent = mock_intent();
        intent.in_token = pair.in_token;
        intent.out_token = pair.out_token;
        let mut rng = thread_rng();
        let share_stream_seed = Scalar::random(&mut rng);
        let recovery_stream_seed = Scalar::random(&mut rng);
        let state_wrapper = StateWrapper::new(intent, share_stream_seed, recovery_stream_seed);
        Order::new(state_wrapper, OrderMetadata::default())
    }
}
