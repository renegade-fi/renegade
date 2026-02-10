//! API types for orders

use alloy::primitives::Address;
use circuit_types::{Amount, fixed_point::FixedPoint, fixed_point::FixedPointShare};
use constants::Scalar;
#[cfg(feature = "full-api")]
use darkpool_types::intent::DarkpoolStateIntent;
use darkpool_types::intent::{Intent, IntentShare};
use serde::{Deserialize, Serialize};
use types_account::{
    OrderId,
    order::{Order, OrderMetadata, PrivacyRing},
    order_auth::OrderAuth as AccountOrderAuth,
};
use uuid::Uuid;

use super::SignatureWithNonce;
use super::crypto_primitives::{ApiPoseidonCSPRNG, ApiSchnorrSignature};
use crate::serde_helpers;

// --------------
// | Core Types |
// --------------

/// The intent of an order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiIntent {
    /// The input token mint address
    #[serde(with = "serde_helpers::address_as_string")]
    pub in_token: Address,
    /// The output token mint address
    #[serde(with = "serde_helpers::address_as_string")]
    pub out_token: Address,
    /// The owner's address
    #[serde(with = "serde_helpers::address_as_string")]
    pub owner: Address,
    /// The minimum price for the order
    #[serde(with = "serde_helpers::fixed_point_as_string")]
    pub min_price: FixedPoint,
    /// The input amount
    #[serde(with = "serde_helpers::amount_as_string")]
    pub amount_in: Amount,
}

impl From<ApiIntent> for Intent {
    fn from(api: ApiIntent) -> Self {
        Intent {
            in_token: api.in_token,
            out_token: api.out_token,
            owner: api.owner,
            min_price: api.min_price,
            amount_in: api.amount_in,
        }
    }
}

#[cfg(feature = "full-api")]
impl From<Intent> for ApiIntent {
    fn from(intent: Intent) -> Self {
        Self {
            in_token: intent.in_token,
            out_token: intent.out_token,
            owner: intent.owner,
            min_price: intent.min_price,
            amount_in: intent.amount_in,
        }
    }
}

/// The core order data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiOrderCore {
    /// The order identifier
    pub id: Uuid,
    /// The intent of the order
    pub intent: ApiIntent,
    /// The minimum fill size
    #[serde(with = "serde_helpers::amount_as_string")]
    pub min_fill_size: Amount,
    /// The type of order
    pub order_type: OrderType,
    /// Whether to allow external matches
    pub allow_external_matches: bool,
}

impl ApiOrderCore {
    /// Return the order metadata from the core order
    pub fn get_order_metadata(&self) -> OrderMetadata {
        OrderMetadata {
            min_fill_size: self.min_fill_size,
            allow_external_matches: self.allow_external_matches,
            has_been_filled: false,
        }
    }

    /// Get the intent from the core order
    pub fn get_intent(&self) -> Intent {
        self.intent.clone().into()
    }

    /// Return the components of an order
    #[cfg(feature = "full-api")]
    pub fn into_order_components(self) -> (Intent, PrivacyRing, OrderMetadata) {
        let intent = self.get_intent();
        let ring = self.order_type.into();
        let meta = self.get_order_metadata();

        (intent, ring, meta)
    }
}

#[cfg(feature = "full-api")]
impl From<Order> for ApiOrderCore {
    fn from(order: Order) -> Self {
        Self {
            id: order.id,
            intent: order.intent().clone().into(),
            min_fill_size: order.metadata.min_fill_size,
            order_type: order.ring.into(),
            allow_external_matches: order.metadata.allow_external_matches,
        }
    }
}

/// The public shares of an order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiOrderShare {
    /// The input token share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub in_token: Scalar,
    /// The output token share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub out_token: Scalar,
    /// The owner share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub owner: Scalar,
    /// The minimum price share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub min_price: Scalar,
    /// The amount in share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub amount_in: Scalar,
}

impl From<IntentShare> for ApiOrderShare {
    fn from(share: IntentShare) -> Self {
        Self {
            in_token: share.in_token,
            out_token: share.out_token,
            owner: share.owner,
            min_price: share.min_price.repr,
            amount_in: share.amount_in,
        }
    }
}

impl From<ApiOrderShare> for IntentShare {
    fn from(share: ApiOrderShare) -> Self {
        IntentShare {
            in_token: share.in_token,
            out_token: share.out_token,
            owner: share.owner,
            min_price: FixedPointShare { repr: share.min_price },
            amount_in: share.amount_in,
        }
    }
}

/// The full order with metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiOrder {
    /// The order identifier
    pub id: OrderId,
    /// The core order data
    pub order: ApiOrderCore,
    /// The recovery stream CSPRNG state
    pub recovery_stream: ApiPoseidonCSPRNG,
    /// The share stream CSPRNG state
    pub share_stream: ApiPoseidonCSPRNG,
    /// The public shares of the order
    pub public_shares: ApiOrderShare,
    /// The current state of the order
    pub state: OrderState,
    /// The fills that have occurred on this order
    pub fills: Vec<ApiPartialOrderFill>,
    /// The creation timestamp
    pub created: u64,
}

#[cfg(feature = "full-api")]
impl From<Order> for ApiOrder {
    fn from(order: Order) -> Self {
        let recovery_stream = order.intent.recovery_stream.clone().into();
        let share_stream = order.intent.share_stream.clone().into();
        let public_shares = order.intent.public_share.clone().into();
        Self {
            id: order.id,
            order: order.into(),
            recovery_stream,
            share_stream,
            public_shares,
            state: OrderState::Created,
            fills: vec![],
            created: 0,
        }
    }
}

#[cfg(feature = "full-api")]
impl From<ApiOrder> for DarkpoolStateIntent {
    fn from(api_order: ApiOrder) -> Self {
        DarkpoolStateIntent {
            recovery_stream: api_order.recovery_stream.into(),
            share_stream: api_order.share_stream.into(),
            inner: api_order.order.get_intent(),
            public_share: api_order.public_shares.into(),
        }
    }
}

#[cfg(feature = "full-api")]
impl From<ApiOrder> for Order {
    fn from(api_order: ApiOrder) -> Self {
        Self {
            id: api_order.id,
            intent: DarkpoolStateIntent {
                recovery_stream: api_order.recovery_stream.into(),
                share_stream: api_order.share_stream.into(),
                inner: api_order.order.get_intent(),
                public_share: api_order.public_shares.into(),
            },
            ring: api_order.order.order_type.into(),
            metadata: api_order.order.get_order_metadata(),
        }
    }
}

/// The type of order
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum OrderType {
    /// A public order visible to all
    PublicOrder,
    /// A natively settled private order
    NativelySettledPrivateOrder,
    /// A Renegade-settled order with public fills
    RenegadeSettledPublicFillOrder,
    /// A Renegade-settled order with private fills
    RenegadeSettledPrivateFillOrder,
}

impl From<OrderType> for PrivacyRing {
    fn from(order_type: OrderType) -> Self {
        match order_type {
            OrderType::PublicOrder => PrivacyRing::Ring0,
            OrderType::NativelySettledPrivateOrder => PrivacyRing::Ring1,
            OrderType::RenegadeSettledPublicFillOrder => PrivacyRing::Ring2,
            OrderType::RenegadeSettledPrivateFillOrder => PrivacyRing::Ring3,
        }
    }
}

impl From<PrivacyRing> for OrderType {
    fn from(privacy_ring: PrivacyRing) -> Self {
        match privacy_ring {
            PrivacyRing::Ring0 => OrderType::PublicOrder,
            PrivacyRing::Ring1 => OrderType::NativelySettledPrivateOrder,
            PrivacyRing::Ring2 => OrderType::RenegadeSettledPublicFillOrder,
            PrivacyRing::Ring3 => OrderType::RenegadeSettledPrivateFillOrder,
        }
    }
}

/// The state of an order
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrderState {
    /// Order has been created
    Created,
    /// Order is being matched
    Matching,
    /// Order is settling a match
    SettlingMatch,
    /// Order has been fully filled
    Filled,
    /// Order has been cancelled
    Cancelled,
}

/// A public intent permit for a public order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiPublicIntentPermit {
    /// The intent this permit authorizes
    pub intent: ApiIntent,
    /// The executor address
    #[serde(with = "serde_helpers::address_as_string")]
    pub executor: Address,
}

#[cfg(feature = "full-api")]
impl From<renegade_solidity_abi::v2::IDarkpoolV2::PublicIntentPermit> for ApiPublicIntentPermit {
    fn from(permit: renegade_solidity_abi::v2::IDarkpoolV2::PublicIntentPermit) -> Self {
        // Convert through circuit Intent as intermediate
        let intent: Intent = permit.intent.into();
        Self { intent: intent.into(), executor: permit.executor }
    }
}

#[cfg(feature = "full-api")]
impl From<ApiPublicIntentPermit> for renegade_solidity_abi::v2::IDarkpoolV2::PublicIntentPermit {
    fn from(permit: ApiPublicIntentPermit) -> Self {
        let intent: Intent = permit.intent.into();
        Self { intent: intent.into(), executor: permit.executor }
    }
}

/// Authentication for an order
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderAuth {
    /// Authentication for a public order
    PublicOrder {
        /// The public intent permit
        permit: ApiPublicIntentPermit,
        /// The intent signature with nonce
        intent_signature: SignatureWithNonce,
    },
    /// Authentication for a natively settled private order
    NativelySettledPrivateOrder {
        /// The intent signature with nonce
        intent_signature: SignatureWithNonce,
    },
    /// Authentication for a Renegade-settled order
    RenegadeSettledOrder {
        /// The Schnorr signature for intent
        intent_signature: ApiSchnorrSignature,
        /// The Schnorr signature for the new output balance, if one is needed
        new_output_balance_signature: ApiSchnorrSignature,
    },
}

#[cfg(feature = "full-api")]
impl From<AccountOrderAuth> for OrderAuth {
    fn from(auth: AccountOrderAuth) -> Self {
        match auth {
            AccountOrderAuth::PublicOrder { permit, intent_signature } => OrderAuth::PublicOrder {
                permit: permit.into(),
                intent_signature: intent_signature.into(),
            },
            AccountOrderAuth::NativelySettledPrivateOrder { intent_signature } => {
                OrderAuth::NativelySettledPrivateOrder { intent_signature: intent_signature.into() }
            },
            AccountOrderAuth::RenegadeSettledOrder {
                intent_signature,
                new_output_balance_signature,
            } => OrderAuth::RenegadeSettledOrder {
                intent_signature: intent_signature.into(),
                new_output_balance_signature: new_output_balance_signature.into(),
            },
        }
    }
}

/// A partial fill of an order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiPartialOrderFill {
    /// The amount filled
    #[serde(with = "serde_helpers::amount_as_string")]
    pub amount: Amount,
    /// The price at which the fill occurred
    pub price: ApiTimestampedPriceFloat,
    /// The fees taken
    pub fees: FeeTake,
    /// The transaction hash of the fill
    pub tx_hash: String,
}

/// A timestamped price with float representation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiTimestampedPriceFloat {
    /// The price as a string to avoid fixed point precision issues
    pub price: String,
    /// The timestamp in milliseconds
    pub timestamp: u64,
}

/// Fees taken from a match
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FeeTake {
    /// The relayer fee amount
    #[serde(with = "serde_helpers::amount_as_string")]
    pub relayer_fee: Amount,
    /// The protocol fee amount
    #[serde(with = "serde_helpers::amount_as_string")]
    pub protocol_fee: Amount,
}

/// The type of order update
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiOrderUpdateType {
    /// Order was created
    Created,
    /// Order was filled internally
    InternalFill,
    /// Order was filled externally
    ExternalFill,
    /// Minimum fill size was updated
    MinFillSizeUpdated,
    /// External matches were toggled
    ExternalMatchesToggled,
    /// Order was assigned to a matching pool
    MatchingPoolAssigned,
    /// Order was cancelled
    Cancelled,
}
