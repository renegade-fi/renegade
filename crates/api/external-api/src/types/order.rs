//! API types for orders

use std::str::FromStr;

use alloy::primitives::{Bytes, U256};
use circuit_types::{Amount, fixed_point::FixedPoint, schnorr::SchnorrSignature};
use constants::Scalar;
use darkpool_types::intent::Intent;
#[cfg(feature = "full-api")]
use renegade_solidity_abi::v2::IDarkpoolV2;
use serde::{Deserialize, Serialize};
use types_account::{
    OrderId,
    order::{Order, OrderMetadata, PrivacyRing},
};
use util::{
    base64::bytes_from_base64_string,
    hex::{address_from_hex_string, address_to_hex_string},
};
use uuid::Uuid;

use super::crypto_primitives::{ApiPoseidonCSPRNG, ApiSchnorrSignature};
use crate::error::ApiTypeError;

// --------------
// | Core Types |
// --------------

/// The core order data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiOrderCore {
    /// The order identifier
    pub id: Uuid,
    /// The input token mint address
    pub in_token: String,
    /// The output token mint address
    pub out_token: String,
    /// The owner's address
    pub owner: String,
    /// The minimum price for the order
    pub min_price: String,
    /// The input amount
    pub amount_in: String,
    /// The minimum fill size
    pub min_fill_size: String,
    /// The type of order
    pub order_type: OrderType,
    /// Whether to allow external matches
    pub allow_external_matches: bool,
}

impl ApiOrderCore {
    /// Return the order metadata from the core order
    pub fn get_order_metadata(&self) -> Result<OrderMetadata, ApiTypeError> {
        let min_fill = Amount::from_str(&self.min_fill_size)
            .map_err(|e| ApiTypeError::parsing(format!("invalid min fill size: {e:?}")))?;

        Ok(OrderMetadata {
            min_fill_size: min_fill,
            allow_external_matches: self.allow_external_matches,
        })
    }

    /// Get the intent from the core order
    pub fn get_intent(&self) -> Result<Intent, ApiTypeError> {
        let in_token = address_from_hex_string(&self.in_token).map_err(ApiTypeError::parsing)?;
        let out_token = address_from_hex_string(&self.out_token).map_err(ApiTypeError::parsing)?;
        let owner = address_from_hex_string(&self.owner).map_err(ApiTypeError::parsing)?;
        let repr = Scalar::from_decimal_string(&self.min_price).map_err(ApiTypeError::parsing)?;
        let min_price = FixedPoint::from_repr(repr);
        let amount_in = Amount::from_str(&self.amount_in).map_err(ApiTypeError::parsing)?;

        Ok(Intent { in_token, out_token, owner, min_price, amount_in })
    }
}

#[cfg(feature = "full-api")]
impl From<Order> for ApiOrderCore {
    fn from(order: Order) -> Self {
        Self {
            id: order.id,
            in_token: address_to_hex_string(&order.intent().in_token),
            out_token: address_to_hex_string(&order.intent().out_token),
            owner: address_to_hex_string(&order.intent().owner),
            min_price: order.intent().min_price.repr.to_string(),
            amount_in: order.intent().amount_in.to_string(),
            min_fill_size: order.metadata.min_fill_size.to_string(),
            order_type: order.ring.into(),
            allow_external_matches: order.metadata.allow_external_matches,
        }
    }
}

/// The public shares of an order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiOrderShare {
    /// The input token share
    pub in_token: String,
    /// The output token share
    pub out_token: String,
    /// The owner share
    pub owner: String,
    /// The minimum price share
    pub min_price: String,
    /// The amount in share
    pub amount_in: String,
}

// TODO: Remove this
fn dummy_api_order_share() -> ApiOrderShare {
    ApiOrderShare {
        in_token: "".to_string(),
        out_token: "".to_string(),
        owner: "".to_string(),
        min_price: "".to_string(),
        amount_in: "".to_string(),
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
        Self {
            id: order.id,
            order: order.into(),
            recovery_stream: ApiPoseidonCSPRNG { seed: "".to_string(), index: 0 },
            share_stream: ApiPoseidonCSPRNG { seed: "".to_string(), index: 0 },
            public_shares: dummy_api_order_share(),
            state: OrderState::Created,
            fills: vec![],
            created: 0,
        }
    }
}

/// The type of order
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

/// Authentication for an order
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderAuth {
    /// Authentication for a public order
    PublicOrder {
        /// The intent signature with nonce
        intent_signature: SignatureWithNonce,
    },
    /// Authentication for a natively settled private order
    NativelySettledPrivateOrder {
        /// The Schnorr signature for intent
        intent_signature: ApiSchnorrSignature,
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
impl TryFrom<OrderAuth> for types_account::order_auth::OrderAuth {
    type Error = ApiTypeError;

    fn try_from(auth: OrderAuth) -> Result<Self, Self::Error> {
        match auth {
            OrderAuth::PublicOrder { intent_signature } => {
                let intent_signature = IDarkpoolV2::SignatureWithNonce::try_from(intent_signature)
                    .map_err(ApiTypeError::parsing)?;
                Ok(types_account::order_auth::OrderAuth::PublicOrder { intent_signature })
            },
            OrderAuth::NativelySettledPrivateOrder { intent_signature } => {
                let intent_signature =
                    SchnorrSignature::try_from(intent_signature).map_err(ApiTypeError::parsing)?;
                Ok(types_account::order_auth::OrderAuth::NativelySettledPrivateOrder {
                    intent_signature,
                })
            },
            OrderAuth::RenegadeSettledOrder { intent_signature, new_output_balance_signature } => {
                let intent_signature =
                    SchnorrSignature::try_from(intent_signature).map_err(ApiTypeError::parsing)?;
                let new_output_balance_signature =
                    SchnorrSignature::try_from(new_output_balance_signature)
                        .map_err(ApiTypeError::parsing)?;
                Ok(types_account::order_auth::OrderAuth::RenegadeSettledOrder {
                    intent_signature,
                    new_output_balance_signature,
                })
            },
        }
    }
}

/// A signature with an associated nonce
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureWithNonce {
    /// The nonce
    pub nonce: String,
    /// The signature bytes (base64 encoded)
    pub signature: String,
}

#[cfg(feature = "full-api")]
impl TryFrom<SignatureWithNonce> for renegade_solidity_abi::v2::IDarkpoolV2::SignatureWithNonce {
    type Error = ApiTypeError;

    fn try_from(signature_with_nonce: SignatureWithNonce) -> Result<Self, Self::Error> {
        let nonce = U256::from_str(&signature_with_nonce.nonce)
            .map_err(|e| ApiTypeError::parsing(format!("invalid nonce: {e}")))?;
        let signature_bytes = bytes_from_base64_string(&signature_with_nonce.signature)
            .map_err(ApiTypeError::parsing)?;
        let signature = Bytes::from(signature_bytes);
        Ok(renegade_solidity_abi::v2::IDarkpoolV2::SignatureWithNonce { nonce, signature })
    }
}

/// A partial fill of an order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiPartialOrderFill {
    /// The amount filled
    pub amount: String,
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
    /// The price as a string
    pub price: String,
    /// The timestamp in milliseconds
    pub timestamp: u64,
}

/// Fees taken from a match
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FeeTake {
    /// The relayer fee amount
    pub relayer_fee: String,
    /// The protocol fee amount
    pub protocol_fee: String,
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
