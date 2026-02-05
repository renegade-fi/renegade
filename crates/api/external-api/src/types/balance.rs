//! API types for balances

use alloy::primitives::Address;
#[cfg(feature = "full-api")]
use alloy::primitives::Bytes;
use alloy::primitives::U256;
#[cfg(feature = "full-api")]
use circuit_types::Amount;
#[cfg(feature = "full-api")]
use constants::Scalar;
#[cfg(feature = "full-api")]
use darkpool_types::balance::{DarkpoolBalance, DarkpoolBalanceShare, DarkpoolStateBalance};
#[cfg(feature = "full-api")]
use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
use serde::{Deserialize, Serialize};
use types_account::balance::Balance;

use super::crypto_primitives::{ApiPoseidonCSPRNG, ApiSchnorrPublicKey, ApiSchnorrPublicKeyShare};
use crate::error::ApiTypeError;
use crate::serde_helpers;

// -----------------
// | Balance Types |
// -----------------

/// A balance in an account
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiBalance {
    /// The token mint address
    #[serde(with = "serde_helpers::address_as_string")]
    pub mint: Address,
    /// The owner address
    #[serde(with = "serde_helpers::address_as_string")]
    pub owner: Address,
    /// The relayer fee recipient address
    #[serde(with = "serde_helpers::address_as_string")]
    pub relayer_fee_recipient: Address,
    /// The authority public key
    pub authority: ApiSchnorrPublicKey,
    /// The relayer fee balance
    #[serde(with = "serde_helpers::amount_as_string")]
    pub relayer_fee_balance: Amount,
    /// The protocol fee balance
    #[serde(with = "serde_helpers::amount_as_string")]
    pub protocol_fee_balance: Amount,
    /// The available amount
    #[serde(with = "serde_helpers::amount_as_string")]
    pub amount: Amount,
    /// The recovery stream CSPRNG state
    pub recovery_stream: ApiPoseidonCSPRNG,
    /// The share stream CSPRNG state
    pub share_stream: ApiPoseidonCSPRNG,
    /// The public shares of the balance
    pub public_shares: ApiBalanceShare,
}

#[cfg(feature = "full-api")]
impl From<Balance> for ApiBalance {
    fn from(bal: Balance) -> Self {
        let inner = bal.inner();
        let elt = &bal.state_wrapper;
        Self {
            mint: inner.mint,
            owner: inner.owner,
            relayer_fee_recipient: inner.relayer_fee_recipient,
            authority: inner.authority.into(),
            relayer_fee_balance: inner.relayer_fee_balance,
            protocol_fee_balance: inner.protocol_fee_balance,
            amount: inner.amount,
            recovery_stream: elt.recovery_stream.clone().into(),
            share_stream: elt.share_stream.clone().into(),
            public_shares: elt.public_share.clone().into(),
        }
    }
}

#[cfg(feature = "full-api")]
impl TryFrom<ApiBalance> for DarkpoolStateBalance {
    type Error = ApiTypeError;

    fn try_from(api_balance: ApiBalance) -> Result<Self, Self::Error> {
        let inner = DarkpoolBalance {
            mint: api_balance.mint,
            owner: api_balance.owner,
            relayer_fee_recipient: api_balance.relayer_fee_recipient,
            authority: api_balance.authority.into(),
            relayer_fee_balance: api_balance.relayer_fee_balance,
            protocol_fee_balance: api_balance.protocol_fee_balance,
            amount: api_balance.amount,
        };
        let recovery_stream = api_balance.recovery_stream.into();
        let share_stream = api_balance.share_stream.into();
        let public_share = api_balance.public_shares.into();

        Ok(DarkpoolStateBalance { recovery_stream, share_stream, inner, public_share })
    }
}

/// Public shares of a balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiBalanceShare {
    /// The token mint address share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub mint: Scalar,
    /// The owner address share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub owner: Scalar,
    /// The relayer fee recipient address share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub relayer_fee_recipient: Scalar,
    /// The authority public key share
    pub authority: ApiSchnorrPublicKeyShare,
    /// The relayer fee balance share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub relayer_fee_balance: Scalar,
    /// The protocol fee balance share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub protocol_fee_balance: Scalar,
    /// The amount share
    #[serde(with = "serde_helpers::scalar_as_string")]
    pub amount: Scalar,
}

#[cfg(feature = "full-api")]
impl From<DarkpoolBalanceShare> for ApiBalanceShare {
    fn from(share: DarkpoolBalanceShare) -> Self {
        Self {
            mint: share.mint,
            owner: share.owner,
            relayer_fee_recipient: share.relayer_fee_recipient,
            authority: share.authority.into(),
            relayer_fee_balance: share.relayer_fee_balance,
            protocol_fee_balance: share.protocol_fee_balance,
            amount: share.amount,
        }
    }
}

#[cfg(feature = "full-api")]
impl From<ApiBalanceShare> for DarkpoolBalanceShare {
    fn from(share: ApiBalanceShare) -> Self {
        DarkpoolBalanceShare {
            mint: share.mint,
            owner: share.owner,
            relayer_fee_recipient: share.relayer_fee_recipient,
            authority: share.authority.into(),
            relayer_fee_balance: share.relayer_fee_balance,
            protocol_fee_balance: share.protocol_fee_balance,
            amount: share.amount,
        }
    }
}

/// A deposit permit for Permit2
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiDepositPermit {
    /// The permit nonce
    #[serde(with = "serde_helpers::u256_as_string")]
    pub nonce: U256,
    /// The permit deadline
    #[serde(with = "serde_helpers::u256_as_string")]
    pub deadline: U256,
    /// The permit signature (base64 encoded)
    #[serde(with = "serde_helpers::bytes_as_base64_string")]
    pub signature: Vec<u8>,
}

#[cfg(feature = "full-api")]
impl From<ApiDepositPermit> for DepositAuth {
    fn from(permit: ApiDepositPermit) -> Self {
        DepositAuth {
            permit2Nonce: permit.nonce,
            permit2Deadline: permit.deadline,
            permit2Signature: Bytes::from(permit.signature),
        }
    }
}
