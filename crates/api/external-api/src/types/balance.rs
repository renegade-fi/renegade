//! API types for balances

#[cfg(feature = "full-api")]
use std::str::FromStr;

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
#[cfg(feature = "full-api")]
use util::hex::address_from_hex_string;
use util::hex::address_to_hex_string;

use super::crypto_primitives::{ApiPoseidonCSPRNG, ApiSchnorrPublicKey, ApiSchnorrPublicKeyShare};
use crate::error::ApiTypeError;

// -----------------
// | Balance Types |
// -----------------

/// A balance in an account
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiBalance {
    /// The token mint address
    pub mint: String,
    /// The owner address
    pub owner: String,
    /// The relayer fee recipient address
    pub relayer_fee_recipient: String,
    /// The authority public key
    pub authority: ApiSchnorrPublicKey,
    /// The relayer fee balance
    pub relayer_fee_balance: String,
    /// The protocol fee balance
    pub protocol_fee_balance: String,
    /// The available amount
    pub amount: String,
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
            mint: address_to_hex_string(&inner.mint),
            owner: address_to_hex_string(&inner.owner),
            relayer_fee_recipient: address_to_hex_string(&inner.relayer_fee_recipient),
            authority: inner.authority.into(),
            relayer_fee_balance: inner.relayer_fee_balance.to_string(),
            protocol_fee_balance: inner.protocol_fee_balance.to_string(),
            amount: inner.amount.to_string(),
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
        let mint = address_from_hex_string(&api_balance.mint).map_err(ApiTypeError::parsing)?;

        let owner = address_from_hex_string(&api_balance.owner).map_err(ApiTypeError::parsing)?;

        let relayer_fee_recipient = address_from_hex_string(&api_balance.relayer_fee_recipient)
            .map_err(ApiTypeError::parsing)?;

        let authority = api_balance.authority.into();
        let relayer_fee_balance =
            Amount::from_str(&api_balance.relayer_fee_balance).map_err(ApiTypeError::parsing)?;

        let protocol_fee_balance =
            Amount::from_str(&api_balance.protocol_fee_balance).map_err(ApiTypeError::parsing)?;

        let amount = Amount::from_str(&api_balance.amount).map_err(ApiTypeError::parsing)?;

        let inner = DarkpoolBalance {
            mint,
            owner,
            relayer_fee_recipient,
            authority,
            relayer_fee_balance,
            protocol_fee_balance,
            amount,
        };
        let recovery_stream = api_balance.recovery_stream.into();
        let share_stream = api_balance.share_stream.into();
        let public_share = api_balance.public_shares.try_into()?;

        Ok(DarkpoolStateBalance { recovery_stream, share_stream, inner, public_share })
    }
}

/// Public shares of a balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiBalanceShare {
    /// The token mint address share
    pub mint: String,
    /// The owner address share
    pub owner: String,
    /// The relayer fee recipient address share
    pub relayer_fee_recipient: String,
    /// The authority public key share
    pub authority: ApiSchnorrPublicKeyShare,
    /// The relayer fee balance share
    pub relayer_fee_balance: String,
    /// The protocol fee balance share
    pub protocol_fee_balance: String,
    /// The amount share
    pub amount: String,
}

#[cfg(feature = "full-api")]
impl From<DarkpoolBalanceShare> for ApiBalanceShare {
    fn from(share: DarkpoolBalanceShare) -> Self {
        Self {
            mint: share.mint.to_string(),
            owner: share.owner.to_string(),
            relayer_fee_recipient: share.relayer_fee_recipient.to_string(),
            authority: share.authority.into(),
            relayer_fee_balance: share.relayer_fee_balance.to_string(),
            protocol_fee_balance: share.protocol_fee_balance.to_string(),
            amount: share.amount.to_string(),
        }
    }
}

#[cfg(feature = "full-api")]
impl TryFrom<ApiBalanceShare> for DarkpoolBalanceShare {
    type Error = ApiTypeError;

    fn try_from(share: ApiBalanceShare) -> Result<Self, Self::Error> {
        let mint = Scalar::from_decimal_string(&share.mint).map_err(ApiTypeError::parsing)?;
        let owner = Scalar::from_decimal_string(&share.owner).map_err(ApiTypeError::parsing)?;
        let relayer_fee_recipient = Scalar::from_decimal_string(&share.relayer_fee_recipient)
            .map_err(ApiTypeError::parsing)?;
        let authority = share.authority.try_into()?;
        let relayer_fee_balance = Scalar::from_decimal_string(&share.relayer_fee_balance)
            .map_err(ApiTypeError::parsing)?;
        let protocol_fee_balance = Scalar::from_decimal_string(&share.protocol_fee_balance)
            .map_err(ApiTypeError::parsing)?;
        let amount = Scalar::from_decimal_string(&share.amount).map_err(ApiTypeError::parsing)?;

        Ok(DarkpoolBalanceShare {
            mint,
            owner,
            relayer_fee_recipient,
            authority,
            relayer_fee_balance,
            protocol_fee_balance,
            amount,
        })
    }
}

/// A deposit permit for Permit2
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiDepositPermit {
    /// The permit nonce
    pub nonce: String,
    /// The permit deadline
    pub deadline: String,
    /// The permit signature (base64 encoded)
    pub signature: String,
}

#[cfg(feature = "full-api")]
impl TryFrom<ApiDepositPermit> for DepositAuth {
    type Error = ApiTypeError;

    fn try_from(permit: ApiDepositPermit) -> Result<Self, Self::Error> {
        use std::str::FromStr;

        use alloy::primitives::{Bytes, U256};
        use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD as BASE64_ENGINE};

        let permit_signature_bytes = BASE64_ENGINE
            .decode(&permit.signature)
            .map_err(|e| ApiTypeError::parsing(format!("invalid permit signature: {e}")))?;

        Ok(DepositAuth {
            permit2Nonce: U256::from_str(&permit.nonce)
                .map_err(|e| ApiTypeError::parsing(format!("invalid permit nonce: {e}")))?,
            permit2Deadline: U256::from_str(&permit.deadline)
                .map_err(|e| ApiTypeError::parsing(format!("invalid permit deadline: {e}")))?,
            permit2Signature: Bytes::from(permit_signature_bytes),
        })
    }
}
