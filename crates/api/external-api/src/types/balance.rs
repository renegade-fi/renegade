//! API types for balances

use darkpool_types::balance::Balance;
#[cfg(feature = "full-api")]
use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
use serde::{Deserialize, Serialize};
use util::hex::address_to_hex_string;

use super::crypto_primitives::{ApiPoseidonCSPRNG, ApiSchnorrPublicKey, ApiSchnorrPublicKeyShare};

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

impl From<Balance> for ApiBalance {
    fn from(bal: Balance) -> Self {
        Self {
            mint: address_to_hex_string(&bal.mint),
            owner: address_to_hex_string(&bal.owner),
            relayer_fee_recipient: address_to_hex_string(&bal.relayer_fee_recipient),
            authority: bal.authority.into(),
            relayer_fee_balance: bal.relayer_fee_balance.to_string(),
            protocol_fee_balance: bal.protocol_fee_balance.to_string(),
            amount: bal.amount.to_string(),
            // TODO: Add the correct CSPRNG state
            recovery_stream: ApiPoseidonCSPRNG { seed: "".to_string(), index: 0 },
            share_stream: ApiPoseidonCSPRNG { seed: "".to_string(), index: 0 },
            public_shares: dummy_api_balance_share(),
        }
    }
}

/// The public shares of a balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiBalanceShare {
    /// The mint share
    pub mint: String,
    /// The owner share
    pub owner: String,
    /// The relayer fee recipient share
    pub relayer_fee_recipient: String,
    /// The authority share
    pub authority: ApiSchnorrPublicKeyShare,
    /// The relayer fee balance share
    pub relayer_fee_balance: String,
    /// The protocol fee balance share
    pub protocol_fee_balance: String,
    /// The amount share
    pub amount: String,
}

// TODO: Remove this
fn dummy_api_balance_share() -> ApiBalanceShare {
    ApiBalanceShare {
        mint: "".to_string(),
        owner: "".to_string(),
        relayer_fee_recipient: "".to_string(),
        authority: ApiSchnorrPublicKeyShare { x: "".to_string(), y: "".to_string() },
        relayer_fee_balance: "".to_string(),
        protocol_fee_balance: "".to_string(),
        amount: "".to_string(),
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
    type Error = String;

    fn try_from(permit: ApiDepositPermit) -> Result<Self, Self::Error> {
        use std::str::FromStr;

        use alloy::primitives::{Bytes, U256};
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};

        let permit_signature_bytes = BASE64_ENGINE
            .decode(&permit.signature)
            .map_err(|e| format!("invalid permit signature: {e}"))?;

        Ok(DepositAuth {
            permit2Nonce: U256::from_str(&permit.nonce)
                .map_err(|e| format!("invalid permit nonce: {e}"))?,
            permit2Deadline: U256::from_str(&permit.deadline)
                .map_err(|e| format!("invalid permit deadline: {e}"))?,
            permit2Signature: Bytes::from(permit_signature_bytes),
        })
    }
}
