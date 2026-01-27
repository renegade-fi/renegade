//! API types for exchange metadata

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

use super::market::ApiToken;
use crate::serde_helpers::address_as_string;

// ------------------
// | Metadata Types |
// ------------------

/// Response containing exchange metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExchangeMetadataResponse {
    /// The chain ID
    pub chain_id: u64,
    /// The settlement contract address
    #[serde(with = "address_as_string")]
    pub settlement_contract_address: Address,
    /// The executor address
    #[serde(with = "address_as_string")]
    pub executor_address: Address,
    /// The relayer fee recipient address
    #[serde(with = "address_as_string")]
    pub relayer_fee_recipient: Address,
    /// The list of supported tokens
    pub supported_tokens: Vec<ApiToken>,
}
