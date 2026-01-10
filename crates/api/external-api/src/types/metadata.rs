//! API types for exchange metadata

use serde::{Deserialize, Serialize};

use super::market::ApiToken;

// ------------------
// | Metadata Types |
// ------------------

/// Response containing exchange metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExchangeMetadataResponse {
    /// The chain ID
    pub chain_id: u64,
    /// The settlement contract address
    pub settlement_contract_address: String,
    /// The executor address
    pub executor_address: String,
    /// The relayer fee recipient address
    pub relayer_fee_recipient: String,
    /// The list of supported tokens
    pub supported_tokens: Vec<ApiToken>,
}
