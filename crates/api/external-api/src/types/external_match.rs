//! API types for external matches

use alloy::rpc::types::TransactionRequest;
use serde::{Deserialize, Serialize};

// ---------------------
// | External Order    |
// ---------------------

/// An external order for matching
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ExternalOrder {
    /// The input token mint address
    pub input_mint: String,
    /// The output token mint address
    pub output_mint: String,
    /// The input amount
    pub input_amount: String,
    /// The output amount
    pub output_amount: String,
    /// Whether to use exact output amount
    pub use_exact_output_amount: bool,
    /// The minimum fill size
    pub min_fill_size: String,
}

// -----------------
// | Quote Types   |
// -----------------

/// A signed quote for an external order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiSignedQuote {
    /// The quote details
    pub quote: ApiExternalQuote,
    /// The signature over the quote
    pub signature: String,
    /// The deadline for the quote
    pub deadline: u64,
}

/// A quote for an external order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiExternalQuote {
    /// The external order
    pub order: ExternalOrder,
    /// The match result
    pub match_result: ApiExternalMatchResult,
    /// The fees for the match
    pub fees: ApiFeeTake,
    /// The amount to send
    pub send: ApiExternalAssetTransfer,
    /// The amount to receive
    pub receive: ApiExternalAssetTransfer,
    /// The price of the match
    pub price: ApiTimestampedPrice,
    /// The timestamp of the quote
    pub timestamp: u64,
}

/// The result of an external match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiExternalMatchResult {
    /// The input token mint
    pub input_mint: String,
    /// The output token mint
    pub output_mint: String,
    /// The input amount
    pub input_amount: String,
    /// The output amount
    pub output_amount: String,
}

/// A timestamped price
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiTimestampedPrice {
    /// The price as a string
    pub price: String,
    /// The timestamp in milliseconds
    pub timestamp: u64,
}

/// Fees taken from a match
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ApiFeeTake {
    /// The relayer fee amount
    pub relayer_fee: String,
    /// The protocol fee amount
    pub protocol_fee: String,
}

/// An asset transfer in an external match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiExternalAssetTransfer {
    /// The token mint address
    pub mint: String,
    /// The amount
    pub amount: String,
}

// -------------------------
// | Match Bundle Types    |
// -------------------------

/// A bounded match result for malleable matches
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiBoundedMatchResult {
    /// The input token mint
    pub input_mint: String,
    /// The output token mint
    pub output_mint: String,
    /// The fixed-point price
    pub price_fp: String,
    /// The output quoted price in fixed-point
    pub output_quoted_price_fp: String,
    /// The minimum input amount
    pub min_input_amount: String,
    /// The maximum input amount
    pub max_input_amount: String,
}

/// Fee rates for a match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeTakeRate {
    /// The relayer fee rate
    pub relayer_fee_rate: String,
    /// The protocol fee rate
    pub protocol_fee_rate: String,
}

/// A malleable atomic match bundle
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MalleableAtomicMatchApiBundle {
    /// The bounded match result
    pub match_result: ApiBoundedMatchResult,
    /// The fee rates
    pub fee_rates: FeeTakeRate,
    /// The maximum receive amount
    pub max_receive: ApiExternalAssetTransfer,
    /// The minimum receive amount
    pub min_receive: ApiExternalAssetTransfer,
    /// The maximum send amount
    pub max_send: ApiExternalAssetTransfer,
    /// The minimum send amount
    pub min_send: ApiExternalAssetTransfer,
    /// The settlement transaction
    pub settlement_tx: TransactionRequest,
    /// The deadline for the match
    pub deadline: u64,
}

/// Gas sponsorship information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GasSponsorshipInfo {
    /// The refund amount
    pub refund_amount: u128,
    /// Whether to refund in native ETH
    pub refund_native_eth: bool,
    /// The optional refund address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
}
