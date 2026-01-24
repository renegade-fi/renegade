//! API types for external matches

use alloy::rpc::types::TransactionRequest;
use serde::{Deserialize, Serialize};
#[cfg(feature = "full-api")]
use types_account::order::Order;

#[cfg(feature = "full-api")]
use crate::error::ApiTypeError;

#[cfg(feature = "full-api")]
use {
    alloy::primitives::Address,
    circuit_types::Amount,
    circuit_types::fixed_point::FixedPoint,
    constants::Scalar,
    darkpool_types::bounded_match_result::BoundedMatchResult,
    darkpool_types::fee::FeeTake,
    darkpool_types::intent::Intent,
    std::str::FromStr,
    types_account::order::OrderMetadata,
    util::get_current_time_millis,
    util::hex::{address_from_hex_string, address_to_hex_string},
};

// ------------------
// | External Order |
// ------------------

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

#[cfg(feature = "full-api")]
impl ExternalOrder {
    /// Parse an intent from the external order
    pub fn parse_intent(&self) -> Result<Intent, ApiTypeError> {
        let in_token = address_from_hex_string(&self.input_mint).map_err(ApiTypeError::parsing)?;
        let out_token =
            address_from_hex_string(&self.output_mint).map_err(ApiTypeError::parsing)?;
        let amount_in = Amount::from_str(&self.input_amount).map_err(ApiTypeError::parsing)?;

        // External orders have no owner or min price
        let owner = Address::ZERO;
        let min_price = FixedPoint::zero();

        Ok(Intent { in_token, out_token, owner, min_price, amount_in })
    }

    /// Parse the metadata for the order
    pub fn parse_order_metadata(&self) -> Result<OrderMetadata, ApiTypeError> {
        let min_fill = Amount::from_str(&self.min_fill_size).map_err(ApiTypeError::parsing)?;
        Ok(OrderMetadata { min_fill_size: min_fill, allow_external_matches: true })
    }
}

#[cfg(feature = "full-api")]
impl TryFrom<ExternalOrder> for Order {
    type Error = ApiTypeError;

    fn try_from(order: ExternalOrder) -> Result<Self, Self::Error> {
        use darkpool_types::intent::DarkpoolStateIntent;

        let intent = order.parse_intent()?;
        let metadata = order.parse_order_metadata()?;

        // An external order has no share or recovery stream, so we default the seeds
        // for compatibility with the matching engine
        let share_stream_seed = Scalar::zero();
        let recovery_stream_seed = Scalar::zero();
        let state_intent =
            DarkpoolStateIntent::new(intent, share_stream_seed, recovery_stream_seed);

        Ok(Order::new(state_intent, metadata))
    }
}

// ---------------
// | Quote Types |
// ---------------

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
    pub match_result: ApiBoundedMatchResult,
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

/// A timestamped price
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiTimestampedPrice {
    /// The price as a string
    pub price: String,
    /// The timestamp in milliseconds
    pub timestamp: u64,
}

#[cfg(feature = "full-api")]
impl ApiTimestampedPrice {
    /// Constructor
    pub fn new(price: FixedPoint) -> Self {
        let price_str = price.repr.to_string();
        let timestamp = get_current_time_millis();
        Self { price: price_str, timestamp }
    }
}

/// Fees taken from a match
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ApiFeeTake {
    /// The relayer fee amount
    pub relayer_fee: String,
    /// The protocol fee amount
    pub protocol_fee: String,
}

#[cfg(feature = "full-api")]
impl From<FeeTake> for ApiFeeTake {
    fn from(fee_take: FeeTake) -> Self {
        Self {
            relayer_fee: fee_take.relayer_fee.to_string(),
            protocol_fee: fee_take.protocol_fee.to_string(),
        }
    }
}

/// An asset transfer in an external match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiExternalAssetTransfer {
    /// The token mint address
    pub mint: String,
    /// The amount
    pub amount: String,
}

#[cfg(feature = "full-api")]
impl ApiExternalAssetTransfer {
    /// Constructor
    pub fn new(mint: Address, amount: Amount) -> Self {
        Self { mint: address_to_hex_string(&mint), amount: amount.to_string() }
    }
}

// ----------------------
// | Match Bundle Types |
// ----------------------

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

#[cfg(feature = "full-api")]
impl From<BoundedMatchResult> for ApiBoundedMatchResult {
    fn from(match_result: BoundedMatchResult) -> Self {
        // This is the price in units of the external party's output per input token
        let output_quoted_price = match_result.price.inverse().expect("price is zero");

        // Compute the input bounds by multiplying through the price
        let input_quoted_price = match_result.price;
        let min_input = input_quoted_price.floor_mul_int(match_result.min_internal_party_amount_in);
        let max_input = input_quoted_price.floor_mul_int(match_result.max_internal_party_amount_in);

        Self {
            input_mint: address_to_hex_string(&match_result.internal_party_output_token),
            output_mint: address_to_hex_string(&match_result.internal_party_input_token),
            price_fp: input_quoted_price.repr.to_string(),
            output_quoted_price_fp: output_quoted_price.repr.to_string(),
            min_input_amount: min_input.to_string(),
            max_input_amount: max_input.to_string(),
        }
    }
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
pub struct BoundedExternalMatchApiBundle {
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
