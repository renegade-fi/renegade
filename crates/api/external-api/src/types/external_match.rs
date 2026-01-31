//! API types for external matches

use alloy::primitives::Address;
use alloy::rpc::types::TransactionRequest;
use circuit_types::{Amount, fixed_point::FixedPoint};
use constants::Scalar;
use serde::{Deserialize, Serialize};

use crate::serde_helpers;

#[cfg(feature = "full-api")]
use {
    crypto::fields::scalar_to_u128, darkpool_types::bounded_match_result::BoundedMatchResult,
    darkpool_types::fee::FeeRates, darkpool_types::fee::FeeTake, darkpool_types::intent::Intent,
    darkpool_types::settlement_obligation::SettlementObligation, types_account::order::Order,
    types_account::order::OrderMetadata, types_core::TimestampedPrice,
    util::get_current_time_millis,
};

// ------------------
// | External Order |
// ------------------

/// An external order for matching
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ExternalOrder {
    /// The input token mint address
    #[serde(with = "serde_helpers::address_as_string")]
    pub input_mint: Address,
    /// The output token mint address
    #[serde(with = "serde_helpers::address_as_string")]
    pub output_mint: Address,
    /// The input amount
    #[serde(with = "serde_helpers::amount_as_string")]
    pub input_amount: Amount,
    /// The output amount
    #[serde(with = "serde_helpers::amount_as_string")]
    pub output_amount: Amount,
    /// Whether to use exact output amount
    pub use_exact_output_amount: bool,
    /// The minimum fill size
    #[serde(with = "serde_helpers::amount_as_string")]
    pub min_fill_size: Amount,
}

#[cfg(feature = "full-api")]
impl ExternalOrder {
    /// Parse an intent from the external order
    pub fn intent(&self) -> Intent {
        // External orders have no owner or min price
        let owner = Address::ZERO;
        let min_price = FixedPoint::zero();

        Intent {
            in_token: self.input_mint,
            out_token: self.output_mint,
            owner,
            min_price,
            amount_in: self.input_amount,
        }
    }

    /// Parse the metadata for the order
    pub fn order_metadata(&self) -> OrderMetadata {
        OrderMetadata { min_fill_size: self.min_fill_size, allow_external_matches: true }
    }
}

#[cfg(feature = "full-api")]
impl From<ExternalOrder> for Order {
    fn from(order: ExternalOrder) -> Self {
        use darkpool_types::intent::DarkpoolStateIntent;

        let intent = order.intent();
        let metadata = order.order_metadata();

        // An external order has no share or recovery stream, so we default the seeds
        // for compatibility with the matching engine
        let share_stream_seed = Scalar::zero();
        let recovery_stream_seed = Scalar::zero();
        let state_intent =
            DarkpoolStateIntent::new(intent, share_stream_seed, recovery_stream_seed);

        Order::new(state_intent, metadata)
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
    #[serde(with = "serde_helpers::bytes_as_hex_string")]
    pub signature: Vec<u8>,
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

/// A timestamped price
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiTimestampedPrice {
    /// The price as a string
    #[serde(with = "serde_helpers::f64_as_string")]
    pub price: f64,
    /// The timestamp in milliseconds
    pub timestamp: u64,
}

#[cfg(feature = "full-api")]
impl ApiTimestampedPrice {
    /// Constructor
    pub fn new(price: FixedPoint) -> Self {
        let price = price.to_f64();
        Self { price, timestamp: get_current_time_millis() }
    }
}

#[cfg(feature = "full-api")]
impl From<ApiTimestampedPrice> for TimestampedPrice {
    fn from(price: ApiTimestampedPrice) -> Self {
        Self { price: price.price, timestamp: price.timestamp }
    }
}

/// Fees taken from a match
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ApiFeeTake {
    /// The relayer fee amount
    #[serde(with = "serde_helpers::amount_as_string")]
    pub relayer_fee: Amount,
    /// The protocol fee amount
    #[serde(with = "serde_helpers::amount_as_string")]
    pub protocol_fee: Amount,
}

#[cfg(feature = "full-api")]
impl From<FeeTake> for ApiFeeTake {
    fn from(fee_take: FeeTake) -> Self {
        Self { relayer_fee: fee_take.relayer_fee, protocol_fee: fee_take.protocol_fee }
    }
}

/// An asset transfer in an external match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiExternalAssetTransfer {
    /// The token mint address
    #[serde(with = "serde_helpers::address_as_string")]
    pub mint: Address,
    /// The amount
    #[serde(with = "serde_helpers::amount_as_string")]
    pub amount: Amount,
}

#[cfg(feature = "full-api")]
impl ApiExternalAssetTransfer {
    /// Constructor
    pub fn new(mint: Address, amount: Amount) -> Self {
        Self { mint, amount }
    }
}

// ----------------------
// | Match Bundle Types |
// ----------------------

/// An API server external match result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiExternalMatchResult {
    /// The mint of the input token in the matched asset pair
    #[serde(with = "serde_helpers::address_as_string")]
    pub input_mint: Address,
    /// The mint of the output token in the matched asset pair
    #[serde(with = "serde_helpers::address_as_string")]
    pub output_mint: Address,
    /// The amount of the input token exchanged by the match
    #[serde(with = "serde_helpers::amount_as_string")]
    pub input_amount: Amount,
    /// The amount of the output token exchanged by the match
    #[serde(with = "serde_helpers::amount_as_string")]
    pub output_amount: Amount,
}

#[cfg(feature = "full-api")]
impl From<SettlementObligation> for ApiExternalMatchResult {
    fn from(obligation: SettlementObligation) -> Self {
        Self {
            input_mint: obligation.input_token,
            output_mint: obligation.output_token,
            input_amount: obligation.amount_in,
            output_amount: obligation.amount_out,
        }
    }
}

/// A bounded match result for malleable matches
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiBoundedMatchResult {
    /// The input token mint
    #[serde(with = "serde_helpers::address_as_string")]
    pub input_mint: Address,
    /// The output token mint
    #[serde(with = "serde_helpers::address_as_string")]
    pub output_mint: Address,
    /// The fixed-point price
    ///
    /// In units of the external party's output per input token
    #[serde(with = "serde_helpers::fixed_point_as_string")]
    pub price_fp: FixedPoint,
    /// The minimum input amount
    #[serde(with = "serde_helpers::amount_as_string")]
    pub min_input_amount: Amount,
    /// The maximum input amount
    #[serde(with = "serde_helpers::amount_as_string")]
    pub max_input_amount: Amount,
}

#[cfg(feature = "full-api")]
impl From<BoundedMatchResult> for ApiBoundedMatchResult {
    fn from(match_result: BoundedMatchResult) -> Self {
        // The price in the bounded match result is in units of the internal party's
        // output per input token
        let input_quoted_price = match_result.price;
        let output_quoted_price = input_quoted_price.inverse().expect("price is zero");

        // Compute the input amount bounds
        let min_input_scalar =
            match_result.price.floor_mul_int(match_result.min_internal_party_amount_in);
        let max_input_scalar =
            match_result.price.floor_mul_int(match_result.max_internal_party_amount_in);

        Self {
            input_mint: match_result.internal_party_output_token,
            output_mint: match_result.internal_party_input_token,
            price_fp: output_quoted_price,
            min_input_amount: scalar_to_u128(&min_input_scalar),
            max_input_amount: scalar_to_u128(&max_input_scalar),
        }
    }
}

#[cfg(feature = "full-api")]
impl From<ApiBoundedMatchResult> for BoundedMatchResult {
    fn from(api_result: ApiBoundedMatchResult) -> Self {
        // The API price is in units of external output / external input
        // which equals internal input / internal output
        // So the internal price is the inverse
        let internal_price = api_result.price_fp.inverse().expect("price is zero");

        // The API amounts are the external party's input amounts
        // To get internal party input amounts, multiply by the API price
        let min_internal_scalar = api_result.price_fp.floor_mul_int(api_result.min_input_amount);
        let max_internal_scalar = api_result.price_fp.floor_mul_int(api_result.max_input_amount);

        Self {
            internal_party_input_token: api_result.output_mint,
            internal_party_output_token: api_result.input_mint,
            min_internal_party_amount_in: scalar_to_u128(&min_internal_scalar),
            max_internal_party_amount_in: scalar_to_u128(&max_internal_scalar),
            price: internal_price,
            block_deadline: 0,
        }
    }
}

/// Fee rates for a match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeTakeRate {
    /// The relayer fee rate
    #[serde(with = "serde_helpers::fixed_point_as_string")]
    pub relayer_fee_rate: FixedPoint,
    /// The protocol fee rate
    #[serde(with = "serde_helpers::fixed_point_as_string")]
    pub protocol_fee_rate: FixedPoint,
}

#[cfg(feature = "full-api")]
impl From<FeeRates> for FeeTakeRate {
    fn from(fee_rates: FeeRates) -> Self {
        Self {
            relayer_fee_rate: fee_rates.relayer_fee_rate,
            protocol_fee_rate: fee_rates.protocol_fee_rate,
        }
    }
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
