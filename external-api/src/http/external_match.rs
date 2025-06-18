//! API types for external matches
//!
//! External matches are those brokered by the darkpool between an "internal"
//! party (one with state committed into the protocol), and an external party,
//! one whose trade obligations are fulfilled directly through erc20 transfers;
//! and importantly do not commit state into the protocol
//!
//! Endpoints here allow permissioned solvers, searchers, etc to "ping the pool"
//! for consenting liquidity on a given token pair.

use alloy::rpc::types::TransactionRequest;
use circuit_types::{
    fees::{FeeTake, FeeTakeRate},
    fixed_point::FixedPoint,
    max_price,
    order::OrderSide,
    r#match::{BoundedMatchResult, ExternalMatchResult},
    Amount,
};
use common::types::TimestampedPrice;
use constants::{Scalar, NATIVE_ASSET_ADDRESS};
use num_bigint::BigUint;
use num_traits::Zero;
use renegade_crypto::fields::scalar_to_u128;
use serde::{Deserialize, Serialize};
use util::{
    get_current_time_millis,
    hex::{biguint_from_hex_string, biguint_to_hex_addr},
    on_chain::get_external_match_fee,
};

use crate::{deserialize_biguint_from_hex_string, serialize_biguint_to_hex_addr};

#[cfg(feature = "full-api")]
use common::types::{
    proof_bundles::{AtomicMatchSettleBundle, MalleableAtomicMatchSettleBundle},
    wallet::Order,
};

// ------------------
// | Error Messages |
// ------------------

/// The error message emitted when an external order specifies both the quote
/// and base size
const ERR_MULTIPLE_SIZING_PARAMS: &str =
    "exactly one of base_amount, quote_amount, or exact_output_amount must be set";
/// The error message emitted when an exact output amount is specified and a
/// min fill size is also specified
const ERR_MIN_FILL_SIZE_NOT_ZERO: &str =
    "Cannot set `min_fill_size` if `exact_output_amount` is specified";

// ---------------
// | HTTP Routes |
// ---------------

/// The route for requesting a quote on an external match
pub const REQUEST_EXTERNAL_QUOTE_ROUTE: &str = "/v0/matching-engine/quote";
/// The route used to assemble an external match quote into a settlement bundle
pub const ASSEMBLE_EXTERNAL_MATCH_ROUTE: &str = "/v0/matching-engine/assemble-external-match";
/// The route used to assemble an external match quote into a malleable
pub const ASSEMBLE_MALLEABLE_EXTERNAL_MATCH_ROUTE: &str =
    "/v0/matching-engine/assemble-malleable-external-match";
/// The route for requesting an atomic match
pub const REQUEST_EXTERNAL_MATCH_ROUTE: &str = "/v0/matching-engine/request-external-match";

// -----------
// | Helpers |
// -----------

/// Processes a settlement transaction for an external match response
///
/// Practically this will swap the `input` and `data` fields, as clients expect
/// transaction calldata to be set in the `data` field
#[cfg(feature = "full-api")]
fn process_settlement_tx(tx: &mut TransactionRequest) {
    // If the data is not empty, do not modify it
    let calldata = &mut tx.input;
    let data_empty = calldata.data.as_ref().map(|d| d.is_empty()).unwrap_or(true);
    if !data_empty {
        return;
    }

    // Otherwise, swap the input and data
    let input = calldata.input.take().unwrap_or_default();
    calldata.data = Some(input);
}

// -------------------------------
// | HTTP Requests and Responses |
// -------------------------------

/// The request type for requesting an external match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalMatchRequest {
    /// Whether or not to include gas estimation in the response
    #[serde(default)]
    pub do_gas_estimation: bool,
    /// The receiver address of the match, if not the message sender
    #[serde(default)]
    pub receiver_address: Option<String>,
    /// The external order
    pub external_order: ExternalOrder,
}

/// The response type for requesting an external match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalMatchResponse {
    /// The match bundle
    pub match_bundle: AtomicMatchApiBundle,
}

/// The response type for requesting a malleable quote on an external order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MalleableExternalMatchResponse {
    /// The match bundle
    pub match_bundle: MalleableAtomicMatchApiBundle,
}

/// The request type for a quote on an external order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalQuoteRequest {
    /// The external order
    pub external_order: ExternalOrder,
}

/// The response type for a quote on an external order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalQuoteResponse {
    /// The signed quote
    pub signed_quote: SignedExternalQuote,
}

/// The request type for assembling an external match quote into a settlement
/// bundle
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssembleExternalMatchRequest {
    /// Whether or not to include gas estimation in the response
    #[serde(default)]
    pub do_gas_estimation: bool,
    /// Whether or not to allow shared access to the resulting bundle
    ///
    /// If true, the bundle may be sent to other clients requesting an external
    /// match. If false, the bundle will be exclusively held for some time
    #[serde(default)]
    pub allow_shared: bool,
    /// The receiver address of the match, if not the message sender
    #[serde(default)]
    pub receiver_address: Option<String>,
    /// The updated order if any changes have been made
    #[serde(default)]
    pub updated_order: Option<ExternalOrder>,
    /// The signed quote
    pub signed_quote: SignedExternalQuote,
}

// ------------------
// | Api Data Types |
// ------------------

/// An external order
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ExternalOrder {
    /// The mint (erc20 address) of the quote token
    #[serde(
        serialize_with = "serialize_biguint_to_hex_addr",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub quote_mint: BigUint,
    /// The mint (erc20 address) of the base token
    #[serde(
        serialize_with = "serialize_biguint_to_hex_addr",
        deserialize_with = "deserialize_biguint_from_hex_string"
    )]
    pub base_mint: BigUint,
    /// The side of the market this order is on
    pub side: OrderSide,
    /// The base amount of the order
    #[serde(default, alias = "amount")]
    pub base_amount: Amount,
    /// The quote amount of the order
    #[serde(default)]
    pub quote_amount: Amount,
    /// The exact output amount of the base token expected from the match
    #[serde(default)]
    pub exact_base_output: Amount,
    /// The exact output amount of the quote token expected from the match
    #[serde(default)]
    pub exact_quote_output: Amount,
    /// The minimum fill size for the order
    #[serde(default)]
    pub min_fill_size: Amount,
}

impl ExternalOrder {
    /// Validate the external order
    #[cfg(feature = "full-api")]
    pub fn validate(&self) -> Result<(), &'static str> {
        // Only one of the order sizing options can be set
        let base_zero = self.base_amount.is_zero();
        let quote_zero = self.quote_amount.is_zero();
        let exact_base_output = self.exact_base_output != 0;
        let exact_quote_output = self.exact_quote_output != 0;

        // Check that exactly one of the sizing constraints is set
        let n_sizes_set = (!base_zero as u8)
            + (!quote_zero as u8)
            + (exact_base_output as u8)
            + (exact_quote_output as u8);
        if n_sizes_set != 1 {
            return Err(ERR_MULTIPLE_SIZING_PARAMS);
        }

        // If an exact output is specified, the min size must be zero
        if self.is_exact_output() && self.min_fill_size > 0 {
            return Err(ERR_MIN_FILL_SIZE_NOT_ZERO);
        }

        Ok(())
    }

    /// Returns whether the order is for the chain-native asset
    pub fn trades_native_asset(&self) -> bool {
        let native_mint = biguint_from_hex_string(NATIVE_ASSET_ADDRESS).unwrap();
        self.base_mint == native_mint
    }

    /// Returns whether the order size is base denominated
    pub fn is_base_denominated(&self) -> bool {
        self.base_amount != 0 || self.exact_base_output != 0
    }

    /// Returns whether the order size is quote denominated
    pub fn is_quote_denominated(&self) -> bool {
        self.quote_amount != 0 || self.exact_quote_output != 0
    }

    /// Whether the order requests an exact output amount
    pub fn is_exact_output(&self) -> bool {
        self.exact_base_output != 0 || self.exact_quote_output != 0
    }

    /// Convert the external order to the standard `Order` type used throughout
    /// the relayer
    ///
    /// We need the price here to convert a quote denominated order into a base
    /// denominated order
    #[cfg(feature = "full-api")]
    pub fn to_internal_order(&self, price: FixedPoint, relayer_fee: FixedPoint) -> Order {
        let mut base_amount = self.get_base_amount(price, relayer_fee);
        let min_fill_size = self.get_min_fill_base();
        base_amount = Amount::max(min_fill_size, base_amount); // Ensure that base amount is at least the min fill size

        // If the min fill size is zero, set it to the base amount
        let worst_case_price = match self.side {
            OrderSide::Buy => max_price(),
            OrderSide::Sell => FixedPoint::from_integer(0),
        };

        Order {
            quote_mint: self.quote_mint.clone(),
            base_mint: self.base_mint.clone(),
            side: self.side,
            amount: base_amount,
            min_fill_size,
            worst_case_price,
            allow_external_matches: true,
        }
    }

    /// Get the base amount of the order implied by the external order
    ///
    /// The price here is expected to be decimal corrected; i.e. multiplied by
    /// the decimal diff for the two tokens
    pub fn get_base_amount(&self, price: FixedPoint, relayer_fee: FixedPoint) -> Amount {
        if self.base_amount != 0 {
            return self.base_amount;
        }

        // If an exact amount is specified, compensate for the fee in the receive amount
        if self.exact_base_output != 0 && self.side == OrderSide::Buy {
            let protocol_fee = get_external_match_fee(&self.base_mint);
            let total_fee = relayer_fee + protocol_fee;
            return Self::get_match_amount_for_receive(self.exact_base_output, total_fee);
        } else if self.exact_base_output != 0 {
            return self.exact_base_output;
        }

        let quote_amount = self.get_quote_amount(price, relayer_fee);
        let implied_base_amount = FixedPoint::ceil_div_int(quote_amount, price);
        scalar_to_u128(&implied_base_amount)
    }

    /// Get the quote amount of the order implied by the external order
    ///
    /// The price here is expected to be decimal corrected; i.e. multiplied by
    /// the decimal diff for the two tokens
    pub fn get_quote_amount(&self, price: FixedPoint, relayer_fee: FixedPoint) -> Amount {
        if self.quote_amount != 0 {
            return self.quote_amount;
        }

        // If an exact amount is specified, compensate for the fee in the receive amount
        if self.exact_quote_output != 0 && self.side == OrderSide::Sell {
            let protocol_fee = get_external_match_fee(&self.base_mint);
            let total_fee = relayer_fee + protocol_fee;
            return Self::get_match_amount_for_receive(self.exact_quote_output, total_fee);
        } else if self.exact_quote_output != 0 {
            return self.exact_quote_output;
        }

        let base_amount = self.get_base_amount(price, relayer_fee);
        let base_amount_scalar = Scalar::from(base_amount);
        let implied_quote_amount = price * base_amount_scalar;
        scalar_to_u128(&implied_quote_amount.floor())
    }

    /// Get the min fill size in units of the base token
    pub fn get_min_fill_base(&self) -> Amount {
        if self.is_quote_denominated() {
            return 0;
        } else if self.is_exact_output() {
            // If an exact output is specified, set the min fill size equal to it
            return self.exact_base_output;
        }

        self.min_fill_size
    }

    /// Get the minimum fill size in the quote token
    pub fn get_min_fill_quote(&self) -> Amount {
        if self.is_base_denominated() {
            return 0;
        } else if self.is_exact_output() {
            // If an exact output is specified, set the min fill size equal to it
            return self.exact_quote_output;
        }

        self.min_fill_size
    }

    /// Get the amount necessary to match the order at such that after fees the
    /// given amount is received exactly
    pub(super) fn get_match_amount_for_receive(
        receive_amount: Amount,
        total_fee: FixedPoint,
    ) -> Amount {
        let one_minus_fee = FixedPoint::one() - total_fee;
        let match_amount = FixedPoint::floor_div_int(receive_amount, one_minus_fee);
        scalar_to_u128(&match_amount)
    }
}

/// An atomic match settlement bundle, sent to the client so that they may
/// settle the match on-chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicMatchApiBundle {
    /// The match result
    pub match_result: ApiExternalMatchResult,
    /// The fees owed by the external party
    pub fees: FeeTake,
    /// The transfer received by the external party, net of fees
    pub receive: ApiExternalAssetTransfer,
    /// The transfer sent by the external party
    pub send: ApiExternalAssetTransfer,
    /// The transaction which settles the match on-chain
    pub settlement_tx: TransactionRequest,
}

impl AtomicMatchApiBundle {
    /// Create a new bundle from a `VALID MATCH SETTLE ATOMIC` bundle and a
    /// settlement transaction
    #[cfg(feature = "full-api")]
    pub fn new(
        match_bundle: &AtomicMatchSettleBundle,
        mut settlement_tx: TransactionRequest,
    ) -> Self {
        let statement = &match_bundle.atomic_match_proof.statement;
        let match_result = statement.match_result.clone();
        let fees = statement.external_party_fees;

        // Compute the received and sent assets net of fees
        let (received_mint, mut received_amount) = match_result.external_party_receive();
        let (sent_mint, sent_amount) = match_result.external_party_send();
        received_amount -= fees.total();

        // Update the format of the settlement transaction
        process_settlement_tx(&mut settlement_tx);
        Self {
            match_result: ApiExternalMatchResult::from(match_result),
            fees,
            receive: ApiExternalAssetTransfer {
                mint: biguint_to_hex_addr(&received_mint),
                amount: received_amount,
            },
            send: ApiExternalAssetTransfer {
                mint: biguint_to_hex_addr(&sent_mint),
                amount: sent_amount,
            },
            settlement_tx,
        }
    }
}

/// An atomic match settlement bundle using a malleable match result
///
/// A malleable match result is one in which the exact `base_amount` swapped
/// is not known at the time the proof is generated, and may be changed up until
/// it is submitted on-chain. Instead, a bounded match result gives a
/// `min_base_amount` and a `max_base_amount`, between which the `base_amount`
/// may take any value
///
/// The bundle is otherwise identical to the standard atomic match bundle
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MalleableAtomicMatchApiBundle {
    /// The match result
    pub match_result: ApiBoundedMatchResult,
    /// The fees owed by the external party
    pub fee_rates: FeeTakeRate,
    /// The maximum amount that the external party will receive
    pub max_receive: ApiExternalAssetTransfer,
    /// The minimum amount that the external party will receive
    pub min_receive: ApiExternalAssetTransfer,
    /// The maximum amount that the external party will send
    pub max_send: ApiExternalAssetTransfer,
    /// The minimum amount that the external party will send
    pub min_send: ApiExternalAssetTransfer,
    /// The transaction which settles the match on-chain
    pub settlement_tx: TransactionRequest,
}

impl MalleableAtomicMatchApiBundle {
    /// Create a new bundle from a `VALID MATCH SETTLE MALLEABLE` bundle and a
    /// settlement transaction
    #[cfg(feature = "full-api")]
    pub fn new(
        match_bundle: &MalleableAtomicMatchSettleBundle,
        mut settlement_tx: TransactionRequest,
    ) -> Self {
        let statement = &match_bundle.atomic_match_proof.statement;
        let match_result = statement.bounded_match_result.clone();
        let fee_rates = statement.external_fee_rates;

        // Compute the received and sent assets net of fees
        let max_base = match_result.max_base_amount;
        let min_base = match_result.min_base_amount;
        let (receive_mint, max_receive_amount) = match_result.external_party_receive(max_base);
        let (_, min_receive_amount) = match_result.external_party_receive(min_base);
        let (sent_mint, max_send_amount) = match_result.external_party_send(max_base);
        let (_, min_send_amount) = match_result.external_party_send(min_base);

        // Update the format of the settlement transaction
        process_settlement_tx(&mut settlement_tx);
        Self {
            match_result: ApiBoundedMatchResult::from(match_result),
            fee_rates,
            max_receive: ApiExternalAssetTransfer {
                mint: biguint_to_hex_addr(&receive_mint),
                amount: max_receive_amount,
            },
            min_receive: ApiExternalAssetTransfer {
                mint: biguint_to_hex_addr(&receive_mint),
                amount: min_receive_amount,
            },
            max_send: ApiExternalAssetTransfer {
                mint: biguint_to_hex_addr(&sent_mint),
                amount: max_send_amount,
            },
            min_send: ApiExternalAssetTransfer {
                mint: biguint_to_hex_addr(&sent_mint),
                amount: min_send_amount,
            },
            settlement_tx,
        }
    }
}

/// An asset transfer from an external party
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiExternalAssetTransfer {
    /// The mint of the asset
    pub mint: String,
    /// The amount of the asset
    pub amount: Amount,
}

/// An API server external match result
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiExternalMatchResult {
    /// The mint of the quote token in the matched asset pair
    pub quote_mint: String,
    /// The mint of the base token in the matched asset pair
    pub base_mint: String,
    /// The amount of the quote token exchanged by the match
    pub quote_amount: Amount,
    /// The amount of the base token exchanged by the match
    pub base_amount: Amount,
    /// The direction of the match
    pub direction: OrderSide,
}

impl From<ExternalMatchResult> for ApiExternalMatchResult {
    fn from(result: ExternalMatchResult) -> Self {
        let quote_mint = biguint_to_hex_addr(&result.quote_mint);
        let base_mint = biguint_to_hex_addr(&result.base_mint);
        // Convert the match direction to the side of the external party
        let direction = if result.direction { OrderSide::Buy } else { OrderSide::Sell };

        Self {
            quote_mint,
            base_mint,
            quote_amount: result.quote_amount,
            base_amount: result.base_amount,
            direction,
        }
    }
}

/// An API server bounded match result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiBoundedMatchResult {
    /// The mint of the quote token in the matched asset pair
    pub quote_mint: String,
    /// The mint of the base token in the matched asset pair
    pub base_mint: String,
    /// The fixed point representation of the price
    pub price_fp: FixedPoint,
    /// The minimum base amount of the match
    pub min_base_amount: Amount,
    /// The maximum base amount of the match
    pub max_base_amount: Amount,
    /// The direction of the match
    pub direction: OrderSide,
}

impl From<BoundedMatchResult> for ApiBoundedMatchResult {
    fn from(result: BoundedMatchResult) -> Self {
        let quote_mint = biguint_to_hex_addr(&result.quote_mint);
        let base_mint = biguint_to_hex_addr(&result.base_mint);
        let direction = if result.direction { OrderSide::Buy } else { OrderSide::Sell };

        Self {
            quote_mint,
            base_mint,
            price_fp: result.price,
            min_base_amount: result.min_base_amount,
            max_base_amount: result.max_base_amount,
            direction,
        }
    }
}

/// A signed quote for an external order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedExternalQuote {
    /// The quote
    pub quote: ApiExternalQuote,
    /// The signature
    pub signature: String,
}

impl SignedExternalQuote {
    /// Get the match result from the quote
    pub fn match_result(&self) -> ApiExternalMatchResult {
        self.quote.match_result.clone()
    }

    /// Get the fees from the quote
    pub fn fees(&self) -> FeeTake {
        self.quote.fees
    }

    /// Get the receive amount from the quote
    pub fn receive_amount(&self) -> ApiExternalAssetTransfer {
        self.quote.receive.clone()
    }

    /// Get the send amount from the quote
    pub fn send_amount(&self) -> ApiExternalAssetTransfer {
        self.quote.send.clone()
    }
}

/// A quote for an external order
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiExternalQuote {
    /// The external order
    pub order: ExternalOrder,
    /// The match result
    pub match_result: ApiExternalMatchResult,
    /// The estimated fees for the match
    pub fees: FeeTake,
    /// The amount sent by the external party
    pub send: ApiExternalAssetTransfer,
    /// The amount received by the external party, net of fees
    pub receive: ApiExternalAssetTransfer,
    /// The price of the match
    pub price: ApiTimestampedPrice,
    /// The timestamp of the quote
    pub timestamp: u64,
}

impl ApiExternalQuote {
    /// Create a new quote from an external match result and order
    pub fn new(order: ExternalOrder, result: &ExternalMatchResult, fees: FeeTake) -> Self {
        // Compute the sent and received assets
        let (send_mint, send_amount) = result.external_party_send();
        let (receive_mint, mut receive_amount) = result.external_party_receive();
        receive_amount -= fees.total();

        // Calculate implied price as quote_amount / base_amount
        let base_amt_f64 = result.base_amount as f64;
        let quote_amt_f64 = result.quote_amount as f64;
        let price = quote_amt_f64 / base_amt_f64;
        let timestamp = get_current_time_millis();

        Self {
            order,
            match_result: result.clone().into(),
            fees,
            send: ApiExternalAssetTransfer {
                mint: biguint_to_hex_addr(&send_mint),
                amount: send_amount,
            },
            receive: ApiExternalAssetTransfer {
                mint: biguint_to_hex_addr(&receive_mint),
                amount: receive_amount,
            },
            price: TimestampedPrice::new(price).into(),
            timestamp,
        }
    }
}

/// The price of a quote
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiTimestampedPrice {
    /// The price, serialized as a string to prevent floating point precision
    /// issues
    pub price: String,
    /// The timestamp, in milliseconds since the epoch
    pub timestamp: u64,
}

impl From<TimestampedPrice> for ApiTimestampedPrice {
    fn from(ts_price: TimestampedPrice) -> Self {
        let price = ts_price.price.to_string();
        Self { price, timestamp: ts_price.timestamp }
    }
}

impl From<ApiTimestampedPrice> for TimestampedPrice {
    fn from(api_price: ApiTimestampedPrice) -> Self {
        let price = api_price.price.parse::<f64>().unwrap();
        Self { price, timestamp: api_price.timestamp }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use circuit_types::fixed_point::FixedPoint;
    use constants::Scalar;
    use rand::{thread_rng, Rng};

    /// Test the method that computes match amounts for exact receive orders
    #[test]
    fn test_get_match_amount_for_receive() {
        let mut rng = thread_rng();
        let desired_amount = rng.gen_range(1e10..1e25) as u128;
        let full_fee = rng.gen_range(0.00001..0.01);
        let full_fee_fp = FixedPoint::from_f64_round_down(full_fee);
        let match_amt = ExternalOrder::get_match_amount_for_receive(desired_amount, full_fee_fp);

        // Apply the fee to this amount and ensure the result is the desired amount
        let match_amt_scalar = Scalar::from(match_amt);
        let fee_amt = full_fee_fp * match_amt_scalar;
        let net_amt = match_amt_scalar - fee_amt.floor();
        assert_eq!(scalar_to_u128(&net_amt), desired_amount);
    }
}
