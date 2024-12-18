//! API types for external matches
//!
//! External matches are those brokered by the darkpool between an "internal"
//! party (one with state committed into the protocol), and an external party,
//! one whose trade obligations are fulfilled directly through erc20 transfers;
//! and importantly do not commit state into the protocol
//!
//! Endpoints here allow permissioned solvers, searchers, etc to "ping the pool"
//! for consenting liquidity on a given token pair.

use circuit_types::{
    fixed_point::FixedPoint,
    max_price,
    order::OrderSide,
    r#match::{ExternalMatchResult, FeeTake},
    Amount,
};
use common::types::{proof_bundles::AtomicMatchSettleBundle, wallet::Order, TimestampedPrice};
use constants::{Scalar, NATIVE_ASSET_ADDRESS};
use ethers::types::transaction::eip2718::TypedTransaction;
use num_bigint::BigUint;
use renegade_crypto::fields::scalar_to_u128;
use serde::{Deserialize, Serialize};
use util::{
    get_current_time_millis,
    hex::{biguint_from_hex_string, biguint_to_hex_string},
};

use crate::{deserialize_biguint_from_hex_string, serialize_biguint_to_hex_addr};

// ---------------
// | HTTP Routes |
// ---------------

/// The route for requesting a quote on an external match
pub const REQUEST_EXTERNAL_QUOTE_ROUTE: &str = "/v0/matching-engine/quote";
/// The route to assemble an external match quote into a settlement bundle
pub const ASSEMBLE_EXTERNAL_MATCH_ROUTE: &str = "/v0/matching-engine/assemble-external-match";
/// The route for requesting an atomic match
pub const REQUEST_EXTERNAL_MATCH_ROUTE: &str = "/v0/matching-engine/request-external-match";

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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// The minimum fill size for the order
    #[serde(default)]
    pub min_fill_size: Amount,
}

impl ExternalOrder {
    /// Returns whether the order is for the chain-native asset
    pub fn trades_native_asset(&self) -> bool {
        let native_mint = biguint_from_hex_string(NATIVE_ASSET_ADDRESS).unwrap();
        self.base_mint == native_mint
    }

    /// Convert the external order to the standard `Order` type used throughout
    /// the relayer
    ///
    /// We need the price here to convert a quote denominated order into a base
    /// denominated order
    pub fn to_order_with_price(&self, price: FixedPoint) -> Order {
        let base_amount = self.get_base_amount(price);
        let mut min_fill_size = self.get_min_fill_in_base(price);
        min_fill_size = u128::min(min_fill_size, base_amount); // Ensure min fill size is not greater than the order size

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
    pub fn get_base_amount(&self, price: FixedPoint) -> Amount {
        if self.base_amount != 0 {
            return self.base_amount;
        }

        let implied_base_amount = FixedPoint::floor_div_int(self.quote_amount, price);
        scalar_to_u128(&implied_base_amount)
    }

    /// Get the quote amount of the order implied by the external order
    ///
    /// The price here is expected to be decimal corrected; i.e. multiplied by
    /// the decimal diff for the two tokens
    pub fn get_quote_amount(&self, price: FixedPoint) -> Amount {
        if self.quote_amount != 0 {
            return self.quote_amount;
        }

        let base_amount_scalar = Scalar::from(self.base_amount);
        let implied_quote_amount = price * base_amount_scalar;
        scalar_to_u128(&implied_quote_amount.floor())
    }

    /// Get the min fill size in units of the base token
    ///
    /// If the order size is specified in the `base_amount` field, this is
    /// trivial. If instead the order size is specified in the `quote_amount`
    /// field, we must convert through the price
    fn get_min_fill_in_base(&self, price: FixedPoint) -> Amount {
        let min_fill = self.min_fill_size;
        if self.base_amount != 0 {
            return min_fill;
        }

        // Add one to round up
        let div = FixedPoint::floor_div_int(min_fill, price) + Scalar::one();
        scalar_to_u128(&div)
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
    pub settlement_tx: TypedTransaction,
}

impl AtomicMatchApiBundle {
    /// Create a new bundle from a `VALID MATCH SETTLE ATOMIC` bundle and a
    /// settlement transaction
    pub fn new(match_bundle: &AtomicMatchSettleBundle, settlement_tx: TypedTransaction) -> Self {
        let statement = &match_bundle.atomic_match_proof.statement;
        let match_result = statement.match_result.clone();
        let fees = statement.external_party_fees;

        // Compute the received and sent assets net of fees
        let (received_mint, mut received_amount) = match_result.external_party_receive();
        received_amount -= fees.total();
        let (sent_mint, sent_amount) = match_result.external_party_send();

        Self {
            match_result: ApiExternalMatchResult::from(match_result),
            fees,
            receive: ApiExternalAssetTransfer {
                mint: biguint_to_hex_string(&received_mint),
                amount: received_amount,
            },
            send: ApiExternalAssetTransfer {
                mint: biguint_to_hex_string(&sent_mint),
                amount: sent_amount,
            },
            settlement_tx,
        }
    }
}

/// An asset transfer from an external party
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiExternalAssetTransfer {
    /// The mint of the asset
    pub mint: String,
    /// The amount of the asset
    pub amount: Amount,
}

/// An API server external match result
#[derive(Clone, Debug, Serialize, Deserialize)]
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
        let quote_mint = biguint_to_hex_string(&result.quote_mint);
        let base_mint = biguint_to_hex_string(&result.base_mint);
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
                mint: biguint_to_hex_string(&send_mint),
                amount: send_amount,
            },
            receive: ApiExternalAssetTransfer {
                mint: biguint_to_hex_string(&receive_mint),
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
