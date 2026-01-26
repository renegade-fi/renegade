//! HTTP route definitions and request/response types for external match
//! operations

use crate::serde_helpers;
use alloy::primitives::Address;
#[cfg(feature = "full-api")]
use circuit_types::Amount;
use serde::{Deserialize, Serialize};
use types_account::MatchingPoolName;

use crate::types::{ApiSignedQuote, BoundedExternalMatchApiBundle, ExternalOrder};

// ---------------
// | HTTP Routes |
// ---------------

/// Route to get a quote for an external match
pub const GET_EXTERNAL_MATCH_QUOTE_ROUTE: &str = "/v2/external-matches/get-quote";
/// Route to assemble a match bundle
pub const ASSEMBLE_MATCH_BUNDLE_ROUTE: &str = "/v2/external-matches/assemble-match-bundle";

// --------------------
// | Request/Response |
// --------------------

/// Request to get an external match quote
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalQuoteRequest {
    /// The external order
    pub external_order: ExternalOrder,
    /// The options for the external matching engine
    #[serde(default)]
    pub options: ExternalMatchingEngineOptions,
}

/// Response for external match quote
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalQuoteResponse {
    /// The signed quote
    pub signed_quote: ApiSignedQuote,
}

/// The assembly type for an external match
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[allow(clippy::large_enum_variant)]
pub enum ExternalMatchAssemblyType {
    /// External order from a quoted order
    QuotedOrder {
        /// The signed quote
        signed_quote: ApiSignedQuote,
        /// An optional updated order
        #[serde(skip_serializing_if = "Option::is_none")]
        updated_order: Option<ExternalOrder>,
    },
    /// External order from a new order
    DirectOrder {
        /// The external order
        external_order: ExternalOrder,
    },
}

#[cfg(feature = "full-api")]
impl ExternalMatchAssemblyType {
    /// Get the amount in for an assembly type
    pub fn amount_in(&self) -> Amount {
        match self {
            Self::QuotedOrder { updated_order, signed_quote } => {
                updated_order.as_ref().unwrap_or(&signed_quote.quote.order).input_amount
            },
            Self::DirectOrder { external_order } => external_order.input_amount,
        }
    }

    /// Get a reference to the external order from an assembly type
    pub fn get_external_order_ref(&self) -> &ExternalOrder {
        match self {
            Self::QuotedOrder { updated_order, signed_quote } => {
                updated_order.as_ref().unwrap_or(&signed_quote.quote.order)
            },
            Self::DirectOrder { external_order } => external_order,
        }
    }

    /// Get the external order from an assembly type
    pub fn get_external_order(&self) -> ExternalOrder {
        self.get_external_order_ref().clone()
    }
}

/// Request to assemble an external match bundle
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssembleExternalMatchRequest {
    /// Whether to do gas estimation
    #[serde(default)]
    pub do_gas_estimation: bool,
    /// The receiver address
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "serde_helpers::option_address_as_string")]
    pub receiver_address: Option<Address>,
    /// The assembly type
    pub order: ExternalMatchAssemblyType,
    /// The options for the external matching engine
    #[serde(default)]
    pub options: ExternalMatchingEngineOptions,
}

/// Response for external match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalMatchResponse {
    /// The match bundle
    pub match_bundle: BoundedExternalMatchApiBundle,
}

/// Options for the external matching engine
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExternalMatchingEngineOptions {
    /// The relayer fee rate to apply to the match
    ///
    /// Defaults to the default relayer fee rate
    pub relayer_fee_rate: Option<f64>,
    /// The matching pool to request a quote from
    ///
    /// Defaults to all matching pools if not specified
    pub matching_pool: Option<MatchingPoolName>,
}
