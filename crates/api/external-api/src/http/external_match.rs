//! HTTP route definitions and request/response types for external match
//! operations

use serde::{Deserialize, Serialize};

use crate::types::{
    ApiSignedQuote, ExternalOrder, GasSponsorshipInfo, MalleableAtomicMatchApiBundle,
};

// ---------------
// | HTTP Routes |
// ---------------

/// Route to get a quote for an external match
pub const GET_EXTERNAL_MATCH_QUOTE_ROUTE: &str = "/v2/external-matches/get-quote";
/// Route to assemble a match bundle
pub const ASSEMBLE_MATCH_BUNDLE_ROUTE: &str = "/v2/external-matches/assemble-match-bundle";

// -------------------
// | Request/Response |
// -------------------

/// Request to get an external match quote
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalQuoteRequest {
    /// The external order
    pub external_order: ExternalOrder,
}

/// Response for external match quote
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalQuoteResponse {
    /// The signed quote
    pub signed_quote: ApiSignedQuote,
    /// Optional gas sponsorship information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_sponsorship_info: Option<GasSponsorshipInfo>,
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

/// Request to assemble an external match bundle
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssembleExternalMatchRequest {
    /// Whether to do gas estimation
    #[serde(default)]
    pub do_gas_estimation: bool,
    /// The receiver address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_address: Option<String>,
    /// The assembly type
    pub order: ExternalMatchAssemblyType,
}

/// Response for external match
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalMatchResponse {
    /// The match bundle
    pub match_bundle: MalleableAtomicMatchApiBundle,
    /// Optional gas sponsorship information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_sponsorship_info: Option<GasSponsorshipInfo>,
}
