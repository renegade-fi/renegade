//! HTTP route definitions and request/response types for metadata operations

// ---------------
// | HTTP Routes |
// ---------------

/// Route to get exchange metadata
pub const GET_EXCHANGE_METADATA_ROUTE: &str = "/v2/metadata/exchange";

// -------------------
// | Request/Response |
// -------------------

// Response is re-exported from types
pub use crate::types::ExchangeMetadataResponse;
