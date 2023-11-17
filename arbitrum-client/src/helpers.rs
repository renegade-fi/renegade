//! Various helpers for Arbitrum client execution

use ethers::types::Bytes;
use serde::{Deserialize, Serialize};

use crate::errors::ArbitrumClientError;

/// Serializes a calldata element for a contract call
pub fn serialize_calldata<T: Serialize>(data: &T) -> Result<Bytes, ArbitrumClientError> {
    postcard::to_allocvec(data)
        .map(Bytes::from)
        .map_err(|e| ArbitrumClientError::Serde(e.to_string()))
}

/// Deserializes a return value from a contract call
pub fn deserialize_retdata<'de, T: Deserialize<'de>>(
    retdata: &'de Bytes,
) -> Result<T, ArbitrumClientError> {
    postcard::from_bytes(retdata).map_err(|e| ArbitrumClientError::Serde(e.to_string()))
}
