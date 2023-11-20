//! Various helpers for Arbitrum client execution

use constants::Scalar;
use ethers::{
    types::{Bytes, H256},
    utils::keccak256,
};
use serde::{Deserialize, Serialize};

use crate::{errors::ArbitrumClientError, serde_def_types::SerdeScalarField};

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

/// Computes the Keccak-256 hash of the serialization of a scalar,
/// used for filtering events that have indexed scalar topics
pub fn keccak_hash_scalar(scalar: Scalar) -> Result<H256, ArbitrumClientError> {
    let scalar_bytes = serialize_calldata(&SerdeScalarField(scalar.inner()))?;
    Ok(keccak256(scalar_bytes).into())
}
