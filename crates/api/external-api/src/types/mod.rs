//! API types for the relayer's websocket and HTTP APIs

pub mod account;
#[cfg(feature = "admin-api")]
pub mod admin;
pub mod balance;
pub mod crypto_primitives;
pub mod external_match;
pub mod market;
pub mod metadata;
pub mod network;
pub mod order;
pub mod task;
#[cfg(feature = "websocket")]
pub mod websocket;

pub use account::*;
#[cfg(feature = "admin-api")]
pub use admin::*;
#[cfg(feature = "full-api")]
use alloy::primitives::Bytes;
use alloy::primitives::U256;
pub use balance::*;
pub use crypto_primitives::*;
pub use external_match::*;
pub use market::*;
pub use metadata::*;
pub use network::*;
pub use order::*;
use serde::{Deserialize, Serialize};
pub use task::*;
#[cfg(feature = "websocket")]
pub use websocket::*;

use crate::serde_helpers;

/// A signature with an associated nonce
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureWithNonce {
    /// The nonce
    #[serde(with = "serde_helpers::u256_as_string")]
    pub nonce: U256,
    /// The signature bytes (base64 encoded)
    #[serde(with = "serde_helpers::bytes_as_base64_string")]
    pub signature: Vec<u8>,
}

#[cfg(feature = "full-api")]
impl From<SignatureWithNonce> for renegade_solidity_abi::v2::IDarkpoolV2::SignatureWithNonce {
    fn from(signature_with_nonce: SignatureWithNonce) -> Self {
        let nonce = signature_with_nonce.nonce;
        let signature = Bytes::from(signature_with_nonce.signature);
        renegade_solidity_abi::v2::IDarkpoolV2::SignatureWithNonce { nonce, signature }
    }
}

#[cfg(feature = "full-api")]
impl From<renegade_solidity_abi::v2::IDarkpoolV2::SignatureWithNonce> for SignatureWithNonce {
    fn from(sig: renegade_solidity_abi::v2::IDarkpoolV2::SignatureWithNonce) -> Self {
        SignatureWithNonce { nonce: sig.nonce, signature: sig.signature.to_vec() }
    }
}
