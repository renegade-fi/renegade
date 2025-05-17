//! Helpers for constructing external transfer auth data which the contracts
//! will validate
//!
//! For deposits this is a Permit2 signature, with the root key used as the
//! deposit witness.
//!
//! For withdrawals, this is just the serialized transfer struct, signed by the
//! root key.

mod common;
mod permit2_abi;

#[cfg(feature = "arbitrum")]
pub mod arbitrum;
#[cfg(feature = "base")]
pub mod base;
