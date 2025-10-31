//! V1 hash functions and utilities

#[cfg(feature = "non-wasm")]
pub mod csprng;

#[cfg(feature = "non-wasm")]
pub use csprng::*;
