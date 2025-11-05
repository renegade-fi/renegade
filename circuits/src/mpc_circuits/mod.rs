//! Defines circuitry for specific multiparty computations performed by a
//! relayer

#[cfg(feature = "v1")]
pub mod v1;

#[cfg(feature = "v1")]
pub use v1::*;
