//! Defines circuitry for specific multiparty computations performed by a
//! relayer

#[cfg(feature = "v1")]
pub mod v1;
#[cfg(feature = "v2")]
pub mod v2;

#[cfg(feature = "v1")]
pub use v1::*;
#[cfg(feature = "v2")]
pub use v2::*;
