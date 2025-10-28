//! Groups circuitry for full zero knowledge circuits that we are interested
//! in proving knowledge of witness for throughout the network

#[cfg(feature = "v1")]
pub mod v1;
#[cfg(feature = "v2")]
pub mod v2;

#[cfg(feature = "v1")]
pub use v1::*;
#[cfg(feature = "v2")]
pub use v2::*;
