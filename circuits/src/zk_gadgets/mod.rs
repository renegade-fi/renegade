//! Groups gadgets used in zero knowledge circuits
//!
//! Some gadgets are implemented in `mpc-jellyfish` so that they can be
//! implemented generically over provers. Gadgets in this module are built on
//! top of those low level gadgets defined in `mpc-jellyfish`.
//!
//! Some low level gadgets are defined here to provide MPC efficiency

pub mod arithmetic;
pub mod bits;
pub mod comparators;
pub mod elgamal;
pub mod fixed_point;
pub mod merkle;
pub mod poseidon;
pub mod select;

#[cfg(feature = "v1")]
pub mod v1;
#[cfg(feature = "v2")]
pub mod v2;

// Re-exports from v1
#[cfg(feature = "v1")]
pub use v1::*;
// Re-exports from v2
#[cfg(feature = "v2")]
pub use v2::*;

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;
