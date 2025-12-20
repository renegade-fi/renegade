//! Cryptographic and mathematical primitives used in circuits

pub mod csprng;
pub mod elgamal;
pub mod fixed_point;
pub mod merkle;
pub mod schnorr;
#[cfg(feature = "proof-system-types")]
pub mod srs;

use constants::Scalar;

// ----------------
// | Type Aliases |
// ----------------

/// A commitment to a state element
pub type Commitment = Scalar;
/// A nullifier for a state element
pub type Nullifier = Scalar;
