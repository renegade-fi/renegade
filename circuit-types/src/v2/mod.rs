//! V2 circuit types

pub mod balance;
pub mod csprng;
pub mod deposit;
pub mod intent;
pub mod note;
pub mod state_wrapper;
pub mod withdrawal;

use constants::Scalar;

// ----------------
// | Type Aliases |
// ----------------

/// A commitment to a state element
pub type Commitment = Scalar;
/// A nullifier for a state element
pub type Nullifier = Scalar;
