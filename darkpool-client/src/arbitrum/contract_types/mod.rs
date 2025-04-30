//! Types from the contracts
//!
//! We copy here instead of importing to avoid having to depend on the contracts
//! repo. The dependencies in the contracts are specified very strictly, and we
//! wish to decouple the relayer from the contract's dependencies.
//!
//! See: https://github.com/renegade-fi/renegade-contracts/tree/main/contracts-common
//! for the original types

pub mod conversion;
pub mod serde_def_types;
pub mod types;
pub(crate) use types::*;

// ----------------------------
// | Contract Types Constants |
// ----------------------------

/// The number of wire types in the circuit
pub const NUM_WIRE_TYPES: usize = 5;
