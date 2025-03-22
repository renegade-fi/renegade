//! Types from the contracts
//!
//! We copy here instead of importing to avoid having to depend on the contracts
//! repo. The dependencies in the contracts are specified very strictly, and we
//! wish to decouple the relayer from the contract's dependencies.
//!
//! See: https://github.com/renegade-fi/renegade-contracts/tree/main/contracts-common
//! for the original types

mod serde_def_types;
mod types;
pub(crate) use types::*;

// ----------------------------
// | Contract Types Constants |
// ----------------------------

/// The number of wire types in the circuit
pub const NUM_WIRE_TYPES: usize = 5;
/// The number of selectors in the circuit
pub const NUM_SELECTORS: usize = 13;
/// The number of u64s it takes to represent a field element
pub const NUM_U64S_FELT: usize = 4;
/// The number of scalars it takes to encode a secp256k1 public key
pub const NUM_SCALARS_PK: usize = 4;
