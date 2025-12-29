//! Remote type shims and wrapper types for rkyv serialization
//!
//! This module provides two categories of types:
//!
//! - **Remote types** (`remote_types`): Type shims used with `#[rkyv(with =
//!   ...)]` to serialize types that don't natively support rkyv.
//!
//! - **Wrapper types** (`wrapper_types`): Wrapper structs that use the remote
//!   type shims to satisfy the storage layer's `Value` trait requirements.

mod remote_types;
mod wrapper_types;

// Re-export remote types
pub use remote_types::{
    AddressDef, ArchivedAddress, ArchivedBabyJubJubPoint, ArchivedFixedPoint, ArchivedScalar,
    ArchivedSchnorrPublicKey, BabyJubJubPointDef, FixedPointDef, ScalarDef, SchnorrPublicKeyDef,
};

// Re-export wrapper types
pub use wrapper_types::{WrappedAddress, WrappedBabyJubJubPoint, WrappedFixedPoint};
