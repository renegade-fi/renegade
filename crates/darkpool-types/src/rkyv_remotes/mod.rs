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

// Re-export remote types (always available)
pub use remote_types::{
    AddressDef, ArchivedAddress, ArchivedBabyJubJubPoint, ArchivedFixedPoint, ArchivedScalar,
    ArchivedSchnorrPublicKey, ArchivedSchnorrSignature, ArchivedU256, BabyJubJubPointDef,
    FixedPointDef, ScalarDef, SchnorrPublicKeyDef, SchnorrSignatureDef, U256Def,
};

// Re-export share type definitions (only when proof-system-types is enabled)
#[cfg(feature = "proof-system-types")]
pub use remote_types::{
    ArchivedBabyJubJubPointShare, ArchivedFixedPointShare, ArchivedSchnorrPublicKeyShare,
    BabyJubJubPointShareDef, FixedPointShareDef, SchnorrPublicKeyShareDef,
};
