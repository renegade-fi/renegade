//! Proof bundle types for the Renegade relayer
//!
//! This crate provides types for bundling proofs together, including
//! Plonk proofs and linking proofs.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::missing_docs_in_private_items)]

mod bundles;
mod validity_storage;

#[cfg(feature = "rkyv")]
pub mod rkyv_impls;

#[cfg(feature = "mocks")]
pub mod mocks;

pub use bundles::*;
pub use validity_storage::*;

#[cfg(feature = "rkyv")]
mod stored_validity_proof;

#[cfg(feature = "rkyv")]
pub use stored_validity_proof::{StoredValidityProof, ALL_VALIDITY_PROOF_KEYS};

// TODO: Redefine this as we add more order types
/// A bundle of validity proofs for an order
pub type OrderValidityProofBundle = bundles::IntentAndBalanceValidityBundle;
