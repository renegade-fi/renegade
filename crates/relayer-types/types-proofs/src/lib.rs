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

// Re-export witness types from circuits-core for downstream consumers
pub use circuits_core::zk_circuits::validity_proofs::{
    intent_and_balance::SizedIntentAndBalanceValidityWitness,
    intent_and_balance_first_fill::SizedIntentAndBalanceFirstFillValidityWitness,
    intent_only::SizedIntentOnlyValidityWitness,
    intent_only_first_fill::IntentOnlyFirstFillValidityWitness,
    new_output_balance::SizedNewOutputBalanceValidityWitness,
    output_balance::SizedOutputBalanceValidityWitness,
};

#[cfg(feature = "rkyv")]
mod stored_validity_proof;

#[cfg(feature = "rkyv")]
pub use stored_validity_proof::{
    ALL_VALIDITY_PROOF_KEYS, ALL_VALIDITY_WITNESS_KEYS, OUTPUT_BALANCE_VALIDITY_PROOF_KEYS,
    StoredValidityProof, StoredValidityWitness,
};

// TODO: Redefine this as we add more order types
/// A bundle of validity proofs for an order
pub type OrderValidityProofBundle = bundles::IntentAndBalanceValidityBundle;
