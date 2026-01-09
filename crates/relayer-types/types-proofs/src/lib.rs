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

#[cfg(feature = "mocks")]
pub mod mocks;

pub use bundles::*;
