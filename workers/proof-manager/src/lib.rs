//! The proof generation worker handles the core of generating single-prover
//! proofs for wallet updates

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

pub mod error;
#[cfg(feature = "mocks")]
pub mod mock;
pub mod proof_manager;
pub mod worker;
