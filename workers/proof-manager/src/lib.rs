//! The proof generation worker handles the core of generating single-prover
//! proofs for wallet updates

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

pub mod error;
pub mod proof_manager;
pub mod worker;
