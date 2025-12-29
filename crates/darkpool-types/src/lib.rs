//! Protocol-level types for the darkpool

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod balance;
pub mod bounded_match_result;
pub mod deposit;
pub mod fee;
pub mod intent;
pub mod note;
pub mod settlement_obligation;
pub mod state_wrapper;
pub mod withdrawal;

#[cfg(feature = "rkyv")]
pub mod rkyv_remotes;
