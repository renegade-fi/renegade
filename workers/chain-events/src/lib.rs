//! Defines and implements the worker that listens for on-chain events
//!
//! The event listener is responsible for:
//! - MPC Shootdown: listening for nullifier spent events and sending a
//!   shootdown event so that all future or in-flight MPCs on a given nullifier
//!   are halted
//! - Merkle path updates: As the Merkle tree is updated, wallets' Merkle paths
//!   should be updated. If these paths are allowed to stale their root reveals
//!   information about where in the contract history the wallet was last
//!   updated: potentially down to the exact transaction. So fresh Merkle paths
//!   give privacy.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]

pub mod error;
pub mod listener;
pub mod post_settlement;
pub mod worker;
