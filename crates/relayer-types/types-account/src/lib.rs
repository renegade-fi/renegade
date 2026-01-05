//! Wallet types for the Renegade relayer
//!
//! This crate provides wallet-related types including balances, orders,
//! keychain, and Merkle authentication paths.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]

pub mod account;
mod merkle;

pub use account::*;
pub use merkle::*;
