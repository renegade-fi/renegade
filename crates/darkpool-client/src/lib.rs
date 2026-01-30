//! Provides a client for interacting with the Renegade smart contracts
//! and the blockchain more generally.
//!
//! This contains abstractions for handling configuration details like
//! RPC endpoint, contract address, etc.; executing transactions /
//! calling functions on the smart contracts; indexing through events; etc.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(iterator_try_collect)]

pub mod client;
pub mod constants;
pub mod errors;

pub use client::DarkpoolClient;
