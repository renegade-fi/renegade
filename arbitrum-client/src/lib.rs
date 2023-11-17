//! Provides a client for interacting with the Renegade smart contracts
//! on Arbitrum.
//!
//! This contains abstractions for handling configuration details like
//! RPC endpoint, contract address, etc.; executing transactions /
//! calling functions on the smart contracts; indexing through events; etc.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod abi;
pub mod client;
mod conversion;
pub mod errors;
mod helpers;
pub mod types;
