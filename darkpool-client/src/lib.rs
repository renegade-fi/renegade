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
#![feature(generic_const_exprs)]
#![feature(let_chains)]

pub mod client;
pub mod constants;
pub mod conversion;
pub mod errors;
pub mod traits;

#[cfg(feature = "arbitrum")]
pub mod arbitrum;

#[cfg(feature = "arbitrum")]
/// The darkpool client for the Arbitrum chain
pub type DarkpoolClient = client::DarkpoolClient<arbitrum::ArbitrumDarkpool>;
