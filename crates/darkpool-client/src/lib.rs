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

// TODO: Do we need the arbitrum and base features still?

// // Make sure we don't enable both features at the same time
// #[cfg(all(feature = "arbitrum", feature = "base", not(feature =
// "all-chains")))] compile_error!("Only one of features 'arbitrum' or 'base'
// should be enabled at a time");

pub mod client;
pub mod constants;
// pub mod conversion;
pub mod errors;
pub mod solidity;
pub mod traits;

// #[cfg(feature = "transfer-auth")]
// pub mod transfer_auth;

/// The darkpool client for the Solidity implementation
pub type DarkpoolClient = client::DarkpoolClientInner<solidity::SolidityDarkpool>;

// #[cfg(feature = "arbitrum")]
// pub mod arbitrum;
// #[cfg(all(feature = "arbitrum", not(feature = "all-chains")))]
// /// The darkpool client for the Arbitrum chain
// pub type DarkpoolClient =
// client::DarkpoolClientInner<arbitrum::ArbitrumDarkpool>; #[cfg(all(feature =
// "arbitrum", not(feature = "all-chains")))] /// The darkpool implementation
// for the Arbitrum chain ///
// /// Exported here to allow lower level access from other workers
// pub type DarkpoolImplementation = arbitrum::ArbitrumDarkpool;

// #[cfg(feature = "base")]
// pub mod base;
// #[cfg(all(feature = "base", not(feature = "all-chains")))]
// /// The darkpool client for the Base chain
// pub type DarkpoolClient = client::DarkpoolClientInner<base::BaseDarkpool>;
// #[cfg(all(feature = "base", not(feature = "all-chains")))]
// /// The darkpool implementation for the Base chain
// ///
// /// Exported here to allow lower level access from other workers
// pub type DarkpoolImplementation = base::BaseDarkpool;
