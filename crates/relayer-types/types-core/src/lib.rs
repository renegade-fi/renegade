//! Core types for the Renegade relayer
//!
//! This crate provides fundamental types used throughout the relayer with
//! minimal dependencies. Heavy circuit dependencies are avoided here.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::missing_docs_in_private_items)]

mod chain;
mod exchange;
#[cfg(feature = "hmac")]
mod hmac;
mod price;
mod token;

pub use chain::*;
pub use exchange::*;
#[cfg(feature = "hmac")]
pub use hmac::*;
pub use price::*;
pub use token::*;

/// A type alias for the account identifier type, currently a UUID
pub type AccountId = uuid::Uuid;
