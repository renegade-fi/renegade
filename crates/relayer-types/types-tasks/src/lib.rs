//! Task types for the Renegade relayer
//!
//! This crate provides task descriptors and queue management types.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::missing_docs_in_private_items)]

mod descriptors;
mod error;
mod history;
#[cfg(feature = "mocks")]
pub mod mocks;

pub use descriptors::*;
pub use error::*;
pub use history::*;
