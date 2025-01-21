//! Defines common types, traits, and functionality useful throughout the
//! workspace

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![deny(clippy::missing_docs_in_private_items)]
#![feature(generic_const_exprs)]

#[cfg(feature = "internal-types")]
pub mod default_wrapper;
#[cfg(feature = "wallet")]
pub mod keyed_list;
#[cfg(feature = "internal-types")]
pub mod worker;

pub mod types;
