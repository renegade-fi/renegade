//! Defines common types, traits, and functionality useful throughout the
//! workspace

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![deny(clippy::missing_docs_in_private_items)]
#![feature(generic_const_exprs)]

pub mod default_wrapper;
pub mod keyed_list;
pub mod types;
pub mod worker;
