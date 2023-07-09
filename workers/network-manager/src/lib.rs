//! Groups logic for the network manager

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

mod composed_protocol;
pub mod error;
pub mod manager;
pub mod worker;
