//! Defines and implements the worker that listens for on-chain events

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

pub mod error;
pub mod listener;
pub mod worker;
