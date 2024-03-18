//! The external price reporter module manages a connection to an external
//! standalone price reporter service, streaming in exchange prices
//! from it to compute PriceReports.
//!
//! Much of the types and logic employed by this worker are shared with the
//! native PriceReporter worker

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(let_chains)]
#![feature(generic_const_exprs)]

pub mod errors;
pub mod manager;
pub mod worker;
