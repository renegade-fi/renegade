//! The price reporter module manages all external price feeds, including
//! PriceReporter spin-up and tear-down, websocket connections to all exchanges
//! (both centralized and decentralized), and aggregation of individual
//! PriceReports into medians.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(let_chains)]
#![feature(generic_const_exprs)]

pub mod errors;
pub mod exchange;
pub mod manager;
pub mod reporter;
pub mod worker;

/// The pubsub topic source name for median price reports
pub const MEDIAN_SOURCE_NAME: &str = "median";
