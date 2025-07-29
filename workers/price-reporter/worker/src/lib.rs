//! The price reporter module manages all external price feeds, including
//! PriceReporter spin-up and tear-down, websocket connections to all exchanges
//! (both centralized and decentralized), and computing PriceReports.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![allow(incomplete_features)]
#![feature(let_chains)]

pub mod errors;
pub mod exchange;
pub mod manager;
#[cfg(feature = "mocks")]
pub mod mock;
pub mod worker;
