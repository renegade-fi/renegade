//! The price reporter module manages all external price feeds, including PriceReporter spin-up and
//! tear-down, websocket connections to all exchanges (both centralized and decentralized), and
//! aggregation of individual PriceReports into medians.
pub mod errors;
mod exchanges;
pub mod jobs;
pub mod manager;
pub mod reporter;
pub mod tokens;
pub mod worker;
