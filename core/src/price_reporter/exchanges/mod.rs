//! The exchanges module defines individual ExchangeConnection logic, including all parsing logic
//! for price messages from both centralized and decentralized exchanges.
/// Defines the raw ExchangeConnection logic.
mod connection;
/// Defines message handlers for centralized exchanges.
mod handlers_centralized;
/// Defines message handlers for decentralized exchanges.
mod handlers_decentralized;
pub use connection::{
    get_current_time, Exchange, ExchangeConnection, ExchangeConnectionState, ALL_EXCHANGES,
};
