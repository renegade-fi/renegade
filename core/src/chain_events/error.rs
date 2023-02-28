//! Defines error types for the on-chain event listener

use std::fmt::Display;

/// The error type that the event listener emits
#[derive(Clone, Debug)]
pub enum OnChainEventListenerError {
    /// An RPC error with the StarkNet provider
    Rpc(String),
    /// Error setting up the on-chain event listener
    Setup(String),
}

impl Display for OnChainEventListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
