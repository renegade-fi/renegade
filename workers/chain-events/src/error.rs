//! Defines error types for the on-chain event listener

use std::{error::Error, fmt::Display};

/// The error type that the event listener emits
#[derive(Clone, Debug)]
pub enum OnChainEventListenerError {
    /// An error executing some method in the Arbitrum client
    Arbitrum(String),
    /// An RPC error with the StarkNet provider
    Rpc(String),
    /// An error sending a message to another worker in the local node
    SendMessage(String),
    /// Error setting up the on-chain event listener
    Setup(String),
    /// The stream unexpectedly stopped
    StreamEnded,
}

impl Display for OnChainEventListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for OnChainEventListenerError {}
