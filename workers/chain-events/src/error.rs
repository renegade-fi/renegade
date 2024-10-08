//! Defines error types for the on-chain event listener

use std::{error::Error, fmt::Display};

use state::error::StateError;

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
    /// Error interacting with global state
    State(String),
    /// The stream unexpectedly stopped
    StreamEnded,
    /// An error starting up a task
    TaskStartup(String),
}

impl Display for OnChainEventListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for OnChainEventListenerError {}

impl From<StateError> for OnChainEventListenerError {
    fn from(e: StateError) -> Self {
        OnChainEventListenerError::State(e.to_string())
    }
}
