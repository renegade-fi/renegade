//! Defines error types for the on-chain event listener

use std::{error::Error, fmt::Display};

use darkpool_client::errors::DarkpoolClientError;
use state::error::StateError;

/// The error type that the event listener emits
#[derive(Clone, Debug)]
pub enum OnChainEventListenerError {
    /// An error with the darkpool client
    Darkpool(String),
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

impl OnChainEventListenerError {
    /// Create a new darkpool error
    #[allow(clippy::needless_pass_by_value)]
    pub fn darkpool<T: ToString>(e: T) -> Self {
        OnChainEventListenerError::Darkpool(e.to_string())
    }

    /// Create a new state error
    #[allow(clippy::needless_pass_by_value)]
    pub fn state<T: ToString>(msg: T) -> Self {
        OnChainEventListenerError::State(msg.to_string())
    }
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

impl From<DarkpoolClientError> for OnChainEventListenerError {
    fn from(e: DarkpoolClientError) -> Self {
        OnChainEventListenerError::darkpool(e)
    }
}

impl<E: Display> From<alloy::transports::RpcError<E>> for OnChainEventListenerError {
    fn from(e: alloy::transports::RpcError<E>) -> Self {
        OnChainEventListenerError::darkpool(e)
    }
}

impl From<alloy::sol_types::Error> for OnChainEventListenerError {
    fn from(e: alloy::sol_types::Error) -> Self {
        OnChainEventListenerError::darkpool(e)
    }
}
