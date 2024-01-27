//! Groups error definitions for the network manager

use std::fmt::Display;

use statev2::error::StateError;

/// The generic error type for the network manager
#[derive(Debug)]
pub enum NetworkManagerError {
    /// Authentication error, e.g. failed signature verification
    Authentication(String),
    /// An error originating from a cancel signal
    Cancelled(String),
    /// Error forwarding a job from the network layer to a worker
    EnqueueJob(String),
    /// An error with the underlying network operation
    Network(String),
    /// An error while setting up the network manager
    SetupError(String),
    /// An error serializing or deserializing a message
    Serialization(String),
    /// An error interacting with global state
    State(String),
}

impl Display for NetworkManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<StateError> for NetworkManagerError {
    fn from(value: StateError) -> Self {
        NetworkManagerError::State(value.to_string())
    }
}
