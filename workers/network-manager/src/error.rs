//! Groups error definitions for the network manager

use std::fmt::Display;

use ed25519_dalek::SignatureError;
use state::error::StateError;

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
    /// An error when a given request type is unhandled
    UnhandledRequest(String),
}

impl Display for NetworkManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<SignatureError> for NetworkManagerError {
    fn from(value: SignatureError) -> Self {
        NetworkManagerError::Authentication(value.to_string())
    }
}

impl From<StateError> for NetworkManagerError {
    fn from(value: StateError) -> Self {
        NetworkManagerError::State(value.to_string())
    }
}
