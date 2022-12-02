//! Groups error definitions for the network manager

use std::fmt::Display;

/// The generic error type for the network manager
#[derive(Clone, Debug)]
pub enum NetworkManagerError {
    /// An error while setting up the network manager
    SetupError(String),
    /// An error originating from a cancel signal
    Cancelled(String),
    /// An error forwarding a cancel signal to the network worker
    CancelForwardFailed(String),
    /// Serialization/Deserialization error
    SerializeDeserialize(String),
    /// Authentication error, e.g. failed signature verification
    Authentication(String),
}

impl Display for NetworkManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
