//! Groups error definitions for the network manager

use std::fmt::Display;

/// The generic error type for the network manager
#[derive(Clone, Debug)]
pub enum NetworkManagerError {
    /// An error while setting up the network manager
    SetupError(String),
}

impl Display for NetworkManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
