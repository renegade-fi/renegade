//! Groups gossip error definitions

use std::fmt;

// Defines an error for Gossip operation
#[derive(Clone, Debug)]
pub enum GossipError {
    /// An error setting up the gossip server
    ServerSetupError(String),
    /// An error resulting from a cancellation signal
    Cancelled(String),
}

impl fmt::Display for GossipError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
