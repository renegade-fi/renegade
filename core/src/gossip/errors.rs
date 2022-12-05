//! Groups gossip error definitions

use std::fmt;

/// Defines an error for Gossip operation
#[derive(Clone, Debug)]
pub enum GossipError {
    /// An error resulting from a cancellation signal
    Cancelled(String),
    /// An error setting up the gossip server
    ServerSetup(String),
    /// An error forwarding a message to the network manager
    SendMessage(String),
    /// Timer failed to send a heartbeat
    TimerFailed(String),
}

impl fmt::Display for GossipError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
