//! Handshake-related types for network connections

use serde::{Deserialize, Serialize};

/// The role of a party in a two-party network connection
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ConnectionRole {
    /// The party that initiates the connection (dials the peer)
    Dialer,
    /// The party that accepts the connection (listens for incoming connections)
    Listener,
}

impl ConnectionRole {
    /// Returns the party ID for MPC network setup
    /// Dialer = 0, Listener = 1
    pub fn get_party_id(self) -> u64 {
        match self {
            ConnectionRole::Dialer => 0,
            ConnectionRole::Listener => 1,
        }
    }
}
