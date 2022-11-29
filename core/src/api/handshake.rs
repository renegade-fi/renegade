//! Groups API definitions for handshake request response
use serde::{Deserialize, Serialize};

// Represents a gossip message sent to initiate a handshake request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    // The handshake operation to perform
    pub operation: HandshakeOperation,
}

// Enumerates the different operations possible via handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeOperation {
    Mpc,
}
