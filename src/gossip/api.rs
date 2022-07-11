// Groups the gossip API definition for communication between peers
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
// Defines the heartbeat message, both request and response take
// on this message format
pub struct HeartbeatMessage {
    known_peers: [String; 5],
}

