use libp2p::PeerId;
use serde::{Serialize, Deserialize};

// Groups the gossip API definition for communication between peers
#[derive(Debug, Serialize, Deserialize)]
// Defines the heartbeat message, both request and response take
// on this message format
pub struct HeartbeatMessage {
    known_peers: Vec<Vec<u8>>,
}

impl HeartbeatMessage {
    pub fn new(known_peers: Vec<PeerId>) -> Self {
        let mut serialized_peers = Vec::new();
        for peer in known_peers {
            serialized_peers.push(peer.to_bytes());
        }

        Self { known_peers: serialized_peers }
    }

    // Parses known peers from byte data
    pub fn get_known_peers(&self) -> Result<Vec<PeerId>, Box<dyn std::error::Error>> {
        let mut parsed = Vec::new();
        for peer in self.known_peers.iter() {
            parsed.push(PeerId::from_bytes(peer)?);
        }

        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use libp2p::{identity, PeerId};

    use super::HeartbeatMessage;

    #[test]
    fn test_serialize_deserialize() {
        let key = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from_public_key(&key.public());

        let message = HeartbeatMessage::new(vec![peer_id]);
        assert_eq!(1, message.get_known_peers().unwrap().len());
        assert_eq!(peer_id, *message.get_known_peers().unwrap().get(0).unwrap());
    }
}