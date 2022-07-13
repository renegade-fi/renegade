use libp2p::{
    PeerId,
    request_response::ResponseChannel, Multiaddr,
};
use serde::{Serialize, Deserialize};

use super::types::PeerInfo;

/**
 * This file groups API related definitions for the relayer's libp2p protocol
 */

// Represents an outbound gossip message, either a request to a peer
// or a response to a peer's request
#[derive(Debug)]
pub enum GossipOutbound {
    // A generic request sent to the network manager for outbound delivery
    Request { peer_id: PeerId, message: GossipMessage },
    // A generic response sent to the network manager for outbound delivery
    Response { channel: ResponseChannel<GossipMessage>, message: GossipMessage },
    // A command signalling to the network manager that a new node has been
    // discovered at the application level. The network manager should register
    // this node with the KDHT and propagate this change
    NewAddr { peer_id: PeerId, address: Multiaddr }
}

// Represents the message data passed via the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    Heartbeat(HeartbeatMessage)
}

// Defines the heartbeat message, both request and response take
// on this message format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    // Known peers represents a serialized PeerId, this is separated out
    // from addrs to allow for easy serialization/deserializtion of the message
    known_peers: Vec<Vec<u8>>,
    known_peer_addrs: Vec<Multiaddr>,
}

impl HeartbeatMessage {
    pub fn new(known_peers: Vec<PeerInfo>) -> Self {
        let mut serialized_peers = Vec::new();
        let mut peer_addrs = Vec::new();

        for peer in known_peers {
            serialized_peers.push(peer.get_peer_id().to_bytes());
            peer_addrs.push(peer.get_addr());
        }

        Self { known_peers: serialized_peers, known_peer_addrs: peer_addrs }
    }

    // Parses known peers from byte data
    pub fn get_known_peers(&self) -> Result<Vec<PeerInfo>, Box<dyn std::error::Error>> {
        let mut parsed = Vec::new();
        for (peer, addr) in self.known_peers.iter().zip(self.known_peer_addrs.clone()) {
            parsed.push(
                PeerInfo::new(
                    PeerId::from_bytes(peer)?,
                    addr
                )
            );
        }

        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use libp2p::{identity, PeerId, Multiaddr};

    use crate::gossip::types::PeerInfo;

    use super::HeartbeatMessage;

    #[test]
    fn test_serialize_deserialize() {
        let key = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from_public_key(&key.public());
        let addr = Multiaddr::empty();

        let expected_peer_info = vec![
            PeerInfo::new(peer_id, addr)
        ];

        let message = HeartbeatMessage::new(expected_peer_info);
        assert_eq!(1, message.get_known_peers().unwrap().len());
        assert_eq!(peer_id, message.get_known_peers()
                                .unwrap()
                                .get(0)
                                .unwrap()
                                .get_peer_id()
                            );
    }
}