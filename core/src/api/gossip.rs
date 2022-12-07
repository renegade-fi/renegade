//! Groups API definitions for standard gossip network requests/responses

use ed25519_dalek::{Digest, Keypair, Sha512, SignatureError};
use libp2p::{request_response::ResponseChannel, Multiaddr};
use serde::{Deserialize, Serialize};

use crate::gossip::types::{ClusterId, WrappedPeerId};

use super::{
    cluster_management::{
        ClusterAuthRequest, ClusterAuthResponse, ClusterManagementMessage, ReplicateRequestBody,
    },
    handshake::HandshakeMessage,
    hearbeat::HeartbeatMessage,
};

/// Represents an outbound gossip message, either a request to a peer
/// or a response to a peer's request
#[derive(Debug)]
pub enum GossipOutbound {
    /// A generic request sent to the network manager for outbound delivery
    Request {
        /// The PeerId of the peer sending the request
        peer_id: WrappedPeerId,
        /// The message contents in the request
        message: GossipRequest,
    },
    /// A generic response sent to the network manager for outbound delivery
    Response {
        /// The libp2p channel on which to send the response
        channel: ResponseChannel<GossipResponse>,
        /// The response body
        message: GossipResponse,
    },
    /// An outbound pubsub message to be flooded into the peer-to-peer network
    Pubsub {
        /// The topic being published to
        topic: String,
        /// The message contents
        message: PubsubMessage,
    },
    /// A command signalling to the network manager that a new node has been
    /// discovered at the application level. The network manager should register
    /// this node with the KDHT and propagate this change
    NewAddr {
        /// The PeerID to which the new address belongs
        peer_id: WrappedPeerId,
        /// The new address
        address: Multiaddr,
    },
}

/// Represents a request delivered point-to-point through the libp2p
/// request-response protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipRequest {
    /// A request from a peer to prove that the local peer is part of the given cluster
    ClusterAuth(ClusterAuthRequest),
    /// A request from a peer initiating a heartbeat
    Heartbeat(HeartbeatMessage),
    /// A request from a peer initiating a handshake
    Handshake(HandshakeMessage),
    /// A request that a peer replicate a set of wallets
    Replicate(ReplicateRequestBody),
}

/// Represents the possible response types for a request-response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipResponse {
    /// A repsonse from a peer proving that they are authroized to join a given cluster
    ClusterAuth(ClusterAuthResponse),
    /// A response from a peer to a sender's heartbeat request
    Heartbeat(HeartbeatMessage),
    /// A response from a peer to a sender's handshake request
    Handshake(),
}

/// Represents a pubsub message flooded through the network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PubsubMessage {
    /// A message broadcast to indicate an even relevant to cluster management
    ClusterManagement {
        /// The ID of the cluster this message is intended for
        cluster_id: ClusterId,
        /// The signature of the message body using the cluster's private key
        signature: Vec<u8>,
        /// The message body
        message: ClusterManagementMessage,
    },
}

impl PubsubMessage {
    /// Create a new cluster management message signed with the cluster private key
    pub fn new_cluster_management(
        cluster_key: &Keypair,
        message: ClusterManagementMessage,
    ) -> Result<PubsubMessage, SignatureError> {
        let mut hash_digest: Sha512 = Sha512::new();
        hash_digest.update(&Into::<Vec<u8>>::into(&message));
        let signature = cluster_key
            .sign_prehashed(hash_digest, None)?
            .to_bytes()
            .to_vec();

        Ok(PubsubMessage::ClusterManagement {
            cluster_id: ClusterId::new(&cluster_key.public),
            signature,
            message,
        })
    }

    /// Create a new cluster management message with an empty signature; the assumption being
    /// that a lower level module will fill in the signature
    pub fn new_cluster_management_unsigned(
        cluster_id: ClusterId,
        message: ClusterManagementMessage,
    ) -> PubsubMessage {
        PubsubMessage::ClusterManagement {
            cluster_id,
            signature: vec![],
            message,
        }
    }
}

/// Explicit byte serialization and deserialization
///
/// libp2p gossipsub interface expects a type that can be cast
/// to and from bytes
impl From<PubsubMessage> for Vec<u8> {
    fn from(message: PubsubMessage) -> Self {
        serde_json::to_vec(&message).unwrap()
    }
}

impl From<Vec<u8>> for PubsubMessage {
    fn from(buf: Vec<u8>) -> Self {
        serde_json::from_slice(&buf).unwrap()
    }
}
