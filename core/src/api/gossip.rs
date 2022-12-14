//! Groups API definitions for standard gossip network requests/responses

use ed25519_dalek::{Digest, Keypair, Sha512, SignatureError};
use libp2p::{request_response::ResponseChannel, Multiaddr};
use portpicker::Port;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::gossip::types::{ClusterId, WrappedPeerId};

use super::{
    cluster_management::{
        ClusterAuthRequest, ClusterAuthResponse, ClusterManagementMessage, ReplicateRequestBody,
    },
    handshake::HandshakeMessage,
    hearbeat::{BootstrapRequest, HeartbeatMessage},
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
    /// A command signalling to the network manager to open up a QUIC connection and build
    /// an MPC network instance to handshake over
    BrokerMpcNet {
        /// The ID of the ongoing handshake
        request_id: Uuid,
        /// The ID of the peer to dial
        peer_id: WrappedPeerId,
        /// The port that the peer has exposed to dial on
        peer_port: Port,
        /// The local port that should be used to accept the strem
        local_port: Port,
        /// The role of the local node in the connection setup
        local_role: ConnectionRole,
    },
}

/// The role in an MPC network setup; either Dialer or Listener depending on which node
/// initiates the connection
#[derive(Clone, Debug)]
pub enum ConnectionRole {
    /// Dials the peer, initiating the connection
    /// The dialer also plays the role of the king in the subsequent MPC computation
    Dialer,
    /// Listens for an inbound connection from the dialer
    Listener,
}

impl ConnectionRole {
    /// Get the party_id for an MPC dialed up through this connection
    pub fn get_party_id(&self) -> u64 {
        match self {
            // Party 0 dials party 1
            ConnectionRole::Dialer => 0,
            ConnectionRole::Listener => 1,
        }
    }
}

/// Represents a request delivered point-to-point through the libp2p
/// request-response protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipRequest {
    /// A request from a peer to bootstrap the network state from the recipient
    Boostrap(BootstrapRequest),
    /// A request from a peer to prove that the local peer is part of the given cluster
    ClusterAuth(ClusterAuthRequest),
    /// A request from a peer initiating a heartbeat
    Heartbeat(HeartbeatMessage),
    /// A request from a peer initiating a handshake
    Handshake {
        /// The request ID; used track handshakes across events
        request_id: Uuid,
        /// The message contents
        message: HandshakeMessage,
    },
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
    Handshake {
        /// The request ID; used track handshakes across events
        request_id: Uuid,
        /// The message contents
        message: HandshakeMessage,
    },
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
