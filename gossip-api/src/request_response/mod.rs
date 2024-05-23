//! The request/response API types for the gossip protocol

use ed25519_dalek::{Keypair as SigKeypair, PublicKey, SignatureError};
use serde::{Deserialize, Serialize};

use crate::{check_signature, sign_message, GossipDestination};

use self::{
    handshake::HandshakeMessage,
    heartbeat::{BootstrapRequest, HeartbeatMessage, PeerInfoRequest, PeerInfoResponse},
    orderbook::{OrderInfoRequest, OrderInfoResponse},
};

pub mod handshake;
pub mod heartbeat;
pub mod orderbook;

// -----------------
// | Request Types |
// -----------------

/// A wrapper around the GossipRequest type that allows us to attach cluster
/// signatures to each request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedGossipRequest {
    /// A signature of the request body with the sender's cluster private key
    pub sig: Vec<u8>,
    /// The body of the request
    pub body: GossipRequest,
}

impl AuthenticatedGossipRequest {
    /// Constructs a new authenticated gossip request given the request body
    ///
    /// Attaches a signature of the body using the given cluster private key
    /// if one is necessary
    pub fn new_with_body(
        body: GossipRequest,
        keypair: &SigKeypair,
    ) -> Result<Self, SignatureError> {
        // Create a signature fo the body
        let sig =
            if body.requires_cluster_auth() { sign_message(&body, keypair)? } else { Vec::new() };

        Ok(Self { sig, body })
    }

    /// Verify the signature on an authenticated request
    pub fn verify_cluster_auth(&self, key: &PublicKey) -> Result<(), SignatureError> {
        if !self.body.requires_cluster_auth() {
            return Ok(());
        }

        check_signature(&self.body, &self.sig, key)
    }
}

/// Represents a request delivered point-to-point through the libp2p
/// request-response protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipRequest {
    /// An ack, used to send a non-empty response so that libp2p will keep alive
    /// the connection
    Ack,

    // --- Peer Discovery --- //
    /// A request from a peer to bootstrap the network state from the recipient
    Bootstrap(BootstrapRequest),
    /// A request from a peer initiating a heartbeat
    Heartbeat(HeartbeatMessage),
    /// A request for peer info
    PeerInfo(PeerInfoRequest),

    // --- Handshakes --- //
    /// A request from a peer communicating about a potential handshake
    Handshake(HandshakeMessage),

    // --- Raft Consensus --- //
    /// A raft message from a peer
    ///
    /// We (de)serialize at the raft networking layer and pass an opaque byte
    /// buffer here to avoid pulling in `state` dependencies to the `gossip-api`
    /// package
    Raft(Vec<u8>),

    // --- Order Book --- //
    /// A request for order information from a peer
    OrderInfo(OrderInfoRequest),
}

impl GossipRequest {
    /// Explicitly states which requests need cluster authentication
    ///
    /// The code here is intentionally verbose to force any new request/response
    /// types to be defined with authentication in mind
    pub fn requires_cluster_auth(&self) -> bool {
        match self {
            GossipRequest::Ack => false,
            // Raft messages are always cluster authenticated
            GossipRequest::Raft(..) => true,
            GossipRequest::Bootstrap(..) => false,
            GossipRequest::Heartbeat(..) => false,
            GossipRequest::PeerInfo(..) => false,
            GossipRequest::Handshake { .. } => false,
            GossipRequest::OrderInfo(..) => false,
        }
    }

    /// The destination to which a request should be sent
    pub fn destination(&self) -> GossipDestination {
        match self {
            GossipRequest::Ack => GossipDestination::NetworkManager,
            // We send to the network manager so that it will implicitly give an ack
            GossipRequest::Raft(..) => GossipDestination::NetworkManager,
            GossipRequest::Bootstrap(..) => GossipDestination::GossipServer,
            GossipRequest::Heartbeat(..) => GossipDestination::GossipServer,
            GossipRequest::PeerInfo(..) => GossipDestination::GossipServer,
            GossipRequest::OrderInfo(..) => GossipDestination::GossipServer,
            GossipRequest::Handshake { .. } => GossipDestination::HandshakeManager,
        }
    }
}

// ------------------
// | Response Types |
// ------------------

/// A wrapper around the `GossipResponse` type that allows us to attach
/// signatures
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedGossipResponse {
    /// A signature of the request body with the sender's cluster private key
    pub sig: Vec<u8>,
    /// The body of the request
    pub body: GossipResponse,
}

impl AuthenticatedGossipResponse {
    /// A helper function to create a simple ack without needing to explicitly
    /// construct the nested enumerative types
    pub fn new_ack() -> Self {
        Self { sig: Vec::new(), body: GossipResponse::Ack }
    }

    /// Constructs a new authenticated gossip request given the request body.
    /// Attaches a signature of the body using the given cluster private key
    /// if one is necessary
    pub fn new_with_body(
        body: GossipResponse,
        cluster_key: &SigKeypair,
    ) -> Result<Self, SignatureError> {
        // Create a signature fo the body
        let sig = if body.requires_cluster_auth() {
            sign_message(&body, cluster_key)?
        } else {
            Vec::new()
        };

        Ok(Self { sig, body })
    }

    /// Verify the signature on an authenticated request
    pub fn verify_cluster_auth(&self, cluster_pubkey: &PublicKey) -> Result<(), SignatureError> {
        if !self.body.requires_cluster_auth() {
            return Ok(());
        }

        check_signature(&self.body, &self.sig, cluster_pubkey)
    }
}

/// Represents the possible response types for a request-response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipResponse {
    /// An ack, used to send a non-empty response so that libp2p will keep alive
    /// the connection
    Ack,
    /// A response from a peer to a sender's heartbeat request
    Heartbeat(HeartbeatMessage),
    /// A response from a peer communicating about a potential handshake
    Handshake(HandshakeMessage),
    /// A response from a peer to a sender's request for peer info
    PeerInfo(PeerInfoResponse),
    /// A response to a request for order information
    OrderInfo(OrderInfoResponse),
    /// A response to a raft message
    ///
    /// We (de)serialize at the raft networking layer and pass an opaque byte
    /// buffer here to avoid pulling in `state` dependencies to the `gossip-api`
    /// package
    Raft(Vec<u8>),
}

impl GossipResponse {
    /// Explicitly states which requests need cluster authentication
    ///
    /// The code here is intentionally verbose to force any new request/response
    /// types to be defined with authentication in mind
    pub fn requires_cluster_auth(&self) -> bool {
        match self {
            GossipResponse::Ack => false,
            GossipResponse::Heartbeat(..) => false,
            GossipResponse::Handshake { .. } => false,
            GossipResponse::OrderInfo(..) => false,
            GossipResponse::PeerInfo(..) => false,
            GossipResponse::Raft(..) => true,
        }
    }

    /// The destination to which a request should be sent
    pub fn destination(&self) -> GossipDestination {
        match self {
            GossipResponse::Ack => GossipDestination::NetworkManager,
            GossipResponse::Heartbeat(..) => GossipDestination::GossipServer,
            GossipResponse::PeerInfo(..) => GossipDestination::GossipServer,
            GossipResponse::OrderInfo(..) => GossipDestination::GossipServer,
            GossipResponse::Handshake { .. } => GossipDestination::HandshakeManager,
            GossipResponse::Raft(..) => GossipDestination::NetworkManager,
        }
    }
}
