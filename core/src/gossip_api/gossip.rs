//! Groups API definitions for standard gossip network requests/responses

use ed25519_dalek::{Digest, Keypair as SigKeypair, PublicKey, Sha512, Signature, SignatureError};
use libp2p::{request_response::ResponseChannel, Multiaddr};
use portpicker::Port;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    gossip::types::{ClusterId, WrappedPeerId},
    proof_generation::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    state::{wallet::Wallet, OrderIdentifier},
};

use super::{
    cluster_management::{ClusterManagementMessage, ReplicateRequestBody},
    handshake::HandshakeMessage,
    heartbeat::{BootstrapRequest, HeartbeatMessage},
    orderbook_management::{OrderBookManagementMessage, OrderInfoRequest, OrderInfoResponse},
};

/// Represents an outbound gossip message, either a request to a peer
/// or a response to a peer's request
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
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
        channel: ResponseChannel<AuthenticatedGossipResponse>,
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
    /// A message to the network manager itself indicating some control directive
    /// from another module
    ManagementMessage(ManagerControlDirective),
}

/// A wrapper around the GossipRequest type that allows us to attach cluster signatures
/// to each request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedGossipRequest {
    /// A signature of the request body with the sender's cluster private key
    pub sig: Vec<u8>,
    /// The body of the request
    pub body: GossipRequest,
}

impl AuthenticatedGossipRequest {
    /// Constructs a new authenticated gossip request given the request body.
    /// Attaches a signature of the body using the given cluster private key
    /// if one is necessary
    pub fn new_with_body(
        body: GossipRequest,
        cluster_key: &SigKeypair,
    ) -> Result<Self, SignatureError> {
        // Create a signature fo the body
        let sig = if body.requires_cluster_auth() {
            let mut hash_digest: Sha512 = Sha512::new();
            hash_digest.update(&serde_json::to_vec(&body).unwrap());
            cluster_key
                .sign_prehashed(hash_digest, None)?
                .to_bytes()
                .to_vec()
        } else {
            Vec::new()
        };

        Ok(Self { sig, body })
    }

    /// Verify the signature on an authenticated request
    pub fn verify_cluster_auth(&self, cluster_pubkey: &PublicKey) -> bool {
        if !self.body.requires_cluster_auth() {
            return true;
        }

        // Unmarshal the signature into its runtime type
        let sig_unmarshalled = Signature::from_bytes(&self.sig);
        if let Ok(sig) = sig_unmarshalled {
            let mut hash_digest = Sha512::new();
            hash_digest.update(&serde_json::to_vec(&self.body).unwrap());
            cluster_pubkey
                .verify_prehashed(hash_digest, None, &sig)
                .is_ok()
        } else {
            false
        }
    }
}

/// Represents a request delivered point-to-point through the libp2p
/// request-response protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipRequest {
    /// A request from a peer to bootstrap the network state from the recipient
    Bootstrap(BootstrapRequest),
    /// A request from a peer initiating a heartbeat
    Heartbeat(HeartbeatMessage),
    /// A request from a peer initiating a handshake
    Handshake {
        /// The request ID; used track handshakes across events
        request_id: Uuid,
        /// The message contents
        message: HandshakeMessage,
    },
    /// A request for order information from a peer
    OrderInfo(OrderInfoRequest),
    /// A request that a peer replicate a set of wallets
    Replicate(ReplicateRequestBody),
    /// A pushed message forwarded from the sender when a validity proof bundle is
    /// requested, updated, or constructed for the first time
    ValidityProof {
        /// The order this proof is for
        order_id: OrderIdentifier,
        /// The bundle of validity proofs; includes `VALID REBLIND` for the order's
        /// wallet, and `VALID COMMITMENTS` for the order itself
        proof_bundle: OrderValidityProofBundle,
    },
    /// A request type that pushes the witness used in the validity proofs for
    /// an order to the receiver
    ///
    /// This may be triggered when the receiver broadcasts a pubsub message indicating that it
    /// needs a copy of the witness
    ValidityWitness {
        /// The order this witness is for
        order_id: OrderIdentifier,
        /// The witness used in the validity proofs
        witness: OrderValidityWitnessBundle,
    },
    /// A pushed wallet update from a peer
    WalletUpdate {
        /// The updated wallet
        wallet: Wallet,
    },
}

impl GossipRequest {
    /// Explicitly states which requests need cluster authentication
    ///
    /// The code here is intentionally verbose to force any new request/response types
    /// to be defined with authentication in mind
    pub fn requires_cluster_auth(&self) -> bool {
        match self {
            GossipRequest::Bootstrap(..) => false,
            GossipRequest::Heartbeat(..) => false,
            GossipRequest::Handshake { .. } => false,
            GossipRequest::OrderInfo(..) => false,
            GossipRequest::Replicate(..) => false,
            GossipRequest::ValidityProof { .. } => true,
            GossipRequest::ValidityWitness { .. } => true,
            GossipRequest::WalletUpdate { .. } => true,
        }
    }
}

/// A wrapper around the `GossipResponse` type that allows us to attach signatures
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedGossipResponse {
    /// A signature of the request body with the sender's cluster private key
    pub sig: Vec<u8>,
    /// The body of the request
    pub body: GossipResponse,
}

impl AuthenticatedGossipResponse {
    /// A helper function to create a simple ack without needing to explicitly construct
    /// the nested enumerative types
    pub fn new_ack() -> Self {
        Self {
            sig: Vec::new(),
            body: GossipResponse::Ack,
        }
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
            let mut hash_digest: Sha512 = Sha512::new();
            hash_digest.update(&serde_json::to_vec(&body).unwrap());
            cluster_key
                .sign_prehashed(hash_digest, None)?
                .to_bytes()
                .to_vec()
        } else {
            Vec::new()
        };

        Ok(Self { sig, body })
    }

    /// Verify the signature on an authenticated request
    pub fn verify_cluster_auth(&self, cluster_pubkey: &PublicKey) -> bool {
        if !self.body.requires_cluster_auth() {
            return true;
        }

        // Unmarshal the signature into its runtime type
        let sig_unmarshalled = Signature::from_bytes(&self.sig);
        if let Ok(sig) = sig_unmarshalled {
            let mut hash_digest = Sha512::new();
            hash_digest.update(&serde_json::to_vec(&self.body).unwrap());
            cluster_pubkey
                .verify_prehashed(hash_digest, None, &sig)
                .is_ok()
        } else {
            false
        }
    }
}

/// Represents the possible response types for a request-response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipResponse {
    /// A simple Ack response, libp2p sometimes closes connections if no response is
    /// sent, so we can send an empty ack in place for requests that need no response
    Ack,
    /// A response from a peer to a sender's heartbeat request
    Heartbeat(HeartbeatMessage),
    /// A response from a peer to a sender's handshake request
    Handshake {
        /// The request ID; used track handshakes across events
        request_id: Uuid,
        /// The message contents
        message: HandshakeMessage,
    },
    /// A response to a request for order information
    OrderInfo(OrderInfoResponse),
}

impl GossipResponse {
    /// Explicitly states which requests need cluster authentication
    ///
    /// The code here is intentionally verbose to force any new request/response types
    /// to be defined with authentication in mind
    pub fn requires_cluster_auth(&self) -> bool {
        match self {
            GossipResponse::Ack => false,
            GossipResponse::Heartbeat(..) => false,
            GossipResponse::Handshake { .. } => false,
            GossipResponse::OrderInfo(..) => false,
        }
    }
}

/// A wrapper around pubsub messages that allows us to attach signatures to the message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedPubsubMessage {
    /// The signature attached to the message
    pub sig: Vec<u8>,
    /// The body of the message
    pub body: PubsubMessage,
}

impl AuthenticatedPubsubMessage {
    /// Construct a new authenticated pubsub message from the pubsub body
    /// Sign the message if its type requires a signature
    pub fn new_with_body(
        body: PubsubMessage,
        cluster_key: &SigKeypair,
    ) -> Result<Self, SignatureError> {
        // Create a signature fo the body
        let sig = if body.requires_cluster_auth() {
            let mut hash_digest: Sha512 = Sha512::new();
            hash_digest.update(&serde_json::to_vec(&body).unwrap());
            cluster_key
                .sign_prehashed(hash_digest, None)?
                .to_bytes()
                .to_vec()
        } else {
            Vec::new()
        };

        Ok(Self { sig, body })
    }

    /// Verify the signature on an authenticated request
    pub fn verify_cluster_auth(&self, cluster_pubkey: &PublicKey) -> bool {
        if !self.body.requires_cluster_auth() {
            return true;
        }

        // Unmarshal the signature into its runtime type
        let sig_unmarshalled = Signature::from_bytes(&self.sig);
        if let Ok(sig) = sig_unmarshalled {
            let mut hash_digest = Sha512::new();
            hash_digest.update(&serde_json::to_vec(&self.body).unwrap());
            cluster_pubkey
                .verify_prehashed(hash_digest, None, &sig)
                .is_ok()
        } else {
            false
        }
    }
}

/// Explicit byte serialization and deserialization
///
/// libp2p gossipsub interface expects a type that can be cast
/// to and from bytes
impl From<AuthenticatedPubsubMessage> for Vec<u8> {
    fn from(msg: AuthenticatedPubsubMessage) -> Self {
        serde_json::to_vec(&msg).unwrap()
    }
}

impl From<Vec<u8>> for AuthenticatedPubsubMessage {
    fn from(bytes: Vec<u8>) -> Self {
        serde_json::from_slice(&bytes).unwrap()
    }
}

/// Represents a pubsub message flooded through the network
///
/// Practically, enum variants listed at this scope should be published on
/// a unique topic per variant; i.e. this is the granularity at which we
/// specify a topic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PubsubMessage {
    /// A message broadcast to indicate an even relevant to cluster management
    ClusterManagement {
        /// The ID of the cluster this message is intended for
        cluster_id: ClusterId,
        /// The message body
        message: ClusterManagementMessage,
    },
    /// A message broadcast to the network to indicate that OrderBook state has changed
    OrderBookManagement(OrderBookManagementMessage),
}

impl PubsubMessage {
    /// Explicitly states which messages need cluster authentication
    ///
    /// The code here is intentionally verbose to force any new request/response types
    /// to be defined with authentication in mind
    pub fn requires_cluster_auth(&self) -> bool {
        match self {
            PubsubMessage::ClusterManagement { .. } => true,
            PubsubMessage::OrderBookManagement(..) => false,
        }
    }
}

/// A message type send from a worker to the network manager itself to explicitly
/// control or signal information
#[derive(Clone, Debug)]
pub enum ManagerControlDirective {
    /// A command signalling to the network manager to open up a QUIC connection and build
    /// an MPC network instance to handshake over
    BrokerMpcNet {
        /// The ID of the ongoing handshake
        request_id: Uuid,
        /// The ID of the peer to dial
        peer_id: WrappedPeerId,
        /// The port that the peer has exposed to dial on
        peer_port: Port,
        /// The local port that should be used to accept the stream
        local_port: Port,
        /// The role of the local node in the connection setup
        local_role: ConnectionRole,
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
    /// A command informing the network manager that the gossip protocol has warmed up
    /// in the network
    ///
    /// The network manager delays Pubsub messages (buffering them) until warmup has elapsed
    /// to allow the libp2p swarm time to build connections that the gossipsub protocol may
    /// graft to
    GossipWarmupComplete,
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
