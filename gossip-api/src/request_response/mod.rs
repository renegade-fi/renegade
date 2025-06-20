//! The request/response API types for the gossip protocol

use common::types::hmac::HmacKey;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use util::telemetry::propagation::{trace_context, TraceContext};

use crate::{check_hmac, create_hmac, GossipDestination};

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
    pub inner: GossipRequest,
}

impl AuthenticatedGossipRequest {
    /// Constructs a new authenticated gossip request given the request body
    ///
    /// Attaches a signature of the body using the given cluster private key
    /// if one is necessary
    pub fn new_with_body(req: GossipRequest, cluster_key: &HmacKey) -> Self {
        // Create a signature fo the body
        let sig = if req.requires_cluster_auth() {
            create_hmac(&req.body, cluster_key)
        } else {
            Vec::new()
        };

        Self { sig, inner: req }
    }

    /// Verify the signature on an authenticated request
    #[instrument(name = "verify_cluster_auth", skip_all)]
    pub fn verify_cluster_auth(&self, key: &HmacKey) -> bool {
        if !self.inner.requires_cluster_auth() {
            return true;
        }

        check_hmac(&self.inner.body, &self.sig, key)
    }
}

/// A request send via the p2p layer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipRequest {
    /// The tracing context
    pub tracing_context: Option<TraceContext>,
    /// The type of the request
    pub body: GossipRequestType,
}

impl GossipRequest {
    /// Construct a new request and add the current tracing information
    pub fn new(body: GossipRequestType) -> Self {
        let tracing_context = Some(trace_context());
        Self { tracing_context, body }
    }

    /// Get the tracing headers
    ///
    /// Returns an empty `TraceContext` if no tracing context is present
    pub fn tracing_headers(&self) -> TraceContext {
        self.tracing_context.clone().unwrap_or_default()
    }
}

/// The type of a gossip request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipRequestType {
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
        match self.body {
            GossipRequestType::Ack => false,
            // Raft messages are always cluster authenticated
            GossipRequestType::Raft(..) => true,
            GossipRequestType::Bootstrap(..) => false,
            GossipRequestType::Heartbeat(..) => false,
            GossipRequestType::PeerInfo(..) => false,
            GossipRequestType::Handshake { .. } => false,
            GossipRequestType::OrderInfo(..) => false,
        }
    }

    /// The destination to which a request should be sent
    pub fn destination(&self) -> GossipDestination {
        match self.body {
            GossipRequestType::Ack => GossipDestination::NetworkManager,
            // We send to the network manager so that it will implicitly give an ack
            GossipRequestType::Raft(..) => GossipDestination::NetworkManager,
            GossipRequestType::Bootstrap(..) => GossipDestination::GossipServer,
            GossipRequestType::Heartbeat(..) => GossipDestination::GossipServer,
            GossipRequestType::PeerInfo(..) => GossipDestination::GossipServer,
            GossipRequestType::OrderInfo(..) => GossipDestination::GossipServer,
            GossipRequestType::Handshake { .. } => GossipDestination::HandshakeManager,
        }
    }
}

impl From<GossipRequestType> for GossipRequest {
    fn from(body: GossipRequestType) -> Self {
        GossipRequest::new(body)
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
    pub inner: GossipResponse,
}

impl AuthenticatedGossipResponse {
    /// A helper function to create a simple ack without needing to explicitly
    /// construct the nested enumerative types
    pub fn new_ack() -> Self {
        Self { sig: Vec::new(), inner: GossipResponseType::Ack.into() }
    }

    /// Constructs a new authenticated gossip request given the request body.
    /// Attaches a signature of the body using the given cluster private key
    /// if one is necessary
    pub fn new_with_body(req: GossipResponse, cluster_key: &HmacKey) -> Self {
        // Create a signature fo the body
        let sig = if req.requires_cluster_auth() {
            create_hmac(&req.body, cluster_key)
        } else {
            Vec::new()
        };

        Self { sig, inner: req }
    }

    /// Verify the signature on an authenticated request
    #[instrument(name = "verify_cluster_auth", skip_all)]
    pub fn verify_cluster_auth(&self, cluster_key: &HmacKey) -> bool {
        if !self.inner.requires_cluster_auth() {
            return true;
        }

        check_hmac(&self.inner.body, &self.sig, cluster_key)
    }
}

/// A response sent via the p2p layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipResponse {
    /// The tracing context
    pub tracing_context: Option<TraceContext>,
    /// The type of response
    pub body: GossipResponseType,
}

impl GossipResponse {
    /// Construct a new response and add the current tracing information
    pub fn new(body: GossipResponseType) -> Self {
        let tracing_context = Some(trace_context());
        Self { tracing_context, body }
    }

    /// Get the tracing headers
    ///
    /// Returns an empty `TraceContext` if no tracing context is present
    pub fn tracing_headers(&self) -> TraceContext {
        self.tracing_context.clone().unwrap_or_default()
    }
}

/// Represents the type of gossip response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipResponseType {
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
        match self.body {
            GossipResponseType::Ack => false,
            GossipResponseType::Heartbeat(..) => false,
            GossipResponseType::Handshake { .. } => false,
            GossipResponseType::OrderInfo(..) => false,
            GossipResponseType::PeerInfo(..) => false,
            GossipResponseType::Raft(..) => true,
        }
    }

    /// The destination to which a request should be sent
    pub fn destination(&self) -> GossipDestination {
        match self.body {
            GossipResponseType::Ack => GossipDestination::NetworkManager,
            GossipResponseType::Heartbeat(..) => GossipDestination::GossipServer,
            GossipResponseType::PeerInfo(..) => GossipDestination::GossipServer,
            GossipResponseType::OrderInfo(..) => GossipDestination::GossipServer,
            GossipResponseType::Handshake { .. } => GossipDestination::HandshakeManager,
            GossipResponseType::Raft(..) => GossipDestination::NetworkManager,
        }
    }
}

impl From<GossipResponseType> for GossipResponse {
    fn from(body: GossipResponseType) -> Self {
        GossipResponse::new(body)
    }
}
