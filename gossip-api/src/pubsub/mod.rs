//! Pubsub API definitions for the gossip protocol

use ed25519_dalek::{Keypair as SigKeypair, PublicKey, SignatureError};
use serde::{Deserialize, Serialize};

use crate::{check_signature, sign_message, GossipDestination};

use self::{cluster::ClusterManagementMessage, orderbook::OrderBookManagementMessage};

pub mod cluster;
pub mod orderbook;

/// A wrapper around pubsub messages that allows us to attach signatures to the
/// message
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

/// Explicit byte serialization and deserialization
///
/// libp2p gossipsub interface expects a type that can be cast
/// to and from bytes
impl From<AuthenticatedPubsubMessage> for Vec<u8> {
    fn from(msg: AuthenticatedPubsubMessage) -> Self {
        serde_json::to_vec(&msg).unwrap()
    }
}

impl TryFrom<Vec<u8>> for AuthenticatedPubsubMessage {
    type Error = String;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
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
    Cluster(ClusterManagementMessage),
    /// A message broadcast to the network to indicate that OrderBook state has
    /// changed
    Orderbook(OrderBookManagementMessage),
}

impl PubsubMessage {
    /// Explicitly states which messages need cluster authentication
    ///
    /// The code here is intentionally verbose to force any new request/response
    /// types to be defined with authentication in mind
    pub fn requires_cluster_auth(&self) -> bool {
        match self {
            PubsubMessage::Cluster(..) => true,
            PubsubMessage::Orderbook(..) => false,
        }
    }

    /// The destination to send the pubsub message for processing
    pub fn destination(&self) -> GossipDestination {
        match self {
            // All cluster management types are handshake caching messages
            PubsubMessage::Cluster(..) => GossipDestination::HandshakeManager,
            PubsubMessage::Orderbook(..) => GossipDestination::GossipServer,
        }
    }
}
