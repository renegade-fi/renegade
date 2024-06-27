//! This file defines the logic for combining various libp2p network behaviors
//! into a single protocol. We combine a handful of different libp2p protocols
//! to support different use cases:
//!      1. RequestResponse: Used for p2p direct communication (e.g. heartbeat)
//!      2. KAD: Used for peer discovery and application level routing
//!         information (e.g. wallet ownership)
//!      3. GossipSub: a decentralized pubsub protocol, used for broadcast
//!         primitives.

use async_trait::async_trait;
use gossip_api::request_response::{AuthenticatedGossipRequest, AuthenticatedGossipResponse};
use libp2p::{
    core::upgrade::{read_length_prefixed, write_length_prefixed},
    futures::{AsyncRead, AsyncWrite, AsyncWriteExt},
    gossipsub::{
        Behaviour as Gossipsub, ConfigBuilder as GossipsubConfigBuilder, Event as GossipsubEvent,
        MessageAuthenticity,
    },
    identify::{Behaviour as IdentifyProtocol, Config as IdentifyConfig, Event as IdentifyEvent},
    identity::Keypair,
    kad::{record::store::MemoryStore, Kademlia, KademliaEvent},
    request_response::{
        Behaviour as RequestResponse, Codec as RequestResponseCodec,
        Config as RequestResponseConfig, Event as RequestResponseEvent, ProtocolName,
        ProtocolSupport,
    },
    PeerId,
};
use libp2p_swarm_derive::NetworkBehaviour;
use std::{
    fmt::{Display, Formatter},
    io::{Error as IoError, ErrorKind},
    iter,
    time::Duration,
};

use super::error::NetworkManagerError;

// -------------
// | Constants |
// -------------

/// The maximum size libp2p should allocate buffer space for
const MAX_MESSAGE_SIZE: usize = 1_000_000_000;

/// The timeout for inbound/outbound requests, in seconds
const REQ_RES_TIMEOUT_SECS: u64 = 60;

/// The composed behavior that handles all types of network requests that
/// various workers need access to
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ComposedProtocolEvent")]
pub struct ComposedNetworkBehavior {
    /// The request/response behavior; provides a point-to-point communication
    /// primitive for relayers to dial each other directly on
    pub request_response: RequestResponse<RelayerGossipCodec>,
    /// The Kademlia DHT behavior; used for storing distributed state, including
    /// peer address information
    pub kademlia_dht: Kademlia<MemoryStore>,
    /// The Gossipsub behavior; used for broadcast (pubsub) primitives
    pub pubsub: Gossipsub,
    /// The identify protocol behavior, used for getting publicly facing
    /// information about the local node
    pub identify: IdentifyProtocol,
}

impl ComposedNetworkBehavior {
    /// Construct the behavior
    pub fn new(
        peer_id: PeerId,
        protocol_version: ProtocolVersion,
        keypair: &Keypair,
    ) -> Result<Self, NetworkManagerError> {
        // Construct the point-to-point request response protocol
        let mut request_response_config: RequestResponseConfig = Default::default();
        request_response_config.set_request_timeout(Duration::from_secs(REQ_RES_TIMEOUT_SECS));
        let request_response = RequestResponse::new(
            RelayerGossipCodec::new(),
            iter::once((RelayerGossipProtocol::new(protocol_version), ProtocolSupport::Full)),
            request_response_config,
        );

        // Construct the peer info KDHT
        let memory_store = MemoryStore::new(peer_id);
        let kademlia_dht = Kademlia::new(peer_id, memory_store);

        // Construct the pubsub network behavior
        let pubsub = Gossipsub::new(
            MessageAuthenticity::Signed(keypair.clone()),
            GossipsubConfigBuilder::default().max_transmit_size(MAX_MESSAGE_SIZE).build().unwrap(),
        )
        .map_err(|err| NetworkManagerError::SetupError(err.to_string()))?;

        // The identify protocol; used to allow the local node to gain publicly facing
        // info about itself; i.e. dialable IP
        let identify = IdentifyProtocol::new(IdentifyConfig::new(
            protocol_version.to_string(),
            keypair.public(),
        ));

        Ok(Self { request_response, kademlia_dht, pubsub, identify })
    }
}

/// A level of indirection that papers over the different message types that
/// each behavior may implement
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ComposedProtocolEvent {
    /// An event from the request/response behavior, point-to-point
    RequestResponse(RequestResponseEvent<AuthenticatedGossipRequest, AuthenticatedGossipResponse>),
    /// An event from the KDHT behavior; e.g. new address
    Kademlia(KademliaEvent),
    /// An event from the pubsub behavior; broadcast
    PubSub(GossipsubEvent),
    /// An event from the identify behavior
    Identify(IdentifyEvent),
}

/// Composed event trait implementations; simply choose the correct enum value
impl From<KademliaEvent> for ComposedProtocolEvent {
    fn from(e: KademliaEvent) -> Self {
        ComposedProtocolEvent::Kademlia(e)
    }
}

impl From<RequestResponseEvent<AuthenticatedGossipRequest, AuthenticatedGossipResponse>>
    for ComposedProtocolEvent
{
    fn from(
        e: RequestResponseEvent<AuthenticatedGossipRequest, AuthenticatedGossipResponse>,
    ) -> Self {
        ComposedProtocolEvent::RequestResponse(e)
    }
}

impl From<GossipsubEvent> for ComposedProtocolEvent {
    fn from(e: GossipsubEvent) -> Self {
        ComposedProtocolEvent::PubSub(e)
    }
}

impl From<IdentifyEvent> for ComposedProtocolEvent {
    fn from(e: IdentifyEvent) -> Self {
        ComposedProtocolEvent::Identify(e)
    }
}

// --------------------------
// | Request Response Codec |
// --------------------------

/// Specifies versioning information about the protocol
#[derive(Debug, Clone, Copy)]
pub enum ProtocolVersion {
    /// The version of the protocol in use
    Version0,
}

impl Display for ProtocolVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ProtocolVersion::Version0 => "0.0.0",
        })
    }
}

/// Represents the gossip protocol
#[derive(Debug, Clone)]
pub struct RelayerGossipProtocol {
    /// The version of the protocol in use
    version: ProtocolVersion,
}

impl RelayerGossipProtocol {
    /// Create a new instance of the protocol
    pub fn new(version: ProtocolVersion) -> Self {
        Self { version }
    }
}

impl ProtocolName for RelayerGossipProtocol {
    fn protocol_name(&self) -> &[u8] {
        match self.version {
            ProtocolVersion::Version0 => b"/relayer-gossip/1.0",
        }
    }
}

/// The request/response codec used in the gossip protocol
#[derive(Clone, Default)]
pub struct RelayerGossipCodec;
impl RelayerGossipCodec {
    /// Create a new instance of the marshal/unmarshal codec
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl RequestResponseCodec for RelayerGossipCodec {
    type Protocol = RelayerGossipProtocol;
    type Request = AuthenticatedGossipRequest;
    type Response = AuthenticatedGossipResponse;

    /// Deserializes a read request
    async fn read_request<T>(
        &mut self,
        _: &RelayerGossipProtocol,
        io: &mut T,
    ) -> Result<Self::Request, IoError>
    where
        T: AsyncRead + Unpin + Send,
    {
        let req_data = read_length_prefixed(io, MAX_MESSAGE_SIZE).await?;
        if req_data.is_empty() {
            return Err(IoError::new(ErrorKind::InvalidData, "empty request"));
        }

        let deserialized: AuthenticatedGossipRequest = serde_json::from_slice(&req_data).unwrap();
        Ok(deserialized)
    }

    /// Deserializes a read response
    async fn read_response<T>(
        &mut self,
        _: &RelayerGossipProtocol,
        io: &mut T,
    ) -> Result<Self::Response, IoError>
    where
        T: AsyncRead + Unpin + Send,
    {
        let resp_data = read_length_prefixed(io, MAX_MESSAGE_SIZE).await?;
        if resp_data.is_empty() {
            return Err(IoError::new(ErrorKind::InvalidData, "empty response"));
        }

        let deserialized: AuthenticatedGossipResponse = serde_json::from_slice(&resp_data).unwrap();
        Ok(deserialized)
    }

    /// Serializes a write request
    async fn write_request<T>(
        &mut self,
        _: &RelayerGossipProtocol,
        io: &mut T,
        req: Self::Request,
    ) -> Result<(), IoError>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Serialize the data and write to socket
        let serialized = serde_json::to_string(&req).unwrap();
        write_length_prefixed(io, serialized.as_bytes()).await?;

        io.close().await?;
        Ok(())
    }

    /// Serializes a write response
    async fn write_response<T>(
        &mut self,
        _: &RelayerGossipProtocol,
        io: &mut T,
        resp: Self::Response,
    ) -> Result<(), IoError>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Serialize the response and write to socket
        let serialized = serde_json::to_string(&resp).unwrap();
        write_length_prefixed(io, serialized.as_bytes()).await?;

        io.close().await?;
        Ok(())
    }
}
