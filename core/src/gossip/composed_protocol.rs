use async_trait::async_trait;
use libp2p::{
    core::upgrade::{read_length_prefixed, write_length_prefixed},
    futures::{AsyncRead, AsyncWrite, AsyncWriteExt},
    kad::{record::store::MemoryStore, Kademlia, KademliaEvent},
    request_response::{
        ProtocolName, ProtocolSupport, RequestResponse, RequestResponseCodec, RequestResponseEvent,
    },
    NetworkBehaviour, PeerId,
};
use std::iter;

use crate::gossip::api::{GossipRequest, GossipResponse};

/**
 * Constants
 */

// The maximum size libp2p should allocate buffer space for
const MAX_MESSAGE_SIZE: usize = 1_000_000_000;

/**
 * This file defines the logic for combining various libp2p network behaviors into a single
 * protocol. We combine a handfull of different libp2p protocols to support different
 * use cases:
 *      1. RequestResponse: Used for p2p direct communication (e.g. heartbeat)
 *      2. KAD: Used for peer discovery and application level routing information (e.g. wallet ownership)
 *      3. GossipSub: a decentralized pubsub protocol, used for broadcast primitives.
 */

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ComposedProtocolEvent")]
pub struct ComposedNetworkBehavior {
    pub request_response: RequestResponse<RelayerGossipCodec>,
    pub kademlia_dht: Kademlia<MemoryStore>,
}

impl ComposedNetworkBehavior {
    pub fn new(peer_id: PeerId) -> Self {
        let request_response = RequestResponse::new(
            RelayerGossipCodec::new(),
            iter::once((
                RelayerGossipProtocol::new(ProtocolVersion::Version1),
                ProtocolSupport::Full,
            )),
            Default::default(),
        );

        let memory_store = MemoryStore::new(peer_id);
        let kademlia_dht = Kademlia::new(peer_id, memory_store);

        Self {
            request_response,
            kademlia_dht,
        }
    }
}

#[derive(Debug)]
pub enum ComposedProtocolEvent {
    RequestResponse(RequestResponseEvent<GossipRequest, GossipResponse>),
    Kademlia(KademliaEvent),
}

/*
 * Composed event trait implementations; simply choose the correct enum value
 */
impl From<KademliaEvent> for ComposedProtocolEvent {
    fn from(e: KademliaEvent) -> Self {
        ComposedProtocolEvent::Kademlia(e)
    }
}

impl From<RequestResponseEvent<GossipRequest, GossipResponse>> for ComposedProtocolEvent {
    fn from(e: RequestResponseEvent<GossipRequest, GossipResponse>) -> Self {
        ComposedProtocolEvent::RequestResponse(e)
    }
}

/**
 * Heartbeat protocol versioning, metadata, and codec
 */

// Specifies versioning information about the protocol
#[derive(Debug, Clone)]
pub enum ProtocolVersion {
    Version1,
}

// Represents the gossip protocol
#[derive(Debug, Clone)]
pub struct RelayerGossipProtocol {
    version: ProtocolVersion,
}

impl RelayerGossipProtocol {
    pub fn new(version: ProtocolVersion) -> Self {
        Self { version }
    }
}

impl ProtocolName for RelayerGossipProtocol {
    fn protocol_name(&self) -> &[u8] {
        match self.version {
            ProtocolVersion::Version1 => b"/relayer-gossip/1.0",
        }
    }
}

#[derive(Clone)]
// The request/response codec used in the gossip protocol
pub struct RelayerGossipCodec {}

impl RelayerGossipCodec {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl RequestResponseCodec for RelayerGossipCodec {
    type Protocol = RelayerGossipProtocol;
    type Request = GossipRequest;
    type Response = GossipResponse;

    // Deserializes a read request
    async fn read_request<T>(
        &mut self,
        _: &RelayerGossipProtocol,
        io: &mut T,
    ) -> Result<Self::Request, std::io::Error>
    where
        T: AsyncRead + Unpin + Send,
    {
        let req_data = read_length_prefixed(io, MAX_MESSAGE_SIZE).await?;
        let deserialized: GossipRequest = serde_json::from_slice(&req_data).unwrap();
        Ok(deserialized)
    }

    // Deserializes a read response
    async fn read_response<T>(
        &mut self,
        _: &RelayerGossipProtocol,
        io: &mut T,
    ) -> Result<Self::Response, std::io::Error>
    where
        T: AsyncRead + Unpin + Send,
    {
        let resp_data = read_length_prefixed(io, MAX_MESSAGE_SIZE).await?;
        let deserialized: GossipResponse = serde_json::from_slice(&resp_data).unwrap();
        Ok(deserialized)
    }

    // Serializes a write request
    async fn write_request<T>(
        &mut self,
        _: &RelayerGossipProtocol,
        io: &mut T,
        req: Self::Request,
    ) -> Result<(), std::io::Error>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Serialize the data and write to socket
        let serialized = serde_json::to_string(&req).unwrap();
        write_length_prefixed(io, serialized.as_bytes()).await?;

        io.close().await?;
        Ok(())
    }

    // Serializes a write response
    async fn write_response<T>(
        &mut self,
        _: &RelayerGossipProtocol,
        io: &mut T,
        resp: Self::Response,
    ) -> Result<(), std::io::Error>
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
