use libp2p::{
    NetworkBehaviour,
    request_response::{
        RequestResponse, RequestResponseEvent, ProtocolSupport
    },
    kad::{
        Kademlia,
        record::store::MemoryStore, KademliaEvent
    }, PeerId
};
use std::iter;
use crate::{
    gossip::api::HeartbeatMessage, 
    gossip::heartbeat_protocol::{
        RelayerGossipCodec,
        RelayerGossipProtocol,
        ProtocolVersion,
    }
};

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
            Default::default()
        );

        let memory_store = MemoryStore::new(peer_id);
        let kademlia_dht = Kademlia::new(peer_id, memory_store);

        Self { request_response, kademlia_dht }
    }
}

#[derive(Debug)]
pub enum ComposedProtocolEvent {
    RequestResponse(RequestResponseEvent<HeartbeatMessage, HeartbeatMessage>),
    Kademlia(KademliaEvent)
}

/*
 * Composed event trait implementations; simply choose the correct enum value
 */
impl From<KademliaEvent> for ComposedProtocolEvent {
    fn from(e: KademliaEvent) -> Self {
        ComposedProtocolEvent::Kademlia(e)
    }
}

impl From<RequestResponseEvent<HeartbeatMessage, HeartbeatMessage>> for ComposedProtocolEvent {
    fn from(e: RequestResponseEvent<HeartbeatMessage, HeartbeatMessage>) -> Self {
        ComposedProtocolEvent::RequestResponse(e)
    }
}