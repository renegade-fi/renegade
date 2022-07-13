use crossbeam::channel::Sender;
use futures::executor::block_on;
use libp2p::{
    futures::StreamExt,
    identity,
    Multiaddr, 
    PeerId,
    request_response::{RequestResponseEvent, RequestResponseMessage},
    Swarm, 
    swarm::SwarmEvent, kad::KademliaEvent, 
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    thread::{
        Builder,
        JoinHandle, self,
    }
};
use tokio::{
    sync::mpsc::{UnboundedReceiver},
};

use crate::gossip::{
    composed_protocol::{
        ComposedNetworkBehavior, ComposedProtocolEvent
    }, 
    types::PeerInfo, 
    heartbeat_protocol::HeartbeatExecutorJob
};

use super::api::{GossipOutbound, GossipMessage};

// Groups logic around monitoring and requesting the network
pub struct NetworkManager {
    // The peerId of the locally running node
    pub local_peer_id: PeerId,

    // The join handle of the executor loop
    pub thread_handle: JoinHandle<()> 
}

// The NetworkManager handles both incoming and outbound messages to the p2p network
// It accepts events from workers elsewhere in the relayer that are to be propagated
// out to the network; as well as listening on the network for messages from other peers.
impl NetworkManager {
    pub async fn new(
        port: u32,
        peer_info: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
        send_channel: UnboundedReceiver<GossipOutbound>,
        heartbeat_work_queue: Sender<HeartbeatExecutorJob>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Build the peer keys
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = local_key.public().to_peer_id();
        println!("peer ID: {}", local_peer_id);

        // Transport is TCP for now, this will eventually move to QUIC
        let transport = libp2p::development_transport(local_key).await?;

        // Behavior is a composed behavior of RequestResponse with Kademlia
        let mut behavior = ComposedNetworkBehavior::new(local_peer_id);

        // Add all addresses for bootstrap servers
        for (peer_id, peer_info) in peer_info.clone()
                                        .read()
                                        .unwrap()
                                        .iter() 
        {
            println!("Adding {}: {} to routing table...", peer_id, peer_info.get_addr());
            behavior.kademlia_dht.add_address(peer_id, peer_info.get_addr());
        }            

        // Connect the behavior and the transport via swarm
        // and begin listening for requests
        let mut swarm = Swarm::new(transport, behavior, local_peer_id);
        let hostport = format!("/ip4/127.0.0.1/tcp/{}", port);
        let addr: Multiaddr = hostport.parse()?;
        swarm.listen_on(addr.clone())?;

        // Add self to known peers
        peer_info.clone()
            .write()
            .unwrap()
            .insert(
                local_peer_id, PeerInfo::new(local_peer_id, addr)
            );

        // Start up the worker thread
        let thread_handle = Builder::new()
            .name("network-manager".to_string())
            .spawn(move || {
                // Block on this to execute the future in a separate thread
                block_on(
                    Self::executor_loop(
                        local_peer_id,
                        swarm,
                        send_channel,
                        heartbeat_work_queue,
                    ) 
                )
            })
            .unwrap();
        
        Ok(Self { local_peer_id, thread_handle })
    }

    // Joins the calling thread to the execution of the network manager loop
    pub fn join(self) -> thread::Result<()> {
        self.thread_handle.join()
    }

    // The main loop in which the worker thread processes requests
    // The worker handles two types of events:
    //      1. Events from the network; which it dispatches to appropriate handler threads
    //      2. Events from workers to be sent over the network
    // It handles these in the tokio select! macro below
    async fn executor_loop(
        local_peer_id: PeerId,
        mut swarm: Swarm<ComposedNetworkBehavior>,
        mut send_channel: UnboundedReceiver<GossipOutbound>,
        heartbeat_work_queue: Sender<HeartbeatExecutorJob>
    ) {
        println!("Starting executor loop for network manager...");
        loop {
            tokio::select! {
                // Handle network requests from worker components of the relayer
                Some(message) = send_channel.recv() => {
                    // Forward the message
                    Self::handle_outbound_message(message, &mut swarm);
                },
                
                // Handle network events and dispatch
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(event) => {
                            Self::handle_inbound_messsage(
                                event,
                                heartbeat_work_queue.clone()
                            )
                        },
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("Listening on {}/p2p/{}\n", address, local_peer_id);
                        },
                        _ => { println!("Unmatched event {:?}", event) }
                    }
                }
            }
        } 
    }

    // Handles an outbound message from worker threads to other relayers
    fn handle_outbound_message(
        msg: GossipOutbound,
        swarm: &mut Swarm<ComposedNetworkBehavior>
    ) {
        match msg {
            GossipOutbound::Request { peer_id, message } => {
                swarm.behaviour_mut()
                    .request_response
                    .send_request(&peer_id, message);
            },
            GossipOutbound::Response { channel, message } => {
                swarm.behaviour_mut()
                    .request_response
                    .send_response(channel, message);
            },

            // Register a new peer in the distributed routing tables
            GossipOutbound::NewAddr { peer_id, address } => {
                swarm.behaviour_mut()
                    .kademlia_dht
                    .add_address(&peer_id, address);
            }
        }
    }

    // Handles a network event from the relayer's protocol
    fn handle_inbound_messsage(
        message: ComposedProtocolEvent,
        heartbeat_work_queue: Sender<HeartbeatExecutorJob>
    ) {
        match message {
            ComposedProtocolEvent::RequestResponse(request_response) => {
                if let RequestResponseEvent::Message{ peer, message } = request_response {
                    Self::handle_inbound_request_response_message(peer, message, heartbeat_work_queue);
                }
            },
            ComposedProtocolEvent::Kademlia(event) => { Self::handle_inbound_kademlia_event(event) }
        }
    }

    /**
     * Request/Response event handlers
     */

    fn handle_inbound_request_response_message(
        peer_id: PeerId,
        message: RequestResponseMessage<GossipMessage, GossipMessage>,
        heartbeat_work_queue: Sender<HeartbeatExecutorJob>,
    ) {
        // Multiplex over request/response message types
        match message {
            // Handle inbound request from another peer
            RequestResponseMessage::Request { request, channel, ..} => {
                match request {
                    GossipMessage::Heartbeat(heartbeat_message) => {
                        heartbeat_work_queue.send(
                            HeartbeatExecutorJob::HandleHeartbeatReq { peer_id, message: heartbeat_message, channel }
                        );
                    }
                }
            },

            // Handle inbound response 
            RequestResponseMessage::Response { response, .. } => {
                match response {
                    GossipMessage::Heartbeat(heartbeat_message) => {
                        heartbeat_work_queue.send(
                            HeartbeatExecutorJob::HandleHeartbeatResp { peer_id, message: heartbeat_message }
                        );
                    }
                }
            }
        }
    }

    /**
     * Kademlia event handlers
     */

    // Handles Kademlia network events
    fn handle_inbound_kademlia_event(
        event: KademliaEvent
    ) {
        println!("Received KAD event: {:?}", event);
    }
}