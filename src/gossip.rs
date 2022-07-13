mod api;
mod errors;
mod composed_protocol;
mod heartbeat_protocol;

// This file groups logic for the package-public gossip interface
use libp2p::{
    identity, 
    futures::StreamExt,
    Multiaddr,
    PeerId,
    request_response::{
        RequestResponseEvent,
        RequestResponseMessage
    },
    swarm::{Swarm, SwarmEvent}, kad::KademliaEvent,
};
use std::{
    collections::HashMap,
    error::Error,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    time::{sleep, Duration},
};
use crate::gossip::{
    api::HeartbeatMessage, 
    composed_protocol::{
        ComposedNetworkBehavior,
        ComposedProtocolEvent
    }
};

const HEARTBEAT_INTERVAL_MS: u64 = 5000;
const HEARTBEAT_FAILURE_S: u64 = 10;

pub struct GossipServer {
    // Local peer information
    port: u32,
    local_peer_id: PeerId,
    
    // Network information
    known_peers: HashMap<PeerId, PeerInfo>,
    swarm: Swarm<ComposedNetworkBehavior>
}

// Contains information about connected peers
#[derive(Debug)]
struct PeerInfo {
    // Last time a successful hearbeat was received from this peer
    last_heartbeat: AtomicU64
}

impl PeerInfo {
    pub fn new() -> Self {
        Self { last_heartbeat: AtomicU64::new(current_time_seconds()) }
    }

    // Records a successful heartbeat
    pub fn successful_heartbeat(&mut self) {
        self.last_heartbeat.store(current_time_seconds(), Ordering::Relaxed);
    }
}

// Returns a u64 representing the current unix timestamp in seconds
fn current_time_seconds() -> u64 {
    SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("negative timestamp")
                .as_secs()
}

// Clones PeerInfo to reference the curren time for the last heartbeat
impl Clone for PeerInfo {
    fn clone(&self) -> Self {
        Self { last_heartbeat: AtomicU64::new(self.last_heartbeat.load(Ordering::Relaxed)) }         
    }
}

impl GossipServer {
    // Creates a new gossip server
    pub async fn new(
        port: u32,
        bootstrap_servers: Vec<PeerId>
    ) -> Result<Self, Box<dyn Error>> {
        // Build the peer keys
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = local_key.public().to_peer_id();
        println!("peer ID: {}", local_peer_id);

        // Transport is TCP for now, this will eventually move to QUIC
        let transport = libp2p::development_transport(local_key).await?;

        let mut behavior = ComposedNetworkBehavior::new(local_peer_id);
        // Add all addresses for bootstrap servers
        let mut known_peers = HashMap::new();
        for known_peer in bootstrap_servers.iter() {
            let addr: Multiaddr = "/ip4/127.0.0.1/tcp/12345".parse()?;
            behavior.kademlia_dht.add_address(known_peer, addr);

            let peer_info = PeerInfo::new(); 
            known_peers.insert(*known_peer, peer_info);
        }

        // Connect the behavior and transport together through swarm
        let swarm = Swarm::new(transport, behavior, local_peer_id);

        Ok(Self { 
            port, 
            local_peer_id,
            known_peers,
            swarm
        })
    }

    // Starts the gossip server and connects to boostrap servers
    pub async fn start(&mut self) -> Result<(), Box<dyn Error>> {
        println!("Starting server...");
        // Start listening on the given port
        let hostport = format!("/ip4/127.0.0.1/tcp/{}", self.port);
        let addr: Multiaddr = hostport.parse()?;
        self.swarm.listen_on(addr)?;

        // Main event loop
        loop {
            tokio::select! {
                // Heartbeat interval, check in with peers
                _ = sleep(Duration::from_millis(HEARTBEAT_INTERVAL_MS)) => {
                    println!("heartbeat interval...");
                    self.send_heartbeats().await;
                },
                event = self.swarm.select_next_some() => {
                    match event {
                        // Matches a new socket binding
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("Listening on {}/p2p/{}\n\n", address, self.local_peer_id);
                        },

                        // Matches a P2P message sent with the RequestResponse behavior
                        SwarmEvent::Behaviour(event) => {
                            self.process_network_event(event).await?;
                        },

                        // Matches an event produced when the local peer dials another peer
                        SwarmEvent::Dialing(peer_id) => { println!("Dialing peer: {}", peer_id); }

                        // Default behavior is to log unmatched events
                        _ => {
                            println!("Event not matched: {:?}\n\n", event);
                        }
                    }
                }
            }
        }
    }

    async fn process_network_event(&mut self, event: ComposedProtocolEvent) 
        -> Result<(), Box<dyn std::error::Error>> {
        match event {
            ComposedProtocolEvent::RequestResponse(e) => { self.process_request_response_event(e).await?; }
            ComposedProtocolEvent::Kademlia(e) => { self.process_kademlia_event(e).await?; }
        }
        Ok(())
    }

    // Processes a request or response from a peer under the RequestResponse network behavior
    async fn process_request_response_event(
        &mut self, 
        event: RequestResponseEvent<HeartbeatMessage, HeartbeatMessage>
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Only match messages for now, later connection informtation will be matched and traced
        if let RequestResponseEvent::Message { message, peer } = event {
            match message {
                // A peer has dialed the local peer to check for a heartbeat
                RequestResponseMessage::Request { request, channel, .. } => {
                    // Add heartbeat peers to list of known peers
                    let mut known_peers = request.get_known_peers()?;
                    known_peers.push(peer);
                    self.merge_peers(known_peers);

                    // Construct response with known peers
                    let resp = self.get_heartbeat_message();
                    self.swarm
                        .behaviour_mut()
                        .request_response
                        .send_response(channel, resp)
                        .unwrap();
                },

                // A peer has responded to a dialup, confirming their heartbeat
                RequestResponseMessage::Response { response, .. } => {
                    // Update the heartbeat for the peer that responded
                    self.record_heartbeat(&peer);

                    // Update routing and replication information 
                    self.merge_peers(response.get_known_peers()?);
                    println!("Received heartbeat response: {:?}", response);
                }
            }
        }

        Ok(())
    }

    // Records a successful heartbeat
    fn record_heartbeat(&mut self, peer_id: &PeerId) {
        if let Some(peer_info) = self.known_peers.get_mut(peer_id) {
            peer_info.successful_heartbeat();
        }
    }

    // Merges the peers from a heartbeat into the set of known peers
    fn merge_peers(&mut self, new_peers: Vec<PeerId>) {
        for peer in new_peers.iter() {
            if *peer == self.local_peer_id || self.known_peers.contains_key(peer) {
                continue;
            }

            self.known_peers.insert(*peer, PeerInfo::new());
        }
    }

    // Sends heartbeats to peers to exchange network information and ensure liveness
    async fn send_heartbeats(&mut self) { 
        // Send an outbound heartbeat for every known peer
        println!("I know {} peers...", self.known_peers.len());
        for peer_id in self.known_peers.clone().into_iter() {
            println!("Sending heartbeat to {:?}...", peer_id);
            let request = self.get_heartbeat_message();
            self.swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id.0, request);
        }

        // Remove any peers that have timed out on heartbeats
        self.expire_peers();
    }

    // Expires any peers that have not replied to a heartbeat recently
    fn expire_peers(&mut self) {
        let now = current_time_seconds();
        let mut peers_to_remove = Vec::new();

        for (peer_id, peer_info) in self.known_peers.iter() {
            if now - peer_info.last_heartbeat.load(Ordering::Relaxed) >= HEARTBEAT_FAILURE_S {
                println!("Expiring peer: {}", peer_id);
                peers_to_remove.push(*peer_id);
            } 
        }

        for peer in peers_to_remove.iter() {
            self.known_peers.remove(peer);
        }

        println!("Finished expiring {} peers", peers_to_remove.len());
    }

    // Constructs the heartbeat message for the local peer
    fn get_heartbeat_message(&self) -> HeartbeatMessage {
        let mut known_peers: Vec<PeerId> = Vec::new();
        for peer in self.known_peers.iter() {
            known_peers.push(*peer.0);
        }

        HeartbeatMessage::new(known_peers)
    }

    // Processes a Kademlia DHT event from the Kademlia network behavior
    async fn process_kademlia_event(
        &mut self,
        event: KademliaEvent
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("Received Kademlia event: {:?}", event);
        Ok(())
    }
}