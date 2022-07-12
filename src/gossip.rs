mod api;
mod errors;
mod heartbeat_protocol;

// This file groups logic for the package-public gossip interface
use heartbeat_protocol::{
    ProtocolVersion,
    RelayerGossipCodec,
    RelayerGossipProtocol
};
use libp2p::{
    identity, 
    futures::StreamExt,
    Multiaddr,
    PeerId,
    request_response::{
        ProtocolSupport,
        RequestResponse,
        RequestResponseEvent,
        RequestResponseMessage
    },
    swarm::{Swarm, SwarmEvent},
};
use std::{
    collections::HashSet,
    error::Error,
    iter
};
use tokio::{
    time::{sleep, Duration},
};

use crate::gossip::api::HeartbeatMessage;

const HEARTBEAT_INTERVAL_MS: u64 = 5000;

pub struct GossipPeer {
    // Local peer information
    port: u32,
    local_peer_id: PeerId,
    
    // Network information
    known_peers: HashSet<PeerId>,
    swarm: Swarm<RequestResponse<RelayerGossipCodec>>
}

impl GossipPeer {
    // Creates a new gossip server
    pub async fn new(
        port: u32,
        bootstrap_servers: Vec<PeerId>
    ) -> Result<Self, Box<dyn Error>> {
        // Build the peer keys
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        println!("peer ID: {}", local_peer_id);

        // Transport is TCP for now, this will eventually move to QUIC
        let transport = libp2p::development_transport(local_key).await?;

        // Build the network behavior
        let mut behavior = RequestResponse::new(
            RelayerGossipCodec::new(),
            iter::once((
                RelayerGossipProtocol::new(ProtocolVersion::Version1),
                ProtocolSupport::Full
            )),
            Default::default()
        );

        // Add all addresses for bootstrap servers
        let mut known_peers = HashSet::new();
        for known_peer in bootstrap_servers.iter() {
            let addr: Multiaddr = "/ip4/127.0.0.1/tcp/12345".parse()?;
            behavior.add_address(known_peer, addr);

            known_peers.insert(*known_peer);
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
                        SwarmEvent::Behaviour(
                            RequestResponseEvent::Message { peer, message }
                        ) => {
                            println!("Recieved {:?} from peer {}\n\n", message, peer);
                            self.process_request_response_event(message).await?;
                        },

                        // Matches an event produced when the local peer dials another peer
                        SwarmEvent::Dialing(peer_id) => { println!("Dialing peer: {}", peer_id); }
                        _ => {
                            println!("Event not matched: {:?}\n\n", event);
                        }
                    }
                }
            }
        }
    }

    // Sends heartbeats to peers to exchange network information and ensure liveness
    async fn send_heartbeats(&mut self) { 
        // Send an outbound heartbeat for every known peer
        println!("I know {} peers...", self.known_peers.len());
        for peer_id in self.known_peers.clone().into_iter() {
            println!("Sending heartbeat to {:?}...", peer_id);
            let request = self.get_heartbeat_message();
            self.swarm.behaviour_mut()
                .send_request(&peer_id, request);
        }
    }

    // Processes a request or response from a peer under the RequestResponse network behavior
    async fn process_request_response_event(
        &mut self, 
        message: RequestResponseMessage<HeartbeatMessage, HeartbeatMessage>
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Switch over request vs response
        match message {
            // A peer has dialed the local peer to check for a heartbeat
            RequestResponseMessage::Request { request, channel, .. } => {
                // Add heartbeat peers to list of known peers
                self.merge_peers(request.get_known_peers()?);

                // Construct response with known peers
                let resp = self.get_heartbeat_message();
                self.swarm.behaviour_mut().send_response(channel, resp).unwrap();
            },

            // A peer has responded to a dialup, confirming their heartbeat
            RequestResponseMessage::Response { response, .. } => {
                self.merge_peers(response.get_known_peers()?);
                println!("Received heartbeat response: {:?}", response);
            }
        }
        Ok(())
    }

    // Constructs the heartbeat message for the local peer
    fn get_heartbeat_message(&self) -> HeartbeatMessage {
        let mut known_peers: Vec<PeerId> = Vec::new();
        for peer in self.known_peers.iter() {
            known_peers.push(*peer);
        }

        HeartbeatMessage::new(known_peers)
    }

    // Merges the peers from a heartbeat into the set of known peers
    fn merge_peers(&mut self, new_peers: Vec<PeerId>) {
        for peer in new_peers.iter() {
            self.known_peers.insert(*peer);
        }
    }
}