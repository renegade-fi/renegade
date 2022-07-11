mod protocol;
mod api;
mod errors;

// This file groups logic for the package-public gossip interface
use libp2p::{
    identity,
    PeerId,
    request_response::{
        ProtocolSupport,
        RequestResponse
    },
    swarm::Swarm,
};
use std::{
    error::Error,
    iter
};
use crate::gossip::protocol::ProtocolVersion;

// Starts the gossip server and connects to boostrap servers
pub async fn start_gossip_server(bootstrap_servers: Vec<String>) -> Result<(), Box<dyn Error>> {
    // Build the peer keys
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    // Transport is TCP for now, this will eventually move to QUIC
    let transport = libp2p::development_transport(local_key).await?;

    // Build the network behavior
    // let behavior = GossipBehavior::new();
    let behavior = RequestResponse::new(
        protocol::RelayerGossipCodec::new(),
        iter::once((
            protocol::RelayerGossipProtocol::new(ProtocolVersion::Version1),
            ProtocolSupport::Full
        )),
        Default::default()
    );

    // Connect the behavior and transport together through swarm
    let mut swarm = Swarm::new(transport, behavior, local_peer_id);
    println!("Started server...");
    Ok(())
}
