mod config;
mod gossip;
mod handshake;
mod state;

use crate::{
    gossip::GossipServer,
    handshake::HandshakeManager,
    state::{RelayerState}
};

#[tokio::main]
async fn main() -> Result<(), String> {
    // Parse command line arguments
    let args = config::parse_command_line_args().expect("error parsing command line args");
    println!("Relayer running with\n\t version: {}\n\t port: {}", args.version, args.port);

    // Construct the global state
    let global_state = RelayerState::initialize_global_state(args.wallet_ids);

    // Start the gossip server
    let gossip_server = GossipServer::new(
        args.port, 
        args.boostrap_servers,
        global_state
    ).await.unwrap();
    
    // Start the handshake manager
    let handshake_manager = HandshakeManager::new();
    
    // Await the gossip server's termination
    gossip_server.join();
    handshake_manager.join();
    Err("Relayer terminated...".to_string())
}
