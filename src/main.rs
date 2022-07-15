mod config;
mod gossip;
mod state;

use crate::{
    gossip::GossipServer,
    state::{RelayerState}
};

#[tokio::main]
async fn main() -> Result<(), String> {
    // Parse command line arguments
    let args = config::parse_command_line_args().expect("error parsing command line args");
    println!("Relayer running with\n\t version: {}\n\t port: {}", args.version, args.port);

    // Construct the global state
    let global_state = RelayerState::initialize_global_state();

    let gossip_server = GossipServer::new(
        args.port, 
        args.boostrap_servers,
        global_state
    ).await.unwrap();
    
    // Await the gossip server's termination
    gossip_server.join();
    Err("Relayer terminated...".to_string())
}
