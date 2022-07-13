mod config;
mod gossip;

use crate::gossip::GossipServer;

#[tokio::main]
async fn main() -> Result<(), String> {
    // Parse command line arguments
    let args = config::parse_command_line_args().expect("error parsing command line args");
    println!("Relayer running with\n\t version: {}\n\t port: {}", args.version, args.port);

    let gossip_server = GossipServer::new(
        args.port, 
        args.boostrap_servers
    ).await.unwrap();
    
    // Await the gossip server's termination
    gossip_server.join();
    Err("Relayer terminated...".to_string())
}
