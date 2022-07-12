mod config;
mod gossip;

use crate::gossip::GossipPeer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args = config::parse_command_line_args().expect("error parsing command line args");
    println!("Relayer running with\n\t version: {}\n\t port: {}", args.version, args.port);

    let mut gossip_peer = GossipPeer::new(
        args.port, 
        args.boostrap_servers
    ).await.unwrap();
    gossip_peer.start().await
}
