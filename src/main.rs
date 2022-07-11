mod config;
mod gossip;

use crate::gossip::start_gossip_server;

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args = config::parse_command_line_args();
    let version = match args.version {
        Some(s) => s,
        None => String::from("no version")
    };
    println!("Relayer running with\n\t version: {}\n\t port: {}", version, args.port);

    start_gossip_server(vec![String::from("")]).await;
}
