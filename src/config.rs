use clap::Parser;
use libp2p::{Multiaddr, PeerId};
use std::error::Error;

use crate::gossip::types::PeerInfo;

const DEFAULT_VERSION: &str = "1";

// Defines the relayer system command line interface
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(short, long, value_parser)]
    // The software version of the relayer
    pub version: Option<String>,

    #[clap(short, long, value_parser)]
    // The bootstrap servers that the peer should dial initially
    pub bootstrap_servers: Option<Vec<String>>,

    #[clap(short, long, value_parser, default_value="12345")]
    // The port to listen on
    pub port: u32,
}

// Defines the system config for the relayer
#[derive(Debug)]
pub struct RelayerConfig {
    // Software version of the relayer
    pub version: String,

    // Bootstrap servers that the peer should connect to
    pub boostrap_servers: Vec<PeerInfo>,

    // The port to listen on
    pub port: u32,
}

// Parses command line args into the node config
pub fn parse_command_line_args() -> Result<Box<RelayerConfig>, Box<dyn Error>> {
    let cli_args = Cli::parse();

    // Parse the bootstrap servers into multiaddrs
    let mut parsed_bootstrap_addrs: Vec<PeerInfo> = Vec::new();
    for addr in cli_args.bootstrap_servers.unwrap_or_default().iter() {
        let parsed_addr: Multiaddr = addr.parse().expect("Invalid address passed as --bootstrap-server");
        let peer_id = PeerId::try_from_multiaddr(&parsed_addr).expect("Invalid address passed as --bootstrap-server");
        println!("parsed peer {}: {}", peer_id, parsed_addr);
        parsed_bootstrap_addrs.push(PeerInfo::new(peer_id, parsed_addr));
    }

    Ok(
        Box::new(
            RelayerConfig{
                version: cli_args.version.unwrap_or_else(|| String::from(DEFAULT_VERSION)),
                boostrap_servers: parsed_bootstrap_addrs,
                port: cli_args.port,
            }
        )
    )
}