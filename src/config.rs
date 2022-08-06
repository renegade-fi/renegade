use base64;
use clap::Parser;
use ed25519_dalek::{SignatureError, Keypair, Sha512, Digest};
use libp2p::{Multiaddr, PeerId};
use serde::{Serialize, Deserialize};
use std::{error::Error, fs};
use toml;

use crate::gossip::types::{PeerInfo, WrappedPeerId};

// The default version of the node
const DEFAULT_VERSION: &str = "1";

// The dummy message used for checking elliptic curve key pairs
const DUMMY_MESSAGE: &str = "signature check";

// Defines the relayer system command line interface
#[derive(Debug, Parser, Serialize, Deserialize)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(short, long, value_parser)]
    // The bootstrap servers that the peer should dial initially
    pub bootstrap_servers: Option<Vec<String>>,

    #[clap(short, long, value_parser)]
    // An auxiliary config file to read from
    pub config_file: Option<String>,

    #[clap(long="private-key", value_parser)]
    // The cluster private key to use
    pub cluster_private_key: Option<String>,

    #[clap(long="public-key", value_parser)]
    // The cluster public key to use
    pub cluster_public_key: Option<String>,

    #[clap(short, long, value_parser, default_value="12345")]
    // The port to listen on
    pub port: u32,

    #[clap(short, long, value_parser)]
    // The software version of the relayer
    pub version: Option<String>,

    #[clap(short, long, value_parser)]
    // The wallet IDs to manage locally
    pub wallet_ids: Option<Vec<String>>,
}

// Defines the system config for the relayer
#[derive(Debug)]
pub struct RelayerConfig {
    // Software version of the relayer
    pub version: String,

    // Bootstrap servers that the peer should connect to
    pub bootstrap_servers: Vec<PeerInfo>,

    // The port to listen on
    pub port: u32,

    // The wallet IDs to manage locally
    pub wallet_ids: Vec<String>,

    // The cluster keypair
    pub cluster_keypair: Option<Keypair>,
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
        parsed_bootstrap_addrs.push(
            PeerInfo::new(WrappedPeerId(peer_id), parsed_addr)
        );
    }

    // Parse the cluster keypair from CLI args
    // dalek library expects a packed byte array of [PRIVATE_KEY||PUBLIC_KEY]
    let mut wrapped_keypair: Option<Keypair> = None; 
    if cli_args.cluster_public_key.is_some() && cli_args.cluster_private_key.is_some() {
        let mut public_key: Vec<u8> = base64::decode(cli_args.cluster_public_key.unwrap()).unwrap();
        let mut private_key: Vec<u8> = base64::decode(cli_args.cluster_private_key.unwrap()).unwrap();
        private_key.append(&mut public_key);

        let keypair = ed25519_dalek::Keypair::from_bytes(&private_key[..]).unwrap();

        // Verify that the keypair represents a valid elliptic curve pair
        if validate_keypair(&keypair).is_err() {
            panic!("cluster keypair invalid")
        }

        wrapped_keypair = Some(keypair)
    } 

    let config = RelayerConfig{
        version: cli_args.version.unwrap_or_else(|| String::from(DEFAULT_VERSION)),
        bootstrap_servers: parsed_bootstrap_addrs,
        port: cli_args.port,
        wallet_ids: cli_args.wallet_ids.unwrap_or_default(),
        cluster_keypair: wrapped_keypair, 
    };

    Ok(Box::new(config))
}

// Runtime validation of the keypair passed into the relayer via config
// Sign a simple request and verify the signature
fn validate_keypair(keypair: &Keypair) -> Result<(), SignatureError> {
    // Hash the message
    let mut hash_digest: Sha512 = Sha512::new();
    hash_digest.update(DUMMY_MESSAGE);

    // Sign and verify with keypair
    let sig = keypair.sign_prehashed(hash_digest, None /* context */).unwrap();

    // Rehash, hashes are not clonable
    let mut second_hash: Sha512 = Sha512::new();
    second_hash.update(DUMMY_MESSAGE);
    keypair.verify_prehashed(second_hash, None /* context */, &sig)
}
