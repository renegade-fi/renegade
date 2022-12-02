//! Groups configurations used throughout the relayer passed to the CLI

use clap::Parser;
use ed25519_dalek::{Digest, Keypair, Sha512, SignatureError};
use libp2p::{Multiaddr, PeerId};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    env::{self},
    fs,
};
use toml::{value::Map, Value};

use crate::{
    error::CoordinatorError,
    gossip::types::{ClusterId, PeerInfo, WrappedPeerId},
};

/// The default version of the node
const DEFAULT_VERSION: &str = "1";
/// The dummy message used for checking elliptic curve key pairs
const DUMMY_MESSAGE: &str = "signature check";
/// The CLI argument name for the config file
const CONFIG_FILE_ARG: &str = "--config-file";

/// Defines the relayer system command line interface
#[derive(Debug, Parser, Serialize, Deserialize)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(short, long, value_parser)]
    /// The bootstrap servers that the peer should dial initially
    pub bootstrap_servers: Option<Vec<String>>,
    #[clap(long, value_parser)]
    /// An auxiliary config file to read from
    pub config_file: Option<String>,
    #[clap(long = "cluster-private-key", value_parser)]
    /// The cluster private key to use
    pub cluster_private_key: Option<String>,
    #[clap(long = "cluster-public-key", value_parser)]
    /// The cluster public key to use
    pub cluster_public_key: Option<String>,
    #[clap(short, long, value_parser, default_value = "12345")]
    /// The port to listen on
    pub port: u32,
    #[clap(short, long, value_parser)]
    /// The software version of the relayer
    pub version: Option<String>,
    #[clap(short, long, value_parser)]
    /// The wallet IDs to manage locally
    pub wallet_ids: Option<Vec<String>>,
}

/// Defines the system config for the relayer
#[derive(Debug)]
pub struct RelayerConfig {
    /// Software version of the relayer
    pub version: String,
    /// Bootstrap servers that the peer should connect to
    pub bootstrap_servers: Vec<PeerInfo>,
    /// The port to listen on
    pub port: u32,
    /// The wallet IDs to manage locally
    pub wallet_ids: Vec<String>,
    /// The cluster keypair
    pub cluster_keypair: Keypair,
    /// The cluster ID, a parsed version of the cluster's pubkey
    pub cluster_id: ClusterId,
}

/// Parses command line args into the node config
///
/// We allow for configurations to come from both a config file and overrides
/// on the command line directly. To support this, we first read configuration
/// options from the config file, prepend them to the cli args string, and parse
/// using the `overrides_with("self")` option so that cli args (which come after
/// config file args) take precedence.
pub fn parse_command_line_args() -> Result<Box<RelayerConfig>, CoordinatorError> {
    // Parse args from command line and config file, place the config file args
    // *before* the command line args so that clap will give precedence to the
    // command line arguments
    // However, the first argument from the command line is the executable name, so
    // place this before all args
    let mut command_line_args: Vec<String> = env::args_os()
        .into_iter()
        .map(|val| val.to_str().unwrap().to_string())
        .collect();
    let config_file_args = config_file_args(&command_line_args)?;

    let mut full_args = vec![command_line_args.remove(0)];
    full_args.extend(config_file_args);
    full_args.extend(command_line_args);

    let cli_args = Cli::parse_from(full_args);

    // Parse the cluster keypair from CLI args
    // dalek library expects a packed byte array of [PRIVATE_KEY||PUBLIC_KEY]
    let keypair = if cli_args.cluster_public_key.is_some() && cli_args.cluster_private_key.is_some()
    {
        let mut public_key: Vec<u8> = base64::decode(cli_args.cluster_public_key.unwrap()).unwrap();
        let mut private_key: Vec<u8> =
            base64::decode(cli_args.cluster_private_key.unwrap()).unwrap();
        private_key.append(&mut public_key);

        let keypair = ed25519_dalek::Keypair::from_bytes(&private_key[..]).unwrap();

        // Verify that the keypair represents a valid elliptic curve pair
        if validate_keypair(&keypair).is_err() {
            panic!("cluster keypair invalid")
        }

        keypair
    } else {
        let mut rng = OsRng {};
        Keypair::generate(&mut rng)
    };
    let cluster_id = ClusterId::new(keypair.public);

    // Parse the bootstrap servers into multiaddrs
    let mut parsed_bootstrap_addrs: Vec<PeerInfo> = Vec::new();
    for addr in cli_args.bootstrap_servers.unwrap_or_default().iter() {
        let parsed_addr: Multiaddr = addr
            .parse()
            .expect("Invalid address passed as --bootstrap-server");
        let peer_id = PeerId::try_from_multiaddr(&parsed_addr)
            .expect("Invalid address passed as --bootstrap-server");
        println!("parsed peer {}: {}", peer_id, parsed_addr);
        parsed_bootstrap_addrs.push(PeerInfo::new(
            WrappedPeerId(peer_id),
            cluster_id.clone(),
            parsed_addr,
        ));
    }

    let config = RelayerConfig {
        version: cli_args
            .version
            .unwrap_or_else(|| String::from(DEFAULT_VERSION)),
        bootstrap_servers: parsed_bootstrap_addrs,
        port: cli_args.port,
        wallet_ids: cli_args.wallet_ids.unwrap_or_default(),
        cluster_keypair: keypair,
        cluster_id,
    };

    Ok(Box::new(config))
}

/// Parse args from a config file
fn config_file_args(cli_args: &[String]) -> Result<Vec<String>, CoordinatorError> {
    // Find a match for the config file argument
    let mut found = false;
    let mut index = 0;

    for arg in cli_args.iter() {
        index += 1;
        // If we find "--config-file", the next argument is the file to read from
        if arg == CONFIG_FILE_ARG {
            found = true;
            break;
        }
    }

    // No config file found
    if !found {
        return Ok(vec![]);
    }

    // Read in the config file
    let file_contents = fs::read_to_string(cli_args[index].clone())
        .map_err(|err| CoordinatorError::ConfigParse(err.to_string()))?;

    let config_kv_pairs: Map<_, _> = toml::from_str(&file_contents)
        .map_err(|err| CoordinatorError::ConfigParse(err.to_string()))?;

    let mut config_file_args: Vec<String> = Vec::with_capacity(config_kv_pairs.len());
    for (toml_key, value) in config_kv_pairs.iter() {
        // Format the TOML key into --key
        let cli_arg = format!("--{}", toml_key);

        // Parse the values for this TOML entry into a CLI-style vector of strings
        let values: Vec<String> = match value {
            // Just the flag, i.e. --flag
            Value::Boolean(_) => vec![cli_arg],
            // Parse all values into multiple repititions, i.e. --key val1 --key val2 ...
            Value::Array(arr) => {
                let mut res: Vec<String> = Vec::new();
                for val in arr.iter() {
                    res.push(cli_arg.clone());
                    res.push(toml_value_to_string(val)?);
                }

                res
            }
            // All other type may simply be parsed as --key val
            _ => {
                vec![
                    cli_arg.clone(),
                    toml_value_to_string(value).map_err(|_| {
                        CoordinatorError::ConfigParse(format!(
                            "error parsing config value: {:?} = {:?}",
                            cli_arg, value
                        ))
                    })?,
                ]
            }
        };

        config_file_args.extend(values);
    }

    Ok(config_file_args)
}

/// Helper method to convert a toml value to a string
fn toml_value_to_string(val: &Value) -> Result<String, CoordinatorError> {
    Ok(match val {
        Value::String(val) => val.clone(),
        Value::Integer(val) => format!("{:?}", val),
        Value::Float(val) => format!("{:?}", val),
        Value::Boolean(val) => format!("{:?}", val),
        _ => {
            return Err(CoordinatorError::ConfigParse(
                "unsupported value".to_string(),
            ));
        }
    })
}

/// Runtime validation of the keypair passed into the relayer via config
/// Sign a simple request and verify the signature
fn validate_keypair(keypair: &Keypair) -> Result<(), SignatureError> {
    // Hash the message
    let mut hash_digest: Sha512 = Sha512::new();
    hash_digest.update(DUMMY_MESSAGE);

    // Sign and verify with keypair
    let sig = keypair
        .sign_prehashed(hash_digest, None /* context */)
        .unwrap();

    // Rehash, hashes are not clonable
    let mut second_hash: Sha512 = Sha512::new();
    second_hash.update(DUMMY_MESSAGE);
    keypair.verify_prehashed(second_hash, None /* context */, &sig)
}
