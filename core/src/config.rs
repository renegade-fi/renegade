//! Groups configurations used throughout the relayer passed to the CLI

use clap::Parser;
use ed25519_dalek::{Digest, Keypair, Sha512, SignatureError};
use libp2p::{Multiaddr, PeerId};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    env::{self},
    fs,
    net::SocketAddr,
};
use toml::{value::Map, Value};

use crate::{
    error::CoordinatorError,
    gossip::types::{ClusterId, WrappedPeerId},
    starknet_client::ChainId,
    state::wallet::Wallet,
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
#[rustfmt::skip]
struct Cli {
    // ---------------
    // | Config File |
    // ---------------
    /// An auxiliary config file to read from
    #[clap(long, value_parser)]
    pub config_file: Option<String>,

    // -----------------------
    // | Environment Configs |
    // -----------------------

    /// The blockchain this node targets for settlement
    #[clap(long)]
    pub chain_id: ChainId,
    /// The address of the darkpool contract, defaults to the Goerli deployment
    #[clap(long, value_parser, default_value = "0x02179f01358c09410f234f1ece40d235719e05db3babca7bef0babc974333162")]
    pub contract_address: String,

    // ----------------------------
    // | Networking Configuration |
    // ----------------------------

    /// Allow for discovery of nodes on the localhost IP address
    #[clap(long, value_parser, default_value="false")]
    pub allow_local: bool,

    /// The known public IP address of the local peer
    #[clap(long, value_parser)] 
    pub public_ip: Option<SocketAddr>,
    
    // -------------------------
    // | Cluster Configuration |
    // -------------------------
    /// The bootstrap servers that the peer should dial initially
    #[clap(short, long, value_parser)]
    pub bootstrap_servers: Option<Vec<String>>,
    /// The cluster private key to use
    #[clap(long = "cluster-private-key", value_parser)]
    pub cluster_private_key: Option<String>,
    /// The cluster public key to use
    #[clap(long = "cluster-public-key", value_parser)]
    pub cluster_public_key: Option<String>,

    // ----------------------------
    // | Local Node Configuration |
    // ----------------------------
    /// The port to listen on for libp2p
    #[clap(short = 'p', long, value_parser, default_value = "8000")]
    pub p2p_port: u16,
    /// The port to listen on for the externally facing HTTP API
    #[clap(long, value_parser, default_value = "3000")]
    pub http_port: u16,
    /// The port to listen on for the externally facing websocket API
    #[clap(long, value_parser, default_value = "4000")]
    pub websocket_port: u16,
    /// The local peer's base64 encoded p2p key
    /// A fresh key is generated at startup if this is not present
    #[clap(long, value_parser)]
    pub p2p_key: Option<String>,
    /// Flag to disable the price reporter
    #[clap(long, value_parser)]
    pub disable_price_reporter: bool,
    /// Flag to disable streaming price from Binance
    /// 
    /// This is useful for testing in a region that Binance has IP blocked
    #[clap(long, value_parser)]
    pub disable_binance: bool,
    /// Whether or not to run the relayer in debug mode
    #[clap(short, long, value_parser)]
    pub debug: bool,
    /// The software version of the relayer
    #[clap(short, long, value_parser)]
    pub version: Option<String>,

    // -----------
    // | Secrets |
    // -----------
    /// The Coinbase API key to use for price streaming
    #[clap(long = "coinbase-key", value_parser)]
    pub coinbase_api_key: Option<String>,
    /// The Coinbase API secret to use for price streaming
    #[clap(long = "coinbase-secret", value_parser)]
    pub coinbase_api_secret: Option<String>,
    /// The Ethereum RPC node websocket address to dial for on-chain data
    #[clap(long = "eth-websocket", value_parser)]
    pub eth_websocket_addr: Option<String>,
    /// The HTTP addressable StarkNet JSON-RPC node
    #[clap(long = "starknet-gateway", value_parser)]
    pub starknet_jsonrpc_node: Option<String>,
    /// The StarkNet addresses corresponding to the given private keys
    #[clap(long = "starknet-account-addr", value_parser, requires = "starknet-private-keys")]
    pub starknet_account_addresses: Vec<String>,
    /// The StarkNet private keys used to send transactions
    #[clap(long = "starknet-account-pkey", value_parser, requires = "starknet-account-addresses")]
    pub starknet_private_keys: Vec<String>,
    /// A file holding a json representation of the wallets the local node
    /// should manage
    #[clap(short, long, value_parser)]
    pub wallet_file: Option<String>,
}

/// Defines the system config for the relayer
#[derive(Debug)]
pub struct RelayerConfig {
    // -----------------------
    // | Environment Configs |
    // -----------------------
    /// Software version of the relayer
    pub version: String,
    /// The blockchain this node targets for settlement
    pub chain_id: ChainId,
    /// The address of the contract in the target network
    pub contract_address: String,

    // ----------------------------
    // | Networking Configuration |
    // ----------------------------
    /// Allow for discovery of nodes on the localhost IP address
    pub allow_local: bool,
    /// The known public IP address of the local peer
    pub public_ip: Option<SocketAddr>,

    // -------------------------
    // | Cluster Configuration |
    // -------------------------
    /// Bootstrap servers that the peer should connect to
    pub bootstrap_servers: Vec<(WrappedPeerId, Multiaddr)>,
    /// The cluster keypair
    pub cluster_keypair: Keypair,

    // ----------------------------
    // | Local Node Configuration |
    // ----------------------------
    /// The port to listen on for libp2p
    pub p2p_port: u16,
    /// The port to listen on for the externally facing HTTP API
    pub http_port: u16,
    /// The port to listen on for the externally facing websocket API
    pub websocket_port: u16,
    /// The local peer's base64 encoded p2p key
    pub p2p_key: Option<String>,
    /// Whether to disable the price reporter if e.g. we are streaming from a dedicated
    /// external API gateway node in the cluster
    pub disable_price_reporter: bool,
    /// Whether to disable price streaming from Binance for location blocks
    pub disable_binance: bool,
    /// Whether or not the relayer is in debug mode
    pub debug: bool,

    // -----------
    // | Secrets |
    // -----------
    /// The apriori known wallets to begin managing
    pub wallets: Vec<Wallet>,
    /// The cluster ID, a parsed version of the cluster's pubkey
    pub cluster_id: ClusterId,
    /// The Coinbase API key to use for price streaming
    pub coinbase_api_key: Option<String>,
    /// The Coinbase API secret to use for price streaming
    pub coinbase_api_secret: Option<String>,
    /// The StarkNet JSON-RPC API gateway
    pub starknet_jsonrpc_node: Option<String>,
    /// The StarkNet addresses corresponding to the given private keys
    pub starknet_account_addresses: Vec<String>,
    /// The StarkNet private keys used for signing transactions
    pub starknet_private_keys: Vec<String>,
    /// The Ethereum RPC node websocket address to dial for on-chain data
    pub eth_websocket_addr: Option<String>,
}

/// A custom clone implementation specifically for the cluster keypair which does not
/// implement clone
impl Clone for RelayerConfig {
    fn clone(&self) -> Self {
        Self {
            version: self.version.clone(),
            chain_id: self.chain_id,
            contract_address: self.contract_address.clone(),
            bootstrap_servers: self.bootstrap_servers.clone(),
            p2p_port: self.p2p_port,
            http_port: self.http_port,
            websocket_port: self.websocket_port,
            p2p_key: self.p2p_key.clone(),
            allow_local: self.allow_local,
            public_ip: self.public_ip,
            disable_price_reporter: self.disable_price_reporter,
            disable_binance: self.disable_binance,
            wallets: self.wallets.clone(),
            cluster_keypair: Keypair::from_bytes(&self.cluster_keypair.to_bytes()).unwrap(),
            cluster_id: self.cluster_id.clone(),
            coinbase_api_key: self.coinbase_api_key.clone(),
            coinbase_api_secret: self.coinbase_api_secret.clone(),
            starknet_jsonrpc_node: self.starknet_jsonrpc_node.clone(),
            starknet_account_addresses: self.starknet_account_addresses.clone(),
            starknet_private_keys: self.starknet_private_keys.clone(),
            eth_websocket_addr: self.eth_websocket_addr.clone(),
            debug: self.debug,
        }
    }
}

/// Parses command line args into the node config
///
/// We allow for configurations to come from both a config file and overrides
/// on the command line directly. To support this, we first read configuration
/// options from the config file, prepend them to the cli args string, and parse
/// using the `overrides_with("self")` option so that cli args (which come after
/// config file args) take precedence.
pub fn parse_command_line_args() -> Result<RelayerConfig, CoordinatorError> {
    // Parse args from command line and config file, place the config file args
    // *before* the command line args so that clap will give precedence to the
    // command line arguments
    // However, the first argument from the command line is the executable name, so
    // place this before all args
    let mut command_line_args: Vec<String> = env::args_os()
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
    let cluster_id = ClusterId::new(&keypair.public);

    // Parse the bootstrap servers into multiaddrs
    let mut parsed_bootstrap_addrs: Vec<(WrappedPeerId, Multiaddr)> = Vec::new();
    for addr in cli_args.bootstrap_servers.unwrap_or_default().iter() {
        let parsed_addr: Multiaddr = addr
            .parse()
            .expect("Invalid address passed as --bootstrap-server");
        let peer_id = PeerId::try_from_multiaddr(&parsed_addr)
            .expect("Invalid address passed as --bootstrap-server");
        parsed_bootstrap_addrs.push((WrappedPeerId(peer_id), parsed_addr));
    }

    let config = RelayerConfig {
        version: cli_args
            .version
            .unwrap_or_else(|| String::from(DEFAULT_VERSION)),
        chain_id: cli_args.chain_id,
        contract_address: cli_args.contract_address,
        bootstrap_servers: parsed_bootstrap_addrs,
        p2p_port: cli_args.p2p_port,
        http_port: cli_args.http_port,
        websocket_port: cli_args.websocket_port,
        allow_local: cli_args.allow_local,
        p2p_key: cli_args.p2p_key,
        public_ip: cli_args.public_ip,
        disable_price_reporter: cli_args.disable_price_reporter,
        disable_binance: cli_args.disable_binance,
        wallets: parse_wallet_file(cli_args.wallet_file)?,
        cluster_keypair: keypair,
        cluster_id,
        coinbase_api_key: cli_args.coinbase_api_key,
        coinbase_api_secret: cli_args.coinbase_api_secret,
        starknet_jsonrpc_node: cli_args.starknet_jsonrpc_node,
        starknet_account_addresses: cli_args.starknet_account_addresses,
        starknet_private_keys: cli_args.starknet_private_keys,
        eth_websocket_addr: cli_args.eth_websocket_addr,
        debug: cli_args.debug,
    };

    Ok(config)
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
            // Parse all values into multiple repetitions, i.e. --key val1 --key val2 ...
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

/// Parse a file holding wallet data
fn parse_wallet_file(file_name: Option<String>) -> Result<Vec<Wallet>, CoordinatorError> {
    if file_name.is_none() {
        return Ok(Vec::new());
    }

    let file_data = fs::read_to_string(file_name.unwrap())
        .map_err(|err| CoordinatorError::ConfigParse(err.to_string()))?;

    serde_json::from_str(&file_data).map_err(|err| CoordinatorError::ConfigParse(err.to_string()))
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
///
/// The public interface does not allow us to more directly check the keypair
/// as public_key == private_key * ed25519_generator, so we opt for this instead.
/// Happens once at startup so we are not concerned with performance
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
