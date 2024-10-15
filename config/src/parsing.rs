//! Parsing logic for the config

pub use crate::token_remaps::setup_token_remaps;
use crate::{cli::RelayerConfig, validation::validate_config, Cli, RelayerFeeKey};
use circuit_types::{elgamal::DecryptionKey, fixed_point::FixedPoint};
use clap::Parser;
use common::types::{
    gossip::{ClusterId, WrappedPeerId},
    wallet::{keychain::HmacKey, WalletIdentifier},
};
use constants::set_bootstrap_mode;
use ed25519_dalek::{Keypair as DalekKeypair, PublicKey, SecretKey};
use ethers::{core::rand::thread_rng, signers::LocalWallet};
use libp2p::{identity::Keypair, Multiaddr, PeerId};
use rand_core::OsRng;
use serde::Deserialize;
use std::{env, fs, str::FromStr};
use toml::{value::Map, Value};
use url::Url;
use util::{
    arbitrum::{parse_addr_from_deployments_file, DARKPOOL_PROXY_CONTRACT_KEY},
    hex::jubjub_from_hex_string,
};

/// The CLI argument name for the config file
const CONFIG_FILE_ARG: &str = "--config-file";

/// Parses command line args into the node config
///
/// We allow for configurations to come from both a config file and overrides
/// on the command line directly. To support this, we first read configuration
/// options from the config file, prepend them to the cli args string, and parse
/// using the `overrides_with("self")` option so that cli args (which come after
/// config file args) take precedence.
pub fn parse_command_line_args() -> Result<RelayerConfig, String> {
    // Parse args from command line and config file, place the config file args
    // *before* the command line args so that clap will give precedence to the
    // command line arguments
    // However, the first argument from the command line is the executable name, so
    // place this before all args
    let mut command_line_args: Vec<String> =
        env::args_os().map(|val| val.to_str().unwrap().to_string()).collect();
    let config_file_args = config_file_args(&command_line_args)?;

    let mut full_args = vec![command_line_args.remove(0)];
    full_args.extend(config_file_args);
    full_args.extend(command_line_args);

    let cli = Cli::parse_from(full_args);
    // Setup the token remap
    setup_token_remaps(cli.token_remap_file.clone(), cli.chain_id)?;

    // Set the bootstrap mode
    set_bootstrap_mode(cli.bootstrap_mode);

    let config = parse_config_from_args(cli)?;
    Ok(config)
}

/// Parse the config from a set of command line arguments
///
/// Separating out this functionality allows us to easily inject custom args
/// apart from what is specified on the command line
pub(crate) fn parse_config_from_args(cli_args: Cli) -> Result<RelayerConfig, String> {
    let (cluster_symmetric_key, cluster_keypair) = parse_cluster_keys(&cli_args)?;
    let admin_api_key = cli_args.admin_api_key.map(parse_symmetric_key).transpose()?;

    // Parse the local relayer's arbitrum wallet from the cli
    let arbitrum_private_keys = cli_args
        .arbitrum_private_keys
        .iter()
        .map(|k| LocalWallet::from_str(k).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let fee_key = parse_fee_key(cli_args.fee_encryption_key, cli_args.fee_decryption_key)?;

    // Parse the p2p keypair or generate one
    let p2p_key = if let Some(keypair) = cli_args.p2p_key {
        let decoded = base64::decode(keypair).expect("p2p key formatted incorrectly");
        Keypair::from_protobuf_encoding(&decoded).expect("error parsing p2p key")
    } else {
        Keypair::generate_ed25519()
    };

    let cluster_id = ClusterId::new(&cluster_keypair.public);

    // Parse the bootstrap servers into multiaddrs
    let mut parsed_bootstrap_addrs: Vec<(WrappedPeerId, Multiaddr)> = Vec::new();
    for addr in cli_args.bootstrap_servers.unwrap_or_default().iter() {
        let parsed_addr: Multiaddr =
            addr.parse().expect("Invalid address passed as --bootstrap-server");
        let peer_id = PeerId::try_from_multiaddr(&parsed_addr)
            .expect("Invalid address passed as --bootstrap-server");
        parsed_bootstrap_addrs.push((WrappedPeerId(peer_id), parsed_addr));
    }

    // Parse the price reporter URL, if there is one
    let price_reporter_url = cli_args
        .price_reporter_url
        .map(|url| Url::parse(&url).expect("Invalid price reporter URL"));

    // Parse the relayer fee whitelist, if there is one
    let relayer_fee_whitelist = parse_relayer_whitelist_file(cli_args.relayer_fee_whitelist)?;

    let mut config = RelayerConfig {
        min_fill_size: cli_args.min_fill_size,
        match_take_rate: FixedPoint::from_f64_round_down(cli_args.match_take_rate),
        auto_redeem_fees: cli_args.auto_redeem_fees,
        relayer_fee_whitelist,
        price_reporter_url,
        chain_id: cli_args.chain_id,
        contract_address: cli_args.contract_address,
        compliance_service_url: cli_args.compliance_service_url,
        bootstrap_mode: cli_args.bootstrap_mode,
        bootstrap_servers: parsed_bootstrap_addrs,
        p2p_port: cli_args.p2p_port,
        http_port: cli_args.http_port,
        websocket_port: cli_args.websocket_port,
        allow_local: cli_args.allow_local,
        max_merkle_staleness: cli_args.max_merkle_staleness,
        p2p_key,
        db_path: cli_args.db_path,
        raft_snapshot_path: cli_args.raft_snapshot_path,
        wallet_task_rate_limit: cli_args.wallet_task_rate_limit,
        min_transfer_amount: cli_args.min_transfer_amount,
        bind_addr: cli_args.bind_addr,
        public_ip: cli_args.public_ip,
        gossip_warmup: cli_args.gossip_warmup,
        disable_price_reporter: cli_args.disable_price_reporter,
        disabled_exchanges: cli_args.disabled_exchanges,
        cluster_keypair,
        cluster_symmetric_key,
        admin_api_key,
        cluster_id,
        coinbase_api_key: cli_args.coinbase_api_key,
        coinbase_api_secret: cli_args.coinbase_api_secret,
        rpc_url: cli_args.rpc_url,
        arbitrum_private_keys,
        fee_key,
        eth_websocket_addr: cli_args.eth_websocket_addr,
        debug: cli_args.debug,
        otlp_enabled: cli_args.otlp_enabled,
        otlp_collector_url: cli_args.otlp_collector_url,
        datadog_enabled: cli_args.datadog_enabled,
        metrics_enabled: cli_args.metrics_enabled,
        statsd_host: cli_args.statsd_host,
        statsd_port: cli_args.statsd_port,
    };

    validate_config(&config)?;
    set_contract_from_file(&mut config, cli_args.deployments_file)?;
    Ok(config)
}

// ---------------
// | Key Parsing |
// ---------------

/// Parse the cluster's symmetric and asymmetric keys from the CLI
pub fn parse_cluster_keys(cli: &Cli) -> Result<(HmacKey, DalekKeypair), String> {
    // Parse the cluster keypair from CLI args
    // dalek library expects a packed byte array of [PRIVATE_KEY||PUBLIC_KEY]
    let keypair = if let Some(key_str) = cli.cluster_private_key.clone() {
        let pkey_bytes: Vec<u8> = base64::decode(key_str.clone()).unwrap();

        let private_key = SecretKey::from_bytes(&pkey_bytes).unwrap();
        let public_key = PublicKey::from(&private_key);
        DalekKeypair { secret: private_key, public: public_key }
    } else {
        let mut rng = OsRng {};
        DalekKeypair::generate(&mut rng)
    };

    // Parse the symmetric key from its string or generate
    let symmetric_key: HmacKey = if let Some(key_str) = cli.cluster_symmetric_key.clone() {
        parse_symmetric_key(key_str)?
    } else {
        HmacKey::random()
    };

    Ok((symmetric_key, keypair))
}

/// Parse a symmetric key from a base64 string
fn parse_symmetric_key(key_str: String) -> Result<HmacKey, String> {
    base64::decode(key_str)
        .map_err(|e| e.to_string())?
        .try_into()
        .map(HmacKey)
        .map_err(|_| "Invalid symmetric key".to_string())
}

/// Parse the relayer's decryption key from a string
pub fn parse_fee_key(
    encryption_key: Option<String>,
    decryption_key: Option<String>,
) -> Result<RelayerFeeKey, String> {
    if let Some(k) = encryption_key {
        let key = jubjub_from_hex_string(&k)?;
        Ok(RelayerFeeKey::new_public(key))
    } else if let Some(k) = decryption_key {
        let key = DecryptionKey::from_hex_str(&k)?;
        Ok(RelayerFeeKey::new_secret(key))
    } else {
        #[cfg(not(feature = "silent"))]
        {
            // Must print here as logger is not yet setup
            use colored::*;
            println!("{}\n", "WARN: No fee decryption key provided, generating one".yellow());
        }

        let key = DecryptionKey::random(&mut thread_rng());
        Ok(RelayerFeeKey::new_secret(key))
    }
}

// ---------------------------------
// | Relayer Fee Whitelist Parsing |
// ---------------------------------

/// A struct representing the JSON structure of a relayer whitelist file
#[derive(Clone, Debug, Deserialize)]
pub struct RelayerFeeWhitelistEntry {
    /// The wallet ID to set the fee for
    pub wallet_id: WalletIdentifier,
    /// The fee to set for the relayer
    pub fee: f64,
}

/// Parse a relayer whitelist file
fn parse_relayer_whitelist_file(
    file_path: Option<String>,
) -> Result<Vec<RelayerFeeWhitelistEntry>, String> {
    let file = match file_path {
        Some(path) => fs::read_to_string(path).map_err(|e| e.to_string())?,
        None => return Ok(vec![]),
    };

    // Parse the file as json
    serde_json::from_str(&file).map_err(|e| e.to_string())
}

// -----------------------
// | Config File Parsing |
// -----------------------

/// Parse args from a config file
fn config_file_args(cli_args: &[String]) -> Result<Vec<String>, String> {
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
    read_config_file(&cli_args[index])
}

/// Parse a config entirely from a file
pub fn parse_config_from_file(path: &str) -> Result<RelayerConfig, String> {
    let mut file_args = read_config_file(path)?;
    file_args.insert(0, "dummy-program-name".to_string());
    let cli = Cli::parse_from(file_args);
    let config = parse_config_from_args(cli)?;
    validate_config(&config)?;
    Ok(config)
}

/// Parse a config file
fn read_config_file(path: &str) -> Result<Vec<String>, String> {
    // Read in the config file
    let file_contents = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let config_kv_pairs: Map<_, _> =
        toml::from_str(&file_contents).map_err(|err| err.to_string())?;

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
            },
            // All other type may simply be parsed as --key val
            _ => {
                vec![
                    cli_arg.clone(),
                    toml_value_to_string(value).map_err(|_| {
                        format!("error parsing config value: {:?} = {:?}", cli_arg, value)
                    })?,
                ]
            },
        };

        config_file_args.extend(values);
    }

    Ok(config_file_args)
}

/// Helper method to convert a toml value to a string
fn toml_value_to_string(val: &Value) -> Result<String, String> {
    Ok(match val {
        Value::String(val) => val.clone(),
        Value::Integer(val) => format!("{:?}", val),
        Value::Float(val) => format!("{:?}", val),
        Value::Boolean(val) => format!("{:?}", val),
        _ => {
            return Err("unsupported value".to_string());
        },
    })
}

/// Parse the contract address from a deployments file, overriding the default
/// value in the config
fn set_contract_from_file(config: &mut RelayerConfig, file: Option<String>) -> Result<(), String> {
    // Do not override if the file is not specified
    if let Some(path) = file {
        let darkpool_addr = parse_addr_from_deployments_file(&path, DARKPOOL_PROXY_CONTRACT_KEY)
            .map_err(|e| e.to_string())?;
        config.contract_address = darkpool_addr;
    }

    Ok(())
}
