//! Parsing logic for the relayer config

use std::{env, str::FromStr};

use alloy::signers::local::PrivateKeySigner;
use circuit_types::fixed_point::FixedPoint;
use clap::Parser;
use constants::set_bootstrap_mode;
use libp2p::{Multiaddr, PeerId, identity::Keypair};
use types_gossip::{ClusterId, WrappedPeerId};
use url::Url;
use util::hex::address_from_hex_string;

use crate::{
    Cli, RelayerConfig,
    parsing::{
        config_file::config_file_args,
        utils::{parse_cluster_keys, parse_symmetric_key},
    },
    setup_token_remaps,
    token_remaps::warn_on_disabled_mismatch,
    validation::validate_config,
};

pub mod config_file;
pub(crate) mod utils;

/// Parse a URL string into a `Url` type
///
/// Returns a descriptive error message if parsing fails
fn parse_url(url_str: &str, description: &str) -> Result<Url, String> {
    url_str.parse().map_err(|e| format!("Invalid {description}: {e}"))
}

/// Load a libp2p keypair from `path`, or generate one and persist it there.
///
/// The key is stored as base64-encoded protobuf. Persisting it gives the node a
/// stable peer id (and thus raft node id) across restarts, so a restarting node
/// rejoins under its existing identity rather than appearing as a brand-new node.
#[allow(deprecated)]
fn load_or_create_p2p_key(path: &str) -> Keypair {
    use std::{fs, io::Write, os::unix::fs::OpenOptionsExt};

    if std::path::Path::new(path).exists() {
        let encoded = fs::read_to_string(path).expect("error reading p2p key file");
        let decoded = base64::decode(encoded.trim()).expect("p2p key file formatted incorrectly");
        return Keypair::from_protobuf_encoding(&decoded).expect("error parsing p2p key file");
    }

    // Generate a fresh key and persist it for subsequent restarts
    let keypair = Keypair::generate_ed25519();
    let encoded = base64::encode(keypair.to_protobuf_encoding().expect("error encoding p2p key"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .expect("error creating p2p key file");
    file.write_all(encoded.as_bytes()).expect("error writing p2p key file");
    keypair
}

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
    let json_disabled = setup_token_remaps(cli.token_remap_file.clone(), cli.chain_id)?;
    warn_on_disabled_mismatch(&json_disabled, &cli.disabled_assets);
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

    // Parse the local relayer's keys and fee configuration from the CLI
    let private_key =
        PrivateKeySigner::from_str(&cli_args.private_key).map_err(|e| e.to_string())?;
    let executor_private_key = PrivateKeySigner::from_str(&cli_args.executor_private_key)
        .map_err(|e| format!("Failed to parse executor private key: {e}"))?;
    let relayer_fee_addr = address_from_hex_string(&cli_args.relayer_fee_addr)
        .map_err(|e| format!("could not parse relayer fee address: {e}"))?;
    let contract_address = address_from_hex_string(&cli_args.contract_address)
        .map_err(|e| format!("could not parse contract address: {e}"))?;
    let permit2_address = address_from_hex_string(&cli_args.permit2_address)
        .map_err(|e| format!("could not parse permit2 address: {e}"))?;

    // Parse the p2p keypair. Precedence: an inline `p2p_key`, then a persisted
    // key at `p2p_key_path` (loaded or created), otherwise a fresh ephemeral key.
    let p2p_key = if let Some(keypair) = cli_args.p2p_key {
        let decoded = base64::decode(keypair).expect("p2p key formatted incorrectly");
        Keypair::from_protobuf_encoding(&decoded).expect("error parsing p2p key")
    } else if let Some(path) = cli_args.p2p_key_path.as_ref() {
        load_or_create_p2p_key(path)
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

    // --- Parse Service URLs --- //
    let compliance_service_url = cli_args
        .compliance_service_url
        .map(|url| parse_url(&url, "compliance service URL"))
        .transpose()?;
    let event_export_url =
        cli_args.event_export_url.map(|url| parse_url(&url, "event export URL")).transpose()?;
    let price_reporter_url =
        cli_args.price_reporter_url.map(|url| parse_url(&url, "price reporter URL")).transpose()?;

    let prover_service_url =
        cli_args.prover_service_url.map(|url| parse_url(&url, "prover service URL")).transpose()?;

    // Parse indexer config
    let indexer_url = parse_url(&cli_args.indexer_url, "indexer URL")?;
    let indexer_hmac_key = parse_symmetric_key(cli_args.indexer_hmac_key)?;

    // Fee conversion
    let max_match_fee = FixedPoint::from_f64_round_down(cli_args.max_match_fee);
    let default_match_fee = FixedPoint::from_f64_round_down(cli_args.default_match_fee);
    let per_asset_fees = cli_args
        .per_asset_fees
        .into_iter()
        .map(|(k, v)| (k, FixedPoint::from_f64_round_down(v)))
        .collect();

    let config = RelayerConfig {
        min_fill_size: cli_args.min_fill_size,
        max_match_fee,
        default_match_fee,
        per_asset_fees,
        external_match_validity_window: cli_args.external_match_validity_window,
        relayer_fee_addr,
        price_reporter_url,
        chain_id: cli_args.chain_id,
        contract_address,
        permit2_address,
        compliance_service_url,
        prover_service_url,
        prover_service_password: cli_args.prover_service_password,
        indexer_url,
        indexer_hmac_key,
        bootstrap_mode: cli_args.bootstrap_mode,
        raft_seed: cli_args.raft_seed,
        bootstrap_servers: parsed_bootstrap_addrs,
        p2p_port: cli_args.p2p_port,
        http_port: cli_args.http_port,
        websocket_port: cli_args.websocket_port,
        allow_local: cli_args.allow_local,
        max_merkle_staleness: cli_args.max_merkle_staleness,
        p2p_key,
        db_path: cli_args.db_path,
        raft_snapshot_path: cli_args.raft_snapshot_path,
        record_historical_state: cli_args.record_historical_state,
        event_export_url,
        wallet_task_rate_limit: cli_args.wallet_task_rate_limit,
        min_transfer_amount: cli_args.min_transfer_amount,
        bind_addr: cli_args.bind_addr,
        public_ip: cli_args.public_ip,
        gossip_warmup: cli_args.gossip_warmup,
        disable_price_reporter: cli_args.disable_price_reporter,
        disabled_exchanges: cli_args.disabled_exchanges,
        disabled_assets: cli_args.disabled_assets,
        cluster_keypair,
        cluster_symmetric_key,
        admin_api_key,
        cluster_id,
        coinbase_key_name: cli_args.coinbase_key_name,
        coinbase_key_secret: cli_args.coinbase_key_secret,
        rpc_url: cli_args.rpc_url,
        private_key,
        executor_private_key,
        eth_websocket_addr: cli_args.eth_websocket_addr,
        otlp_enabled: cli_args.otlp_enabled,
        otlp_collector_url: cli_args.otlp_collector_url,
        datadog_enabled: cli_args.datadog_enabled,
        metrics_enabled: cli_args.metrics_enabled,
        statsd_host: cli_args.statsd_host,
        statsd_port: cli_args.statsd_port,
    };

    validate_config(&config)?;
    Ok(config)
}
