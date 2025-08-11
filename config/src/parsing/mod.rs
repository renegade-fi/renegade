//! Parsing logic for the relayer config

use std::{env, str::FromStr};

use alloy::signers::local::PrivateKeySigner;
use circuit_types::fixed_point::FixedPoint;
use clap::Parser;
use common::types::gossip::{ClusterId, WrappedPeerId};
use constants::set_bootstrap_mode;
use libp2p::{Multiaddr, PeerId, identity::Keypair};
use util::hex::biguint_from_hex_string;

use crate::{
    Cli, RelayerConfig,
    parsing::{
        config_file::config_file_args,
        utils::{parse_cluster_keys, parse_fee_key, parse_symmetric_key},
    },
    setup_token_remaps,
    validation::validate_config,
};

pub mod config_file;
pub(crate) mod utils;

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

    // Parse the local relayer's keys and fee configuration from the CLI
    let private_key =
        PrivateKeySigner::from_str(&cli_args.private_key).map_err(|e| e.to_string())?;
    let fee_key = parse_fee_key(cli_args.fee_encryption_key, cli_args.fee_decryption_key)?;
    let external_fee_addr = cli_args
        .external_fee_addr
        .map(|a| biguint_from_hex_string(&a).expect("could not parse external fee address"));

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

    // --- Parse Service URLs --- //
    let compliance_service_url = cli_args
        .compliance_service_url
        .map(|url| url.parse().expect("Invalid compliance service URL"));
    let event_export_url =
        cli_args.event_export_url.map(|url| url.parse().expect("Invalid event export URL"));
    let price_reporter_url =
        cli_args.price_reporter_url.map(|url| url.parse().expect("Invalid price reporter URL"));

    let prover_service_url =
        cli_args.prover_service_url.map(|url| url.parse().expect("Invalid prover service URL"));

    let config = RelayerConfig {
        min_fill_size: cli_args.min_fill_size,
        match_take_rate: FixedPoint::from_f64_round_down(cli_args.match_take_rate),
        external_fee_addr,
        auto_redeem_fees: cli_args.auto_redeem_fees,
        price_reporter_url,
        chain_id: cli_args.chain_id,
        contract_address: cli_args.contract_address,
        compliance_service_url,
        prover_service_url,
        prover_service_password: cli_args.prover_service_password,
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
        record_historical_state: cli_args.record_historical_state,
        event_export_url,
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
        coinbase_key_name: cli_args.coinbase_key_name,
        coinbase_key_secret: cli_args.coinbase_key_secret,
        rpc_url: cli_args.rpc_url,
        private_key,
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
    Ok(config)
}
