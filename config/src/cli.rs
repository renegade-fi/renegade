//! The relayer CLI and config definitions

use alloy::signers::local::PrivateKeySigner;
use circuit_types::{
    elgamal::{DecryptionKey, EncryptionKey},
    fixed_point::FixedPoint,
    Address, Amount,
};
use clap::Parser;
use common::types::{
    chain::Chain,
    exchange::Exchange,
    gossip::{ClusterId, WrappedPeerId},
    hmac::HmacKey,
    token::Token,
};
use ed25519_dalek::Keypair as DalekKeypair;
use libp2p::{identity::Keypair, Multiaddr};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
};
use url::Url;
use util::telemetry::configure_telemetry;

use crate::parsing::{parse_config_from_args, RelayerFeeWhitelistEntry};

// -------
// | CLI |
// -------

/// Defines the relayer system command line interface
#[derive(Debug, Parser, Serialize, Deserialize)]
#[clap(author, about, long_about = None)]
#[rustfmt::skip]
pub struct Cli {
    // ---------------
    // | Config File |
    // ---------------
    /// An auth config file to read from
    #[clap(long, value_parser)]
    pub config_file: Option<String>,
    /// The price reporter from which to stream prices.
    /// If unset, the relayer will connect to exchanges directly.
    #[clap(long, value_parser, conflicts_with_all = &["coinbase_key_name", "coinbase_key_secret"])]
    pub price_reporter_url: Option<String>,

    // -----------------------------
    // | Application Level Configs |
    // -----------------------------

    /// The minimum amount of the quote asset that the relayer should settle matches on
    #[clap(long, value_parser, default_value = "0")]
    pub min_fill_size: Amount,
    /// The take rate of this relayer on a managed match, i.e. the amount of the received asset 
    /// that the relayer takes as a fee
    /// 
    /// Defaults to 8 basis points
    #[clap(long, value_parser, default_value = "0.0002")]
    pub match_take_rate: f64,
    /// The address at which to collect externally paid fees
    /// 
    /// External fees are generated when an atomic match is settled. An atomic match is one between an 
    /// internal party (one with state in the darkpool) and an external party (one without). 
    /// The external party pays fees directly to this address.
    /// 
    /// If not set, atomic matches are not supported
    #[clap(long, value_parser, env = "EXTERNAL_FEE_ADDR")]
    pub external_fee_addr: Option<String>,
    /// The path to the file containing relayer fee whitelist info
    #[clap(long, value_parser)]
    pub relayer_fee_whitelist: Option<String>,
    /// When set, the relayer will automatically redeem new fees into its wallet
    #[clap(long, value_parser, default_value = "false")]
    pub auto_redeem_fees: bool,

    // -----------------------
    // | Environment Configs |
    // -----------------------

    /// The chain that the relayer settles to
    #[clap(long, value_parser, default_value = "testnet", env = "CHAIN")]
    pub chain_id: Chain,
    /// The address of the darkpool contract, defaults to the internal testnet deployment
    #[clap(long, value_parser, env = "DARKPOOL_ADDRESS", default_value = "0x2f88458fc25591f1de247dd3297f039eecfcd534")]
    pub contract_address: String,
    /// The path to the file containing deployments info for the darkpool contract
    #[clap(long, value_parser)]
    pub deployments_file: Option<String>,
    /// The path to the file containing token remaps for the given chain
    /// 
    /// See https://github.com/renegade-fi/token-mappings for more information on the format of this file
    #[clap(long, value_parser)]
    pub token_remap_file: Option<String>,
    /// The address of the compliance service to use for wallet screening. If not configured, wallet screening is disabled
    /// 
    /// The API of the compliance service must match that defined here:
    ///     https://github.com/renegade-fi/relayer-extensions/tree/master/compliance/compliance-api 
    #[clap(long, value_parser)]
    pub compliance_service_url: Option<String>,
    /// The URL to export relayer events to.
    /// If ommitted, the event manager is disabled.
    #[clap(long, value_parser)]
    pub event_export_url: Option<String>,

    // ----------------------------
    // | Networking Configuration |
    // ----------------------------

    /// Allow for discovery of nodes on the localhost IP address
    #[clap(long, value_parser, default_value="false")]
    pub allow_local: bool,
    /// The address to bind to for gossip, defaults to 0.0.0.0 (all interfaces)
    #[clap(long, value_parser, default_value = "0.0.0.0")]
    pub bind_addr: IpAddr,
    /// The known public IP address of the local peer
    #[clap(long, value_parser)] 
    pub public_ip: Option<SocketAddr>,
    /// The amount of time to allow for gossip warmup, in milliseconds
    /// 
    /// Defaults to 30s
    #[clap(long, value_parser, default_value = "30000")]
    pub gossip_warmup: u64,
    
    // -------------------------
    // | Cluster Configuration |
    // -------------------------

    /// Run the relayer in bootstrap mode
    /// 
    /// Bootstrap mode omits much of the relayer's functionality and ignores most messages
    #[clap(long, env = "BOOTSTRAP_MODE")]
    pub bootstrap_mode: bool,

    /// The bootstrap servers that the peer should dial initially
    #[clap(short, long, value_parser, env = "BOOTSTRAP_SERVERS", use_value_delimiter = true)]
    pub bootstrap_servers: Option<Vec<String>>,
    /// The cluster private key to use
    #[clap(long = "cluster-private-key", value_parser, env = "CLUSTER_PRIVATE_KEY")]
    pub cluster_private_key: Option<String>,
    /// The cluster symmetric key to use for authenticating intra-cluster messages
    /// 
    /// Encoded as a base64 string
    #[clap(long, value_parser, env = "CLUSTER_SYMMETRIC_KEY")]
    pub cluster_symmetric_key: Option<String>,
    /// The admin key used to authenticate requests to the relayer's API
    /// 
    /// This is a symmetric key encoded as a base64 string
    /// 
    /// If not set, the admin API is disabled
    #[clap(long, value_parser, env = "ADMIN_API_KEY")]
    pub admin_api_key: Option<String>,

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
    /// The path at which to open up the database
    #[clap(long, value_parser, default_value = "./relayer_state.db")]
    pub db_path: String,
    /// The path at which to save raft snapshots
    #[clap(long, value_parser, default_value = "/raft_snapshots")]
    pub raft_snapshot_path: String,
    /// Whether to record historical state locally
    #[clap(long, value_parser)]
    pub record_historical_state: bool,
    /// The maximum number of wallet operations a user is allowed to perform per hour
    /// 
    /// Defaults to 500
    #[clap(long, value_parser, default_value = "500")]
    pub wallet_task_rate_limit: u32,
    /// The minimum usdc denominated value for a deposit or withdrawal
    /// 
    /// Defaults to 1 USDC (ignoring decimals)
    #[clap(long, value_parser, default_value = "1.0")]
    pub min_transfer_amount: f64,
    /// The maximum staleness (number of newer roots observed) to allow on Merkle proofs for 
    /// managed wallets. After this threshold is exceeded, the Merkle proof will be updated
    #[clap(long, value_parser, default_value = "100")]
    pub max_merkle_staleness: usize,
    /// Flag to disable the price reporter
    #[clap(long, value_parser)]
    pub disable_price_reporter: bool,
    /// Disables exchanges for price reporting
    #[clap(long, value_parser, num_args=1.., value_delimiter=' ')]
    pub disabled_exchanges: Vec<Exchange>,
    /// Whether or not to run the relayer in debug mode
    #[clap(short, long, value_parser)]
    pub debug: bool,

    // -----------
    // | Secrets |
    // -----------
    /// The Coinbase API key name to use for price streaming
    #[clap(long = "coinbase-key-name", value_parser)]
    pub coinbase_key_name: Option<String>,
    /// The Coinbase API secret to use for price streaming
    /// 
    /// Expected as a PKCS#8 encoded ES256 private key 
    #[clap(long = "coinbase-key-secret", value_parser)]
    pub coinbase_key_secret: Option<String>,
    /// The Ethereum RPC node websocket address to dial for on-chain data
    #[clap(long = "eth-websocket-url", value_parser, env = "ETH_WEBSOCKET_URL")]
    pub eth_websocket_addr: Option<String>,
    /// The HTTP addressable Ethereum JSON-RPC node
    #[clap(long = "rpc-url", value_parser, env = "RPC_URL")]
    pub rpc_url: Option<String>,
    /// The on-chain private key used to send transactions.
    /// 
    /// Defaults to the devnet pre-funded key
    #[clap(
        value_parser,
        long = "private-key",  
        default_value = "0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659",
    )]
    pub private_key: String,
    /// The key used to encrypt fee payments
    /// 
    /// May be specified _instead of_ `fee_decryption_key` in the case that separate infrastructure is used for 
    /// fee collection and settlement
    #[clap(long = "fee-encryption-key", value_parser, conflicts_with = "fee_decryption_key", env = "FEE_ENCRYPTION_KEY")]
    pub fee_encryption_key: Option<String>,
    /// The key used to decrypt fee payments
    #[clap(long = "fee-decryption-key", value_parser, conflicts_with = "fee_encryption_key", env = "FEE_DECRYPTION_KEY")]
    pub fee_decryption_key: Option<String>,

    // -------------
    // | Telemetry |
    // -------------

    /// Whether or not to enable OTLP tracing
    #[clap(long = "enable-otlp", value_parser)]
    pub otlp_enabled: bool,
    /// The OTLP collector endpoint to send traces to
    #[clap(long, value_parser, default_value = "http://localhost:4317")]
    pub otlp_collector_url: String,
    /// Whether or not to enable Datadog-formatted logs
    #[clap(long = "enable-datadog", value_parser)]
    pub datadog_enabled: bool,
    /// Whether or not to enable metrics collection
    #[clap(long = "enable-metrics", value_parser)]
    pub metrics_enabled: bool,
    /// The StatsD recorder host to send metrics to
    #[clap(long, value_parser, default_value = "127.0.0.1")]
    pub statsd_host: String,

    /// The StatsD recorder port to send metrics to
    #[clap(long, value_parser, default_value = "8125")]
    pub statsd_port: u16,
}

// ----------
// | Config |
// ----------

/// Defines the system config for the relayer
#[derive(Debug)]
pub struct RelayerConfig {
    // -----------------------------
    // | Application Level Configs |
    // -----------------------------
    /// The minimum amount of the quote asset that the relayer should settle
    /// matches on
    pub min_fill_size: Amount,
    /// The take rate of this relayer on a managed match, i.e. the amount of the
    /// received asset that the relayer takes as a fee
    pub match_take_rate: FixedPoint,
    /// The address at which to collect externally paid fees
    pub external_fee_addr: Option<Address>,
    /// When set, the relayer will automatically redeem new fees into its wallet
    pub auto_redeem_fees: bool,
    /// The price reporter from which to stream prices.
    /// If unset, the relayer will connect to exchanges directly.
    pub price_reporter_url: Option<Url>,
    /// The relayer fee whitelist
    ///
    /// Specifies a mapping of wallet IDs to fees for the relayer
    pub relayer_fee_whitelist: Vec<RelayerFeeWhitelistEntry>,

    // -----------------------
    // | Environment Configs |
    // -----------------------
    /// The chain that the relayer settles to
    pub chain_id: Chain,
    /// The address of the contract in the target network
    pub contract_address: String,
    /// The address of the compliance service to use for wallet screening. If
    /// not configured, wallet screening is disabled
    ///
    /// The API of the compliance service must match that defined here:
    ///     https://github.com/renegade-fi/relayer-extensions/tree/master/compliance/compliance-api
    pub compliance_service_url: Option<String>,
    /// The URL to export relayer events to.
    /// If ommitted, the event manager is disabled.
    pub event_export_url: Option<Url>,

    // ----------------------------
    // | Networking Configuration |
    // ----------------------------
    /// Allow for discovery of nodes on the localhost IP address
    pub allow_local: bool,
    /// The address to bind to for gossip, defaults to 0.0.0.0 (all interfaces)
    pub bind_addr: IpAddr,
    /// The known public IP address of the local peer
    pub public_ip: Option<SocketAddr>,
    /// The amount of time to allow for gossip warmup, in milliseconds
    pub gossip_warmup: u64,

    // -------------------------
    // | Cluster Configuration |
    // -------------------------
    /// Run the relayer in bootstrap mode
    ///
    /// Bootstrap mode omits much of the relayer's functionality and ignores
    /// most messages
    pub bootstrap_mode: bool,
    /// Bootstrap servers that the peer should connect to
    pub bootstrap_servers: Vec<(WrappedPeerId, Multiaddr)>,
    /// The cluster keypair
    pub cluster_keypair: DalekKeypair,
    /// The cluster symmetric keypair
    pub cluster_symmetric_key: HmacKey,
    /// The admin key used to authenticate requests to the relayer's API
    ///
    /// This is a symmetric key encoded as a base64 string
    ///
    /// If not set, the admin API is disabled
    pub admin_api_key: Option<HmacKey>,

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
    pub p2p_key: Keypair,
    /// The path at which to open up the database
    pub db_path: String,
    /// The path at which to save raft snapshots
    pub raft_snapshot_path: String,
    /// Whether to record historical state locally
    pub record_historical_state: bool,
    /// The maximum number of wallet operations a user is allowed to perform per
    /// hour
    pub wallet_task_rate_limit: u32,
    /// The minimum usdc denominated value for a deposit or withdrawal
    pub min_transfer_amount: f64,
    /// The maximum staleness (number of newer roots observed) to allow on
    /// Merkle proofs for managed wallets. After this threshold is exceeded,
    /// the Merkle proof will be updated
    pub max_merkle_staleness: usize,
    /// Whether to disable the price reporter if e.g. we are streaming from a
    /// dedicated external API gateway node in the cluster
    pub disable_price_reporter: bool,
    /// The exchanges explicitly disabled for price reports
    pub disabled_exchanges: Vec<Exchange>,
    /// Whether or not the relayer is in debug mode
    pub debug: bool,

    // -----------
    // | Secrets |
    // -----------
    /// The cluster ID, a parsed version of the cluster's pubkey
    pub cluster_id: ClusterId,
    /// The Coinbase API key to use for price streaming
    pub coinbase_key_name: Option<String>,
    /// The Coinbase API secret to use for price streaming
    pub coinbase_key_secret: Option<String>,
    /// The HTTP addressable Ethereum JSON-RPC node
    pub rpc_url: Option<String>,
    /// The private key used to send transactions
    pub private_key: PrivateKeySigner,
    /// The Ethereum RPC node websocket address to dial for on-chain data
    pub eth_websocket_addr: Option<String>,
    /// The key used to encrypt (and possibly decrypt) fee payments
    pub fee_key: RelayerFeeKey,

    // -------------
    // | Telemetry |
    // -------------
    /// Whether or not to enable OTLP tracing
    pub otlp_enabled: bool,
    /// The OTLP collector endpoint to send traces to
    pub otlp_collector_url: String,
    /// Whether or not to enable Datadog-formatted logs
    pub datadog_enabled: bool,
    /// Whether or not to enable metrics collection
    pub metrics_enabled: bool,
    /// The StatsD recorder host to send metrics to
    pub statsd_host: String,
    /// The StatsD recorder port to send metrics to
    pub statsd_port: u16,
}

impl RelayerConfig {
    /// Get the peer ID associated with the p2p key
    pub fn peer_id(&self) -> WrappedPeerId {
        WrappedPeerId(self.p2p_key.public().to_peer_id())
    }

    /// Get the private key from which the relayer's wallet is derived
    pub fn relayer_wallet_key(&self) -> &PrivateKeySigner {
        &self.private_key
    }

    /// Get a path ref to the raft snapshot path
    pub fn raft_snapshot_path(&self) -> &Path {
        Path::new(&self.raft_snapshot_path)
    }

    /// Whether the relayer needs a wallet to support its configuration or not
    ///
    /// If it does not, the relayer may skip the wallet creation/lookup step
    pub fn needs_relayer_wallet(&self) -> bool {
        self.auto_redeem_fees
    }

    /// Get the minimum fill size as a decimal adjusted USDC value
    pub fn min_fill_size_decimal_adjusted(&self) -> f64 {
        let token = Token::from_ticker("USDC");
        token.convert_to_decimal(self.min_fill_size)
    }

    /// Configure the telemetry layers from the relayer config
    pub fn configure_telemetry(&self) -> Result<(), String> {
        configure_telemetry(
            self.datadog_enabled,
            self.otlp_enabled,
            self.metrics_enabled,
            self.otlp_collector_url.clone(),
            &self.statsd_host,
            self.statsd_port,
        )
        .map_err(|e| e.to_string())
    }
}
impl Default for RelayerConfig {
    fn default() -> Self {
        // Parse a dummy set of command line args and convert this to a config
        let cli = Cli::parse_from(Vec::<String>::new());
        parse_config_from_args(cli).expect("default config does not parse")
    }
}

/// A custom clone implementation specifically for the cluster keypair which
/// does not implement clone
impl Clone for RelayerConfig {
    fn clone(&self) -> Self {
        Self {
            min_fill_size: self.min_fill_size,
            match_take_rate: self.match_take_rate,
            external_fee_addr: self.external_fee_addr.clone(),
            auto_redeem_fees: self.auto_redeem_fees,
            relayer_fee_whitelist: self.relayer_fee_whitelist.clone(),
            price_reporter_url: self.price_reporter_url.clone(),
            chain_id: self.chain_id,
            contract_address: self.contract_address.clone(),
            compliance_service_url: self.compliance_service_url.clone(),
            bootstrap_mode: self.bootstrap_mode,
            bootstrap_servers: self.bootstrap_servers.clone(),
            p2p_port: self.p2p_port,
            http_port: self.http_port,
            websocket_port: self.websocket_port,
            p2p_key: self.p2p_key.clone(),
            db_path: self.db_path.clone(),
            raft_snapshot_path: self.raft_snapshot_path.clone(),
            record_historical_state: self.record_historical_state,
            event_export_url: self.event_export_url.clone(),
            wallet_task_rate_limit: self.wallet_task_rate_limit,
            min_transfer_amount: self.min_transfer_amount,
            max_merkle_staleness: self.max_merkle_staleness,
            allow_local: self.allow_local,
            bind_addr: self.bind_addr,
            public_ip: self.public_ip,
            gossip_warmup: self.gossip_warmup,
            disable_price_reporter: self.disable_price_reporter,
            disabled_exchanges: self.disabled_exchanges.clone(),
            cluster_keypair: DalekKeypair::from_bytes(&self.cluster_keypair.to_bytes()).unwrap(),
            cluster_symmetric_key: self.cluster_symmetric_key,
            admin_api_key: self.admin_api_key,
            cluster_id: self.cluster_id.clone(),
            coinbase_key_name: self.coinbase_key_name.clone(),
            coinbase_key_secret: self.coinbase_key_secret.clone(),
            rpc_url: self.rpc_url.clone(),
            private_key: self.private_key.clone(),
            fee_key: self.fee_key,
            eth_websocket_addr: self.eth_websocket_addr.clone(),
            debug: self.debug,
            otlp_enabled: self.otlp_enabled,
            otlp_collector_url: self.otlp_collector_url.clone(),
            datadog_enabled: self.datadog_enabled,
            metrics_enabled: self.metrics_enabled,
            statsd_host: self.statsd_host.clone(),
            statsd_port: self.statsd_port,
        }
    }
}

/// Wraps an encryption key (public or private) to allow for the relayer to be
/// configured with either of the encryption key or the decryption key
///
/// Configuring the relayer with the decryption key allows the relayer to
/// automate tasks like fee redemption
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum RelayerFeeKey {
    /// A public-only configuration
    Public(EncryptionKey),
    /// A private-key configuration
    Secret(DecryptionKey),
}

impl RelayerFeeKey {
    /// Construct a new public-only key configuration
    pub fn new_public(key: EncryptionKey) -> Self {
        RelayerFeeKey::Public(key)
    }

    /// Construct a new private-key configuration
    pub fn new_secret(key: DecryptionKey) -> Self {
        RelayerFeeKey::Secret(key)
    }

    /// Get the public key
    pub fn public_key(&self) -> EncryptionKey {
        match self {
            RelayerFeeKey::Public(key) => *key,
            RelayerFeeKey::Secret(key) => key.public_key(),
        }
    }

    /// Get the secret key
    pub fn secret_key(&self) -> Option<DecryptionKey> {
        match self {
            RelayerFeeKey::Public(_) => None,
            RelayerFeeKey::Secret(key) => Some(*key),
        }
    }
}

// ---------
// | Tests |
// ---------

/// Tests for the cli
#[cfg(test)]
mod test {
    use crate::RelayerConfig;

    /// Test that the default config parses
    #[test]
    fn test_default_config() {
        RelayerConfig::default();
    }
}
