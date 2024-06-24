//! The relayer CLI and config definitions

use arbitrum_client::constants::Chain;
use circuit_types::{elgamal::DecryptionKey, fixed_point::FixedPoint, Amount};
use clap::Parser;
use common::types::{
    exchange::Exchange,
    gossip::{ClusterId, SymmetricAuthKey, WrappedPeerId},
    wallet::WalletIdentifier,
};
use ed25519_dalek::Keypair as DalekKeypair;
use ethers::signers::LocalWallet;
use libp2p::{identity::Keypair, Multiaddr};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    path::Path,
};
use url::Url;

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
    #[clap(long, value_parser, conflicts_with_all = &["coinbase_api_key", "coinbase_api_secret", "eth_websocket_addr"])]
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
    #[clap(long, value_parser, default_value = "0.0008")]
    pub match_take_rate: f64,
    /// The mutual exclusion list for matches, two wallets in this list will never be matched internally by the node
    #[clap(long, value_parser, value_delimiter=' ', num_args=0..)]
    pub match_mutual_exclusion_list: Vec<WalletIdentifier>,
    /// The path to the file containing relayer fee whitelist info
    #[clap(long, value_parser)]
    pub relayer_fee_whitelist: Option<String>,

    // -----------------------
    // | Environment Configs |
    // -----------------------

    /// The chain that the relayer settles to
    #[clap(long, value_parser, default_value = "testnet")]
    pub chain_id: Chain,
    /// The address of the darkpool contract, defaults to the internal testnet deployment
    #[clap(long, value_parser, default_value = "0x84bc75bc4fb943d5576545fb4724c5cab781a61e")]
    pub contract_address: String,
    /// The path to the file containing deployments info for the darkpool contract
    #[clap(long, value_parser)]
    pub deployments_file: Option<String>,
    /// The path to the file containing token remaps for the given chain
    /// 
    /// See https://github.com/renegade-fi/token-mappings for more information on the format of this file
    #[clap(long, value_parser)]
    pub token_remap_file: Option<String>,

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
    /// The bootstrap servers that the peer should dial initially
    #[clap(short, long, value_parser)]
    pub bootstrap_servers: Option<Vec<String>>,
    /// The cluster private key to use
    #[clap(long = "cluster-private-key", value_parser)]
    pub cluster_private_key: Option<String>,
    /// The cluster symmetric key to use for authenticating intra-cluster messages
    /// 
    /// Encoded as a base64 string
    #[clap(long, value_parser)]
    pub cluster_symmetric_key: Option<String>,
    /// The admin key used to authenticate requests to the relayer's API
    /// 
    /// This is a symmetric key encoded as a base64 string
    /// 
    /// If not set, the admin API is disabled
    #[clap(long, value_parser)]
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
    /// The Coinbase API key to use for price streaming
    #[clap(long = "coinbase-key", value_parser)]
    pub coinbase_api_key: Option<String>,
    /// The Coinbase API secret to use for price streaming
    #[clap(long = "coinbase-secret", value_parser)]
    pub coinbase_api_secret: Option<String>,
    /// The Ethereum RPC node websocket address to dial for on-chain data
    #[clap(long = "eth-websocket", value_parser)]
    pub eth_websocket_addr: Option<String>,
    /// The HTTP addressable Arbitrum JSON-RPC node
    #[clap(long = "rpc-url", value_parser)]
    pub rpc_url: Option<String>,
    /// The Arbitrum private keys used to send transactions.
    /// Multiple keys can be provided to mitigate nonce contention across a node / cluster.
    /// 
    /// Defaults to the devnet pre-funded key
    #[clap(
        value_parser,
        long = "arbitrum-pkeys",  
        default_values_t = ["0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659".to_string()],
        num_args = 1..,
        value_delimiter = ' ',
    )]
    pub arbitrum_private_keys: Vec<String>,
    /// The key used to decrypt fee payments
    #[clap(long = "fee-decryption-key", value_parser)]
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
    /// The mutual exclusion list for matches, two wallets in this list will
    /// never be matched internally by the node
    pub match_mutual_exclusion_list: HashSet<WalletIdentifier>,
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
    /// Bootstrap servers that the peer should connect to
    pub bootstrap_servers: Vec<(WrappedPeerId, Multiaddr)>,
    /// The cluster keypair
    pub cluster_keypair: DalekKeypair,
    /// The cluster symmetric keypair
    pub cluster_symmetric_key: SymmetricAuthKey,
    /// The admin key used to authenticate requests to the relayer's API
    ///
    /// This is a symmetric key encoded as a base64 string
    ///
    /// If not set, the admin API is disabled
    pub admin_api_key: Option<SymmetricAuthKey>,

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
    pub coinbase_api_key: Option<String>,
    /// The Coinbase API secret to use for price streaming
    pub coinbase_api_secret: Option<String>,
    /// The HTTP addressable Arbitrum JSON-RPC node
    pub rpc_url: Option<String>,
    /// The Arbitrum private keys used to send transactions
    pub arbitrum_private_keys: Vec<LocalWallet>,
    /// The Ethereum RPC node websocket address to dial for on-chain data
    pub eth_websocket_addr: Option<String>,
    /// The decryption key used to settle managed match fees
    pub fee_decryption_key: DecryptionKey,

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

    /// Get the Arbitrum private key from which the relayer's wallet is derived
    pub fn relayer_arbitrum_key(&self) -> &LocalWallet {
        self.arbitrum_private_keys.first().expect("no arbitrum private keys configured")
    }

    /// Get a path ref to the raft snapshot path
    pub fn raft_snapshot_path(&self) -> &Path {
        Path::new(&self.raft_snapshot_path)
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
            match_mutual_exclusion_list: self.match_mutual_exclusion_list.clone(),
            relayer_fee_whitelist: self.relayer_fee_whitelist.clone(),
            price_reporter_url: self.price_reporter_url.clone(),
            chain_id: self.chain_id,
            contract_address: self.contract_address.clone(),
            bootstrap_servers: self.bootstrap_servers.clone(),
            p2p_port: self.p2p_port,
            http_port: self.http_port,
            websocket_port: self.websocket_port,
            p2p_key: self.p2p_key.clone(),
            db_path: self.db_path.clone(),
            raft_snapshot_path: self.raft_snapshot_path.clone(),
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
            coinbase_api_key: self.coinbase_api_key.clone(),
            coinbase_api_secret: self.coinbase_api_secret.clone(),
            rpc_url: self.rpc_url.clone(),
            arbitrum_private_keys: self.arbitrum_private_keys.clone(),
            fee_decryption_key: self.fee_decryption_key,
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

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    //! Tests for the cli
    use crate::RelayerConfig;

    /// Test that the default config parses
    #[test]
    fn test_default_config() {
        RelayerConfig::default();
    }
}
