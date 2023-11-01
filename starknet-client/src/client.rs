//! A wrapper around the starknet client made available by:
//! https://docs.rs/starknet-core/latest/starknet_core/

mod chain_state;
mod contract_interaction;
mod pathfinder;

pub use pathfinder::TransactionStatus;

use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use common::types::chain_id::ChainId;
use constants::{
    DEVNET_CONTRACT_DEPLOYMENT_BLOCK, GOERLI_CONTRACT_DEPLOYMENT_BLOCK,
    MAINNET_CONTRACT_DEPLOYMENT_BLOCK,
};

use reqwest::{Client, Url as ReqwestUrl};
use starknet::{
    accounts::SingleOwnerAccount,
    core::types::FieldElement as StarknetFieldElement,
    providers::jsonrpc::{HttpTransport, JsonRpcClient},
    signers::{LocalWallet, SigningKey},
};

/// A type alias for a felt that represents a transaction hash
pub type TransactionHash = StarknetFieldElement;
/// A type alias for a `JsonRpc` provider that uses `HttpTransport`
pub type RpcProvider = JsonRpcClient<HttpTransport>;
/// A type alias for the account used by the `starknet-client` crate
pub type StarknetAcct = SingleOwnerAccount<RpcProvider, LocalWallet>;

/// The block length of the window to poll events in while paginating
///
/// I.e. when paginating events, we paginate backwards by increments of
/// `BLOCK_PAGINATION_WINDOW` blocks. Meaning we first fetch the most recent
/// `BLOCK_PAGINATION_WINDOW` blocks; scan them, then search the next
/// `BLOCK_PAGINATION_WINDOW` blocks
const BLOCK_PAGINATION_WINDOW: usize = 1000;
/// The page size to request when querying events
const EVENTS_PAGE_SIZE: u64 = 50;
/// The interval at which to poll the gateway for transaction status
const TX_STATUS_POLL_INTERVAL_MS: u64 = 3_000; // 3 seconds
/// The fee estimate multiplier to use as `MAX_FEE` for transactions
const MAX_FEE_MULTIPLIER: f32 = 3.0;

/// Error message emitted when an unexpected transaction type is found
const ERR_UNEXPECTED_TX_TYPE: &str = "unexpected transaction type found";

/// The config type for the client, consists of secrets needed to connect to
/// the gateway and API server, as well as keys for sending transactions
#[derive(Clone)]
pub struct StarknetClientConfig {
    /// The chain this client should submit requests to
    pub chain: ChainId,
    /// The address of the Darkpool contract on chain
    pub contract_addr: String,
    /// The HTTP addressable JSON-RPC node to connect to for
    /// requests that cannot go through the gateway
    pub starknet_json_rpc_addr: String,
    /// The API key for the JSON-RPC node
    ///
    /// For now, we require only the API key's ID on our RPC node,
    /// so this parameter is unused
    pub infura_api_key: Option<String>,
    /// The starknet addresses of the accounts corresponding to the given keys
    pub starknet_account_addresses: Vec<String>,
    /// The starknet signing keys, used to submit transactions on-chain
    pub starknet_pkeys: Vec<String>,
}

impl StarknetClientConfig {
    /// Whether or not a signing account has been passed with the config
    ///
    /// Only when this is enabled may the client write transactions to the
    /// sequencer
    pub fn account_enabled(&self) -> bool {
        !self.starknet_pkeys.is_empty() && !self.starknet_account_addresses.is_empty()
    }

    /// Get the darkpool contract address as a `StarknetFieldElement`
    pub fn contract_address(&self) -> StarknetFieldElement {
        StarknetFieldElement::from_hex_be(&self.contract_addr).unwrap()
    }

    /// Create a new JSON-RPC client using the API credentials in the config
    ///
    /// Returns `None` if the config does not specify the correct credentials
    pub fn new_jsonrpc_client(&self) -> JsonRpcClient<HttpTransport> {
        let transport = HttpTransport::new(
            ReqwestUrl::parse(&self.starknet_json_rpc_addr).expect("invalid JSON-RPC URL"),
        );
        JsonRpcClient::new(transport)
    }

    /// Get the earliest block at which the contract may have been deployed
    pub fn earliest_block(&self) -> u64 {
        match self.chain {
            ChainId::AlphaGoerli => GOERLI_CONTRACT_DEPLOYMENT_BLOCK,
            ChainId::Mainnet => MAINNET_CONTRACT_DEPLOYMENT_BLOCK,
            ChainId::Devnet | ChainId::Katana => DEVNET_CONTRACT_DEPLOYMENT_BLOCK,
        }
    }
}

/// A wrapper around the concrete JSON-RPC client that provides helpers for
/// common Renegade-specific access patterns
#[derive(Clone)]
pub struct StarknetClient {
    /// The config for the client
    pub config: StarknetClientConfig,
    /// The address of the contract on-chain
    pub contract_address: StarknetFieldElement,
    /// The client used to send starknet JSON-RPC requests
    jsonrpc_client: Arc<JsonRpcClient<HttpTransport>>,
    /// An HTTP client used for making raw JSON-RPC requests    
    http_client: Client,
    /// The accounts that may be used to sign outbound transactions
    accounts: Arc<Vec<StarknetAcct>>,
    /// The account index to use for the next transaction
    account_index: Arc<Mutex<usize>>,
}

impl StarknetClient {
    /// Constructor
    pub fn new(config: StarknetClientConfig) -> Self {
        // Build a JSON-RPC client
        let jsonrpc_client = Arc::new(config.new_jsonrpc_client());

        // Build the accounts to sign transactions with
        let account_addrs = config.starknet_account_addresses.clone();
        let keys = config.starknet_pkeys.clone();
        let accounts = account_addrs
            .into_iter()
            .zip(keys)
            .map(|(account_addr, key)| {
                // Parse the account address and key
                let account_addr_felt = StarknetFieldElement::from_str(&account_addr).unwrap();
                let key_felt = StarknetFieldElement::from_str(&key).unwrap();

                // Build the account
                let signer = LocalWallet::from(SigningKey::from_secret_scalar(key_felt));
                SingleOwnerAccount::new(
                    config.new_jsonrpc_client(),
                    signer,
                    account_addr_felt,
                    config.chain.into(),
                )
            })
            .collect::<Vec<_>>();

        // Wrap the accounts an Arc for read access across workers
        let accounts = Arc::new(accounts);

        // Parse the contract address
        let contract_address = config.contract_address();

        Self {
            config,
            contract_address,
            jsonrpc_client,
            http_client: Client::new(),
            accounts,
            account_index: Arc::new(Mutex::new(0)),
        }
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get the underlying RPC client as an immutable reference
    pub fn get_jsonrpc_client(&self) -> &JsonRpcClient<HttpTransport> {
        self.jsonrpc_client.as_ref()
    }

    /// Get the underlying account at the given index as an immutable reference
    pub fn get_account(&self, account_index: usize) -> &StarknetAcct {
        self.accounts.as_ref().get(account_index).unwrap()
    }

    /// Query the current nonce and advance it by one
    pub fn next_account_index(&self) -> usize {
        // Acquire a lock on self.account_index, copy it to a usize, and increment it
        let mut account_index = self.account_index.lock().unwrap();
        let current_account_index = *account_index;
        *account_index = (*account_index + 1) % self.accounts.as_ref().len();
        current_account_index
    }
}
