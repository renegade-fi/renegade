//! The definition of the Arbitrum client, which holds the configuration
//! details, along with a lower-level handle for the darkpool smart contract

use std::str::FromStr;

use alloy::{
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    transports::http::reqwest::Url,
};
use alloy_contract::CallBuilder;
use alloy_primitives::{Address, BlockNumber, ChainId};
use constants::{DEVNET_DEPLOY_BLOCK, MAINNET_DEPLOY_BLOCK, TESTNET_DEPLOY_BLOCK};
use util::err_str;

use crate::{
    abi::Darkpool::DarkpoolInstance,
    constants::Chain,
    errors::{ArbitrumClientConfigError, ArbitrumClientError},
};

mod contract_interaction;
mod event_indexing;

/// A type alias for the RPC client, which is an ethers middleware stack that
/// includes a signer derived from a raw private key, and a provider that
/// connects to the RPC endpoint over HTTP.
pub type RenegadeProvider = DynProvider;
/// A darkpool contract instance
pub type Darkpool = DarkpoolInstance<RenegadeProvider>;
/// A darkpool call builder type
pub type DarkpoolCallBuilder<'a, C> = CallBuilder<&'a DynProvider, C>;

/// contract addresses, and endpoint for setting up an RPC client, and a private
/// key for signing transactions.
pub struct ArbitrumClientConfig {
    /// The address of the darkpool proxy contract.
    ///
    /// This is the main entrypoint to interaction with the darkpool.
    pub darkpool_addr: String,
    /// Which chain the client should interact with,
    /// e.g. mainnet, testnet, or devnet
    pub chain: Chain,
    /// HTTP-addressable RPC endpoint for the client to connect to
    pub rpc_url: String,
    /// The private key of the account to use for signing transactions
    pub private_key: PrivateKeySigner,
    /// The interval at which to poll for event filters and pending transactions
    pub block_polling_interval_ms: u64,
}

impl ArbitrumClientConfig {
    /// Gets the block number at which the darkpool was deployed
    fn get_deploy_block(&self) -> BlockNumber {
        match self.chain {
            Chain::Mainnet => MAINNET_DEPLOY_BLOCK,
            Chain::Testnet => TESTNET_DEPLOY_BLOCK,
            Chain::Devnet => DEVNET_DEPLOY_BLOCK,
        }
    }

    /// Constructs RPC clients capable of signing transactions from the
    /// configuration
    fn get_provider(&self) -> Result<RenegadeProvider, ArbitrumClientConfigError> {
        let url = Url::parse(&self.rpc_url)
            .map_err(err_str!(ArbitrumClientConfigError::RpcClientInitialization))?;
        let key = self.private_key.clone();
        let provider = ProviderBuilder::new().wallet(key).on_http(url);

        Ok(DynProvider::new(provider))
    }

    /// Parses the darkpool proxy address from the configuration,
    /// returning an [`ethers::types::Address`]
    fn get_darkpool_address(&self) -> Result<Address, ArbitrumClientConfigError> {
        Address::from_str(&self.darkpool_addr)
            .map_err(|e| ArbitrumClientConfigError::AddressParsing(e.to_string()))
    }
}

/// The Arbitrum client, which provides a higher-level interface to the darkpool
/// contract for Renegade-specific access patterns.
#[derive(Clone)]
pub struct ArbitrumClient {
    /// The darkpool contract instance
    darkpool: Darkpool,
    /// The block number at which the darkpool was deployed
    deploy_block: BlockNumber,
}

impl ArbitrumClient {
    /// Constructs a new Arbitrum client from the given configuration
    pub async fn new(config: ArbitrumClientConfig) -> Result<Self, ArbitrumClientError> {
        let darkpool_address = config.get_darkpool_address()?;
        let provider = config.get_provider()?;
        let darkpool = Darkpool::new(darkpool_address, provider);
        let deploy_block = config.get_deploy_block();

        Ok(Self { darkpool, deploy_block })
    }

    /// Get a darkpool contract client
    pub fn darkpool_client(&self) -> &Darkpool {
        &self.darkpool
    }

    /// Get an alloy address for the darkpool contract
    pub fn darkpool_addr(&self) -> Address {
        *self.darkpool.address()
    }

    /// Get a reference to some underlying RPC client
    pub fn provider(&self) -> &RenegadeProvider {
        self.darkpool_client().provider()
    }

    /// Get the chain ID
    pub async fn chain_id(&self) -> Result<ChainId, ArbitrumClientError> {
        self.provider().get_chain_id().await.map_err(err_str!(ArbitrumClientError::Rpc))
    }

    /// Get the current Stylus block number
    pub async fn block_number(&self) -> Result<BlockNumber, ArbitrumClientError> {
        self.provider().get_block_number().await.map_err(err_str!(ArbitrumClientError::Rpc))
    }

    /// Resets the deploy block to the current block number.
    ///
    /// Used in integration tests to ensure that we are only querying for events
    /// from the desired block onwards.
    #[cfg(feature = "integration")]
    pub async fn reset_deploy_block(&mut self) -> Result<(), ArbitrumClientError> {
        self.deploy_block = self.block_number().await?;

        Ok(())
    }
}
