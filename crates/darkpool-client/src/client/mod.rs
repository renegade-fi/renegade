//! The definition of the darkpool client, which holds the configuration
//! details, along with a lower-level handle for the darkpool smart contract

use std::{str::FromStr, time::Duration};

use alloy::{
    providers::{
        DynProvider, Provider, ProviderBuilder,
        fillers::{BlobGasFiller, ChainIdFiller, GasFiller},
    },
    signers::local::PrivateKeySigner,
    transports::http::reqwest::Url,
};
use alloy_contract::{CallBuilder, Event};
use alloy_primitives::{Address, BlockNumber, ChainId};
use alloy_sol_types::SolEvent;
use common::types::chain::Chain;
use constants::{
    ARBITRUM_ONE_DEPLOY_BLOCK, ARBITRUM_SEPOLIA_DEPLOY_BLOCK, BASE_MAINNET_DEPLOY_BLOCK,
    BASE_SEPOLIA_DEPLOY_BLOCK, DEVNET_DEPLOY_BLOCK,
};
use util::err_str;

use crate::{
    errors::{DarkpoolClientConfigError, DarkpoolClientError},
    traits::DarkpoolImpl,
};

mod contract_interaction;
mod event_indexing;

/// A type alias for the RPC client, which is an alloy middleware stack that
/// includes a signer derived from a raw private key, and a provider that
/// connects to the RPC endpoint over HTTP.
pub type RenegadeProvider = DynProvider;
/// A darkpool call builder type
pub type DarkpoolCallBuilder<'a, C> = CallBuilder<&'a DynProvider, C>;

/// A configuration struct for the darkpool client, consists of relevant
/// contract addresses, and endpoint for setting up an RPC client, and a private
/// key for signing transactions.
pub struct DarkpoolClientConfig {
    /// The address of the darkpool proxy contract.
    ///
    /// This is the main entrypoint to interaction with the darkpool.
    pub darkpool_addr: String,
    /// Which chain the client should interact with,
    /// e.g. arbitrum-sepolia, base-mainnet, etc.
    pub chain: Chain,
    /// HTTP-addressable RPC endpoint for the client to connect to
    pub rpc_url: String,
    /// The private key of the account to use for signing transactions
    pub private_key: PrivateKeySigner,
    /// The interval at which to poll for event filters and pending transactions
    pub block_polling_interval: Duration,
}

impl DarkpoolClientConfig {
    /// Gets the block number at which the darkpool was deployed
    fn get_deploy_block(&self) -> BlockNumber {
        match self.chain {
            Chain::ArbitrumSepolia => ARBITRUM_SEPOLIA_DEPLOY_BLOCK,
            Chain::ArbitrumOne => ARBITRUM_ONE_DEPLOY_BLOCK,
            Chain::BaseSepolia => BASE_SEPOLIA_DEPLOY_BLOCK,
            Chain::BaseMainnet => BASE_MAINNET_DEPLOY_BLOCK,
            Chain::Devnet => DEVNET_DEPLOY_BLOCK,
        }
    }

    /// Constructs RPC clients capable of signing transactions from the
    /// configuration
    fn get_provider(&self) -> Result<RenegadeProvider, DarkpoolClientConfigError> {
        let url = Url::parse(&self.rpc_url)
            .map_err(err_str!(DarkpoolClientConfigError::RpcClientInitialization))?;
        let key = self.private_key.clone();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            .with_simple_nonce_management()
            .filler(ChainIdFiller::default())
            .filler(GasFiller)
            .filler(BlobGasFiller)
            .wallet(key)
            .connect_http(url);
        provider.client().set_poll_interval(self.block_polling_interval);

        Ok(DynProvider::new(provider))
    }

    /// Parses the darkpool proxy address from the configuration,
    /// returning an [`alloy::primitives::Address`]
    fn get_darkpool_address(&self) -> Result<Address, DarkpoolClientConfigError> {
        Address::from_str(&self.darkpool_addr)
            .map_err(|e| DarkpoolClientConfigError::AddressParsing(e.to_string()))
    }
}

/// The darkpool client, which provides a higher-level interface to the darkpool
/// contract for Renegade-specific access patterns.
#[derive(Clone)]
pub struct DarkpoolClientInner<D: DarkpoolImpl> {
    /// The darkpool contract instance
    darkpool: D,
    /// The block number at which the darkpool was deployed
    deploy_block: BlockNumber,
}

impl<D: DarkpoolImpl> DarkpoolClientInner<D> {
    /// Constructs a new darkpool client from the given configuration
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(config: DarkpoolClientConfig) -> Result<Self, DarkpoolClientError> {
        let darkpool_address = config.get_darkpool_address()?;
        let provider = config.get_provider()?;
        let darkpool = D::new(darkpool_address, provider);
        let deploy_block = config.get_deploy_block();

        Ok(Self { darkpool, deploy_block })
    }

    /// Get a darkpool contract client
    pub fn darkpool(&self) -> &D {
        &self.darkpool
    }

    /// Get an alloy address for the darkpool contract
    pub fn darkpool_addr(&self) -> Address {
        self.darkpool.address()
    }

    /// Get a reference to some underlying RPC client
    pub fn provider(&self) -> &RenegadeProvider {
        self.darkpool.provider()
    }

    /// Get the chain ID
    pub async fn chain_id(&self) -> Result<ChainId, DarkpoolClientError> {
        self.provider().get_chain_id().await.map_err(err_str!(DarkpoolClientError::Rpc))
    }

    /// Get the current Stylus block number
    pub async fn block_number(&self) -> Result<BlockNumber, DarkpoolClientError> {
        self.provider().get_block_number().await.map_err(err_str!(DarkpoolClientError::Rpc))
    }

    /// Create an event filter
    pub fn event_filter<E: SolEvent>(&self) -> Event<&RenegadeProvider, E> {
        let provider = self.provider();
        let address = self.darkpool_addr();
        Event::new_sol(provider, &address)
    }

    /// Resets the deploy block to the current block number.
    ///
    /// Used in integration tests to ensure that we are only querying for events
    /// from the desired block onwards.
    #[cfg(feature = "integration")]
    pub async fn reset_deploy_block(&mut self) -> Result<(), DarkpoolClientError> {
        self.deploy_block = self.block_number().await?;

        Ok(())
    }
}
