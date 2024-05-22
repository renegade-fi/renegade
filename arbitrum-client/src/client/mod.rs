//! The definition of the Arbitrum client, which holds the configuration
//! details, along with a lower-level handle for the darkpool smart contract

use std::{str::FromStr, sync::Arc, time::Duration};

use alloy_primitives::ChainId;
use constants::{DEVNET_DEPLOY_BLOCK, TESTNET_DEPLOY_BLOCK};
use ethers::{
    core::k256::ecdsa::SigningKey,
    middleware::{MiddlewareBuilder, NonceManagerMiddleware, SignerMiddleware},
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer, Wallet},
    types::{Address, BlockNumber},
};
use util::err_str;

use crate::{
    abi::DarkpoolContract,
    constants::Chain,
    errors::{ArbitrumClientConfigError, ArbitrumClientError},
};

mod contract_interaction;
mod event_indexing;

/// A configuration struct for the Arbitrum client, consists of relevant
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
    /// The private keys of the accounts to use for signing transactions.
    /// Multiple keys can be provided to mitigate nonce contention across a node
    /// / cluster.
    pub arb_priv_keys: Vec<LocalWallet>,
    /// The interval at which to poll for event filters and pending transactions
    pub block_polling_interval_ms: u64,
}

/// A type alias for the RPC client, which is an ethers middleware stack that
/// includes a signer derived from a raw private key, and a provider that
/// connects to the RPC endpoint over HTTP.
pub type MiddlewareStack =
    NonceManagerMiddleware<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>;

impl ArbitrumClientConfig {
    /// Gets the block number at which the darkpool was deployed
    fn get_deploy_block(&self) -> BlockNumber {
        match self.chain {
            Chain::Mainnet => unimplemented!(),
            Chain::Testnet => BlockNumber::Number(TESTNET_DEPLOY_BLOCK.into()),
            Chain::Devnet => BlockNumber::Number(DEVNET_DEPLOY_BLOCK.into()),
        }
    }

    /// Constructs RPC clients capable of signing transactions from the
    /// configuration
    async fn get_accounts(&self) -> Result<Vec<Arc<MiddlewareStack>>, ArbitrumClientConfigError> {
        let mut provider = Provider::<Http>::try_from(&self.rpc_url)
            .map_err(|e| ArbitrumClientConfigError::RpcClientInitialization(e.to_string()))?;

        provider.set_interval(Duration::from_millis(self.block_polling_interval_ms));

        let chain_id = provider
            .get_chainid()
            .await
            .map_err(|e| ArbitrumClientConfigError::RpcClientInitialization(e.to_string()))?
            .as_u64();

        // Build the RPC clients
        let accounts = self
            .arb_priv_keys
            .iter()
            .map(|wallet| {
                let account = wallet.clone().with_chain_id(chain_id);
                let addr = account.address();
                Arc::new(provider.clone().with_signer(account).nonce_manager(addr))
            })
            .collect();

        Ok(accounts)
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
    /// A list of darkpool contract clients, each configured with a different
    /// Arbitrum account as the signer
    darkpool_clients: Vec<DarkpoolContract<MiddlewareStack>>,
    /// The block number at which the darkpool was deployed
    deploy_block: BlockNumber,
}

impl ArbitrumClient {
    /// Constructs a new Arbitrum client from the given configuration
    pub async fn new(config: ArbitrumClientConfig) -> Result<Self, ArbitrumClientError> {
        let darkpool_address = config.get_darkpool_address()?;
        let darkpool_clients = config
            .get_accounts()
            .await?
            .into_iter()
            .map(|account| DarkpoolContract::new(darkpool_address, account))
            .collect();
        let deploy_block = config.get_deploy_block();

        Ok(Self { darkpool_clients, deploy_block })
    }

    /// Get a darkpool contract client
    pub fn get_darkpool_client(&self) -> DarkpoolContract<MiddlewareStack> {
        #[cfg(feature = "rand")]
        {
            use rand::{seq::SliceRandom, thread_rng};
            self.darkpool_clients
                .choose(&mut thread_rng())
                .expect("no darkpool clients configured")
                .clone()
        }

        #[cfg(not(feature = "rand"))]
        {
            // We generally always want to select a Darkpool contract client randomly, but
            // the contracts repo also imports the `arbitrum_client` crate, and
            // it must compile to WASM. The `rand` crate does not compile to
            // WASM, but the contracts repo only uses the conversion utilites
            // defined in this crate, so we make this no-op fallback to prevent compilation
            // errors in the contracts repo.
            unimplemented!()
        }
    }

    /// Get a reference to some underlying RPC client
    pub fn client(&self) -> Arc<MiddlewareStack> {
        self.get_darkpool_client().client()
    }

    /// Get the chain ID
    pub async fn chain_id(&self) -> Result<ChainId, ArbitrumClientError> {
        self.client()
            .get_chainid()
            .await
            .map_err(err_str!(ArbitrumClientError::Rpc))
            .map(|id| id.as_u64())
    }

    /// Get the current Stylus block number
    pub async fn block_number(&self) -> Result<BlockNumber, ArbitrumClientError> {
        self.client()
            .get_block_number()
            .await
            .map(BlockNumber::Number)
            .map_err(|e| ArbitrumClientError::Rpc(e.to_string()))
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
