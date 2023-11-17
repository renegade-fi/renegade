//! The definition of the Arbitrum client, which holds the configuration
//! details, along with a lower-level handle for the darkpool smart contract

use std::{str::FromStr, sync::Arc};

use ethers::{
    core::k256::ecdsa::SigningKey,
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer, Wallet},
    types::Address,
};

use crate::{
    abi::DarkpoolContract,
    errors::{ArbitrumClientConfigError, ArbitrumClientError},
};

mod contract_interaction;

/// A configuration struct for the Arbitrum client, consists of relevant
/// contract addresses, and endpoint for setting up an RPC client, and a private
/// key for signing transactions.
pub struct ArbitrumClientConfig {
    /// The address of the darkpool proxy contract.
    ///
    /// This is the main entrypoint to interaction with the darkpool.
    pub darkpool_addr: String,
    /// The address of the darkpool implementation contract.
    ///
    /// This is used to filter for events emitted by the darkpool.
    pub event_source: String,
    /// The HTTP-addressable URL of the Arbitrum RPC endpoint
    pub rpc_url: String,
    /// The private key of the account to use for signing transactions
    pub arb_priv_key: String,
}

/// A type alias for the RPC client, which is an ethers middleware stack that
/// includes a signer derived from a raw private key, and a provider that
/// connects to the RPC endpoint over HTTP.
type SignerHttpProvider = SignerMiddleware<Provider<Http>, Wallet<SigningKey>>;

impl ArbitrumClientConfig {
    /// Constructs an RPC client capable of signing transactions from the
    /// configuration
    async fn get_rpc_client(&self) -> Result<Arc<SignerHttpProvider>, ArbitrumClientConfigError> {
        let provider = Provider::<Http>::try_from(&self.rpc_url)
            .map_err(|e| ArbitrumClientConfigError::RpcClientInitialization(e.to_string()))?;

        let wallet = LocalWallet::from_str(&self.arb_priv_key)
            .map_err(|e| ArbitrumClientConfigError::RpcClientInitialization(e.to_string()))?;

        let chain_id = provider
            .get_chainid()
            .await
            .map_err(|e| ArbitrumClientConfigError::RpcClientInitialization(e.to_string()))?
            .as_u64();

        let rpc_client = Arc::new(SignerMiddleware::new(
            provider,
            wallet.clone().with_chain_id(chain_id),
        ));

        Ok(rpc_client)
    }

    /// Parses the darkpool proxy address from the configuration,
    /// returning an [`ethers::types::Address`]
    fn get_darkpool_address(&self) -> Result<Address, ArbitrumClientConfigError> {
        Address::from_str(&self.darkpool_addr)
            .map_err(|e| ArbitrumClientConfigError::AddressParsing(e.to_string()))
    }

    /// Parses the darkpool implementation address from the configuration,
    /// from which the events are emitted, returning an
    /// [`ethers::types::Address`]
    pub fn get_event_source(&self) -> Result<Address, ArbitrumClientConfigError> {
        Address::from_str(&self.event_source)
            .map_err(|e| ArbitrumClientConfigError::AddressParsing(e.to_string()))
    }

    /// Constructs a [`DarkpoolContract`] instance from the configuration,
    /// which provides strongly-typed, RPC-client-aware bindings for the
    /// darkpool contract methods.
    pub async fn get_contract_instance(
        &self,
    ) -> Result<DarkpoolContract<SignerHttpProvider>, ArbitrumClientConfigError> {
        let rpc_client = self.get_rpc_client().await?;
        let contract_address = self.get_darkpool_address()?;
        let contract = DarkpoolContract::new(contract_address, rpc_client);
        Ok(contract)
    }
}

#[derive(Clone)]
/// The Arbitrum client, which provides a higher-level interface to the darkpool
/// contract for Renegade-specific access patterns.
pub struct ArbitrumClient {
    /// The darkpool contract instance, used to make calls to the darkpool
    darkpool_contract: DarkpoolContract<SignerHttpProvider>,
    /// The address of the darkpool implementation contract, used to filter
    /// for events emitted from the darkpool
    darkpool_event_source: Address,
}

impl ArbitrumClient {
    /// Constructs a new Arbitrum client from the given configuration
    pub async fn new(config: ArbitrumClientConfig) -> Result<Self, ArbitrumClientError> {
        let darkpool_contract = config.get_contract_instance().await?;
        let darkpool_implementation_address = config.get_event_source()?;

        Ok(Self {
            darkpool_contract,
            darkpool_event_source: darkpool_implementation_address,
        })
    }
}
