//! The definition of the darkpool client, which holds the configuration
//! details, along with a lower-level handle for the darkpool smart contract

use std::time::Duration;

use alloy::{
    contract::Error as ContractError,
    providers::{
        DynProvider, Provider, ProviderBuilder,
        fillers::{BlobGasFiller, ChainIdFiller, GasFiller},
    },
    signers::local::PrivateKeySigner,
    transports::{TransportError, http::reqwest::Url},
};
use alloy_contract::{CallBuilder, CallDecoder, Event};
use alloy_primitives::{Address, BlockNumber, ChainId, U256};
use alloy_sol_types::SolEvent;
use constants::{
    ARBITRUM_ONE_DEPLOY_BLOCK, ARBITRUM_SEPOLIA_DEPLOY_BLOCK, BASE_MAINNET_DEPLOY_BLOCK,
    BASE_SEPOLIA_DEPLOY_BLOCK, DEVNET_DEPLOY_BLOCK, MERKLE_HEIGHT,
};
use renegade_solidity_abi::v2::IDarkpoolV2::{self, IDarkpoolV2Instance};
use tracing::info;
use types_core::Chain;
use util::err_str;

use crate::errors::{DarkpoolClientConfigError, DarkpoolClientError};

mod contract_interaction;
pub mod erc20;
mod event_indexing;

// -------------
// | Constants |
// -------------

/// The timeout for awaiting the receipt of a pending transaction
const TX_RECEIPT_TIMEOUT: Duration = Duration::from_secs(15);

/// The multiple of the gas price estimate we use for submitting a transaction
const GAS_PRICE_MULTIPLIER: u128 = 2;

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
    pub darkpool_addr: Address,
    /// The address of the permit2 contract.
    pub permit2_addr: Address,
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
            .filler(BlobGasFiller::default())
            .wallet(key)
            .connect_http(url);
        provider.client().set_poll_interval(self.block_polling_interval);

        Ok(DynProvider::new(provider))
    }
}

/// The darkpool client, which provides a higher-level interface to the darkpool
/// contract for Renegade-specific access patterns.
#[derive(Clone)]
pub struct DarkpoolClient {
    /// The darkpool contract instance
    darkpool: IDarkpoolV2Instance<RenegadeProvider>,
    /// The block number at which the darkpool was deployed
    deploy_block: BlockNumber,
    /// The address of the permit2 contract
    permit2_addr: Address,
}

impl DarkpoolClient {
    /// Constructs a new darkpool client from the given configuration
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(config: DarkpoolClientConfig) -> Result<Self, DarkpoolClientError> {
        let provider = config.get_provider()?;
        let darkpool = IDarkpoolV2Instance::new(config.darkpool_addr, provider);
        let deploy_block = config.get_deploy_block();
        Ok(Self { darkpool, deploy_block, permit2_addr: config.permit2_addr })
    }

    /// Get a reference to the darkpool contract instance
    pub fn darkpool(&self) -> &IDarkpoolV2Instance<RenegadeProvider> {
        &self.darkpool
    }

    /// Get an alloy address for the darkpool contract
    pub fn darkpool_addr(&self) -> Address {
        *self.darkpool.address()
    }

    /// Get a reference to some underlying RPC client
    pub fn provider(&self) -> &RenegadeProvider {
        self.darkpool.provider()
    }

    /// Get the chain ID
    pub async fn chain_id(&self) -> Result<ChainId, DarkpoolClientError> {
        self.provider().get_chain_id().await.map_err(err_str!(DarkpoolClientError::Rpc))
    }

    /// Get the current block number
    pub async fn block_number(&self) -> Result<BlockNumber, DarkpoolClientError> {
        self.provider().get_block_number().await.map_err(err_str!(DarkpoolClientError::Rpc))
    }

    /// Create an event filter
    pub fn event_filter<E: SolEvent>(&self) -> Event<&RenegadeProvider, E> {
        let provider = self.provider();
        let address = self.darkpool_addr();
        Event::new_sol(provider, &address)
    }

    /// Get the Merkle depth to use for contract calls
    pub(crate) fn merkle_depth(&self) -> U256 {
        U256::from(MERKLE_HEIGHT as u64)
    }

    // ----------------
    // | Transactions |
    // ----------------

    /// Send a transaction and return the receipt
    pub(crate) async fn send_tx<'a, C>(
        &self,
        tx: DarkpoolCallBuilder<'a, C>,
    ) -> Result<alloy::rpc::types::TransactionReceipt, DarkpoolClientError>
    where
        C: CallDecoder + Send + Sync,
    {
        let gas_price = self.get_adjusted_gas_price().await?;
        let pending_tx = tx.gas_price(gas_price).send().await;
        let pending_tx = match pending_tx {
            Ok(tx) => tx,
            Err(ContractError::TransportError(TransportError::ErrorResp(err_payload))) => {
                // Decode the error payload if possible using the ABI
                let decoded =
                    err_payload.as_decoded_interface_error::<IDarkpoolV2::IDarkpoolV2Errors>();
                let err_str = decoded.map(|e| format!("{e:?}")).unwrap_or_else(|| {
                    let msg = err_payload.message;
                    let data = err_payload.data.unwrap_or_default();
                    format!("unknown error: {msg} (data = {data})")
                });
                return Err(DarkpoolClientError::contract_interaction(err_str));
            },
            Err(e) => return Err(DarkpoolClientError::contract_interaction(e)),
        };

        info!("Pending tx hash: {:#x}", pending_tx.tx_hash());
        let receipt = pending_tx
            .with_timeout(Some(TX_RECEIPT_TIMEOUT))
            .get_receipt()
            .await
            .map_err(DarkpoolClientError::contract_interaction)?;

        // Check for failure
        if !receipt.status() {
            let error_msg = format!("tx ({:#x}) failed with status 0", receipt.transaction_hash);
            return Err(DarkpoolClientError::contract_interaction(error_msg));
        }

        Ok(receipt)
    }

    /// Get the adjusted gas price for submitting a transaction
    ///
    /// We double the latest basefee to prevent reverts
    async fn get_adjusted_gas_price(&self) -> Result<u128, DarkpoolClientError> {
        let gas_price = self.provider().get_gas_price().await.map_err(DarkpoolClientError::rpc)?;
        let adjusted_gas_price = gas_price * GAS_PRICE_MULTIPLIER;
        Ok(adjusted_gas_price)
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
