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
    BASE_SEPOLIA_DEPLOY_BLOCK, DEVNET_DEPLOY_BLOCK, ETHEREUM_MAINNET_DEPLOY_BLOCK,
    ETHEREUM_SEPOLIA_DEPLOY_BLOCK, MERKLE_HEIGHT,
};
use renegade_solidity_abi::v2::IDarkpoolV2::{self, IDarkpoolV2Instance};
use types_core::Chain;
use util::err_str;
use util::log_task;
use util::logging::Outcome;

use crate::errors::{DarkpoolClientConfigError, DarkpoolClientError};
use crate::logging::Task;

mod contract_interaction;
pub mod erc20;
mod event_indexing;
mod nonce;

use nonce::ResyncNonceManager;

// -------------
// | Constants |
// -------------

/// The timeout for awaiting the receipt of a pending transaction
const TX_RECEIPT_TIMEOUT: Duration = Duration::from_secs(15);

/// The timeout for the submit path (gas-price fetch + tx broadcast).
///
/// Without this, a hung RPC on the send path leaves the task parked in
/// `SubmittingTx` forever: `send()` never returns, so it never reaches the
/// receipt timeout above, and the nonce-manager lock is held, blocking every
/// other settle on this signer. That permanently wedges the account task queue
/// (`deferred-queue full`, 0 internal fills). Bounding the send path lets a
/// stuck RPC fail fast so the queue head pops and the next settle proceeds.
const TX_SUBMIT_TIMEOUT: Duration = Duration::from_secs(20);

/// Bound on the diagnostic pending-nonce fetch performed just before submit.
/// Kept short and separate so the diagnostic can never reintroduce a send-path
/// hang.
const NONCE_DIAG_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for read-only RPC calls (e.g. `eth_blockNumber`, `eth_chainId`).
///
/// The HTTP provider is built without a transport timeout, and read calls
/// (unlike the submit path, bounded by `TX_SUBMIT_TIMEOUT`) were unbounded. A
/// stalled RPC on `block_number()` in `SettleExternalMatchTask::generate_calldata`
/// hung the settle task forever. Bounding read calls makes a stalled RPC surface
/// as a (retryable=false) RPC error instead of an infinite await.
const RPC_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The multiple of the gas price estimate we use for submitting a transaction
const GAS_PRICE_MULTIPLIER: u128 = 2;

/// The minimum max-priority-fee we attach to a transaction, in wei (0.001
/// gwei).
///
/// alloy's default EIP-1559 estimator floors the priority fee at 1 WEI when
/// the recent blocks' reward percentiles are zero (quiet testnet blocks); a
/// 1-wei tip can leave a tx accepted but never included. Both sepolia
/// testnets include comfortably at a 0.001-gwei tip, and on mainnets this
/// floor is far below real tips, so it only ever raises pathological
/// estimates.
const MIN_PRIORITY_FEE_WEI: u128 = 1_000_000;

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
    /// This is the main entrypoint to interaction with the darkpool.
    ///
    /// The address of the darkpool proxy contract.
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
            Chain::EthereumSepolia => ETHEREUM_SEPOLIA_DEPLOY_BLOCK,
            Chain::EthereumMainnet => ETHEREUM_MAINNET_DEPLOY_BLOCK,
            Chain::Devnet => DEVNET_DEPLOY_BLOCK,
        }
    }

    /// Constructs RPC clients capable of signing transactions from the
    /// configuration
    ///
    /// Takes the nonce manager from the caller so the `DarkpoolClient` keeps a
    /// handle for poisoning the cache after a failed submission.
    pub fn get_provider(
        &self,
        nonce_manager: ResyncNonceManager,
    ) -> Result<RenegadeProvider, DarkpoolClientConfigError> {
        let url = Url::parse(&self.rpc_url)
            .map_err(err_str!(DarkpoolClientConfigError::RpcClientInitialization))?;
        let key = self.private_key.clone();
        let provider = ProviderBuilder::new()
            .disable_recommended_fillers()
            // A cached nonce manager (locked, sequential nonces) rather than
            // SimpleNonceManager (fetches `pending` per send). Under concurrent
            // settle submission from this single shared signer, SimpleNonceManager
            // handed two txs the same nonce -> one gapped/unmined -> no receipt ->
            // the settle task hangs in `SubmittingTx` and retries forever, wedging
            // the account's task queue (`deferred-queue full`, 0 internal fills).
            // ResyncNonceManager adds cache invalidation after a failed submit so
            // a lost head tx cannot nonce-gap the signer until process restart.
            .with_nonce_management(nonce_manager)
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
    /// The address of the gas wallet used for signing transactions
    client_addr: Address,
    /// Handle to the provider's nonce cache, used to force a resync from the
    /// chain after a failed submission (see `ResyncNonceManager`)
    nonce_manager: ResyncNonceManager,
}

impl DarkpoolClient {
    /// Constructs a new darkpool client from the given configuration
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(config: DarkpoolClientConfig) -> Result<Self, DarkpoolClientError> {
        let client_addr = config.private_key.address();
        let nonce_manager = ResyncNonceManager::default();
        let provider = config.get_provider(nonce_manager.clone())?;
        let darkpool = IDarkpoolV2Instance::new(config.darkpool_addr, provider);
        let deploy_block = config.get_deploy_block();
        Ok(Self {
            darkpool,
            deploy_block,
            permit2_addr: config.permit2_addr,
            client_addr,
            nonce_manager,
        })
    }

    /// Mark the signer's cached nonce stale after a failed submission, so the
    /// next submit refetches the chain's pending count. One lost head tx
    /// otherwise nonce-gaps every subsequent tx from this signer until process
    /// restart.
    fn resync_nonce_on_failure(&self) {
        self.nonce_manager.poison(self.client_addr);
    }

    /// Get a reference to the darkpool contract instance
    pub fn darkpool(&self) -> &IDarkpoolV2Instance<RenegadeProvider> {
        &self.darkpool
    }

    /// Get an alloy address for the darkpool contract
    pub fn darkpool_addr(&self) -> Address {
        *self.darkpool.address()
    }

    /// Get the permit2 contract address
    pub fn permit2_addr(&self) -> Address {
        self.permit2_addr
    }

    /// Get the client wallet address
    pub fn client_addr(&self) -> Address {
        self.client_addr
    }

    /// Get a reference to some underlying RPC client
    pub fn provider(&self) -> &RenegadeProvider {
        self.darkpool.provider()
    }

    /// Get the chain ID
    pub async fn chain_id(&self) -> Result<ChainId, DarkpoolClientError> {
        tokio::time::timeout(RPC_READ_TIMEOUT, self.provider().get_chain_id())
            .await
            .map_err(|_| {
                DarkpoolClientError::Rpc(format!(
                    "chain_id RPC timed out after {}s",
                    RPC_READ_TIMEOUT.as_secs()
                ))
            })?
            .map_err(err_str!(DarkpoolClientError::Rpc))
    }

    /// Get the current block number
    pub async fn block_number(&self) -> Result<BlockNumber, DarkpoolClientError> {
        tokio::time::timeout(RPC_READ_TIMEOUT, self.provider().get_block_number())
            .await
            .map_err(|_| {
                DarkpoolClientError::Rpc(format!(
                    "block_number RPC timed out after {}s",
                    RPC_READ_TIMEOUT.as_secs()
                ))
            })?
            .map_err(err_str!(DarkpoolClientError::Rpc))
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
        // Bound the fee estimation so a hung RPC can't park the task here.
        let (max_fee_per_gas, max_priority_fee_per_gas) =
            tokio::time::timeout(TX_SUBMIT_TIMEOUT, self.get_adjusted_eip1559_fees())
                .await
                .map_err(|_| {
                    DarkpoolClientError::contract_interaction(format!(
                        "gas fee estimation timed out after {}s (client_addr = {:#x})",
                        TX_SUBMIT_TIMEOUT.as_secs(),
                        self.client_addr
                    ))
                })??;

        let diag_host = std::env::var("HOSTNAME").unwrap_or_else(|_| "?".to_string());

        // Diagnostic: the chain's view of this signer's next (pending) nonce,
        // sampled just before submit and bounded so it can't hang the send path.
        // Comparing this across submits surfaces nonce collisions (same nonce on
        // multiple txs) or a cache lagging the chain -- the likely cause when a
        // settle tx is accepted by the RPC but never mines. `-1` = fetch failed.
        let diag_nonce: i64 = match tokio::time::timeout(
            NONCE_DIAG_TIMEOUT,
            self.darkpool.provider().get_transaction_count(self.client_addr).pending(),
        )
        .await
        {
            Ok(Ok(n)) => n as i64,
            _ => -1,
        };

        // Bound the broadcast. A stuck `send()` otherwise holds the nonce-manager
        // lock and freezes the queue head in `SubmittingTx` indefinitely.
        let pending_tx = match tokio::time::timeout(
            TX_SUBMIT_TIMEOUT,
            tx.max_fee_per_gas(max_fee_per_gas)
                .max_priority_fee_per_gas(max_priority_fee_per_gas)
                .send(),
        )
        .await
        {
            Err(_) => {
                // The nonce filler may or may not have consumed a nonce before
                // the timeout dropped the send future; resync either way
                self.resync_nonce_on_failure();
                log_task!(
                    Task::SubmitTx,
                    Outcome::Failed,
                    host = %diag_host,
                    signer = %self.client_addr,
                    nonce = diag_nonce,
                    "tx submit timed out after {}s (not broadcast); nonce cache resynced",
                    TX_SUBMIT_TIMEOUT.as_secs()
                );
                return Err(DarkpoolClientError::contract_interaction(format!(
                    "tx submit timed out after {}s (client_addr = {:#x})",
                    TX_SUBMIT_TIMEOUT.as_secs(),
                    self.client_addr
                )));
            },
            Ok(res) => res,
        };
        let pending_tx = match pending_tx {
            Ok(tx) => tx,
            Err(ContractError::TransportError(TransportError::ErrorResp(err_payload))) => {
                // Broadcast rejected after the filler consumed a nonce: the
                // cache is now one ahead of the chain
                self.resync_nonce_on_failure();
                // Decode the error payload if possible using the ABI
                let decoded =
                    err_payload.as_decoded_interface_error::<IDarkpoolV2::IDarkpoolV2Errors>();
                let err_str = decoded.map(|e| format!("{e:?}")).unwrap_or_else(|| {
                    let msg = err_payload.message;
                    let data = err_payload.data.unwrap_or_default();
                    format!("unknown error: {msg} (data = {data})")
                });
                return Err(DarkpoolClientError::contract_interaction(format!(
                    "{err_str} (client_addr = {:#x})",
                    self.client_addr
                )));
            },
            Err(e) => {
                // Same as above: a nonce may have been consumed for a tx that
                // never made it to the pool
                self.resync_nonce_on_failure();
                return Err(DarkpoolClientError::contract_interaction(format!(
                    "{e} (client_addr = {:#x})",
                    self.client_addr
                )));
            },
        };

        let tx_hash = format!("{:#x}", pending_tx.tx_hash());
        log_task!(
            Task::SubmitTx,
            Outcome::Started,
            subject = %tx_hash,
            host = %diag_host,
            signer = %self.client_addr,
            nonce = diag_nonce,
            "submitting tx"
        );
        let receipt = match pending_tx.with_timeout(Some(TX_RECEIPT_TIMEOUT)).get_receipt().await {
            Ok(r) => r,
            Err(e) => {
                // Tx broadcast but not mined within the timeout. Distinct from
                // the submit-timeout above (which never broadcasts). The tx may
                // have been dropped by the RPC after ack (observed 2026-06-09:
                // hashes acked then absent from the public pool) -- the cached
                // nonce is then permanently ahead of the chain, gapping every
                // later tx from this signer; resync so the next submit refetches
                // pending and refills the gap.
                self.resync_nonce_on_failure();
                log_task!(
                    Task::SubmitTx,
                    Outcome::Failed,
                    subject = %tx_hash,
                    host = %diag_host,
                    signer = %self.client_addr,
                    nonce = diag_nonce,
                    "tx receipt timeout (not mined); nonce cache resynced: {e}"
                );
                return Err(DarkpoolClientError::contract_interaction(e));
            },
        };

        // Check for failure
        if !receipt.status() {
            let error_msg = format!(
                "tx ({:#x}) failed with status 0 (client_addr = {:#x})",
                receipt.transaction_hash, self.client_addr,
            );
            return Err(DarkpoolClientError::contract_interaction(error_msg));
        }

        Ok(receipt)
    }

    /// Get EIP-1559 fees for submitting a transaction.
    ///
    /// base-sepolia (and other OP-stack chains) expect dynamic-fee (type-2)
    /// transactions; legacy `gas_price` txs were being accepted by the RPC but
    /// never mined. We take the provider's basefee+priority estimate and inflate
    /// the max-fee CAP by `GAS_PRICE_MULTIPLIER` to tolerate basefee growth
    /// between estimation and inclusion (the cap is a ceiling, not the amount
    /// paid). Returns `(max_fee_per_gas, max_priority_fee_per_gas)`.
    async fn get_adjusted_eip1559_fees(&self) -> Result<(u128, u128), DarkpoolClientError> {
        let est =
            self.provider().estimate_eip1559_fees().await.map_err(DarkpoolClientError::rpc)?;
        // Floor the tip: alloy's estimator returns 1 WEI when recent blocks
        // show zero reward percentiles (quiet testnet), which can leave a tx
        // accepted but never included
        let max_priority_fee_per_gas = est.max_priority_fee_per_gas.max(MIN_PRIORITY_FEE_WEI);
        // The cap must cover the (possibly floored) tip on top of basefee
        // growth; overshooting the cap costs nothing (it is a ceiling)
        let max_fee_per_gas =
            est.max_fee_per_gas * GAS_PRICE_MULTIPLIER + max_priority_fee_per_gas;
        Ok((max_fee_per_gas, max_priority_fee_per_gas))
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
