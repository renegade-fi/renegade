//! Defines the core implementation of the on-chain event listener

use std::{thread::JoinHandle, time::Duration};

use super::error::OnChainEventListenerError;
use alloy::{
    primitives::{Address, keccak256},
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use constants::in_bootstrap_mode;
use darkpool_client::DarkpoolClient;
use darkpool_client::client::erc20::abis::erc20::IERC20;
use futures_util::StreamExt;
use job_types::{
    event_manager::EventManagerQueue,
    matching_engine::{MatchingEngineWorkerJob, MatchingEngineWorkerQueue},
};
use rand::Rng;
use state::State;
use tracing::{Instrument, error, info, info_span, warn};
use types_core::{AccountId, get_all_tokens};
use types_runtime::CancelChannel;
use util::concurrency::runtime::sleep_forever_async;

/// The minimum delay in seconds for balance update (crash recovery)
const MIN_BALANCE_UPDATE_DELAY_S: u64 = 20;
/// The maximum delay in seconds for balance update (crash recovery)
const MAX_BALANCE_UPDATE_DELAY_S: u64 = 40;

// ----------
// | Worker |
// ----------

/// The configuration passed to the listener upon startup
#[derive(Clone)]
pub struct OnChainEventListenerConfig {
    /// The ethereum websocket address to use for streaming events
    ///
    /// If not configured, the listener will poll using the darkpool client
    pub websocket_addr: Option<String>,
    /// A darkpool client for listening to events
    pub darkpool_client: DarkpoolClient,
    /// A copy of the relayer global state
    pub global_state: State,
    /// The channel on which the coordinator may send a cancel signal
    pub cancel_channel: CancelChannel,
    /// A sender to the event manager's queue
    pub event_queue: EventManagerQueue,
    /// A sender to the matching engine worker's queue
    pub matching_engine_queue: MatchingEngineWorkerQueue,
}

impl OnChainEventListenerConfig {
    /// Whether or not a websocket listener is configured
    pub fn has_websocket_listener(&self) -> bool {
        self.websocket_addr.is_some()
    }

    /// Create a new websocket client if available
    pub async fn ws_client(&self) -> Result<DynProvider, OnChainEventListenerError> {
        if !self.has_websocket_listener() {
            panic!("no websocket listener configured");
        }

        // Connect to the websocket
        let addr = self.websocket_addr.clone().unwrap();
        let conn = WsConnect::new(addr);
        let provider = ProviderBuilder::new().connect_ws(conn).await?;
        Ok(DynProvider::new(provider))
    }
}

/// The worker responsible for listening for on-chain events, translating them
/// to jobs for other workers, and forwarding these jobs to the relevant workers
pub struct OnChainEventListener {
    /// The executor run in a separate thread
    pub(super) executor: Option<OnChainEventListenerExecutor>,
    /// The thread handle of the executor
    pub(super) executor_handle: Option<JoinHandle<OnChainEventListenerError>>,
}

// ------------
// | Executor |
// ------------

/// The executor that runs in a thread and polls events from on-chain state
#[derive(Clone)]
pub struct OnChainEventListenerExecutor {
    /// A copy of the config that the executor maintains
    pub(crate) config: OnChainEventListenerConfig,
}

impl OnChainEventListenerExecutor {
    /// Create a new executor
    pub fn new(config: OnChainEventListenerConfig) -> Self {
        Self { config }
    }

    /// Shorthand for fetching a reference to the darkpool client
    fn darkpool_client(&self) -> &DarkpoolClient {
        &self.config.darkpool_client
    }

    /// Shorthand for fetching a reference to the global state
    pub(crate) fn state(&self) -> &State {
        &self.config.global_state
    }

    // --------------
    // | Event Loop |
    // --------------

    /// The main execution loop for the executor
    pub async fn execute(self) -> Result<(), OnChainEventListenerError> {
        // If the node is running in bootstrap mode, sleep forever
        // TODO: Remove `|| true` to enable the event listener
        #[allow(clippy::overly_complex_bool_expr)]
        if in_bootstrap_mode() || true {
            sleep_forever_async().await;
        }

        info!("Starting on-chain event listener");

        // Begin the watch loop
        let res = self.watch_transfers().await.unwrap_err();
        error!("on-chain event listener stream ended unexpectedly: {res}");
        Err(res)
    }

    /// Transfer event watch loop
    async fn watch_transfers(&self) -> Result<(), OnChainEventListenerError> {
        if self.config.has_websocket_listener() {
            self.watch_transfers_ws().await
        } else {
            self.watch_transfers_http().await
        }
    }

    /// Watch for Transfer events via a websocket stream
    async fn watch_transfers_ws(&self) -> Result<(), OnChainEventListenerError> {
        info!("Listening for Transfer events via websocket");

        let client = self.config.ws_client().await?;
        let token_addresses = self.get_tracked_token_addresses();
        if token_addresses.is_empty() {
            return Err(OnChainEventListenerError::State("No tokens configured".into()));
        }

        let filter = Filter::new().address(token_addresses).event(IERC20::Transfer::SIGNATURE);

        let mut stream = client.subscribe_logs(&filter).await?.into_stream();

        while let Some(log) = stream.next().await {
            let self_clone = self.clone();
            tokio::task::spawn(
                async move {
                    if let Err(e) = self_clone.handle_transfer_event(log).await {
                        warn!("Error handling transfer event: {e}");
                    }
                }
                .instrument(info_span!("handle_transfer_event")),
            );
        }

        Err(OnChainEventListenerError::StreamEnded)
    }

    /// Watch for Transfer events via HTTP polling
    async fn watch_transfers_http(&self) -> Result<(), OnChainEventListenerError> {
        info!("Listening for Transfer events via HTTP polling");

        let token_addresses = self.get_tracked_token_addresses();
        if token_addresses.is_empty() {
            return Err(OnChainEventListenerError::State("No tokens configured".into()));
        }

        // TODO: Implement HTTP polling loop
        let _filter = Filter::new().address(token_addresses).event(IERC20::Transfer::SIGNATURE);

        Err(OnChainEventListenerError::State("HTTP polling not yet implemented".into()))
    }

    // -------------------
    // | Transfer Events |
    // -------------------

    /// Handle a Transfer event
    async fn handle_transfer_event(&self, log: Log) -> Result<(), OnChainEventListenerError> {
        let token = log.address();
        let tx_hash = match log.transaction_hash {
            Some(h) => h,
            None => {
                warn!("Transfer event missing transaction hash, skipping");
                return Ok(());
            },
        };

        let event = log.log_decode::<IERC20::Transfer>()?;
        let from = event.inner.from;
        let to = event.inner.to;

        // Look up affected accounts for both from and to addresses
        let from_account = self.state().get_account_for_owner(&from, &token).await?;
        let to_account = self.state().get_account_for_owner(&to, &token).await?;

        // Process each affected account
        if let Some(account_id) = from_account {
            self.handle_balance_update(account_id, from, token, tx_hash).await?;
        }
        if let Some(account_id) = to_account {
            self.handle_balance_update(account_id, to, token, tx_hash).await?;
        }

        Ok(())
    }

    /// Handle the balance update for an account affected by a transfer event
    async fn handle_balance_update(
        &self,
        account_id: AccountId,
        owner: Address,
        token: Address,
        tx_hash: alloy::primitives::TxHash,
    ) -> Result<(), OnChainEventListenerError> {
        // Fetch balance and update this node's matching engine cache
        let on_chain_balance = self.darkpool_client().get_erc20_balance(token, owner).await?;
        let Some(mut balance) = self.state().get_account_balance(&account_id, &token).await? else {
            warn!("No balance found for account={account_id:?}, token={token:?}, skipping");
            return Ok(());
        };

        *balance.amount_mut() = on_chain_balance
            .try_into()
            .map_err(|_| OnChainEventListenerError::State("Balance overflow".into()))?;

        self.state().update_matching_engine_for_balance(account_id, &balance).await?;

        // Select one node to propose raft update and enqueue jobs (with crash recovery)
        if !self.should_execute_balance_updates(&owner, &token, &tx_hash).await? {
            let timeout = rand::thread_rng()
                .gen_range(MIN_BALANCE_UPDATE_DELAY_S..=MAX_BALANCE_UPDATE_DELAY_S);
            tokio::time::sleep(Duration::from_secs(timeout)).await;
        }

        self.run_matching_engine_for_account_and_balance(account_id, token).await?;
        self.state().update_account_balance(account_id, balance).await?.await?;

        Ok(())
    }

    /// Run the matching engine on orders that use the given token as input
    async fn run_matching_engine_for_account_and_balance(
        &self,
        account_id: AccountId,
        token: Address,
    ) -> Result<(), OnChainEventListenerError> {
        // Get all order IDs that use this token as input
        let order_ids = self.state().get_orders_with_input_token(&account_id, &token).await?;

        for order_id in order_ids {
            // Note: When private orders (Ring 2/3) are enabled, filter to only enqueue
            // orders that use public balance - private orders aren't affected by ERC20
            // changes
            let job = MatchingEngineWorkerJob::run_internal_engine(account_id, order_id);
            self.config
                .matching_engine_queue
                .clone()
                .send(job)
                .map_err(|e| OnChainEventListenerError::SendMessage(e.to_string()))?;
        }

        Ok(())
    }

    /// Decides the node in a cluster that should execute balance updates for a
    /// given transfer event
    async fn should_execute_balance_updates(
        &self,
        owner: &Address,
        token: &Address,
        tx_hash: &alloy::primitives::TxHash,
    ) -> Result<bool, OnChainEventListenerError> {
        // Fetch cluster state
        let state = self.state();
        let my_id = state.get_peer_id()?;
        let cluster_id = state.get_cluster_id()?;
        let mut peers = state.get_cluster_peers(&cluster_id).await?;
        peers.sort();

        // Compute the selected node
        let n_peers = peers.len();
        let mut input = Vec::with_capacity(72);
        input.extend_from_slice(owner.as_slice());
        input.extend_from_slice(token.as_slice());
        input.extend_from_slice(tx_hash.as_slice());
        let hash = keccak256(&input);
        let peer = usize::from(hash[31]) % n_peers;
        let peer_id = peers[peer];

        Ok(peer_id == my_id)
    }

    /// Get the list of token addresses to watch for transfers
    fn get_tracked_token_addresses(&self) -> Vec<Address> {
        get_all_tokens().into_iter().map(|t: types_core::Token| t.get_alloy_address()).collect()
    }
}
