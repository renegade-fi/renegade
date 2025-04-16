//! Defines the core implementation of the on-chain event listener

use rand::{thread_rng, Rng};
use std::{sync::Arc, thread::JoinHandle, time::Duration};

use arbitrum_client::{
    abi::{DarkpoolContract, NullifierSpentFilter},
    client::ArbitrumClient,
};
use circuit_types::wallet::Nullifier;
use common::types::CancelChannel;
use constants::in_bootstrap_mode;
use ethers::{
    prelude::StreamExt,
    providers::{Provider, Ws},
    types::H256 as TxHash,
};
use job_types::handshake_manager::{HandshakeManagerJob, HandshakeManagerQueue};
use renegade_crypto::fields::u256_to_scalar;
use state::State;
use tracing::{error, info};
use util::concurrency::runtime::sleep_forever_async;

use super::error::OnChainEventListenerError;

/// The minimum delay in seconds for wallet refresh
const MIN_NULLIFIER_REFRESH_DELAY_S: u64 = 20; // 20 seconds
/// The maximum delay in seconds for wallet refresh
const MAX_NULLIFIER_REFRESH_DELAY_S: u64 = 40; // 40 seconds
/// The delay to wait for a task to complete before attempting to refresh a
/// nullifier's wallet
const TASK_COMPLETION_DELAY_S: u64 = 10; // 10 seconds

// ----------
// | Worker |
// ----------

/// The configuration passed to the listener upon startup
#[derive(Clone)]
pub struct OnChainEventListenerConfig {
    /// The ethereum websocket address to use for streaming events
    ///
    /// If not configured, the listener will poll using the arbitrum client
    pub websocket_addr: Option<String>,
    /// An arbitrum client for listening to events
    pub arbitrum_client: ArbitrumClient,
    /// A copy of the relayer global state
    pub global_state: State,
    /// A sender to the handshake manager's job queue, used to enqueue
    /// MPC shootdown jobs
    pub handshake_manager_job_queue: HandshakeManagerQueue,
    /// The channel on which the coordinator may send a cancel signal
    pub cancel_channel: CancelChannel,
}

impl OnChainEventListenerConfig {
    /// Whether or not a websocket listener is configured
    pub fn has_websocket_listener(&self) -> bool {
        self.websocket_addr.is_some()
    }

    /// Create a new websocket client if available
    pub async fn ws_client(
        &self,
    ) -> Result<DarkpoolContract<Provider<Ws>>, OnChainEventListenerError> {
        if !self.has_websocket_listener() {
            panic!("no websocket listener configured");
        }

        // Connect to the websocket
        let addr = self.websocket_addr.clone().unwrap();
        let client = Ws::connect(&addr).await?;
        let provider = Provider::<Ws>::new(client);

        // Create the contract instance
        let contract_addr = self.arbitrum_client.get_darkpool_client().address();
        let contract = DarkpoolContract::new(contract_addr, Arc::new(provider));
        Ok(contract)
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
    config: OnChainEventListenerConfig,
}

impl OnChainEventListenerExecutor {
    /// Create a new executor
    pub fn new(config: OnChainEventListenerConfig) -> Self {
        Self { config }
    }

    /// Shorthand for fetching a reference to the arbitrum client
    fn arbitrum_client(&self) -> &ArbitrumClient {
        &self.config.arbitrum_client
    }

    /// Shorthand for fetching a reference to the global state
    fn state(&self) -> &State {
        &self.config.global_state
    }

    // --------------
    // | Event Loop |
    // --------------

    /// The main execution loop for the executor
    pub async fn execute(self) -> Result<(), OnChainEventListenerError> {
        // If the node is running in bootstrap mode, sleep forever
        if in_bootstrap_mode() {
            sleep_forever_async().await;
        }

        // Get the current block number to start from
        let starting_block_number = self
            .arbitrum_client()
            .block_number()
            .await
            .map_err(|err| OnChainEventListenerError::Arbitrum(err.to_string()))?;
        info!("Starting on-chain event listener from current block {starting_block_number}");

        // Begin the watch loop
        let res = self.watch_nullifiers().await.unwrap_err();
        error!("on-chain event listener stream ended unexpectedly: {res}");
        Err(res)
    }

    /// Nullifier watch loop
    async fn watch_nullifiers(&self) -> Result<(), OnChainEventListenerError> {
        if self.config.has_websocket_listener() {
            self.watch_nullifiers_ws().await
        } else {
            self.watch_nullifiers_http().await
        }
    }

    /// Watch for nullifiers via a websocket stream
    async fn watch_nullifiers_ws(&self) -> Result<(), OnChainEventListenerError> {
        info!("listening for nullifiers via websocket");
        // Create the contract instance and the event stream
        let contract = self.config.ws_client().await?;
        let filter = contract.event::<NullifierSpentFilter>();
        let mut stream = filter.stream_with_meta().await?;

        // Listen for events in a loop
        while let Some(res) = stream.next().await {
            let (event, meta) = res.map_err(OnChainEventListenerError::arbitrum)?;
            self.handle_nullifier_spent(meta.transaction_hash, &event).await?;
        }

        todo!()
    }

    /// Watch for nullifiers via HTTP polling
    async fn watch_nullifiers_http(&self) -> Result<(), OnChainEventListenerError> {
        info!("listening for nullifiers via HTTP polling");
        // Build a filtered stream on events that the chain-events worker listens for
        let filter = self.arbitrum_client().get_darkpool_client().event::<NullifierSpentFilter>();
        let mut event_stream = filter.stream_with_meta().await?;

        // Listen for events in a loop
        while let Some(res) = event_stream.next().await {
            let (event, meta) = res.map_err(OnChainEventListenerError::arbitrum)?;
            self.handle_nullifier_spent(meta.transaction_hash, &event).await?;
        }

        unreachable!()
    }

    // ----------------------
    // | Nullifier Handlers |
    // ----------------------

    /// Handle a nullifier spent event
    async fn handle_nullifier_spent(
        &self,
        tx: TxHash,
        event: &NullifierSpentFilter,
    ) -> Result<(), OnChainEventListenerError> {
        // Send an MPC shootdown request to the handshake manager
        let nullifier = u256_to_scalar(&event.nullifier);
        self.config
            .handshake_manager_job_queue
            .send(HandshakeManagerJob::MpcShootdown { nullifier })
            .map_err(|err| OnChainEventListenerError::SendMessage(err.to_string()))?;
        self.state().nullify_orders(nullifier).await?;

        // Update internal state
        self.handle_nullifier_wallet_updates(nullifier, tx).await
    }

    /// Handle the internal wallet updates resulting from a nullifier spend
    async fn handle_nullifier_wallet_updates(
        &self,
        nullifier: Nullifier,
        tx: TxHash,
    ) -> Result<(), OnChainEventListenerError> {
        // If the current node is not the update handler, sleep for a random timeout
        // then check that the nullifier state updates have been processed.
        // We do this as a crash recovery mechanism to ensure that the updates are
        // processed even if the selected node is crashed
        if !self.should_execute_wallet_updates(nullifier).await? {
            let mut rng = thread_rng();
            let timeout =
                rng.gen_range(MIN_NULLIFIER_REFRESH_DELAY_S..=MAX_NULLIFIER_REFRESH_DELAY_S);
            tokio::time::sleep(Duration::from_secs(timeout)).await;
        }

        // Check whether any wallet is indexed by the nullifier
        let maybe_wallet = self.state().get_wallet_for_nullifier(&nullifier).await?;
        if maybe_wallet.is_none() {
            return Ok(());
        }

        // Record metrics for any external matches in the transaction
        let external_match = self.check_external_match_settlement(tx).await?;

        // External matches will not automatically update the wallet, so we should
        // enqueue a wallet refresh immediately. Otherwise, we wait some time
        // for an ongoing task to finish after it spends a nullifier -- this may
        // clear the nullifier indexed into the state naturally
        if !external_match {
            let duration = Duration::from_secs(TASK_COMPLETION_DELAY_S);
            tokio::time::sleep(duration).await;
        }

        // Clear the wallet's queue and refresh it if the nullifier is still present
        self.clear_queue_for_nullifier(nullifier).await
    }

    /// Decides the node in a cluster that should execute wallet updates for a
    /// given nullifier
    ///
    /// This is done to prevent multiple nodes from enqueuing wallet refreshes
    /// or otherwise updating the same wallet state
    ///
    /// To select a node, we sort the nodes then take (nullifier_lsb % n_nodes)
    /// as the selected node. The nullifier is the result of a cryptographic
    /// hash function, so this should give a roughly uniform distribution
    ///
    /// Returns true if the current node should execute wallet updates for the
    /// given nullifier
    async fn should_execute_wallet_updates(
        &self,
        nullifier: Nullifier,
    ) -> Result<bool, OnChainEventListenerError> {
        // Fetch cluster state
        let state = self.state();
        let my_id = state.get_peer_id().await?;
        let cluster_id = state.get_cluster_id().await?;
        let mut peers = state.get_cluster_peers(&cluster_id).await?;
        peers.sort();

        // Compute the selected node
        let n_peers = peers.len();
        let nullifier_bytes = nullifier.to_bytes_be();
        let nullifier_lsb = *nullifier_bytes.last().unwrap();
        let peer = usize::from(nullifier_lsb) % n_peers;
        let peer_id = peers[peer];

        Ok(peer_id == my_id)
    }

    /// Clear a wallet's task queue and enqueue a wallet refresh task
    async fn clear_queue_for_nullifier(
        &self,
        nullifier: Nullifier,
    ) -> Result<(), OnChainEventListenerError> {
        // Get the wallet ID that this nullifier belongs to
        let maybe_wallet = self.state().get_wallet_for_nullifier(&nullifier).await?;
        if maybe_wallet.is_none() {
            return Ok(());
        }
        let id = maybe_wallet.unwrap();
        info!("refreshing wallet {id} after nullifier spend");

        // Clear the queue
        let waiter = self.state().clear_task_queue(&id).await?;
        waiter.await.map_err(OnChainEventListenerError::arbitrum)?;

        // Refresh the wallet
        self.state().append_wallet_refresh_task(id).await?;
        Ok(())
    }

    /// Check for an external match settlement on the given transaction hash. If
    /// one is present, record metrics for it
    ///
    /// Returns whether the tx settled an external match
    async fn check_external_match_settlement(
        &self,
        tx: TxHash,
    ) -> Result<bool, OnChainEventListenerError> {
        let matches = self.arbitrum_client().find_external_matches_in_tx(tx).await?;
        let external_match = !matches.is_empty();

        // Record metrics for each match
        // TODO: Record a fill on the internal order. We don't do this for now to keep
        // things simple, but when internal volumes increase we should start
        // recording order fills. One way to do this is to lookup the wallet by
        // nullifier and record a fill on the order with matching mint
        for match_result in matches {
            let match_result =
                match_result.try_into().map_err(OnChainEventListenerError::arbitrum)?;
            renegade_metrics::record_match_volume(&match_result, true /* is_external_match */);
        }

        Ok(external_match)
    }
}
