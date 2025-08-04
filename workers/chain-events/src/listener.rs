//! Defines the core implementation of the on-chain event listener

use std::{thread::JoinHandle, time::Duration};

use super::error::OnChainEventListenerError;
use crate::post_settlement::PostSettlementCtx;
use alloy::{
    primitives::TxHash,
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use circuit_types::r#match::ExternalMatchResult;
use circuit_types::wallet::Nullifier;
use common::types::{
    CancelChannel,
    wallet::{OrderIdentifier, WalletIdentifier},
};
use constants::in_bootstrap_mode;
use darkpool_client::{
    DarkpoolClient, DarkpoolImplementation, conversion::u256_to_scalar, traits::DarkpoolImpl,
};
use futures_util::StreamExt;
use job_types::event_manager::EventManagerQueue;
use job_types::handshake_manager::{HandshakeManagerJob, HandshakeManagerQueue};
use rand::{Rng, thread_rng};
use state::State;
use tracing::{error, info};
use util::concurrency::runtime::sleep_forever_async;

/// The minimum delay in seconds for wallet refresh
const MIN_NULLIFIER_REFRESH_DELAY_S: u64 = 20; // 20 seconds
/// The maximum delay in seconds for wallet refresh
const MAX_NULLIFIER_REFRESH_DELAY_S: u64 = 40; // 40 seconds
/// The delay to wait for a task to complete before attempting to refresh a
/// nullifier's wallet
const TASK_COMPLETION_DELAY_S: u64 = 10; // 10 seconds

/// The nullifier spent event configured by the darkpool implementation
type NullifierSpentEvent = <DarkpoolImplementation as DarkpoolImpl>::NullifierSpent;

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
    /// A sender to the handshake manager's job queue, used to enqueue
    /// MPC shootdown jobs
    pub handshake_manager_job_queue: HandshakeManagerQueue,
    /// The channel on which the coordinator may send a cancel signal
    pub cancel_channel: CancelChannel,
    /// A sender to the event manager's queue
    pub event_queue: EventManagerQueue,
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
        if in_bootstrap_mode() {
            sleep_forever_async().await;
        }

        // Get the current block number to start from
        let starting_block_number = self
            .darkpool_client()
            .block_number()
            .await
            .map_err(OnChainEventListenerError::darkpool)?;
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
        let client = self.config.ws_client().await?;
        let contract_addr = self.darkpool_client().darkpool_addr();
        let filter = Filter::new().address(contract_addr).event(NullifierSpentEvent::SIGNATURE);
        let mut stream = client.subscribe_logs(&filter).await?.into_stream();

        // Listen for events in a loop
        while let Some(log) = stream.next().await {
            let tx_hash = log
                .transaction_hash
                .ok_or_else(|| OnChainEventListenerError::darkpool("no tx hash"))?;

            let event = log.log_decode::<NullifierSpentEvent>()?;
            let nullifier = u256_to_scalar(event.data().nullifier);
            if let Err(e) = self.handle_nullifier_spent(tx_hash, nullifier).await {
                self.handle_nullifier_spent_error(nullifier, e).await;
            }
        }

        unreachable!()
    }

    /// Watch for nullifiers via HTTP polling
    async fn watch_nullifiers_http(&self) -> Result<(), OnChainEventListenerError> {
        info!("listening for nullifiers via HTTP polling");
        // Build a filtered stream on events that the chain-events worker listens for
        let filter = self.darkpool_client().event_filter::<NullifierSpentEvent>();
        let mut event_stream =
            filter.subscribe().await.map_err(OnChainEventListenerError::darkpool)?.into_stream();

        // Listen for events in a loop
        while let Some(res) = event_stream.next().await {
            let (event, meta) = res.map_err(OnChainEventListenerError::darkpool)?;
            let tx_hash = meta.transaction_hash.expect("no tx hash for log");
            let nullifier = u256_to_scalar(event.nullifier);

            // Handle the nullifier spent event
            if let Err(e) = self.handle_nullifier_spent(tx_hash, nullifier).await {
                self.handle_nullifier_spent_error(nullifier, e).await;
            }
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
        nullifier: Nullifier,
    ) -> Result<(), OnChainEventListenerError> {
        // Send an MPC shootdown request to the handshake manager
        self.config
            .handshake_manager_job_queue
            .send(HandshakeManagerJob::MpcShootdown { nullifier })
            .map_err(|err| OnChainEventListenerError::SendMessage(err.to_string()))?;
        self.state().nullify_orders(nullifier).await?;

        // Update internal state
        self.handle_nullifier_wallet_updates(nullifier, tx).await
    }

    /// Handle an error processing a nullifier spent event
    async fn handle_nullifier_spent_error(
        &self,
        nullifier: Nullifier,
        err: OnChainEventListenerError,
    ) {
        // Clear the wallet's queue and refresh to sync with on-chain state
        error!("error handling nullifier spent event: {err}");
        if let Err(e) = self.clear_queue_for_nullifier(nullifier).await {
            error!("error clearing queue for nullifier {nullifier}: {e}");
        }
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
        let wallet = match maybe_wallet {
            Some(w) => w,
            None => return Ok(()),
        };

        // Record metrics for any external matches in the transaction
        let external_match = self.check_external_match_settlement(tx, wallet).await?;

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
        let my_id = state.get_peer_id()?;
        let cluster_id = state.get_cluster_id()?;
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
        waiter.await.map_err(OnChainEventListenerError::darkpool)?;

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
        wallet_id: WalletIdentifier,
    ) -> Result<bool, OnChainEventListenerError> {
        let matches = self.darkpool_client().find_external_matches_in_tx(tx).await?;
        let external_match = !matches.is_empty();

        for external_match_result in matches {
            let ctx = PostSettlementCtx::new(wallet_id, external_match_result.clone());
            // Record metrics for the match
            self.record_metrics(&ctx);

            // Update the wallet state
            let order_id = self.find_internal_order(wallet_id, &external_match_result).await?;
            self.record_order_fill(order_id, &ctx).await?;

            // Emit the external fill event to the event manager
            self.emit_event(order_id, &ctx)?;
        }

        Ok(external_match)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Find the internal order in the given wallet that matches the external
    /// match result
    ///
    /// This will return the first order that matches the external match result.
    /// While it is possible for multiple orders to match the same external
    /// match, this is not expected to happen in practice.
    async fn find_internal_order(
        &self,
        wallet_id: WalletIdentifier,
        ext_match: &ExternalMatchResult,
    ) -> Result<OrderIdentifier, OnChainEventListenerError> {
        let wallet = self
            .state()
            .get_wallet(&wallet_id)
            .await?
            .ok_or_else(|| OnChainEventListenerError::state("wallet not found"))?;
        let desired_side = ext_match.internal_party_side();
        for (id, order) in wallet.get_nonzero_orders().into_iter() {
            if order.base_mint == ext_match.base_mint
                && order.quote_mint == ext_match.quote_mint
                && order.side == desired_side
            {
                return Ok(id);
            }
        }
        Err(OnChainEventListenerError::state("matching order not found"))
    }
}
