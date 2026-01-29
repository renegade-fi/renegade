//! Defines the core implementation of the on-chain event listener

use std::{thread::JoinHandle, time::Duration};

use super::error::{
    ERR_AMOUNT_REMAINING_OVERFLOW, ERR_BALANCE_OVERFLOW, ERR_LOG_MISSING_TOPIC,
    OnChainEventListenerError,
};
use alloy::{
    primitives::{Address, keccak256},
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use circuit_types::Amount;
use constants::in_bootstrap_mode;
use darkpool_client::DarkpoolClient;
use darkpool_client::client::erc20::abis::erc20::IERC20;
use futures_util::StreamExt;
use job_types::{
    event_manager::EventManagerQueue,
    matching_engine::{MatchingEngineWorkerJob, MatchingEngineWorkerQueue},
};
use rand::Rng;
use renegade_solidity_abi::v2::IDarkpoolV2::{PublicIntentCancelled, PublicIntentUpdated};
use state::{EventCursor, State};
use tracing::{error, info, warn};
use types_core::{AccountId, get_all_tokens};
use types_runtime::CancelChannel;
use util::concurrency::runtime::sleep_forever_async;

/// The minimum delay in seconds before non-selected nodes process an event
/// (crash recovery)
const MIN_CRASH_RECOVERY_DELAY_S: u64 = 20;
/// The maximum delay in seconds before non-selected nodes process an event
/// (crash recovery)
const MAX_CRASH_RECOVERY_DELAY_S: u64 = 40;

// -----------
// | Helpers |
// -----------

/// Extract an event cursor from a log
///
/// The cursor uniquely identifies the event's position in the chain for
/// stale write prevention.
fn cursor_from_log(log: &Log) -> Result<EventCursor, OnChainEventListenerError> {
    Ok(EventCursor {
        block_number: log
            .block_number
            .ok_or_else(|| OnChainEventListenerError::State("log missing block_number".into()))?,
        tx_index: log.transaction_index.ok_or_else(|| {
            OnChainEventListenerError::State("log missing transaction_index".into())
        })?,
        log_index: log
            .log_index
            .ok_or_else(|| OnChainEventListenerError::State("log missing log_index".into()))?,
    })
}

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

        // Begin the unified event loop
        let res = self.watch_all_events_ws().await.unwrap_err();
        error!("on-chain event listener stream ended unexpectedly: {res}");
        Err(res)
    }

    /// Unified event loop that watches all chain events via websocket
    ///
    /// Uses the multiplexer pattern with two streams:
    /// 1. ERC20 Transfer events from token contracts
    /// 2. Darkpool events (PublicIntentUpdated + PublicIntentCancelled)
    async fn watch_all_events_ws(&self) -> Result<(), OnChainEventListenerError> {
        info!("listening for chain events via websocket");
        let client = self.config.ws_client().await?;
        let darkpool_address = self.darkpool_client().darkpool_addr();
        let token_addresses: Vec<Address> =
            get_all_tokens().into_iter().map(|t| t.get_alloy_address()).collect();

        // Stream 1: ERC20 transfers
        let transfer_filter = Filter::new()
            .address(token_addresses)
            .event_signature(IERC20::Transfer::SIGNATURE_HASH);
        let mut transfer_stream = client.subscribe_logs(&transfer_filter).await?.into_stream();

        // Stream 2: Darkpool events (PublicIntentUpdated + PublicIntentCancelled)
        let darkpool_filter = Filter::new().address(darkpool_address).event_signature(vec![
            PublicIntentUpdated::SIGNATURE_HASH,
            PublicIntentCancelled::SIGNATURE_HASH,
        ]);
        let mut darkpool_stream = client.subscribe_logs(&darkpool_filter).await?.into_stream();

        let mut cancel_channel = self.config.cancel_channel.clone();
        loop {
            tokio::select! {
                Some(log) = transfer_stream.next() => {
                    let self_clone = self.clone();
                    tokio::task::spawn(async move {
                        if let Err(e) = self_clone.handle_transfer_event(log).await {
                            error!("error handling transfer event: {e}");
                        }
                    });
                }
                Some(log) = darkpool_stream.next() => {
                    let self_clone = self.clone();
                    tokio::task::spawn(async move {
                        if let Err(e) = self_clone.dispatch_darkpool_event(log).await {
                            error!("error handling darkpool event: {e}");
                        }
                    });
                }
                _ = cancel_channel.changed() => {
                    info!("on-chain event listener received cancel signal");
                    return Err(OnChainEventListenerError::Cancelled);
                }
                else => break,
            }
        }

        Err(OnChainEventListenerError::StreamEnded)
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
        info!(
            "Handling ERC20 transfer: token={token:#x}, from={from:#x}, to={to:#x}, tx={tx_hash:#x}"
        );

        // Look up affected accounts for both from and to addresses
        let from_account = self.state().get_account_for_owner(&from, &token).await?;
        let to_account = self.state().get_account_for_owner(&to, &token).await?;

        // Process each affected account
        if let Some(account_id) = from_account {
            self.handle_balance_update(account_id, from, token, &log).await?;
        }
        if let Some(account_id) = to_account {
            self.handle_balance_update(account_id, to, token, &log).await?;
        }

        Ok(())
    }

    /// Handle the balance update for an account affected by a transfer event
    async fn handle_balance_update(
        &self,
        account_id: AccountId,
        owner: Address,
        token: Address,
        log: &Log,
    ) -> Result<(), OnChainEventListenerError> {
        let cursor = cursor_from_log(log)?;
        let tx_hash = log
            .transaction_hash
            .ok_or_else(|| OnChainEventListenerError::State("log missing tx_hash".into()))?;

        // Fetch balance and update this node's matching engine cache
        let on_chain_balance = self.darkpool_client().get_erc20_balance(token, owner).await?;
        let Some(mut balance) = self.state().get_account_balance(&account_id, &token).await? else {
            info!("No balance found for account={account_id:?}, token={token:?}, skipping");
            return Ok(());
        };

        *balance.amount_mut() = on_chain_balance
            .try_into()
            .map_err(|_| OnChainEventListenerError::State(ERR_BALANCE_OVERFLOW.into()))?;

        self.state().update_matching_engine_for_balance(account_id, &balance).await?;

        // Select one node to propose raft update and enqueue jobs (with crash recovery)
        if !self
            .is_selected_for_event(&[owner.as_slice(), token.as_slice(), tx_hash.as_slice()])
            .await?
        {
            let timeout = rand::thread_rng()
                .gen_range(MIN_CRASH_RECOVERY_DELAY_S..=MAX_CRASH_RECOVERY_DELAY_S);
            tokio::time::sleep(Duration::from_secs(timeout)).await;
            // No re-fetch needed: cursor guarantees correctness regardless of
            // value staleness
        }

        self.run_matching_engine_for_account_and_balance(account_id, token).await?;
        // Pass cursor for stale write prevention - applicator rejects if stale
        self.state().update_account_balance(account_id, balance, Some(cursor)).await?.await?;

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

    // ------------------------
    // | Public Intent Events |
    // ------------------------

    /// Dispatch darkpool events by topic0 to the appropriate handler
    async fn dispatch_darkpool_event(&self, log: Log) -> Result<(), OnChainEventListenerError> {
        let topic0 = log
            .topics()
            .first()
            .ok_or_else(|| OnChainEventListenerError::State(ERR_LOG_MISSING_TOPIC.into()))?;

        match *topic0 {
            t if t == PublicIntentUpdated::SIGNATURE_HASH => {
                self.handle_public_intent_updated(log).await
            },
            t if t == PublicIntentCancelled::SIGNATURE_HASH => {
                self.handle_public_intent_cancelled(log).await
            },
            _ => {
                tracing::debug!("Unknown darkpool event: topic={topic0}");
                Ok(())
            },
        }
    }

    /// Handle a PublicIntentUpdated event emitted when a public intent is
    /// partially or fully filled on-chain
    ///
    /// Updates the order's remaining amount or removes it if fully filled.
    async fn handle_public_intent_updated(
        &self,
        log: Log,
    ) -> Result<(), OnChainEventListenerError> {
        let cursor = cursor_from_log(&log)?;
        let tx_hash = match log.transaction_hash {
            Some(h) => h,
            None => {
                warn!("PublicIntentUpdated event missing transaction hash, skipping");
                return Ok(());
            },
        };

        let event = log.log_decode::<PublicIntentUpdated>()?;
        let intent_hash = event.inner.intentHash;
        let owner = event.inner.owner;
        let amount_remaining: Amount =
            event.inner.amountRemaining.try_into().map_err(|_| {
                OnChainEventListenerError::State(ERR_AMOUNT_REMAINING_OVERFLOW.into())
            })?;

        // Look up the order by intent hash
        let Some((account_id, order_id)) =
            self.state().get_order_for_intent_hash(&intent_hash).await?
        else {
            // Unknown intent - not managed by this relayer
            return Ok(());
        };
        info!(
            "Handling PublicIntentUpdated: owner={owner:#x}, intent_hash={intent_hash:#x}, amount_remaining={amount_remaining}, tx={tx_hash:#x}"
        );

        // Node selection with crash recovery
        if !self
            .is_selected_for_event(&[owner.as_slice(), intent_hash.as_slice(), tx_hash.as_slice()])
            .await?
        {
            let timeout = rand::thread_rng()
                .gen_range(MIN_CRASH_RECOVERY_DELAY_S..=MAX_CRASH_RECOVERY_DELAY_S);
            tokio::time::sleep(Duration::from_secs(timeout)).await;
            // No re-fetch/re-check needed: cursor guarantees correctness
        }

        if amount_remaining == 0 {
            // Order fully filled - remove it
            // Pass cursor for stale write prevention - applicator rejects if stale
            self.state()
                .remove_order_from_account(account_id, order_id, Some(cursor))
                .await?
                .await?;
        } else {
            // Partial fill - update the order's amount
            let Some(mut order) = self.state().get_account_order(&order_id).await? else {
                return Ok(()); // Order already removed
            };
            order.intent.inner.amount_in = amount_remaining;
            // Pass cursor for stale write prevention - applicator rejects if stale
            self.state().update_order(order, Some(cursor)).await?.await?;
        }

        // TODO: Emit ExternalFillEvent to notify clients

        Ok(())
    }

    /// Handle a PublicIntentCancelled event emitted when a user cancels their
    /// public intent on-chain
    ///
    /// Removes the order from the account.
    async fn handle_public_intent_cancelled(
        &self,
        log: Log,
    ) -> Result<(), OnChainEventListenerError> {
        let cursor = cursor_from_log(&log)?;
        let tx_hash = match log.transaction_hash {
            Some(h) => h,
            None => {
                warn!("PublicIntentCancelled event missing transaction hash, skipping");
                return Ok(());
            },
        };

        let event = log.log_decode::<PublicIntentCancelled>()?;
        let intent_hash = event.inner.intentHash;
        let owner = event.inner.owner;

        // Look up the order by intent hash
        let Some((account_id, order_id)) =
            self.state().get_order_for_intent_hash(&intent_hash).await?
        else {
            // Unknown intent - not managed by this relayer
            return Ok(());
        };
        info!(
            "Handling PublicIntentCancelled: owner={owner:#x}, intent_hash={intent_hash:#x}, tx={tx_hash:#x}"
        );

        // Node selection with crash recovery
        if !self
            .is_selected_for_event(&[owner.as_slice(), intent_hash.as_slice(), tx_hash.as_slice()])
            .await?
        {
            let timeout = rand::thread_rng()
                .gen_range(MIN_CRASH_RECOVERY_DELAY_S..=MAX_CRASH_RECOVERY_DELAY_S);
            tokio::time::sleep(Duration::from_secs(timeout)).await;
            // No re-fetch/re-check needed: cursor guarantees correctness
        }

        // Remove the cancelled order
        // Pass cursor for stale write prevention - applicator rejects if stale
        self.state().remove_order_from_account(account_id, order_id, Some(cursor)).await?.await?;

        // TODO: Emit cancellation event to notify clients

        Ok(())
    }

    // ------------------
    // | Node Selection |
    // ------------------

    /// Selects one node in the cluster to handle an event using consistent
    /// hashing
    ///
    /// Takes input components that uniquely identify the event, hashes them,
    /// and deterministically selects a peer. Returns true if this node is
    /// selected.
    async fn is_selected_for_event(
        &self,
        components: &[&[u8]],
    ) -> Result<bool, OnChainEventListenerError> {
        let state = self.state();
        let my_id = state.get_peer_id()?;
        let cluster_id = state.get_cluster_id()?;
        let mut peers = state.get_cluster_peers(&cluster_id).await?;
        peers.sort();

        let input: Vec<u8> = components.iter().flat_map(|c| c.iter().copied()).collect();
        let hash = keccak256(&input);
        let peer_idx = usize::from(hash[31]) % peers.len();

        Ok(peers[peer_idx] == my_id)
    }
}
