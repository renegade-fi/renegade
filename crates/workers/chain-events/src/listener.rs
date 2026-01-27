//! Defines the core implementation of the on-chain event listener

use std::thread::JoinHandle;

use super::error::OnChainEventListenerError;
use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use constants::in_bootstrap_mode;
use darkpool_client::client::erc20::abis::erc20::IERC20;
use darkpool_client::DarkpoolClient;
use futures_util::StreamExt;
use job_types::event_manager::EventManagerQueue;
use state::State;
use tracing::{error, info, warn};
use types_core::get_all_tokens;
use types_runtime::CancelChannel;
use util::concurrency::runtime::sleep_forever_async;

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
    #[allow(dead_code)] // Will be used for balance queries
    fn darkpool_client(&self) -> &DarkpoolClient {
        &self.config.darkpool_client
    }

    /// Shorthand for fetching a reference to the global state
    #[allow(dead_code)] // Will be used for owner index lookups
    pub(crate) fn state(&self) -> &State {
        &self.config.global_state
    }

    // --------------
    // | Event Loop |
    // --------------

    /// The main execution loop for the executor
    pub async fn execute(self) -> Result<(), OnChainEventListenerError> {
        // If the node is running in bootstrap mode, sleep forever
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

        let filter = Filter::new()
            .address(token_addresses)
            .event(IERC20::Transfer::SIGNATURE);

        let mut stream = client.subscribe_logs(&filter).await?.into_stream();

        while let Some(log) = stream.next().await {
            let self_clone = self.clone();
            tokio::task::spawn(async move {
                if let Err(e) = self_clone.handle_transfer_event(log).await {
                    warn!("Error handling transfer event: {e}");
                }
            });
        }

        Err(OnChainEventListenerError::State("Transfer stream ended".into()))
    }

    /// Watch for Transfer events via HTTP polling
    async fn watch_transfers_http(&self) -> Result<(), OnChainEventListenerError> {
        info!("Listening for Transfer events via HTTP polling");

        let token_addresses = self.get_tracked_token_addresses();
        if token_addresses.is_empty() {
            return Err(OnChainEventListenerError::State("No tokens configured".into()));
        }

        // TODO: Implement HTTP polling loop
        let _filter = Filter::new()
            .address(token_addresses)
            .event(IERC20::Transfer::SIGNATURE);

        Err(OnChainEventListenerError::State("HTTP polling not yet implemented".into()))
    }

    // -------------------
    // | Transfer Events |
    // -------------------

    /// Get the list of token addresses to watch for transfers
    fn get_tracked_token_addresses(&self) -> Vec<Address> {
        get_all_tokens().into_iter().map(|t: types_core::Token| t.get_alloy_address()).collect()
    }

    /// Handle a Transfer event
    async fn handle_transfer_event(&self, _log: Log) -> Result<(), OnChainEventListenerError> {
        // TODO: Decode event, lookup affected accounts, update balances
        // let event = log.log_decode::<IERC20::Transfer>()?;
        // let from = event.data().from;
        // let to = event.data().to;
        // let token = log.address();
        //
        // Look up accounts for from/to addresses
        // Fetch on-chain balance
        // Update state via update_account_balance()
        Ok(())
    }
}
