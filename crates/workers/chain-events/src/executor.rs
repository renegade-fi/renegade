//! The executor for the on-chain event listener

use std::time::Duration;

use alloy::{
    primitives::TxHash,
    providers::{DynProvider, ProviderBuilder, WsConnect},
};
use constants::in_bootstrap_mode;
use darkpool_client::DarkpoolClient;
use futures_util::StreamExt;
use rand::Rng;
use state::State;
use system_bus::{OWNER_INDEX_CHANGED_TOPIC, SystemBus};
use tracing::{error, info};
use util::concurrency::runtime::sleep_forever_async;

use crate::{error::OnChainEventListenerError, worker::OnChainEventListenerConfig};

/// Minimum delay before non-selected nodes process an event (crash recovery)
const MIN_CRASH_RECOVERY_DELAY_S: u64 = 20;
/// Maximum delay before non-selected nodes process an event (crash recovery)
const MAX_CRASH_RECOVERY_DELAY_S: u64 = 40;

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

    /// Get a reference to the darkpool client
    pub(crate) fn darkpool_client(&self) -> &DarkpoolClient {
        &self.config.darkpool_client
    }

    /// Get a reference to the global state
    pub(crate) fn state(&self) -> &State {
        &self.config.global_state
    }

    /// Get a reference to the system bus
    fn system_bus(&self) -> &SystemBus {
        &self.config.system_bus
    }

    /// The main execution loop for the executor
    pub async fn execute(self) -> Result<(), OnChainEventListenerError> {
        if in_bootstrap_mode() {
            sleep_forever_async().await;
        }

        info!("Starting on-chain event listener");

        let res = self.run_event_loop().await.unwrap_err();
        error!("on-chain event listener stream ended unexpectedly: {res}");
        Err(res)
    }

    /// Main event loop that watches all chain events via websocket
    async fn run_event_loop(&self) -> Result<(), OnChainEventListenerError> {
        info!("listening for chain events via websocket");

        // Create websocket client and subscribe to all event streams
        let client = self.create_ws_client().await?;
        let (mut transfer_from, mut transfer_to) =
            self.create_transfer_subscriptions(&client).await?;
        let mut darkpool = self.create_darkpool_subscription(&client).await?;

        // Subscribe to internal notifications for owner index changes
        let mut owner_changes = self.system_bus().subscribe(OWNER_INDEX_CHANGED_TOPIC.to_string());
        let mut cancel = self.config.cancel_channel.clone();

        loop {
            tokio::select! {
                // Handle ERC20 transfers from tracked owners
                Some(log) = transfer_from.next() => {
                    let executor = self.clone();
                    tokio::task::spawn(async move {
                        if let Err(e) = executor.handle_transfer_event(log).await {
                            error!("error handling transfer event: {e}");
                        }
                    });
                }

                // Handle ERC20 transfers to tracked owners
                Some(log) = transfer_to.next() => {
                    let executor = self.clone();
                    tokio::task::spawn(async move {
                        if let Err(e) = executor.handle_transfer_event(log).await {
                            error!("error handling transfer event: {e}");
                        }
                    });
                }

                // Handle darkpool contract events (intent updates/cancellations)
                Some(log) = darkpool.next() => {
                    let executor = self.clone();
                    tokio::task::spawn(async move {
                        if let Err(e) = executor.dispatch_darkpool_event(log).await {
                            error!("error handling darkpool event: {e}");
                        }
                    });
                }

                // Refresh transfer subscriptions when owner set changes
                _ = owner_changes.next_message() => {
                    info!("Owner index changed, refreshing transfer subscriptions");
                    match self.create_transfer_subscriptions(&client).await {
                        Ok((from, to)) => {
                            transfer_from = from;
                            transfer_to = to;
                        }
                        Err(e) => error!("Failed to refresh transfer subscriptions: {e}"),
                    }
                }

                // Handle shutdown signal
                _ = cancel.changed() => {
                    info!("on-chain event listener received cancel signal");
                    return Err(OnChainEventListenerError::Cancelled);
                }

                else => break,
            }
        }

        Err(OnChainEventListenerError::StreamEnded)
    }

    /// Create a new websocket client
    async fn create_ws_client(&self) -> Result<DynProvider, OnChainEventListenerError> {
        let Some(ref addr) = self.config.websocket_addr else {
            panic!("no websocket listener configured");
        };

        let conn = WsConnect::new(addr.clone());
        let provider = ProviderBuilder::new().connect_ws(conn).await?;
        Ok(DynProvider::new(provider))
    }

    /// Sleep for a random crash recovery delay
    ///
    /// Non-selected nodes wait a random interval before processing to give
    /// the selected node time to handle the event first.
    pub(crate) async fn sleep_for_crash_recovery(&self) {
        let delay =
            rand::thread_rng().gen_range(MIN_CRASH_RECOVERY_DELAY_S..=MAX_CRASH_RECOVERY_DELAY_S);
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }

    /// Decides if this node should execute updates for a given tx hash
    ///
    /// To prevent multiple nodes from processing the same event, we select one
    /// node using (tx_hash_lsb % n_nodes). The tx hash is a cryptographic hash,
    /// so this gives roughly uniform distribution.
    pub(crate) async fn should_execute_update(
        &self,
        tx_hash: TxHash,
    ) -> Result<bool, OnChainEventListenerError> {
        let state = self.state();
        let my_id = state.get_peer_id()?;
        let cluster_id = state.get_cluster_id()?;
        let mut peers = state.get_cluster_peers(&cluster_id).await?;
        peers.sort();

        let peer_idx = usize::from(*tx_hash.last().unwrap()) % peers.len();
        Ok(peers[peer_idx] == my_id)
    }
}
