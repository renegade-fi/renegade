//! Defines the core implementation of the on-chain event listener

use std::{sync::atomic::Ordering, thread::JoinHandle};

use arbitrum_client::{
    abi::{DarkpoolContractEvents, NodeChangedFilter, NullifierSpentFilter},
    client::ArbitrumClient,
    constants::{MERKLE_NODE_CHANGED_EVENT_NAME, NULLIFIER_SPENT_EVENT_NAME},
};
use common::types::{wallet::WalletIdentifier, CancelChannel};
use crossbeam::channel::Sender as CrossbeamSender;
use ethers::{prelude::StreamExt, types::Filter};
use gossip_api::gossip::GossipOutbound;
use job_types::{handshake_manager::HandshakeExecutionJob, proof_manager::ProofManagerJob};
use renegade_crypto::fields::u256_to_scalar;
use state::RelayerState;
use task_driver::{
    driver::TaskDriver,
    update_merkle_proof::{UpdateMerkleProofTask, UpdateMerkleProofTaskError},
};
use tokio::sync::mpsc::UnboundedSender as TokioSender;
use tracing::log;

use super::error::OnChainEventListenerError;

// -------------
// | Constants |
// -------------

/// The "height" coordinate value of the root node's children in the Merkle tree
///
/// We do not emit events for the root, so we instead rely on the root's
/// children to count the staleness of Merkle proofs
const ROOT_CHILDREN_HEIGHT: u8 = 0;

// ----------
// | Worker |
// ----------

/// The configuration passed to the listener upon startup
#[derive(Clone)]
pub struct OnChainEventListenerConfig {
    /// The maximum root staleness to allow in Merkle proofs
    pub max_root_staleness: usize,
    /// An arbitrum client for listening to events
    pub arbitrum_client: ArbitrumClient,
    /// A copy of the relayer global state
    pub global_state: RelayerState,
    /// A sender to the handshake manager's job queue, used to enqueue
    /// MPC shootdown jobs
    pub handshake_manager_job_queue: TokioSender<HandshakeExecutionJob>,
    /// The worker job queue for the ProofGenerationManager
    pub proof_generation_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The work queue for the network manager, used to send outbound gossip
    /// messages
    pub network_sender: TokioSender<GossipOutbound>,
    /// The task driver, used to create and manage long-running async tasks
    pub task_driver: TaskDriver,
    /// The channel on which the coordinator may send a cancel signal
    pub cancel_channel: CancelChannel,
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
    /// A copy of the relayer-global state
    global_state: RelayerState,
}

impl OnChainEventListenerExecutor {
    /// Create a new executor
    pub fn new(config: OnChainEventListenerConfig) -> Self {
        let global_state = config.global_state.clone();

        Self { config, global_state }
    }

    /// Shorthand for fetching a reference to the arbitrum client
    fn arbitrum_client(&self) -> &ArbitrumClient {
        &self.config.arbitrum_client
    }

    /// The main execution loop for the executor
    pub async fn execute(self) -> Result<(), OnChainEventListenerError> {
        // Get the current block number to start from
        let starting_block_number = self
            .arbitrum_client()
            .block_number()
            .await
            .map_err(|err| OnChainEventListenerError::Arbitrum(err.to_string()))?;
        log::info!("Starting on-chain event listener from current block {starting_block_number}");

        // Build a filtered stream on events that the chain-events worker listens for
        let filter = Filter::default()
            .events(vec![NULLIFIER_SPENT_EVENT_NAME, MERKLE_NODE_CHANGED_EVENT_NAME]);
        let builder = self
            .arbitrum_client()
            .darkpool_contract
            .event_with_filter::<DarkpoolContractEvents>(filter);
        let mut event_stream = builder
            .stream()
            .await
            .map_err(|err| OnChainEventListenerError::Arbitrum(err.to_string()))?;

        // Listen for events in a loop
        while let Some(res) = event_stream.next().await {
            let event = res.map_err(|err| OnChainEventListenerError::Arbitrum(err.to_string()))?;
            self.handle_event(event).await?;
        }

        log::error!("on-chain event listener stream ended unexpectedly");
        Ok(())
    }

    /// Handle an event from the contract
    async fn handle_event(
        &self,
        event: DarkpoolContractEvents,
    ) -> Result<(), OnChainEventListenerError> {
        // Dispatch based on key
        match event {
            DarkpoolContractEvents::NullifierSpentFilter(event) => {
                self.handle_nullifier_spent(event).await?;
            },
            DarkpoolContractEvents::NodeChangedFilter(event) => {
                self.handle_internal_node_update(event).await?;
            },
            _ => {
                // Simply log the error and ignore the event
                log::warn!("chain listener received unexpected event type: {event}");
            },
        }

        Ok(())
    }

    /// Handle a nullifier spent event
    async fn handle_nullifier_spent(
        &self,
        event: NullifierSpentFilter,
    ) -> Result<(), OnChainEventListenerError> {
        // Send an MPC shootdown request to the handshake manager
        let nullifier = u256_to_scalar(&event.nullifier);
        self.config
            .handshake_manager_job_queue
            .send(HandshakeExecutionJob::MpcShootdown { nullifier })
            .map_err(|err| OnChainEventListenerError::SendMessage(err.to_string()))?;

        // Nullify any orders that used this nullifier in their validity proof
        self.config.global_state.nullify_orders(nullifier).await;

        Ok(())
    }

    /// Handle an internal node update to the contract's Merkle tree
    async fn handle_internal_node_update(
        &self,
        event: NodeChangedFilter,
    ) -> Result<(), OnChainEventListenerError> {
        // Skip events that are not root children updates
        if event.height != ROOT_CHILDREN_HEIGHT {
            return Ok(());
        }

        let wallet_ids = self.global_state.read_wallet_index().await.get_all_wallet_ids();
        for id in wallet_ids.iter() {
            // Increment the staleness on the wallet
            let staleness = self.global_state.get_wallet_merkle_staleness(id).await.unwrap();

            let last_val = staleness.fetch_add(1, Ordering::Relaxed);
            if last_val > self.config.max_root_staleness {
                self.update_wallet_merkle_path(id).await?;
            }
        }

        Ok(())
    }

    /// Update the Merkle path of the given wallet to the latest known root
    ///
    /// Does not block on task completion, if the task fails it will be retried
    /// on subsequent events streamed into the listener
    async fn update_wallet_merkle_path(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<(), OnChainEventListenerError> {
        let wallet =
            self.global_state.read_wallet_index().await.get_wallet(wallet_id).await.unwrap();

        let task = match UpdateMerkleProofTask::new(
            wallet,
            self.arbitrum_client().clone(),
            self.config.global_state.clone(),
            self.config.proof_generation_work_queue.clone(),
            self.config.network_sender.clone(),
        )
        .await
        {
            Ok(task) => task,
            Err(UpdateMerkleProofTaskError::WalletLocked) => {
                // The wallet is locked for an update, the update will give the wallet a new
                // Merkle proof
                return Ok(());
            },
            Err(e) => return Err(OnChainEventListenerError::TaskStartup(e.to_string())),
        };

        // Spawn the task
        self.config.task_driver.start_task(task).await;
        Ok(())
    }
}
