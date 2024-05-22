//! Defines the core implementation of the on-chain event listener

use std::thread::JoinHandle;

use arbitrum_client::{abi::NullifierSpentFilter, client::ArbitrumClient};
use common::types::CancelChannel;
use ethers::prelude::StreamExt;
use job_types::{
    handshake_manager::{HandshakeExecutionJob, HandshakeManagerQueue},
    network_manager::NetworkManagerQueue,
    proof_manager::ProofManagerQueue,
};
use renegade_crypto::fields::u256_to_scalar;
use state::State;
use tracing::{error, info};

use super::error::OnChainEventListenerError;

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
    pub global_state: State,
    /// A sender to the handshake manager's job queue, used to enqueue
    /// MPC shootdown jobs
    pub handshake_manager_job_queue: HandshakeManagerQueue,
    /// The worker job queue for the ProofGenerationManager
    pub proof_generation_work_queue: ProofManagerQueue,
    /// The work queue for the network manager, used to send outbound gossip
    /// messages
    pub network_sender: NetworkManagerQueue,
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

    /// The main execution loop for the executor
    pub async fn execute(self) -> Result<(), OnChainEventListenerError> {
        // Get the current block number to start from
        let starting_block_number = self
            .arbitrum_client()
            .block_number()
            .await
            .map_err(|err| OnChainEventListenerError::Arbitrum(err.to_string()))?;
        info!("Starting on-chain event listener from current block {starting_block_number}");

        // Build a filtered stream on events that the chain-events worker listens for
        let filter = self.arbitrum_client().get_darkpool_client().event::<NullifierSpentFilter>();
        let mut event_stream = filter
            .stream()
            .await
            .map_err(|err| OnChainEventListenerError::Arbitrum(err.to_string()))?;

        // Listen for events in a loop
        while let Some(res) = event_stream.next().await {
            let event = res.map_err(|err| OnChainEventListenerError::Arbitrum(err.to_string()))?;
            self.handle_nullifier_spent(&event).await?;
        }

        error!("on-chain event listener stream ended unexpectedly");
        Ok(())
    }

    /// Handle a nullifier spent event
    async fn handle_nullifier_spent(
        &self,
        event: &NullifierSpentFilter,
    ) -> Result<(), OnChainEventListenerError> {
        // Send an MPC shootdown request to the handshake manager
        let nullifier = u256_to_scalar(&event.nullifier);
        self.config
            .handshake_manager_job_queue
            .send(HandshakeExecutionJob::MpcShootdown { nullifier })
            .map_err(|err| OnChainEventListenerError::SendMessage(err.to_string()))?;

        // Nullify any orders that used this nullifier in their validity proof
        self.config.global_state.nullify_orders(nullifier).await?;
        Ok(())
    }
}
