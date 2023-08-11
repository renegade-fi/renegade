//! Defines a mock for the state object

use common::types::{gossip::ClusterId, wallet::Wallet};
use config::RelayerConfig;
use external_api::bus_message::SystemBusMessage;
use job_types::handshake_manager::HandshakeExecutionJob;
use system_bus::SystemBus;
use tokio::sync::mpsc::UnboundedSender as TokioSender;

use crate::RelayerState;

/// Builds the mock state object for testing
#[derive(Default)]
pub struct StateMockBuilder {
    /// The config to use for the state
    config: RelayerConfig,
    /// A reference to the job queue for the handshake manager
    handshake_job_queue: Option<TokioSender<HandshakeExecutionJob>>,
    /// A reference to the global system bus
    bus: Option<SystemBus<SystemBusMessage>>,
}

impl StateMockBuilder {
    /// Turn on the debug flag
    pub fn debug(mut self) -> Self {
        self.config.debug = true;
        self
    }

    /// Turn on the `allow_local` flag
    pub fn allow_local(mut self) -> Self {
        self.config.allow_local = true;
        self
    }

    /// Turn on the `disable_fee_validation` flag
    pub fn disable_fee_validation(mut self) -> Self {
        self.config.disable_fee_validation = true;
        self
    }

    /// Set the local keypair
    pub fn local_keypair(mut self, key: String) -> Self {
        self.config.p2p_key = Some(key);
        self
    }

    /// Set the cluster ID
    pub fn cluster_id(mut self, cluster_id: ClusterId) -> Self {
        self.config.cluster_id = cluster_id;
        self
    }

    /// Add a wallet to the state
    pub fn wallet(mut self, wallet: Wallet) -> Self {
        self.config.wallets.push(wallet);
        self
    }

    /// Set the handshake job queue
    pub fn handshake_job_queue(mut self, queue: TokioSender<HandshakeExecutionJob>) -> Self {
        self.handshake_job_queue = Some(queue);
        self
    }

    /// Set the system bus
    pub fn bus(mut self, bus: SystemBus<SystemBusMessage>) -> Self {
        self.bus = Some(bus);
        self
    }

    /// Build the mock state
    pub fn build(self) -> RelayerState {
        let handshake_queue = self.handshake_job_queue.unwrap_or_else(|| {
            let (sender, _) = tokio::sync::mpsc::unbounded_channel();
            sender
        });
        let system_bus = self.bus.unwrap_or_else(SystemBus::new);

        RelayerState::initialize_global_state(&self.config, handshake_queue, system_bus)
    }
}
