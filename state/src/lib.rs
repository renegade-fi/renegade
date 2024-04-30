//! This crate defines the relayer's state machine and durable, consistent
//! storage primitives
//!
//! We store our relayer state in an embedded database using `libmdbx` as the
//! underlying storage engine. The database is then replicated by a raft
//! instance at higher layers in the application

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(unsafe_code)]
#![allow(incomplete_features)]
#![feature(let_chains)]
#![feature(io_error_more)]
#![feature(generic_const_exprs)]

use common::types::{
    gossip::{ClusterId, WrappedPeerId},
    mpc_preprocessing::{PairwiseOfflineSetup, PreprocessingSlice},
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    tasks::{QueuedTask, QueuedTaskState, TaskIdentifier, TaskQueueKey},
    wallet::{order_metadata::OrderMetadata, OrderIdentifier, Wallet},
};
use interface::notifications::ProposalResultSender;
use replication::RaftPeerId;
use serde::{Deserialize, Serialize};

pub mod applicator;
mod interface;
pub mod replication;
pub mod storage;
pub mod tui;

/// Re-export the state interface
pub use interface::*;

// -------------
// | Constants |
// -------------

/// The name of the db table that stores node metadata
pub(crate) const NODE_METADATA_TABLE: &str = "node-metadata";

/// The name of the db table that stores peer information
pub(crate) const PEER_INFO_TABLE: &str = "peer-info";
/// The name of the db table that stores cluster membership information
pub(crate) const CLUSTER_MEMBERSHIP_TABLE: &str = "cluster-membership";

/// The name of the db table that stores order and cluster priorities
pub(crate) const PRIORITIES_TABLE: &str = "priorities";
/// The name of the table that stores orders by their ID
pub(crate) const ORDERS_TABLE: &str = "orders";
/// The table that stores order metadata indexed by wallet id
pub(crate) const ORDER_HISTORY_TABLE: &str = "order-history";

/// The name of the db table that maps order to their encapsulating wallet
pub(crate) const ORDER_TO_WALLET_TABLE: &str = "order-to-wallet";
/// The name of the db table that stores wallet information
pub(crate) const WALLETS_TABLE: &str = "wallet-info";

/// The name of the db table that stores task queues
pub(crate) const TASK_QUEUE_TABLE: &str = "task-queues";
/// The name of the db table that maps tasks to their queue key
pub(crate) const TASK_TO_KEY_TABLE: &str = "task-to-key";
/// The name of the db table that stores historical task information
pub(crate) const TASK_HISTORY_TABLE: &str = "task-history";

/// The name of the db table that stores the offline phase values
pub(crate) const MPC_PREPROCESSING_TABLE: &str = "mpc-preprocessing";

/// The `Proposal` type wraps a state transition and the channel on which to
/// send the result of the proposal's application
#[derive(Debug)]
pub struct Proposal {
    /// The state transition to propose
    pub transition: StateTransition,
    /// The channel on which to send the result of the proposal's application
    pub response: ProposalResultSender,
}

/// The `StateTransitionType` encapsulates all possible state transitions,
/// allowing transitions to be handled generically before they are applied
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
#[rustfmt::skip]
pub enum StateTransition {
    // --- Wallets --- //
    /// Add a wallet to the managed state
    AddWallet { wallet: Wallet },
    /// Update a wallet in the managed state
    UpdateWallet { wallet: Wallet },
    /// Add a validity proof to an existing order in the book
    AddOrderValidityBundle {
        order_id: OrderIdentifier,
        proof: OrderValidityProofBundle,
        witness: OrderValidityWitnessBundle,
    },

    // --- Order History --- //
    /// Update the metadata for a given order
    UpdateOrderMetadata { meta: OrderMetadata },

    // --- Task Queue --- //
    /// Add a task to the task queue
    AppendTask { task: QueuedTask },
    /// Pop the top task from the task queue
    PopTask { task_id: TaskIdentifier, success: bool },
    /// Transition the state of the top task in the task queue
    TransitionTask { task_id: TaskIdentifier, state: QueuedTaskState },
    /// Preempt the given task queue
    ///
    /// Returns any running tasks to `Queued` state and pauses the queue
    PreemptTaskQueue { key: TaskQueueKey, task: QueuedTask },
    /// Resume the given task queue
    ResumeTaskQueue { key: TaskQueueKey, success: bool },

    // --- MPC Preprocessing --- //
    /// Add a preprocessing bundle to the state
    AddMpcPreprocessingValues { cluster: ClusterId, values: PairwiseOfflineSetup },
    /// Consume a set of preprocessing values from the state
    ConsumePreprocessingValues {
        recipient: WrappedPeerId,
        cluster: ClusterId,
        request: PreprocessingSlice,
    },

    // --- Raft --- //
    /// Add a raft learner to the cluster
    AddRaftLearner { peer_id: RaftPeerId },
    /// Add a raft peer to the local consensus cluster
    AddRaftPeer { peer_id: RaftPeerId },
    /// Remove a raft peer from the local consensus cluster
    RemoveRaftPeer { peer_id: RaftPeerId },
}

impl From<StateTransition> for Proposal {
    fn from(transition: StateTransition) -> Self {
        // Create a channel that no worker will ever receive on
        let (response, _recv) = tokio::sync::oneshot::channel();
        Self { transition, response }
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "mocks"))]
pub mod test_helpers {
    //! Test helpers for the state crate
    use std::{mem, thread, time::Duration};

    use common::types::gossip::WrappedPeerId;
    use config::RelayerConfig;
    use external_api::bus_message::SystemBusMessage;
    use job_types::{
        handshake_manager::{new_handshake_manager_queue, HandshakeManagerQueue},
        task_driver::{new_task_driver_queue, TaskDriverQueue},
    };
    use system_bus::SystemBus;
    use tempfile::tempdir;
    use test_helpers::mocks::mock_cancel;

    use crate::{
        replication::{
            network::{
                address_translation::PeerIdTranslationMap,
                traits::{test_helpers::MockNetwork, RaftNetwork},
            },
            raft_node::{
                new_raft_proposal_queue, ProposalReceiver, ReplicationNode, ReplicationNodeConfig,
            },
        },
        storage::db::{DbConfig, DB},
        State,
    };

    /// Sleep for the given number of ms
    pub fn sleep_ms(ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }

    /// Get a tempdir to open the DB at
    pub fn tmp_db_path() -> String {
        let tempdir = tempdir().unwrap();
        tempdir.path().to_str().unwrap().to_string()
    }

    /// Create a mock relayer config for testing
    pub fn mock_relayer_config() -> RelayerConfig {
        RelayerConfig { db_path: tmp_db_path(), allow_local: true, ..Default::default() }
    }

    /// Create a mock database in a temporary location
    pub fn mock_db() -> DB {
        // Open the DB
        let path = tmp_db_path();
        let config = DbConfig { path: path.to_string() };

        let db = DB::new(&config).unwrap();

        // Setup the tables
        let tx = db.new_write_tx().unwrap();
        tx.setup_tables().unwrap();
        tx.commit().unwrap();

        db
    }

    /// Create a mock raft config for testing
    ///
    /// We set the timeouts very low to speed up leader election
    pub fn mock_raft_config(relayer_config: &RelayerConfig) -> raft::Config {
        let peer_id = relayer_config.p2p_key.public().to_peer_id();
        let raft_id = PeerIdTranslationMap::get_raft_id(&WrappedPeerId(peer_id));
        raft::Config { id: raft_id, election_tick: 10, ..Default::default() }
    }

    /// Create and run a mock Raft replication node
    pub fn run_mock_replication_node<N: 'static + RaftNetwork + Send>(
        state: &State,
        config: RelayerConfig,
        network: N,
        proposal_receiver: ProposalReceiver,
        task_queue: TaskDriverQueue,
        handshake_manager_queue: HandshakeManagerQueue,
        system_bus: SystemBus<SystemBusMessage>,
    ) {
        let raft_config = mock_raft_config(&config);
        let cancel_channel = mock_cancel();
        let mut replication_config = ReplicationNodeConfig::new(
            config,
            proposal_receiver,
            task_queue,
            handshake_manager_queue,
            system_bus,
            cancel_channel,
        );
        state.fill_replication_config_with_network(&mut replication_config, network);

        let raft_node = ReplicationNode::new_with_config(replication_config, &raft_config).unwrap();

        thread::spawn(move || raft_node.run().unwrap());
    }

    /// Create a mock state instance
    pub fn mock_state() -> State {
        let config = mock_relayer_config();
        mock_state_with_config(config)
    }

    /// Create a mock state instance with the given relayer config
    pub fn mock_state_with_config(config: RelayerConfig) -> State {
        let (task_queue, recv) = new_task_driver_queue();
        mem::forget(recv);
        mock_state_with_task_queue(task_queue, config)
    }

    /// Create a mock state instance with the given task queue
    pub fn mock_state_with_task_queue(task_queue: TaskDriverQueue, config: RelayerConfig) -> State {
        let (_controller, mut nets) = MockNetwork::new_n_way_mesh(1 /* n_nodes */);
        let (handshake_manager_queue, _recv) = new_handshake_manager_queue();
        let (proposal_sender, proposal_receiver) = new_raft_proposal_queue();
        let system_bus = SystemBus::new();
        let state = State::new(&config, proposal_sender, system_bus.clone()).unwrap();

        run_mock_replication_node(
            &state,
            config,
            nets.remove(0),
            proposal_receiver,
            task_queue,
            handshake_manager_queue,
            system_bus,
        );

        // Wait for a leader election before returning
        sleep_ms(500);
        state
    }
}
