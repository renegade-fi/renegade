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
#![feature(inherent_associated_types)]
#![feature(io_error_more)]

use crate::error::StateError;

pub mod applicator;
pub mod error;
mod interface;
pub mod notifications;
pub mod replication;
pub mod state_transition;
pub mod storage;

// Re-export the state interface
pub use interface::*;

// -----------------
// | Serialization |
// -----------------

/// Serialize a value using CBOR
pub fn ciborium_serialize<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, StateError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(StateError::serde)?;
    Ok(buf)
}

/// Deserialize a value using CBOR
pub fn ciborium_deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, StateError> {
    let res = ciborium::de::from_reader(bytes).map_err(StateError::serde)?;
    Ok(res)
}

// -------------
// | Constants |
// -------------

/// The number of tables to open in the database
const NUM_TABLES: usize = 20;

/// The name of the db table that stores node metadata
pub(crate) const NODE_METADATA_TABLE: &str = "node-metadata";
/// The name of the db table that stores relayer fees amounts by wallet ID
pub(crate) const RELAYER_FEES_TABLE: &str = "relayer-fees";

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

/// The name of the db table that stores proofs
pub(crate) const PROOFS_TABLE: &str = "proofs";

/// The name of the db table mapping orders to their matching pool
pub(crate) const POOL_TABLE: &str = "matching-pools";

/// The name of the db table that maps intent to their encapsulating wallet
pub(crate) const INTENT_TO_WALLET_TABLE: &str = "intent-to-wallet";
/// The name of the db table that maps nullifiers to wallets
pub(crate) const NULLIFIER_TO_WALLET_TABLE: &str = "nullifier-to-wallet";
/// The name of the db table that stores wallet information
pub(crate) const WALLETS_TABLE: &str = "wallet-info";

/// The name of the db table that stores task queues
pub(crate) const TASK_QUEUE_TABLE: &str = "task-queues";
/// The name of the db table that maps tasks to their queue keys
pub(crate) const TASK_TO_KEY_TABLE: &str = "task-to-key";
/// The name of the db table that maps nodes to their assigned tasks
pub(crate) const TASK_ASSIGNMENT_TABLE: &str = "task-assignments";
/// The name of the db table that stores historical task information
pub(crate) const TASK_HISTORY_TABLE: &str = "task-history";

/// The name of the db table that stores the offline phase values
pub(crate) const MPC_PREPROCESSING_TABLE: &str = "mpc-preprocessing";

/// The name of the db table that stores Merkle authentication paths (openings)
pub(crate) const MERKLE_PROOFS_TABLE: &str = "merkle-proofs";

/// The name of the raft metadata table in the database
pub const RAFT_METADATA_TABLE: &str = "raft-metadata";
/// The name of the raft logs table in the database
pub const RAFT_LOGS_TABLE: &str = "raft-logs";
/// All tables in the database
pub const ALL_TABLES: [&str; NUM_TABLES] = [
    CLUSTER_MEMBERSHIP_TABLE,
    MERKLE_PROOFS_TABLE,
    MPC_PREPROCESSING_TABLE,
    NODE_METADATA_TABLE,
    NULLIFIER_TO_WALLET_TABLE,
    ORDER_HISTORY_TABLE,
    INTENT_TO_WALLET_TABLE,
    ORDERS_TABLE,
    PEER_INFO_TABLE,
    POOL_TABLE,
    PRIORITIES_TABLE,
    PROOFS_TABLE,
    RAFT_LOGS_TABLE,
    RAFT_METADATA_TABLE,
    RELAYER_FEES_TABLE,
    TASK_ASSIGNMENT_TABLE,
    TASK_HISTORY_TABLE,
    TASK_QUEUE_TABLE,
    TASK_TO_KEY_TABLE,
    WALLETS_TABLE,
];

// ---------
// | Tests |
// ---------

/// Test helpers for the state crate
#[cfg(any(test, feature = "mocks"))]
pub mod test_helpers {
    use std::{mem, sync::Arc, time::Duration};

    use config::RelayerConfig;
    use job_types::{
        event_manager::new_event_manager_queue,
        matching_engine::new_matching_engine_worker_queue,
        task_driver::{TaskDriverQueue, new_task_driver_queue},
    };
    use libp2p::identity::Keypair;
    use system_bus::SystemBus;
    use system_clock::SystemClock;
    use tempfile::tempdir;
    use types_runtime::new_worker_failure_channel;

    use matching_engine_core::MatchingEngine;

    use crate::{
        State, StateConfig, StateInner,
        notifications::OpenNotifications,
        replication::{
            RaftNode, get_raft_id,
            mock_raft::{MockRaft, MockRaftNode, mock_raft_config},
            raft::RaftClientConfig,
        },
        state_transition::StateTransition,
        storage::db::{DB, DbConfig},
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
        RelayerConfig {
            db_path: tmp_db_path(),
            allow_local: true,
            record_historical_state: true,
            ..Default::default()
        }
    }

    /// Create a mock database in a temporary location
    pub fn mock_db() -> DB {
        // Open the DB
        let path = tmp_db_path();
        // Allocate a DB with more tables than needed
        let config = DbConfig { path: path.to_string(), num_tables: 100 };

        let db = DB::new(&config).unwrap();

        // Setup the tables
        let tx = db.new_write_tx().unwrap();
        tx.setup_tables().unwrap();
        tx.set_historical_state_enabled(true).unwrap();
        tx.commit().unwrap();

        db
    }

    /// Create a mock raft config for testing
    ///
    /// We set the timeouts very low to speed up leader election
    pub fn raft_config_from_relayer_config(
        relayer_config: &RelayerConfig,
        delay: u64,
    ) -> RaftClientConfig {
        let peer_id = relayer_config.peer_id();
        let id = get_raft_id(&peer_id);
        let initial_nodes = vec![(id, RaftNode::new(peer_id))];
        RaftClientConfig {
            id,
            init: true,
            initial_nodes,
            snapshot_path: relayer_config.raft_snapshot_path.clone(),
            ..mock_raft_config(vec![] /* initial nodes */, delay)
        }
    }

    /// Create a mock state instance
    pub async fn mock_state() -> State {
        let config = mock_relayer_config();
        mock_state_with_config(&config).await
    }

    /// Create a mock state instance with the given relayer config
    pub async fn mock_state_with_config(config: &RelayerConfig) -> State {
        let (task_queue, recv) = new_task_driver_queue();
        mem::forget(recv);
        mock_state_with_task_queue(0 /* network_delay_ms */, task_queue, config).await
    }

    /// Create a mock state instance with the given task queue
    pub async fn mock_state_with_task_queue(
        network_delay_ms: u64,
        task_queue: TaskDriverQueue,
        config: &RelayerConfig,
    ) -> State {
        // Create the mock raft
        let raft = MockRaft::create_raft(
            2, // n_nodes
            network_delay_ms,
            false, // init
        )
        .await;
        let net = raft.new_network_client();
        let (handshake_manager_queue, _recv) = new_matching_engine_worker_queue();
        let (event_queue, _recv) = new_event_manager_queue();
        let (failure_send, _failure_recv) = new_worker_failure_channel();

        // Add a client to the mock raft as leader
        let raft_config = raft_config_from_relayer_config(config, network_delay_ms);
        let matching_engine = MatchingEngine::new();
        let state = StateInner::new_with_network(
            config,
            raft_config,
            net,
            matching_engine,
            task_queue,
            handshake_manager_queue,
            event_queue,
            SystemBus::new(),
            &SystemClock::new().await,
            failure_send,
        )
        .await
        .unwrap();

        // Promote all nodes to voters
        setup_voters(&state, &raft).await;
        Arc::new(state)
    }

    /// Setup all nodes as voters
    async fn setup_voters(state: &StateInner, mock_raft: &MockRaft) {
        // Add all nodes as voters
        for (id, node) in mock_raft.rafts.read().await.iter() {
            // Configure the follower's DB
            configure_follower(node).await;

            // Add the node as a learner
            let info = RaftNode::default();
            let prop = StateTransition::AddRaftLearners { learners: vec![(*id, info)] };
            state.send_proposal(prop).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;

            // Add the node as a voter
            let prop = StateTransition::AddRaftVoters { peer_ids: vec![*id] };
            state.send_proposal(prop).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Configure the database of a mock raft follower to be properly setup for
    /// use as a state peer
    async fn configure_follower(node: &MockRaftNode) {
        // Create a mock state handle and run node metadata setup on it to modify the
        // underlying DB
        let client = node.get_client().clone();
        let db = node.clone_db();
        let config = StateConfig { allow_local: true, ..Default::default() };
        let matching_engine = MatchingEngine::new();
        let state = StateInner {
            config,
            matching_engine,
            db,
            raft: client,
            bus: SystemBus::new(),
            notifications: OpenNotifications::new(),
        };

        // Configure the node
        let config = RelayerConfig { p2p_key: Keypair::generate_ed25519(), ..Default::default() };
        state.setup_node_metadata(&config).await.unwrap();
    }
}
