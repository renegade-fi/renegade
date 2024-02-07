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
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    tasks::{QueuedTask, QueuedTaskState},
    wallet::{OrderIdentifier, Wallet, WalletIdentifier},
};
use replication::{error::ReplicationError, RaftPeerId};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot::Sender as OneshotSender;

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

/// The name of the db table that maps order to their encapsulating wallet
pub(crate) const ORDER_TO_WALLET_TABLE: &str = "order-to-wallet";
/// The name of the db table that stores wallet information
pub(crate) const WALLETS_TABLE: &str = "wallet-info";

/// The name of the db table that stores task queues
pub(crate) const TASK_QUEUE_TABLE: &str = "task-queues";
/// The name of the db table that maps tasks to wallet
pub(crate) const TASK_TO_WALLET_TABLE: &str = "task-to-wallet";

/// The `Proposal` type wraps a state transition and the channel on which to
/// send the result of the proposal's application
#[derive(Debug)]
pub struct Proposal {
    /// The state transition to propose
    pub transition: StateTransition,
    /// The channel on which to send the result of the proposal's application
    pub response: OneshotSender<Result<(), ReplicationError>>,
}

/// The `StateTransitionType` encapsulates all possible state transitions,
/// allowing transitions to be handled generically before they are applied
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
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

    // --- Task Queue --- //
    /// Add a task to the task queue
    AppendWalletTask { wallet_id: WalletIdentifier, task: QueuedTask },
    /// Pop the top task from the task queue
    PopWalletTask { wallet_id: WalletIdentifier },
    /// Transition the state of the top task in the task queue
    TransitionWalletTask { wallet_id: WalletIdentifier, state: QueuedTaskState },
    /// Preempt the task queue on a given wallet
    ///
    /// Returns any running tasks to `Queued` state and pauses the queue
    PreemptTaskQueue { wallet_id: WalletIdentifier },
    /// Resume a task queue on a given wallet
    ResumeTaskQueue { wallet_id: WalletIdentifier },

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
    use std::{mem, time::Duration};

    use config::RelayerConfig;
    use job_types::task_driver::new_task_driver_queue;
    use system_bus::SystemBus;
    use tempfile::tempdir;

    use crate::{
        replication::network::traits::test_helpers::MockNetwork,
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

    /// Create a mock state instance
    pub fn mock_state() -> State {
        let config =
            RelayerConfig { db_path: tmp_db_path(), allow_local: true, ..Default::default() };
        let (_controller, mut nets) = MockNetwork::new_n_way_mesh(1 /* n_nodes */);
        let (task_queue, recv) = new_task_driver_queue();
        mem::forget(recv);

        let state =
            State::new_with_network(&config, nets.remove(0), task_queue, SystemBus::new()).unwrap();

        // Wait for a leader election before returning
        sleep_ms(500);
        state
    }
}
