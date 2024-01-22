//! The `interface` module defines the interface to the state, methods for
//! proposing state transitions and reading from state

pub mod error;
pub mod wallet_index;

use std::{sync::Arc, thread};

use config::RelayerConfig;
use crossbeam::channel::{unbounded, Sender as UnboundedSender};
use external_api::bus_message::SystemBusMessage;
use system_bus::SystemBus;

use crate::{
    replication::{
        network::RaftNetwork,
        raft_node::{ReplicationNode, ReplicationNodeConfig},
    },
    storage::db::{DbConfig, DB},
    StateTransition,
};

use self::error::StateError;

/// The default tick interval for the raft node
const DEFAULT_TICK_INTERVAL_MS: u64 = 10; // 10 milliseconds

/// A type alias for a proposal queue of state transitions
pub type ProposalQueue = UnboundedSender<StateTransition>;

/// A handle on the state that allows workers throughout the node to access the
/// replication and durability primitives backing the state machine
#[derive(Clone)]
pub struct State {
    /// A handle on the database
    db: Arc<DB>,
    /// A handle on the proposal queue to the raft instance
    proposal_queue: Arc<ProposalQueue>,
}

impl State {
    /// Create a new state handle
    pub fn new<N: 'static + RaftNetwork + Send>(
        config: &RelayerConfig,
        network: N,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Result<Self, StateError> {
        // Open up the DB
        let db = DB::new(&DbConfig { path: config.db_path.clone() }).map_err(StateError::Db)?;
        let db = Arc::new(db);

        // Create a proposal queue and the raft config
        let (proposal_send, proposal_recv) = unbounded();
        let raft_config = ReplicationNodeConfig {
            tick_period_ms: DEFAULT_TICK_INTERVAL_MS,
            relayer_config: config.clone(),
            proposal_queue: proposal_recv,
            network,
            db: db.clone(),
            system_bus,
        };

        // Start the raft in a new thread
        let raft = ReplicationNode::new(raft_config).map_err(StateError::Replication)?;
        thread::spawn(move || {
            raft.run().expect("Raft node failed");
        });

        // Return the state handle
        Ok(Self { db, proposal_queue: Arc::new(proposal_send) })
    }

    // -------------------
    // | Private Helpers |
    // -------------------

    /// Send a proposal to the raft node
    fn send_proposal(&self, proposal: StateTransition) -> Result<(), StateError> {
        self.proposal_queue.send(proposal).map_err(|e| StateError::Proposal(e.to_string()))
    }
}

#[cfg(test)]
mod test_helpers {
    use crate::{
        replication::network::test_helpers::MockNetwork,
        test_helpers::{sleep_ms, tmp_db_path},
        State,
    };
    use config::RelayerConfig;
    use system_bus::SystemBus;

    /// Create a mock state instance
    pub fn mock_state() -> State {
        let config = RelayerConfig { db_path: tmp_db_path(), ..Default::default() };
        let net = MockNetwork::new_n_way_mesh(1 /* n_nodes */).remove(0);
        let state = State::new(&config, net, SystemBus::new()).unwrap();

        // Wait for a leader election before returning
        sleep_ms(500);
        state
    }
}

#[cfg(test)]
mod test {
    use common::types::wallet_mocks::mock_empty_wallet;

    use crate::{interface::test_helpers::mock_state, test_helpers::sleep_ms};

    /// Test adding a wallet to the state
    #[test]
    fn test_add_wallet() {
        let state = mock_state();

        let wallet = mock_empty_wallet();
        state.new_wallet(wallet.clone()).unwrap();

        // Wait for the proposal to be applied
        sleep_ms(100);

        let expected_wallet = wallet.clone();
        let actual_wallet = state.get_wallet(&wallet.wallet_id).unwrap().unwrap();
        assert_eq!(expected_wallet, actual_wallet);
    }
}
