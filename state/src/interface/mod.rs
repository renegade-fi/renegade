//! The `interface` module defines the interface to the state, methods for
//! proposing state transitions and reading from state

pub mod error;
pub mod mpc_preprocessing;
pub mod node_metadata;
pub mod order_book;
pub mod order_history;
pub mod peer_index;
pub mod task_queue;
pub mod wallet_index;

use std::sync::Arc;

use common::types::gossip::WrappedPeerId;
use config::RelayerConfig;
use crossbeam::channel::Sender as UnboundedSender;
use external_api::bus_message::SystemBusMessage;
use job_types::{handshake_manager::HandshakeManagerQueue, task_driver::TaskDriverQueue};
use system_bus::SystemBus;

use crate::{
    applicator::{StateApplicator, StateApplicatorConfig},
    notifications::{OpenNotifications, ProposalWaiter},
    replicationv2::{
        network::address_translation::PeerIdTranslationMap,
        raft::{NetworkEssential, RaftClient, RaftClientConfig},
        state_machine::{StateMachine, StateMachineConfig},
    },
    storage::db::{DbConfig, DB},
    Proposal, StateTransition,
};

use self::error::StateError;

/// The default number of ticks between Raft heartbeats
const DEFAULT_HEARTBEAT_MS: u64 = 1000; // 1 second
/// The default lower bound on the number of ticks before a Raft election
const DEFAULT_MIN_ELECTION_MS: u64 = 10000; // 10 seconds
/// The default upper bound on the number of ticks before a Raft election
const DEFAULT_MAX_ELECTION_MS: u64 = 15000; // 15 seconds

/// A type alias for a proposal queue of state transitions
pub type ProposalQueue = UnboundedSender<Proposal>;

// -------------------
// | State Interface |
// -------------------

/// A handle on the state that allows workers throughout the node to acces the
/// replication and durability primitives backing the state machine
#[derive(Clone)]
pub struct StateHandle<N: NetworkEssential> {
    /// Whether or not the node allows local peers when adding to the peer index
    allow_local: bool,
    /// A handle on the database
    db: Arc<DB>,
    /// The system bus for sending notifications to other workers
    bus: SystemBus<SystemBusMessage>,
    /// The notifications map
    notifications: OpenNotifications,
    /// The raft client
    raft: RaftClient<N>,
}

impl<N: NetworkEssential> StateHandle<N> {
    /// The base constructor allowing for the variadic constructors above
    pub async fn new_with_network(
        config: &RelayerConfig,
        raft_config: RaftClientConfig,
        network: N,
        task_queue: TaskDriverQueue,
        handshake_manager_queue: HandshakeManagerQueue,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Result<Self, StateError> {
        // Open up the DB
        let db_config = DbConfig::new_with_path(&config.db_path);
        let db = DB::new(&db_config).map_err(StateError::Db)?;
        let db = Arc::new(db);

        // Setup the tables in the DB
        let tx = db.new_write_tx()?;
        tx.setup_tables()?;
        tx.commit()?;

        // Setup the state machine
        let applicator_config = StateApplicatorConfig {
            allow_local: config.allow_local,
            cluster_id: config.cluster_id.clone(),
            task_queue,
            handshake_manager_queue,
            db: db.clone(),
            system_bus: system_bus.clone(),
        };
        let applicator = StateApplicator::new(applicator_config).map_err(StateError::Applicator)?;
        let notifications = OpenNotifications::new();
        let sm_config = StateMachineConfig::new(config.raft_snapshot_path.clone());
        let sm = StateMachine::new(sm_config, notifications.clone(), applicator);

        // Start a raft
        let raft = RaftClient::new(raft_config, db.clone(), network, sm)
            .await
            .map_err(StateError::Replication)?;

        // Setup the node metadata from the config
        let this =
            Self { allow_local: config.allow_local, db, bus: system_bus, notifications, raft };
        this.setup_node_metadata(config)?;
        Ok(this)
    }

    // -------------------
    // | Private Helpers |
    // -------------------

    /// Build the raft config for the node
    fn build_raft_config(relayer_config: &RelayerConfig) -> RaftClientConfig {
        let peer_id = relayer_config.p2p_key.public().to_peer_id();
        let raft_id = PeerIdTranslationMap::get_raft_id(&WrappedPeerId(peer_id));

        RaftClientConfig {
            id: raft_id,
            init: true,
            heartbeat_interval: DEFAULT_HEARTBEAT_MS,
            election_timeout_min: DEFAULT_MIN_ELECTION_MS,
            election_timeout_max: DEFAULT_MAX_ELECTION_MS,
            ..Default::default()
        }
    }

    /// Send a proposal to the raft node
    async fn send_proposal(
        &self,
        transition: StateTransition,
    ) -> Result<ProposalWaiter, StateError> {
        let proposal = Proposal::from(transition);
        let recv = self.notifications.register_notification(proposal.id).await;

        self.raft.propose_transition(proposal).await.map_err(StateError::Replication)?;
        Ok(ProposalWaiter::new(recv))
    }
}

#[cfg(test)]
mod test {
    use common::types::wallet_mocks::mock_empty_wallet;

    use crate::test_helpers::mock_state;

    /// Test adding a wallet to the state
    #[tokio::test]
    async fn test_add_wallet() {
        let state = mock_state().await;

        let wallet = mock_empty_wallet();
        let res = state.new_wallet(wallet.clone()).await.unwrap().await;
        assert!(res.is_ok());

        // Check for the wallet in the state
        let expected_wallet = wallet.clone();
        let actual_wallet = state.get_wallet(&wallet.wallet_id).unwrap().unwrap();
        assert_eq!(expected_wallet, actual_wallet);
    }
}
