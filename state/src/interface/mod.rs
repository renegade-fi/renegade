//! The `interface` module defines the interface to the state, methods for
//! proposing state transitions and reading from state

pub mod error;
pub mod mpc_preprocessing;
pub mod node_metadata;
pub mod order_book;
pub mod order_history;
pub mod peer_index;
pub mod raft;
pub mod task_queue;
pub mod wallet_index;

use std::sync::Arc;

use config::RelayerConfig;
use crossbeam::channel::Sender as UnboundedSender;
use external_api::bus_message::SystemBusMessage;
use job_types::{
    handshake_manager::HandshakeManagerQueue, network_manager::NetworkManagerQueue,
    task_driver::TaskDriverQueue,
};
use libmdbx::{RO, RW};
use system_bus::SystemBus;
use util::err_str;

use crate::{
    applicator::{StateApplicator, StateApplicatorConfig},
    notifications::{OpenNotifications, ProposalWaiter},
    replicationv2::{
        get_raft_id,
        network::{gossip::GossipNetwork, P2PNetworkFactory},
        raft::{RaftClient, RaftClientConfig},
        state_machine::{StateMachine, StateMachineConfig},
        RaftNode,
    },
    storage::{
        db::{DbConfig, DB},
        tx::StateTxn,
    },
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

/// A handle on the state that allows workers throughout the node to access the
/// replication and durability primitives backing the state machine
#[derive(Clone)]
pub struct State {
    /// Whether or not the node allows local peers when adding to the peer index
    pub(crate) allow_local: bool,
    /// A handle on the database
    pub(crate) db: Arc<DB>,
    /// The system bus for sending notifications to other workers
    pub(crate) bus: SystemBus<SystemBusMessage>,
    /// The notifications map
    pub(crate) notifications: OpenNotifications,
    /// The raft client
    pub(crate) raft: RaftClient,
}

impl State {
    // ----------------
    // | Constructors |
    // ----------------

    /// Construct a new default state handle using the `GossipNetwork`
    pub async fn new(
        config: &RelayerConfig,
        network_queue: NetworkManagerQueue,
        task_queue: TaskDriverQueue,
        handshake_manager_queue: HandshakeManagerQueue,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Result<Self, StateError> {
        let raft_config = Self::build_raft_config(config);
        let net = GossipNetwork::empty(network_queue);
        Self::new_with_network(
            config,
            raft_config,
            net,
            task_queue,
            handshake_manager_queue,
            system_bus,
        )
        .await
    }

    /// The base constructor allowing for the variadic constructors above
    pub async fn new_with_network<N: P2PNetworkFactory>(
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
        this.setup_node_metadata(config).await?;
        Ok(this)
    }

    // -------------------
    // | Private Helpers |
    // -------------------

    /// Build the raft config for the node
    fn build_raft_config(relayer_config: &RelayerConfig) -> RaftClientConfig {
        let peer_id = relayer_config.peer_id();
        let raft_id = get_raft_id(&peer_id);
        let initial_nodes = vec![(raft_id, RaftNode::new(peer_id))];

        RaftClientConfig {
            id: raft_id,
            init: relayer_config.assume_raft_leader,
            heartbeat_interval: DEFAULT_HEARTBEAT_MS,
            election_timeout_min: DEFAULT_MIN_ELECTION_MS,
            election_timeout_max: DEFAULT_MAX_ELECTION_MS,
            initial_nodes,
            ..Default::default()
        }
    }

    /// Run the given callback with a read tx scoped in on a blocking thread
    ///
    /// This allows us to give an async client interface that will not
    /// excessively block async callers. MDBX operations may occasionally block
    /// for a long time, so we want to avoid blocking async worker threads
    pub async fn with_read_tx<F, T>(&self, f: F) -> Result<T, StateError>
    where
        T: Send + 'static,
        F: FnOnce(&StateTxn<'_, RO>) -> Result<T, StateError> + Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let tx = db.new_read_tx()?;
            let res = f(&tx)?;
            tx.commit()?;
            Ok(res)
        })
        .await
        .map_err(err_str!(StateError::Runtime))?
    }

    /// Run the given callback with a write tx scoped in on a blocking thread
    ///
    /// This allows us to give an async client interface that will not
    /// excessively block async callers. MDBX operations may occasionally block
    /// for a long time, so we want to avoid blocking async worker threads
    pub async fn with_write_tx<F, T>(&self, f: F) -> Result<T, StateError>
    where
        T: Send + 'static,
        F: FnOnce(&StateTxn<'_, RW>) -> Result<T, StateError> + Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let tx = db.new_write_tx()?;
            let res = f(&tx)?;
            tx.commit()?;
            Ok(res)
        })
        .await
        .map_err(err_str!(StateError::Runtime))?
    }

    /// Send a proposal to the raft node
    pub(crate) async fn send_proposal(
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
        let actual_wallet = state.get_wallet(&wallet.wallet_id).await.unwrap().unwrap();
        assert_eq!(expected_wallet, actual_wallet);
    }
}
