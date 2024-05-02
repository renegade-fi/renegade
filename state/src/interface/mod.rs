//! The `interface` module defines the interface to the state, methods for
//! proposing state transitions and reading from state

pub mod error;
pub mod mpc_preprocessing;
pub mod node_metadata;
pub mod notifications;
pub mod order_book;
pub mod order_history;
pub mod peer_index;
pub mod raft;
pub mod task_queue;
pub mod wallet_index;

use std::sync::{Arc, RwLock};

use ::raft::prelude::Config as RaftConfig;
use common::{
    types::{gossip::WrappedPeerId, new_cancel_channel},
    worker::Worker,
};
use config::RelayerConfig;
use crossbeam::channel::{unbounded, Sender as UnboundedSender};
use external_api::bus_message::SystemBusMessage;
use job_types::{
    handshake_manager::HandshakeManagerQueue, network_manager::NetworkManagerQueue,
    task_driver::TaskDriverQueue,
};
use system_bus::SystemBus;
use tokio::sync::watch::Sender;
use util::err_str;

use crate::{
    replication::{
        network::{
            address_translation::{PeerIdTranslationMap, SharedPeerIdTranslationMap},
            gossip::GossipRaftNetwork,
            traits::{RaftMessageReceiver, RaftNetwork},
        },
        raft_node::ReplicationNodeConfig,
        worker::ReplicationNodeWorker,
    },
    storage::db::{DbConfig, DB},
    Proposal, StateTransition,
};

use self::{error::StateError, notifications::ProposalWaiter};

/// The default tick interval for the raft node
const DEFAULT_TICK_INTERVAL_MS: u64 = 10; // 10 milliseconds
/// The default number of ticks between Raft heartbeats
const DEFAULT_HEARTBEAT_TICKS: usize = 100; // 1 second at 10ms per tick
/// The default lower bound on the number of ticks before a Raft election
const DEFAULT_MIN_ELECTION_TICKS: usize = 1000; // 10 seconds at 10ms per tick
/// The default upper bound on the number of ticks before a Raft election
const DEFAULT_MAX_ELECTION_TICKS: usize = 1500; // 15 seconds at 10ms per tick

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
    allow_local: bool,
    /// A handle on the database
    db: Arc<DB>,
    /// A handle on the proposal queue to the raft instance
    proposal_queue: Arc<ProposalQueue>,
    /// The shared mapping from raft IDs to peer IDs for translation
    translation_map: SharedPeerIdTranslationMap,
    /// The system bus for sending notifications to other workers
    bus: SystemBus<SystemBusMessage>,
}

impl State {
    /// Create a new state object using a `GossipRaftNetwork`, returning the
    /// handles to the state, Raft worker, and Raft cancel sender
    pub fn new(
        network_outbound: NetworkManagerQueue,
        raft_inbound: RaftMessageReceiver,
        config: &RelayerConfig,
        task_queue: TaskDriverQueue,
        handshake_manager_queue: HandshakeManagerQueue,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Result<(Self, ReplicationNodeWorker<GossipRaftNetwork>, Sender<()>), StateError> {
        let shared_map = Arc::new(RwLock::new(PeerIdTranslationMap::default()));
        let network = GossipRaftNetwork::new(network_outbound, raft_inbound, shared_map.clone());

        // Build a raft config
        let raft_config = Self::build_raft_config(config);
        Self::new_with_network_and_map(
            config,
            raft_config,
            network,
            task_queue,
            handshake_manager_queue,
            system_bus,
            shared_map,
        )
    }

    /// Create a new state handle with a network specified, also returning
    /// handles to the Raft worker & its cancel channel
    pub fn new_with_network<N: 'static + RaftNetwork + Send>(
        config: &RelayerConfig,
        raft_config: RaftConfig,
        network: N,
        task_queue: TaskDriverQueue,
        handshake_manager_queue: HandshakeManagerQueue,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Result<(Self, ReplicationNodeWorker<N>, Sender<()>), StateError> {
        let shared_map = Arc::new(RwLock::new(PeerIdTranslationMap::default()));
        Self::new_with_network_and_map(
            config,
            raft_config,
            network,
            task_queue,
            handshake_manager_queue,
            system_bus,
            shared_map,
        )
    }

    /// The base constructor allowing for the variadic constructors above
    fn new_with_network_and_map<N: 'static + RaftNetwork + Send>(
        config: &RelayerConfig,
        raft_config: RaftConfig,
        network: N,
        task_queue: TaskDriverQueue,
        handshake_manager_queue: HandshakeManagerQueue,
        system_bus: SystemBus<SystemBusMessage>,
        translation_map: SharedPeerIdTranslationMap,
    ) -> Result<(Self, ReplicationNodeWorker<N>, Sender<()>), StateError> {
        // Open up the DB
        let db = DB::new(&DbConfig { path: config.db_path.clone() }).map_err(StateError::Db)?;
        let db = Arc::new(db);

        // Setup the tables in the DB
        let tx = db.new_write_tx()?;
        tx.setup_tables()?;
        tx.commit()?;

        // Create a proposal queue and the raft config
        let (proposal_send, proposal_receiver) = unbounded();
        let (raft_cancel_sender, raft_cancel_receiver) = new_cancel_channel();
        let replication_config = ReplicationNodeConfig {
            tick_period_ms: DEFAULT_TICK_INTERVAL_MS,
            relayer_config: config.clone(),
            raft_config,
            proposal_receiver,
            network,
            task_queue,
            handshake_manager_queue,
            db: db.clone(),
            system_bus: system_bus.clone(),
            cancel_channel: raft_cancel_receiver,
        };

        // Start the Raft worker
        let mut raft_worker = ReplicationNodeWorker::new(replication_config)
            .expect("failed to build Raft replication node");
        raft_worker.start().expect("failed to start Raft replication node");

        // Setup the node metadata from the config
        let self_ = Self {
            allow_local: config.allow_local,
            db,
            proposal_queue: Arc::new(proposal_send),
            bus: system_bus,
            translation_map,
        };
        self_.setup_node_metadata(config)?;
        Ok((self_, raft_worker, raft_cancel_sender))
    }

    // -------------------
    // | Private Helpers |
    // -------------------

    /// Build the raft config for the node
    fn build_raft_config(relayer_config: &RelayerConfig) -> RaftConfig {
        let peer_id = relayer_config.p2p_key.public().to_peer_id();
        let raft_id = PeerIdTranslationMap::get_raft_id(&WrappedPeerId(peer_id));
        RaftConfig {
            id: raft_id,
            heartbeat_tick: DEFAULT_HEARTBEAT_TICKS,
            election_tick: DEFAULT_MIN_ELECTION_TICKS,
            min_election_tick: DEFAULT_MIN_ELECTION_TICKS,
            max_election_tick: DEFAULT_MAX_ELECTION_TICKS,
            ..Default::default()
        }
    }

    /// Send a proposal to the raft node
    fn send_proposal(&self, transition: StateTransition) -> Result<ProposalWaiter, StateError> {
        let (response, recv) = tokio::sync::oneshot::channel();
        let proposal = Proposal { transition, response };

        self.proposal_queue.send(proposal).map_err(err_str!(StateError::Proposal))?;
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
        let state = mock_state();

        let wallet = mock_empty_wallet();
        let res = state.new_wallet(wallet.clone()).unwrap().await;
        println!("res: {res:?}");
        assert!(res.is_ok());

        // Check for the wallet in the state
        let expected_wallet = wallet.clone();
        let actual_wallet = state.get_wallet(&wallet.wallet_id).unwrap().unwrap();
        assert_eq!(expected_wallet, actual_wallet);
    }
}
