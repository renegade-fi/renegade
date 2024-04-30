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

use common::default_wrapper::default_option;
use config::RelayerConfig;
use external_api::bus_message::SystemBusMessage;
use job_types::network_manager::NetworkManagerQueue;
use system_bus::SystemBus;
use util::err_str;

use crate::{
    replication::{
        network::{
            address_translation::{PeerIdTranslationMap, SharedPeerIdTranslationMap},
            gossip::GossipRaftNetwork,
            traits::{RaftMessageReceiver, RaftNetwork},
        },
        raft_node::{ProposalQueue, ReplicationNodeConfig},
    },
    storage::db::{DbConfig, DB},
    Proposal, StateTransition,
};

use self::{error::StateError, notifications::ProposalWaiter};

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
    /// Create a new state handle using a `GossipRaftNetwork`
    pub fn new(
        config: &RelayerConfig,
        proposal_send: ProposalQueue,
        system_bus: SystemBus<SystemBusMessage>,
    ) -> Result<Self, StateError> {
        let shared_map = Arc::new(RwLock::new(PeerIdTranslationMap::default()));

        Self::new_with_map(config, proposal_send, system_bus, shared_map)
    }

    /// The base constructor allowing for the variadic constructors above
    fn new_with_map(
        config: &RelayerConfig,
        proposal_send: ProposalQueue,
        system_bus: SystemBus<SystemBusMessage>,
        translation_map: SharedPeerIdTranslationMap,
    ) -> Result<Self, StateError> {
        // Open up the DB
        let db = DB::new(&DbConfig { path: config.db_path.clone() }).map_err(StateError::Db)?;
        let db = Arc::new(db);

        // Setup the tables in the DB
        let tx = db.new_write_tx()?;
        tx.setup_tables()?;
        tx.commit()?;

        // Setup the node metadata from the config
        let self_ = Self {
            allow_local: config.allow_local,
            db,
            proposal_queue: Arc::new(proposal_send),
            bus: system_bus,
            translation_map,
        };
        self_.setup_node_metadata(config)?;
        Ok(self_)
    }

    /// Fills in the configuration for the replication node with handles to
    /// state-managed resources, using the network manager to drive the raft
    /// network
    pub fn fill_replication_config(
        &self,
        replication_config: &mut ReplicationNodeConfig<GossipRaftNetwork>,
        network_outbound: NetworkManagerQueue,
        raft_inbound: RaftMessageReceiver,
    ) {
        let network =
            GossipRaftNetwork::new(network_outbound, raft_inbound, self.translation_map.clone());

        self.fill_replication_config_with_network(replication_config, network)
    }

    /// Fills in the configuration for the replication node with handles to
    /// state-managed resources, using the given network
    pub fn fill_replication_config_with_network<N: RaftNetwork>(
        &self,
        replication_config: &mut ReplicationNodeConfig<N>,
        network: N,
    ) {
        replication_config.db = default_option(self.db.clone());
        replication_config.network = default_option(network);
    }

    // -------------------
    // | Private Helpers |
    // -------------------

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
