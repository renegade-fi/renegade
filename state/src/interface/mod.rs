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

use std::{sync::Arc, time::Duration};

use common::worker::WorkerFailureSender;
use config::RelayerConfig;
use crossbeam::channel::Sender as UnboundedSender;
use external_api::bus_message::SystemBusMessage;
use job_types::{
    handshake_manager::HandshakeManagerQueue, network_manager::NetworkManagerQueue,
    task_driver::TaskDriverQueue,
};
use libmdbx::{RO, RW};
use renegade_metrics::labels::{RAFT_CLUSTER_SIZE_METRIC, RAFT_LEADER_METRIC};
use system_bus::SystemBus;
use system_clock::SystemClock;
use tracing::error;
use util::{err_str, raw_err_str};

use crate::{
    applicator::{StateApplicator, StateApplicatorConfig},
    notifications::{OpenNotifications, ProposalWaiter},
    replication::{
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
const DEFAULT_HEARTBEAT_MS: u64 = 1_000; // 1 second
/// The default lower bound on the number of ticks before a Raft election
const DEFAULT_MIN_ELECTION_MS: u64 = 10_000; // 10 seconds
/// The default upper bound on the number of ticks before a Raft election
const DEFAULT_MAX_ELECTION_MS: u64 = 15_000; // 15 seconds

/// The frequency with which to check for raft core panics
const PANIC_CHECK_MS: u64 = 10_000; // 10 seconds
/// The frequency with which to check for missed expiry
const MEMBERSHIP_SYNC_INTERVAL_MS: u64 = 10_000; // 10 seconds
/// The frequency with which to record raft metrics
const RAFT_METRICS_INTERVAL_MS: u64 = 10_000; // 10 seconds

/// A type alias for a proposal queue of state transitions
pub type ProposalQueue = UnboundedSender<Proposal>;

// -------------------
// | State Interface |
// -------------------

/// A handle on the state that allows workers throughout the node to access the
/// replication and durability primitives backing the state machine
#[derive(Clone)]
pub struct State {
    /// Whether the state machine recovered from a snapshot
    pub(crate) recovered_from_snapshot: bool,
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
        system_clock: SystemClock,
        failure_send: WorkerFailureSender,
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
            system_clock,
            failure_send,
        )
        .await
    }

    /// The base constructor allowing for the variadic constructors above
    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_network<N: P2PNetworkFactory>(
        config: &RelayerConfig,
        raft_config: RaftClientConfig,
        network: N,
        task_queue: TaskDriverQueue,
        handshake_manager_queue: HandshakeManagerQueue,
        system_bus: SystemBus<SystemBusMessage>,
        system_clock: SystemClock,
        failure_send: WorkerFailureSender,
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
        let sm = StateMachine::new(sm_config, notifications.clone(), applicator).await?;
        let recovered_from_snapshot = sm.recovered_from_snapshot;

        // Start a raft
        let raft = RaftClient::new(raft_config, db.clone(), network, sm)
            .await
            .map_err(StateError::Replication)?;

        // Setup the node metadata from the config
        let this = Self {
            allow_local: config.allow_local,
            db,
            bus: system_bus,
            notifications,
            raft,
            recovered_from_snapshot,
        };
        this.setup_node_metadata(config).await?;
        this.setup_core_panic_timer(&system_clock, failure_send).await?;
        this.setup_membership_sync_timer(&system_clock).await?;
        this.setup_raft_metrics_timer(&system_clock).await?;

        Ok(this)
    }

    /// Build the raft config for the node
    fn build_raft_config(relayer_config: &RelayerConfig) -> RaftClientConfig {
        let peer_id = relayer_config.peer_id();
        let raft_id = get_raft_id(&peer_id);
        let initial_nodes = vec![(raft_id, RaftNode::new(peer_id))];

        RaftClientConfig {
            id: raft_id,
            heartbeat_interval: DEFAULT_HEARTBEAT_MS,
            election_timeout_min: DEFAULT_MIN_ELECTION_MS,
            election_timeout_max: DEFAULT_MAX_ELECTION_MS,
            initial_nodes,
            snapshot_path: relayer_config.raft_snapshot_path.clone(),
            ..Default::default()
        }
    }

    // ----------
    // | Timers |
    // ----------

    /// Setup a timer to check for core panics
    async fn setup_core_panic_timer(
        &self,
        clock: &SystemClock,
        failure_send: WorkerFailureSender,
    ) -> Result<(), StateError> {
        let duration = Duration::from_millis(PANIC_CHECK_MS);
        let name = "raft-panic-check-loop".to_string();
        let client = self.raft.clone();
        clock
            .add_async_timer(name, duration, move || {
                let client = client.clone();
                let chan = failure_send.clone();
                async move {
                    if client.raft_core_panicked().await {
                        error!("raft core panicked, sending failure signal");
                        chan.send(()).await.expect("could not send state failure signal");
                    }

                    Ok(())
                }
            })
            .await
            .map_err(StateError::Clock)
    }

    /// Periodically checks for missed expiries, i.e. nodes that have been
    /// expired at the gossip layer but not in the raft
    async fn setup_membership_sync_timer(&self, clock: &SystemClock) -> Result<(), StateError> {
        let duration = Duration::from_millis(MEMBERSHIP_SYNC_INTERVAL_MS);
        let name = "raft-membership-sync-loop".to_string();
        let client = self.raft.clone();
        let db = self.db.clone();
        let my_cluster = self.get_cluster_id().await?;

        clock
            .add_async_timer(name, duration, move || {
                let db = db.clone();
                let client = client.clone();
                let cluster_id = my_cluster.clone();

                async move {
                    let tx = db.new_read_tx().map_err(raw_err_str!("{}"))?;
                    let known_cluster_peers =
                        tx.get_cluster_peers(&cluster_id).map_err(raw_err_str!("{}"))?;
                    tx.commit().map_err(raw_err_str!("{}"))?;

                    client.sync_membership(known_cluster_peers).await.map_err(|e| e.to_string())
                }
            })
            .await
            .map_err(StateError::Clock)
    }

    /// A timer that records metrics about the raft cluster
    async fn setup_raft_metrics_timer(&self, clock: &SystemClock) -> Result<(), StateError> {
        let duration = Duration::from_millis(RAFT_METRICS_INTERVAL_MS);
        let name = "raft-metrics-loop".to_string();
        let client = self.raft.clone();

        clock
            .add_timer(name, duration, move || {
                let raft_cluster_size = client.cluster_size();
                let is_leader = if client.is_leader() { 1 } else { 0 };

                metrics::gauge!(RAFT_CLUSTER_SIZE_METRIC).set(raft_cluster_size as f64);
                metrics::gauge!(RAFT_LEADER_METRIC).set(is_leader as f64);

                Ok(())
            })
            .await
            .map_err(StateError::Clock)
    }

    // -------------------
    // | Private Helpers |
    // -------------------

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
