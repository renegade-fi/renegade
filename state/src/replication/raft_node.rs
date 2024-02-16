//! A raft node that processes events from the consensus layer and the network,
//! and handles interactions with storage

use std::{
    collections::HashMap,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use config::RelayerConfig;
use crossbeam::channel::{Receiver as CrossbeamReceiver, TryRecvError};
use external_api::bus_message::SystemBusMessage;
use job_types::{handshake_manager::HandshakeManagerQueue, task_driver::TaskDriverQueue};
use protobuf::{Message, RepeatedField};
use raft::{
    eraftpb::ConfState,
    prelude::{
        ConfChangeSingle, ConfChangeType, ConfChangeV2, Entry, EntryType, HardState,
        Message as RaftMessage, Snapshot,
    },
    Config as RaftConfig, Error as RaftError, RawNode, StateRole, Storage, INVALID_ID,
};
use rand::{thread_rng, RngCore};
use slog::Logger;
use system_bus::SystemBus;
use tokio::sync::oneshot::Sender as OneshotSender;
use tracing::{debug, error, info};
use tracing_slog::TracingSlogDrain;
use util::err_str;
use uuid::Uuid;

use crate::{
    applicator::{StateApplicator, StateApplicatorConfig},
    storage::db::DB,
    Proposal, StateTransition,
};

use super::{
    error::ReplicationError, log_store::LogStore, network::traits::RaftNetwork, RaftPeerId,
};

// -------------
// | Raft Node |
// -------------

/// The interval at which to poll for new inbound messages
const RAFT_POLL_INTERVAL_MS: u64 = 10; // 10 ms
/// the interval at which the leader checks whether any learners can be promoted
/// to voters
const PROMOTION_INTERVAL_MS: u64 = 1_000; // 1 second
/// The matched log threshold at which a learner may be promoted to a voter
///
/// This is the number of log entries that a learner may be behind a leader and
/// still considered for promotion
const PROMOTION_ENTRY_THRESHOLD: u64 = 5;

/// Error message emitted when the proposal queue is disconnected
const PROPOSAL_QUEUE_DISCONNECTED: &str = "Proposal queue disconnected";
/// Error message emitted when sending a proposal response fails
const ERR_PROPOSAL_RESPONSE: &str = "Failed to send proposal response";
/// Error message emitted when an invalid ID is found in a proposal's context
const ERR_INVALID_PROPOSAL_ID: &str = "Invalid proposal ID";

/// The config for the local replication node
#[derive(Clone)]
pub struct ReplicationNodeConfig<N: RaftNetwork> {
    /// The period (in milliseconds) on which to tick the raft node
    pub tick_period_ms: u64,
    /// A copy of the relayer's config
    pub relayer_config: RelayerConfig,
    /// A reference to the channel on which the replication node may receive
    /// proposals
    pub proposal_queue: CrossbeamReceiver<Proposal>,
    /// A reference to the networking layer that backs the raft node
    pub network: N,
    /// A queue for the task driver, used by the applicator to start tasks
    pub task_queue: TaskDriverQueue,
    /// The handshake manager's work queue
    pub handshake_manager_queue: HandshakeManagerQueue,
    /// A handle on the persistent storage layer underlying the raft node
    pub db: Arc<DB>,
    /// A handle to the system-global bus
    pub system_bus: SystemBus<SystemBusMessage>,
}

/// A raft node that replicates the relayer's state machine
pub struct ReplicationNode<N: RaftNetwork> {
    /// The frequency on which to tick the raft node
    tick_period_ms: u64,
    /// The inner raft node
    inner: RawNode<LogStore>,
    /// The queue on which state transition proposals may be received
    proposal_queue: CrossbeamReceiver<Proposal>,
    /// A handle to the state applicator: the module responsible for applying
    /// state transitions to the state machine when they are committed
    applicator: StateApplicator,
    /// The networking layer backing the raft node
    network: N,
    /// A handle on the database underlying the state
    db: Arc<DB>,
    /// Maps proposal IDs to a response channel for the proposal
    proposal_responses: HashMap<Uuid, OneshotSender<Result<(), ReplicationError>>>,
}

impl<N: RaftNetwork> ReplicationNode<N> {
    /// Creates a new replication node
    pub fn new(config: ReplicationNodeConfig<N>) -> Result<Self, ReplicationError> {
        // TODO: Replace random node ID with the first 8 bytes of the local peer ID
        let my_id = thread_rng().next_u64();

        Self::new_with_config(config, &RaftConfig { id: my_id, ..Default::default() })
    }

    /// Creates a new replication node with a given raft config
    pub fn new_with_config(
        config: ReplicationNodeConfig<N>,
        raft_config: &RaftConfig,
    ) -> Result<Self, ReplicationError> {
        // Build the log store on top of the DB
        let store = LogStore::new(config.db.clone())?;
        Self::setup_storage(raft_config.id, &store)?;

        // Build a state applicator to handle state transitions
        let applicator = StateApplicator::new(StateApplicatorConfig {
            allow_local: config.relayer_config.allow_local,
            cluster_id: config.relayer_config.cluster_id,
            task_queue: config.task_queue,
            handshake_manager_queue: config.handshake_manager_queue,
            db: config.db.clone(),
            system_bus: config.system_bus,
        })
        .map_err(ReplicationError::Applicator)?;

        // Build an slog logger and connect it to the tracing logger
        let tracing_drain = TracingSlogDrain;
        let logger = Logger::root(tracing_drain, slog::o!());

        // Build raft node
        let node = RawNode::new(raft_config, store, &logger).map_err(ReplicationError::Raft)?;

        Ok(Self {
            tick_period_ms: config.tick_period_ms,
            inner: node,
            applicator,
            proposal_queue: config.proposal_queue,
            network: config.network,
            db: config.db,
            proposal_responses: HashMap::new(),
        })
    }

    /// Set defaults in the storage module that imply the local peer is a
    /// voter and the only member of the cluster.
    ///
    /// This allows the peer to appear to itself as "promotable" which means it
    /// may campaign for leader election
    ///
    /// This may change as the local peer bootstraps into the network and
    /// discovers cluster peers, at which point it will step down as begin
    /// syncing with the cluster
    fn setup_storage(my_id: u64, storage: &LogStore) -> Result<(), ReplicationError> {
        // Store a default snapshot under the assumption that the raft was just
        // initialized from the local node. This is effectively a raft wherein
        // the first term has just begun, and the log is empty at the first
        // index. We also register the local peer as the only voter known to the
        // cluster. This ensures that the local peer will elect itself leader if no
        // other nodes are found
        let mut snap = Snapshot::new();
        let md = snap.mut_metadata();

        md.index = 1;
        md.term = 1;
        md.mut_conf_state().voters = vec![my_id];

        // Store the snapshot
        storage.apply_snapshot(&snap)
    }

    /// The main loop of the raft consensus engine, we tick the state machine
    /// every `tick_period_ms` milliseconds
    pub fn run(mut self) -> Result<(), ReplicationError> {
        let tick_interval = Duration::from_millis(self.tick_period_ms);
        let promotion_interval = Duration::from_millis(PROMOTION_INTERVAL_MS);
        let poll_interval = Duration::from_millis(RAFT_POLL_INTERVAL_MS);

        let mut last_tick = Instant::now();
        let mut last_promotion_check = Instant::now();

        loop {
            thread::sleep(poll_interval);

            // Check for new proposals
            while let Some(Proposal { transition, response }) =
                self.proposal_queue.try_recv().map(Some).or_else(|e| match e {
                    TryRecvError::Empty => Ok(None),
                    TryRecvError::Disconnected => Err(ReplicationError::ProposalQueue(
                        PROPOSAL_QUEUE_DISCONNECTED.to_string(),
                    )),
                })?
            {
                // Generate a unique ID for the proposal
                let id = Uuid::new_v4();
                self.proposal_responses.insert(id, response);

                if let Err(e) = self.process_proposal(id, &transition) {
                    error!("node-{} error processing proposal: {e:?}, {transition:?}", self.id());
                    self.notify_proposal_sender(&id, Err(e))?;
                };
            }

            // Check for new messages from raft peers
            while let Some(msg) = self.network.try_recv().map_err(Into::into)? {
                match self.inner.step(msg) {
                    // Ignore messages from unknown peers
                    Err(RaftError::StepPeerNotFound) => Ok(()),
                    res => res.map_err(ReplicationError::Raft),
                }?;
            }

            // Leader checks if any learners can be promoted to voters
            if last_promotion_check.elapsed() >= promotion_interval {
                self.promote_learners()?;
                last_promotion_check = Instant::now();
            }

            // Tick the raft node after the sleep interval has elapsed
            if last_tick.elapsed() >= tick_interval {
                self.inner.tick();
                self.process_ready_state()?;

                last_tick = Instant::now();
            }
        }
    }

    // -------------
    // | Proposals |
    // -------------

    /// Process a state transition proposal
    fn process_proposal(
        &mut self,
        id: Uuid,
        proposal: &StateTransition,
    ) -> Result<(), ReplicationError> {
        // Handle raft cluster changes directly, otherwise append the proposal to the
        // log
        match proposal {
            StateTransition::AddRaftLearner { peer_id } => self.add_learner(id, *peer_id),
            StateTransition::AddRaftPeer { peer_id } => self.add_peer(id, *peer_id),
            StateTransition::RemoveRaftPeer { peer_id } => self.remove_peer(id, *peer_id),
            _ => {
                let ctx = id.to_bytes_le().to_vec();
                let payload = serde_json::to_vec(&proposal)
                    .map_err(err_str!(ReplicationError::SerializeValue))?;

                self.inner.propose(ctx, payload).map_err(ReplicationError::Raft)
            },
        }
    }

    /// Leader promotes any learners to voters that are sufficiently caught up
    fn promote_learners(&mut self) -> Result<(), ReplicationError> {
        if !self.is_leader() {
            return Ok(());
        }

        for learner in self.get_learners()? {
            // Check the progress of the learner
            let matched_log =
                self.inner.raft.prs().get(learner).map(|pr| pr.matched).unwrap_or_default();

            // If the learner is sufficiently caught up, promote them to a voter
            let log_idx = self.inner.raft.raft_log.last_index();
            if log_idx.saturating_sub(matched_log) <= PROMOTION_ENTRY_THRESHOLD {
                self.promote_learner(Uuid::new_v4(), learner)?;
            }
        }

        Ok(())
    }

    /// Add a raft learner to the group
    fn add_learner(&mut self, request_id: Uuid, peer_id: u64) -> Result<(), ReplicationError> {
        // Short-circuit if the peer is already present
        if self.peer_present(peer_id)? {
            self.notify_proposal_sender(&request_id, Ok(()))?;
            return Ok(());
        }

        info!("adding raft learner: {peer_id}");
        let mut change = ConfChangeSingle::new();
        change.set_node_id(peer_id);
        change.set_change_type(ConfChangeType::AddLearnerNode);

        self.conf_change(request_id, change)
    }

    /// Promote a learner to a voter
    fn promote_learner(
        &mut self,
        request_id: Uuid,
        peer_id: RaftPeerId,
    ) -> Result<(), ReplicationError> {
        info!("promoting raft learner: {peer_id}");
        let mut change = ConfChangeSingle::new();
        change.set_node_id(peer_id);
        change.set_change_type(ConfChangeType::AddNode);

        self.conf_change(request_id, change)
    }

    /// Add a peer to the raft
    fn add_peer(&mut self, request_id: Uuid, peer_id: u64) -> Result<(), ReplicationError> {
        // Short-circuit if the peer is already present
        if self.peer_present(peer_id)? {
            self.notify_proposal_sender(&request_id, Ok(()))?;
            return Ok(());
        }

        info!("adding raft voter: {peer_id}");
        let mut change = ConfChangeSingle::new();
        change.set_node_id(peer_id);
        change.set_change_type(ConfChangeType::AddNode);

        self.conf_change(request_id, change)
    }

    /// Remove a peer from the raft
    fn remove_peer(&mut self, request_id: Uuid, peer_id: u64) -> Result<(), ReplicationError> {
        // If the cluster has only two voters, we cannot remove a peer through consensus
        // -- no majority can be established when one of two nodes dies -- so we
        // must forcibly append a log
        let voters = self.get_config_state()?.voters;
        if voters.len() == 2 && voters.contains(&peer_id) {
            return self.force_remove_peer(request_id, peer_id);
        }

        // Otherwise remove the peer through consensus
        info!("removing raft peer: {peer_id}");
        let mut change = ConfChangeSingle::new();
        change.set_node_id(peer_id);
        change.set_change_type(ConfChangeType::RemoveNode);

        self.conf_change(request_id, change)
    }

    /// Forcibly remove a peer, going around consensus
    ///
    /// This is dangerous and should only be done when a quorum certainly cannot
    /// form otherwise
    ///
    /// Borrowed from the entry constructor here:
    ///    https://github.com/tikv/raft-rs/blob/eb55032e4708807681d0d8e59c04e8d00665ec60/src/raw_node.rs#L378
    fn force_remove_peer(
        &mut self,
        request_id: Uuid,
        peer_id: u64,
    ) -> Result<(), ReplicationError> {
        info!("forcibly removing raft peer: {peer_id}");

        // Build a config change to remove the node
        let context = request_id.to_bytes_le().to_vec();
        let mut change = ConfChangeSingle::new();
        change.set_node_id(peer_id);
        change.set_change_type(ConfChangeType::RemoveNode);

        let mut conf_change = ConfChangeV2::new();
        conf_change.mut_changes().push(change);
        let change_bytes =
            conf_change.write_to_bytes().map_err(err_str!(ReplicationError::SerializeValue))?;

        // Build a raw log entry to place the conf change in
        let index = self.inner.raft.raft_log.last_index() + 1;
        let term = self.inner.raft.raft_log.last_term();

        let mut entry = Entry::default();
        entry.set_entry_type(EntryType::EntryConfChangeV2);
        entry.data = change_bytes.into();
        entry.context = context.into();
        entry.term = term;
        entry.index = index;

        // Append the entry to the log them commit to it
        self.append_entries(vec![entry.clone()])?;
        self.commit_entries(vec![entry])?;

        // Take a snapshot and restore to it to ensure that the internal state machine
        // reflects our workaround
        // The snapshot can only be applied as a follower so the node must step down
        // then campaign again after applying
        let snap = self.inner.store().snapshot(index, 0 /* to */)?;
        self.inner.raft.become_follower(term + 1, INVALID_ID /* leader */);
        if !self.inner.raft.restore(snap) {
            error!("failed to restore snapshot after forced peer removal");
        }

        self.inner.raft.become_pre_candidate();
        Ok(())
    }

    /// Propose a single configuration change to the cluster
    fn conf_change(&mut self, id: Uuid, change: ConfChangeSingle) -> Result<(), ReplicationError> {
        let mut conf_change = ConfChangeV2::new();
        conf_change.set_changes(RepeatedField::from_vec(vec![change]));

        let ctx = id.to_bytes_le().to_vec();
        self.inner.propose_conf_change(ctx, conf_change).map_err(ReplicationError::Raft)
    }

    // ---------------
    // | Ready State |
    // ---------------

    /// Process the ready state of the node
    ///
    /// The ready state includes a collection of all state transition events
    /// that have occurred since the last time the ready state was polled.
    /// This includes:
    ///     - Messages to be sent to other nodes
    ///     - Snapshots from the leader
    ///     - Committed entries
    ///     - New entries that should be appended to the log, but not yet
    ///       applied
    ///     - `HardState` changes, e.g. new leader, new commit index, etc
    /// and more. For mor information see:
    ///     https://docs.rs/raft/latest/raft/index.html#processing-the-ready-state
    fn process_ready_state(&mut self) -> Result<(), ReplicationError> {
        if !self.inner.has_ready() {
            return Ok(());
        }

        let mut ready = self.inner.ready();

        // Send outbound messages
        self.send_outbound_messages(ready.take_messages())?;

        // Apply snapshot
        if !ready.snapshot().is_empty() {
            self.apply_snapshot(ready.snapshot())?;
        }

        // Commit entries
        self.commit_entries(ready.take_committed_entries())?;

        self.append_entries(ready.take_entries())?;

        // Update the raft hard state
        if let Some(hard_state) = ready.hs().cloned() {
            self.update_hard_state(hard_state)?;
        }

        // Send persisted messages to peers
        self.send_outbound_messages(ready.take_persisted_messages())?;

        // Advance the raft node and handle the outbound messages and committed entires
        // that are stored in the resultant `LightReady`
        let mut light_ready = self.inner.advance(ready);
        self.send_outbound_messages(light_ready.take_messages())?;
        self.commit_entries(light_ready.take_committed_entries())?;
        self.inner.advance_apply();

        Ok(())
    }

    /// Send outbound messages from the raft ready state
    fn send_outbound_messages(
        &mut self,
        messages: Vec<RaftMessage>,
    ) -> Result<(), ReplicationError> {
        for message in messages {
            self.network.send(message).map_err(|e| e.into())?;
        }

        Ok(())
    }

    /// Apply a raft snapshot from the ready state
    fn apply_snapshot(&mut self, snapshot: &Snapshot) -> Result<(), ReplicationError> {
        self.inner.mut_store().apply_snapshot(snapshot)
    }

    /// Commit entries from the ready state and apply them to the state machine
    fn commit_entries(&mut self, entries: Vec<Entry>) -> Result<(), ReplicationError> {
        for entry in entries.into_iter() {
            if entry.get_data().is_empty() {
                // Upon new leader election, the leader sends an empty entry
                // as a heartbeat to each follower. No processing is needed
                continue;
            }

            let entry_id = parse_proposal_id(&entry)?;
            let res = match entry.get_entry_type() {
                EntryType::EntryNormal => {
                    // Apply a normal entry to the state machine
                    let entry_bytes = entry.get_data();
                    let transition: StateTransition = serde_json::from_slice(entry_bytes)
                        .map_err(err_str!(ReplicationError::ParseValue))?;

                    debug!("node {} applying state transition {transition:?}", self.inner.raft.id);

                    self.applicator
                        .handle_state_transition(transition)
                        .map_err(ReplicationError::Applicator)
                },
                EntryType::EntryConfChangeV2 => {
                    // Apply a config change entry to the state machine
                    let mut config_change = ConfChangeV2::new();
                    config_change
                        .merge_from_bytes(entry.get_data())
                        .map_err(err_str!(ReplicationError::ParseValue))?;

                    // Forward the config change to the consensus engine
                    let res = self
                        .inner
                        .apply_conf_change(&config_change)
                        .map_err(ReplicationError::Raft);

                    // Remap the error, it cannot be cloned
                    match res {
                        Ok(conf_state) => {
                            // Store the new config
                            self.inner.mut_store().apply_config_state(conf_state)?;
                            Ok(())
                        },
                        Err(e) => Err(ReplicationError::ConfChange(e.to_string())),
                    }
                },
                _ => panic!("unexpected entry type: {entry:?}"),
            };

            // Notify the proposal sender that the proposal has been
            // applied, either successfully or with an error
            self.notify_proposal_sender(&entry_id, res)?;
        }

        Ok(())
    }

    /// Append new log entries from the ready state
    ///
    /// These entries are not yet committed and should not yet be applied to the
    /// state machine
    fn append_entries(&mut self, entries: Vec<Entry>) -> Result<(), ReplicationError> {
        self.inner.mut_store().append_log_entries(entries)
    }

    /// Update the hard state from the ready state
    fn update_hard_state(&mut self, hard_state: HardState) -> Result<(), ReplicationError> {
        self.inner.mut_store().apply_hard_state(hard_state)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Whether or not the local node is the leader
    pub fn is_leader(&self) -> bool {
        self.inner.raft.state == StateRole::Leader
    }

    /// Get the raft ID of the local node
    pub fn id(&self) -> u64 {
        self.inner.raft.id
    }

    /// Get the config state stored in the log
    fn get_config_state(&self) -> Result<ConfState, ReplicationError> {
        let tx = self.db.new_read_tx()?;
        let conf_state = tx.read_conf_state()?;
        tx.commit()?;

        Ok(conf_state)
    }

    /// Check if the peer is already present
    fn peer_present(&self, peer_id: RaftPeerId) -> Result<bool, ReplicationError> {
        let conf_state = self.get_config_state()?;
        let res = conf_state.voters.contains(&peer_id) || conf_state.learners.contains(&peer_id);
        Ok(res)
    }

    /// Get the set of learners in the cluster
    fn get_learners(&self) -> Result<Vec<RaftPeerId>, ReplicationError> {
        let conf_state = self.get_config_state()?;
        Ok(conf_state.learners)
    }

    /// Notify the proposal sender that the proposal has been applied
    fn notify_proposal_sender(
        &mut self,
        id: &Uuid,
        res: Result<(), ReplicationError>,
    ) -> Result<(), ReplicationError> {
        // If the proposal is not local to the node, or if the channel is dropped, no
        // notification is needed
        if let Some(resp) = self.proposal_responses.remove(id)
            && !resp.is_closed()
        {
            resp.send(res).map_err(|_| {
                ReplicationError::ProposalResponse(ERR_PROPOSAL_RESPONSE.to_string())
            })?;
        }

        Ok(())
    }
}

// -----------
// | Helpers |
// -----------

/// Parse a proposal ID from an entry
fn parse_proposal_id(entry: &Entry) -> Result<Uuid, ReplicationError> {
    let id_bytes = entry
        .get_context()
        .try_into()
        .map_err(|_| ReplicationError::ParseValue(ERR_INVALID_PROPOSAL_ID.to_string()))?;
    Ok(Uuid::from_bytes_le(id_bytes))
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::{
        mem,
        sync::Arc,
        thread::{self, Builder, JoinHandle},
        time::Duration,
    };

    use crossbeam::channel::{unbounded, Receiver as CrossbeamReceiver, Sender};
    use job_types::{
        handshake_manager::new_handshake_manager_queue, task_driver::new_task_driver_queue,
    };
    use raft::prelude::Config as RaftConfig;
    use system_bus::SystemBus;

    use crate::{
        replication::{
            error::ReplicationError,
            network::traits::test_helpers::{MockNetwork, MockNetworkController},
            RaftPeerId,
        },
        storage::db::DB,
        test_helpers::mock_db,
        Proposal, StateTransition,
    };

    use super::{ReplicationNode, ReplicationNodeConfig};

    /// A mock cluster, holds the handles of the threads running each node, as
    /// well as references to their databases and proposal queues
    pub struct MockReplicationCluster {
        /// The handles of the nodes in the cluster
        handles: Vec<JoinHandle<Result<(), ReplicationError>>>,
        /// The dbs of the nodes
        dbs: Vec<Arc<DB>>,
        /// The proposal senders of the nodes
        proposal_senders: Vec<Sender<Proposal>>,
        /// The network controller
        controller: MockNetworkController,
    }

    impl MockReplicationCluster {
        /// Create a mock cluster of nodes
        pub fn new(n_nodes: usize) -> Self {
            let (controller, mut nets) = MockNetwork::new_n_way_mesh(n_nodes);
            let dbs = (0..n_nodes).map(|_| Arc::new(mock_db())).collect::<Vec<_>>();

            let mut senders = Vec::new();
            let mut receivers = Vec::new();
            for _ in 0..n_nodes {
                let (sender, receiver) = unbounded();
                senders.push(sender);
                receivers.push(receiver);
            }

            // Build one leader and `n_nodes - 1` followers
            let leader = mock_leader(
                1, // id
                dbs[0].clone(),
                receivers.remove(0),
                nets.remove(0),
            );

            let followers = (1..n_nodes)
                .zip(receivers)
                .map(|(i, recv)| {
                    mock_follower((i + 1) as u64, dbs[i].clone(), recv, nets.remove(0))
                })
                .collect::<Vec<_>>();

            // Spawn each node in a separate thread
            let handles = vec![leader]
                .into_iter()
                .chain(followers)
                .enumerate()
                .map(|(i, node)| spawn_node(i as u64 + 1, node))
                .collect::<Vec<_>>();

            // Give the cluster some time to stabilize after an election
            thread::sleep(Duration::from_millis(50));

            // Propose a node addition to the cluster for each of the followers
            let leader_proposal_queue = senders[0].clone();
            for node_id in 2..=n_nodes {
                let add_node = StateTransition::AddRaftPeer { peer_id: node_id as u64 }.into();
                leader_proposal_queue.send(add_node).unwrap();
                thread::sleep(Duration::from_millis(50))
            }

            Self { handles, dbs, proposal_senders: senders, controller }
        }

        /// Get a reference to the `n`th node's DB
        ///
        /// We 1-index here to match the node IDs
        pub fn db(&self, node_id: usize) -> Arc<DB> {
            self.dbs[node_id - 1].clone()
        }

        /// Send a proposal to the `n`th node
        ///
        /// We 1-index here to match the node IDs
        pub fn send_proposal(&self, node_id: usize, proposal: StateTransition) {
            self.proposal_senders[node_id - 1].send(proposal.into()).unwrap();
        }

        /// Disconnect the given path between two nodes
        pub fn disconnect(&self, from: RaftPeerId, to: RaftPeerId) {
            self.controller.disconnect(from, to);
        }

        /// Remove a node from the cluster
        pub fn remove_node(&mut self, node_id: usize) {
            let remove_node = StateTransition::RemoveRaftPeer { peer_id: node_id as u64 };
            self.proposal_senders[node_id - 1].send(remove_node.into()).unwrap();
            self.handles.remove(node_id - 1);
        }

        /// Assert that no crashes have occurred
        pub fn assert_no_crashes(&self) {
            for handle in self.handles.iter() {
                assert!(!handle.is_finished());
            }
        }
    }

    /// Create a leader node
    pub fn mock_leader(
        id: u64,
        db: Arc<DB>,
        proposal_queue: CrossbeamReceiver<Proposal>,
        network: MockNetwork,
    ) -> ReplicationNode<MockNetwork> {
        mock_replication_node(id, db, proposal_queue, network)
    }

    /// Create a follower node
    pub fn mock_follower(
        id: u64,
        db: Arc<DB>,
        proposal_queue: CrossbeamReceiver<Proposal>,
        network: MockNetwork,
    ) -> ReplicationNode<MockNetwork> {
        mock_replication_node_with_config(
            db,
            proposal_queue,
            network,
            &RaftConfig {
                id,
                election_tick: 20,
                min_election_tick: 20,
                max_election_tick: 30,
                heartbeat_tick: 1,
                ..Default::default()
            },
        )
    }

    /// Create a mock node
    pub fn mock_replication_node(
        id: u64,
        db: Arc<DB>,
        proposal_queue: CrossbeamReceiver<Proposal>,
        network: MockNetwork,
    ) -> ReplicationNode<MockNetwork> {
        mock_replication_node_with_config(
            db,
            proposal_queue,
            network,
            // Build a raft node that has high tick frequency and low leader timeout intervals to
            // speed up tests. In unit tests there is no practical latency issue, so we can set the
            // timeouts to the minimum values they may validly take
            &RaftConfig {
                id,
                election_tick: 2,
                min_election_tick: 2,
                max_election_tick: 3,
                heartbeat_tick: 1,
                ..Default::default()
            },
        )
    }

    /// Create a moc node with a given raft config
    pub fn mock_replication_node_with_config(
        db: Arc<DB>,
        proposal_queue: CrossbeamReceiver<Proposal>,
        network: MockNetwork,
        raft_config: &RaftConfig,
    ) -> ReplicationNode<MockNetwork> {
        let (task_queue, task_recv) = new_task_driver_queue();
        let (handshake_manager_queue, handshake_recv) = new_handshake_manager_queue();
        mem::forget(task_recv);
        mem::forget(handshake_recv);

        ReplicationNode::new_with_config(
            ReplicationNodeConfig {
                tick_period_ms: 10,
                relayer_config: Default::default(),
                proposal_queue,
                network,
                task_queue,
                handshake_manager_queue,
                db,
                system_bus: SystemBus::new(),
            },
            raft_config,
        )
        .unwrap()
    }

    /// Spawn a node in a thread
    pub fn spawn_node(
        id: RaftPeerId,
        node: ReplicationNode<MockNetwork>,
    ) -> JoinHandle<Result<(), ReplicationError>> {
        Builder::new()
            .name(format!("node-{}", id))
            .spawn(move || {
                if let Err(e) = node.run() {
                    println!("node-{id} error: {e:?}");
                    return Err(e);
                }

                Ok(())
            })
            .unwrap()
    }
}

#[cfg(all(test, feature = "all-tests"))]
mod test {
    use std::{sync::Arc, thread, time::Duration};

    use common::types::{
        wallet::{Wallet, WalletIdentifier},
        wallet_mocks::mock_empty_wallet,
    };
    use crossbeam::channel::unbounded;
    use job_types::{
        handshake_manager::new_handshake_manager_queue, task_driver::new_task_driver_queue,
    };
    use rand::{thread_rng, Rng};

    use crate::{
        replication::{
            network::traits::test_helpers::MockNetwork,
            raft_node::test_helpers::MockReplicationCluster,
        },
        storage::db::DB,
        test_helpers::mock_db,
        StateTransition, WALLETS_TABLE,
    };

    use super::{ReplicationNode, ReplicationNodeConfig};

    /// Find a wallet in the given DB by its wallet ID
    fn find_wallet_in_db(wallet_id: WalletIdentifier, db: &DB) -> Wallet {
        db.read(WALLETS_TABLE, &wallet_id).unwrap().unwrap()
    }

    /// Tests that the constructor works properly, largely this means testing
    /// that the `LogStore` initialization is compatible with the `raft`
    /// setup
    #[test]
    fn test_constructor() {
        let db = Arc::new(mock_db());
        let (_, net, _) = MockNetwork::new_duplex_conn();

        let (_, proposal_receiver) = unbounded();
        let (task_queue, _recv) = new_task_driver_queue();
        let (handshake_manager_queue, _recv) = new_handshake_manager_queue();
        let node_config = ReplicationNodeConfig {
            tick_period_ms: 10,
            relayer_config: Default::default(),
            proposal_queue: proposal_receiver,
            network: net,
            task_queue,
            handshake_manager_queue,
            db: db.clone(),
            system_bus: Default::default(),
        };
        let _node = ReplicationNode::new(node_config).unwrap();
    }

    /// Tests handling a proposal to add a wallet
    #[test]
    fn test_proposal_add_wallet() {
        let mock_cluster = MockReplicationCluster::new(1 /* n_nodes */);
        mock_cluster.assert_no_crashes();

        // Send a proposal to add a wallet
        let wallet = mock_empty_wallet();
        let transition = StateTransition::AddWallet { wallet: wallet.clone() };
        mock_cluster.send_proposal(1 /* node_id */, transition);

        // Wait a bit for the proposal to be processed
        thread::sleep(Duration::from_millis(100));

        // Check that the wallet was added to the index
        let db = mock_cluster.db(1 /* node_id */);
        let wallet_id = wallet.wallet_id;
        let found_wallet = find_wallet_in_db(wallet_id, &db);

        mock_cluster.assert_no_crashes();
        assert_eq!(wallet, found_wallet);
    }

    /// Tests two nodes joining the cluster
    #[test]
    fn test_node_join() {
        let cluster = MockReplicationCluster::new(2 /* n_nodes */);

        // Propose a wallet to the first node
        let wallet = mock_empty_wallet();
        let transition = StateTransition::AddWallet { wallet: wallet.clone() };
        cluster.send_proposal(1 /* node_id */, transition);

        // Wait a bit for the proposal to be processed
        thread::sleep(Duration::from_millis(100));

        // Check that the wallet has been indexed in both DBs
        let db1 = cluster.db(1 /* node_id */);
        let db2 = cluster.db(2 /* node_id */);

        let expected_wallet: Wallet = wallet;
        let wallet1 = find_wallet_in_db(expected_wallet.wallet_id, &db1);
        let wallet2 = find_wallet_in_db(expected_wallet.wallet_id, &db2);

        assert_eq!(wallet1, expected_wallet);
        assert_eq!(wallet2, expected_wallet);
        cluster.assert_no_crashes();
    }

    /// Tests proposing to followers in a larger cluster
    #[test]
    fn test_many_node_consensus() {
        const N: usize = 5;
        let mut rng = thread_rng();
        let cluster = MockReplicationCluster::new(N);

        // Propose a wallet to a random node
        let wallet = mock_empty_wallet();
        let transition = StateTransition::AddWallet { wallet: wallet.clone() };
        let node_id = rng.gen_range(1..=N);
        cluster.send_proposal(node_id, transition);

        thread::sleep(Duration::from_millis(500));

        // Check a random node for the wallet
        let node_id = rng.gen_range(1..=N);
        let db = cluster.db(node_id);

        let expected_wallet: Wallet = wallet;
        let wallet = find_wallet_in_db(expected_wallet.wallet_id, &db);

        assert_eq!(wallet, expected_wallet);
        cluster.assert_no_crashes();
    }

    #[test]
    fn test_node_leave() {
        const N: usize = 5;
        let mut rng = thread_rng();
        let mut cluster = MockReplicationCluster::new(N);

        // Remove a node from the cluster
        let removed_node = rng.gen_range(1..=N);
        cluster.remove_node(removed_node);
        thread::sleep(Duration::from_millis(50));

        // Select a node that was not removed, and propose a new wallet
        let wallet = mock_empty_wallet();
        let transition = StateTransition::AddWallet { wallet: wallet.clone() };

        let mut node_id = rng.gen_range(1..=N);
        while node_id == removed_node {
            node_id = rng.gen_range(1..=N);
        }

        cluster.send_proposal(node_id, transition);
        thread::sleep(Duration::from_millis(500));

        // Check the removed node, verify that it never received the update
        let db = cluster.db(removed_node);

        let expected_wallet: Wallet = wallet;
        let res: Option<Wallet> = db.read(WALLETS_TABLE, &expected_wallet.wallet_id).unwrap();

        assert!(res.is_none());
        cluster.assert_no_crashes();
    }

    /// Tests the forced removal of a peer when the cluster has only two voters
    #[test]
    fn test_force_remove_peer() {
        let cluster = MockReplicationCluster::new(2 /* n_nodes */);

        // Remove a node from the cluster, disconnect its outbound to simulate a crash
        cluster.disconnect(2 /* from */, 1 /* to */);
        cluster.send_proposal(1, StateTransition::RemoveRaftPeer { peer_id: 2 });
        thread::sleep(Duration::from_millis(500)); // allow time for the proposal to be processed

        // Propose a wallet to the remaining node
        let wallet = mock_empty_wallet();
        let transition = StateTransition::AddWallet { wallet: wallet.clone() };
        cluster.send_proposal(1, transition);

        // Wait a bit for the proposal to be processed
        thread::sleep(Duration::from_millis(100));

        // Check that the wallet has been indexed in the remaining DB
        let db = cluster.db(1);
        let expected_wallet: Wallet = wallet;
        let wallet = find_wallet_in_db(expected_wallet.wallet_id, &db);

        assert_eq!(wallet, expected_wallet);
    }
}
