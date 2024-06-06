//! Wraps the inner raft in a client interface that handles requests and waiters

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
    time::Duration,
};

use common::types::gossip::WrappedPeerId;
use openraft::{ChangeMembers, Config as RaftConfig, Membership, RaftMetrics, ServerState};
use tracing::{info, instrument};
use util::{err_str, telemetry::helpers::backfill_trace_field};

use crate::{
    notifications::ProposalId, replication::get_raft_id, storage::db::DB, Proposal, StateTransition,
};

use super::{
    error::ReplicationV2Error,
    log_store::LogStore,
    network::{
        P2PNetworkFactory, P2PNetworkFactoryWrapper, P2PRaftNetwork, RaftRequest, RaftResponse,
    },
    state_machine::StateMachine,
    Node, NodeId, Raft, RaftNode,
};

/// The default cluster name
const DEFAULT_CLUSTER_NAME: &str = "relayer-raft-cluster";
/// The default heartbeat interval for the raft client
const DEFAULT_HEARTBEAT_INTERVAL: u64 = 3000; // 3 seconds
/// The default election timeout min
const DEFAULT_ELECTION_TIMEOUT_MIN: u64 = 15000; // 15 seconds
/// The default election timeout max
const DEFAULT_ELECTION_TIMEOUT_MAX: u64 = 20000; // 20 seconds
/// The default log lag threshold for promoting learners
const DEFAULT_LEARNER_PROMOTION_THRESHOLD: u64 = 20; // 20 log entries
/// The amount of time to await promotion before timing out
///
/// Set to five minutes; giving enough time to receive snapshots and catch up to
/// logs
const DEFAULT_PROMOTION_TIMEOUT_MS: u64 = 5 * 60 * 1000;
/// The amount of time to await a leader election before timing out
const DEFAULT_LEADER_ELECTION_TIMEOUT_MS: u64 = 30_000; // 30 seconds
/// The default max chunk size for snapshots
const DEFAULT_SNAPSHOT_MAX_CHUNK_SIZE: u64 = 10 * 1024 * 1024; // 10MiB
/// The default timeout to use when sending `InstallSnapshot` RPCs
const DEFAULT_INSTALL_SNAPSHOT_TIMEOUT_MS: u64 = 60_000; // 1 minute
/// The default max number of log entries in an `AppendEntries` payload
const DEFAULT_MAX_PAYLOAD_ENTRIES: u64 = 100;

/// Error message emitted when there is no known leader
const ERR_NO_LEADER: &str = "no leader";

/// The config for the raft client
#[derive(Clone)]
pub struct RaftClientConfig {
    /// The id of the local node
    pub id: NodeId,
    /// Whether to initialize the cluster
    ///
    /// Initialization handles the process of setting up an initial set of nodes
    /// and running an initial election
    pub init: bool,
    /// The name of the cluster
    pub cluster_name: String,
    /// The interval in milliseconds between heartbeats
    pub heartbeat_interval: u64,
    /// The minimum election timeout in milliseconds
    pub election_timeout_min: u64,
    /// The maximum election timeout in milliseconds
    pub election_timeout_max: u64,
    /// The length of a learner's log lag before being promoted to a follower
    pub learner_promotion_threshold: u64,
    /// The directory at which snapshots are stored
    pub snapshot_path: String,
    /// The nodes to initialize the membership with
    pub initial_nodes: Vec<(NodeId, RaftNode)>,
    /// The maximum size of snapshot chunks in bytes
    pub snapshot_max_chunk_size: u64,
    /// The timeout on individual `InstallSnapshot` RPC calls
    pub install_snapshot_timeout: u64,
    /// The maximum number of log entries in an `AppendEntries` payload
    pub max_payload_entries: u64,
}

impl Default for RaftClientConfig {
    fn default() -> Self {
        Self {
            id: 0,
            init: false,
            cluster_name: DEFAULT_CLUSTER_NAME.to_string(),
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            election_timeout_min: DEFAULT_ELECTION_TIMEOUT_MIN,
            election_timeout_max: DEFAULT_ELECTION_TIMEOUT_MAX,
            learner_promotion_threshold: DEFAULT_LEARNER_PROMOTION_THRESHOLD,
            snapshot_path: "./raft-snapshots".to_string(),
            initial_nodes: vec![],
            snapshot_max_chunk_size: DEFAULT_SNAPSHOT_MAX_CHUNK_SIZE,
            install_snapshot_timeout: DEFAULT_INSTALL_SNAPSHOT_TIMEOUT_MS,
            max_payload_entries: DEFAULT_MAX_PAYLOAD_ENTRIES,
        }
    }
}

/// A client interface to the raft
#[derive(Clone)]
pub struct RaftClient {
    /// The client's config
    pub(crate) config: RaftClientConfig,
    /// The inner raft
    raft: Raft,
    /// The network to use for the raft client
    network_factory: P2PNetworkFactoryWrapper,
}

impl RaftClient {
    /// Create a new raft client
    pub async fn new<N: P2PNetworkFactory>(
        config: RaftClientConfig,
        db: Arc<DB>,
        net_factory: N,
        state_machine: StateMachine,
    ) -> Result<Self, ReplicationV2Error> {
        let raft_config = Arc::new(RaftConfig {
            cluster_name: config.cluster_name.clone(),
            heartbeat_interval: config.heartbeat_interval,
            election_timeout_min: config.election_timeout_min,
            election_timeout_max: config.election_timeout_max,
            snapshot_max_chunk_size: config.snapshot_max_chunk_size,
            install_snapshot_timeout: config.install_snapshot_timeout,
            max_payload_entries: config.max_payload_entries,
            ..Default::default()
        });

        // Create the raft
        let p2p_factory = P2PNetworkFactoryWrapper::new(net_factory);
        let log_store = LogStore::new(db.clone());
        let raft = Raft::new(config.id, raft_config, p2p_factory.clone(), log_store, state_machine)
            .await
            .map_err(err_str!(ReplicationV2Error::RaftSetup))?;

        // Initialize the raft
        if config.init {
            let initial_nodes = config.initial_nodes.clone();
            let members = initial_nodes.into_iter().collect::<BTreeMap<_, _>>();
            raft.initialize(members).await.map_err(err_str!(ReplicationV2Error::RaftSetup))?;
        }

        Ok(Self { config, raft, network_factory: p2p_factory })
    }

    /// Get the inner raft
    pub fn raft(&self) -> &Raft {
        &self.raft
    }

    /// Get the node ID of the local raft
    pub fn node_id(&self) -> NodeId {
        self.config.id
    }

    /// Get the current leader
    pub async fn leader(&self) -> Option<NodeId> {
        self.raft.current_leader().await
    }

    /// Whether the raft is initialized
    pub async fn is_initialized(&self) -> Result<bool, ReplicationV2Error> {
        self.raft.is_initialized().await.map_err(err_str!(ReplicationV2Error::Raft))
    }

    /// Get a copy of the raft metrics
    pub fn metrics(&self) -> RaftMetrics<NodeId, Node> {
        self.raft.metrics().borrow().clone()
    }

    /// Get the membership of the cluster
    fn membership(&self) -> Membership<NodeId, Node> {
        let metrics = self.metrics();
        metrics.membership_config.membership().clone()
    }

    /// Get the node info an ID for the current leader
    pub(crate) fn leader_info(&self) -> Option<(NodeId, RaftNode)> {
        let metrics = self.metrics();
        let leader_nid = metrics.current_leader?;
        let leader_info = *metrics
            .membership_config
            .membership()
            .get_node(&leader_nid)
            // `expect` is safe, if `leader_nid` is `Some`; membership must contain leader
            .expect("leader info not found");

        Some((leader_nid, leader_info))
    }

    /// Get the ids of the learners in the raft
    fn learners(&self) -> Vec<NodeId> {
        let metrics = self.metrics();
        metrics.membership_config.membership().learner_ids().collect()
    }

    /// Check for a panic in the raft core
    ///
    /// Returns `true` if the raft core panicked
    pub async fn raft_core_panicked(&self) -> bool {
        // The raft state method will return a `Fatal` error iff the core panicked
        self.raft.with_raft_state(|_| ()).await.is_err()
    }

    /// Shutdown the raft
    pub async fn shutdown(&self) -> Result<(), ReplicationV2Error> {
        self.raft.shutdown().await.map_err(err_str!(ReplicationV2Error::RaftTeardown))
    }

    // -------------------
    // | Wait Conditions |
    // -------------------

    /// Await the promotion of the local peer to a voter
    pub async fn await_promotion(&self) -> Result<(), ReplicationV2Error> {
        let timeout = Duration::from_millis(DEFAULT_PROMOTION_TIMEOUT_MS);
        self.raft
            .wait(Some(timeout))
            .state(ServerState::Follower, "local-node-promotion")
            .await
            .map_err(err_str!(ReplicationV2Error::Raft))
            .map(|_| ())
    }

    /// Await the election of a leader in the raft
    pub async fn await_leader_election(&self) -> Result<(), ReplicationV2Error> {
        let timeout = Duration::from_millis(DEFAULT_LEADER_ELECTION_TIMEOUT_MS);
        self.raft
            .wait(Some(timeout))
            .metrics(|metrics| metrics.current_leader.is_some(), "leader-election")
            .await
            .map_err(err_str!(ReplicationV2Error::Raft))
            .map(|_| ())
    }

    // -------------
    // | Proposals |
    // -------------

    /// Propose an update to the raft
    pub async fn propose_transition(&self, update: Proposal) -> Result<(), ReplicationV2Error> {
        // If the current node is not the leader, forward to the leader
        let (leader_nid, leader_info) = self
            .leader_info()
            .ok_or_else(|| ReplicationV2Error::Proposal(ERR_NO_LEADER.to_string()))?;

        // If we're expiring the leader, first change leader then propose an expiry
        if let &StateTransition::RemoveRaftPeer { peer_id } = update.transition.as_ref()
            && leader_nid == peer_id
        {
            info!("removing raft leader");
            self.change_leader().await?;
        }

        if leader_nid != self.node_id() {
            // Get a client to the leader's raft
            let net = self.network_factory.new_p2p_client(leader_nid, leader_info);

            // Send a message
            let msg = RaftRequest::ForwardedProposal(update);
            net.send_request(leader_nid, msg)
                .await
                .map_err(err_str!(ReplicationV2Error::Proposal))?;
            return Ok(());
        }

        match *update.transition {
            StateTransition::AddRaftLearners { learners } => {
                self.handle_add_learners(learners).await
            },
            StateTransition::AddRaftVoters { peer_ids } => self.handle_add_voters(peer_ids).await,
            StateTransition::RemoveRaftPeer { peer_id } => self.handle_remove_peer(peer_id).await,
            _ => self
                .raft()
                .client_write(update)
                .await
                .map_err(err_str!(ReplicationV2Error::Proposal))
                .map(|_| ()),
        }
    }

    /// Handle a proposal to add learners
    async fn handle_add_learners(
        &self,
        learners: Vec<(NodeId, RaftNode)>,
    ) -> Result<(), ReplicationV2Error> {
        let learners = BTreeMap::from_iter(learners.into_iter());
        let change = ChangeMembers::AddNodes(learners);
        self.raft()
            .change_membership(change, true /* retain */)
            .await
            .map_err(err_str!(ReplicationV2Error::Proposal))
            .map(|_| ())
    }

    /// Handle a proposal to add voters
    async fn handle_add_voters(&self, peer_ids: Vec<NodeId>) -> Result<(), ReplicationV2Error> {
        let voters = BTreeSet::from_iter(peer_ids.into_iter());
        let change = ChangeMembers::AddVoterIds(voters);
        self.raft()
            .change_membership(change, false /* retain */)
            .await
            .map_err(err_str!(ReplicationV2Error::Proposal))
            .map(|_| ())
    }

    /// Handle a proposal to remove a peer
    async fn handle_remove_peer(&self, peer_id: NodeId) -> Result<(), ReplicationV2Error> {
        // First, check whether the peer has already been removed
        let members = self.membership();
        let mut nodes = members.nodes();

        if !nodes.any(|(id, _)| id == &peer_id) {
            info!("peer {peer_id} already removed, skipping proposal...");
            return Ok(());
        }

        let change = ChangeMembers::RemoveVoters(BTreeSet::from([peer_id]));
        self.raft()
            .change_membership(change, false /* retain */)
            .await
            .map_err(err_str!(ReplicationV2Error::Proposal))
            .map(|_| ())
    }

    // ---------------------
    // | External Messages |
    // ---------------------

    /// Handle a raft request from a peer
    #[instrument(name = "handle_raft_request", skip_all, err, fields(req_type))]
    pub(crate) async fn handle_raft_request(
        &self,
        req: RaftRequest,
    ) -> Result<RaftResponse, ReplicationV2Error> {
        backfill_trace_field("req_type", req.type_str());
        match req {
            RaftRequest::AppendEntries(req) => {
                let res = self.raft().append_entries(req).await?;
                Ok(RaftResponse::AppendEntries(res))
            },
            RaftRequest::Vote(req) => {
                let res = self.raft().vote(req).await?;
                Ok(RaftResponse::Vote(res))
            },
            RaftRequest::InstallSnapshot(req) => {
                let res = self.raft().install_snapshot(req).await?;
                Ok(RaftResponse::InstallSnapshot(Ok(res)))
            },
            RaftRequest::ForwardedProposal(req) => {
                self.propose_transition(req).await?;
                Ok(RaftResponse::Ack)
            },
        }
    }

    // ----------------------
    // | Cluster Membership |
    // ----------------------

    /// Initialize the raft with a new set of peers
    pub async fn initialize(
        &self,
        peers: BTreeMap<NodeId, RaftNode>,
    ) -> Result<(), ReplicationV2Error> {
        self.raft().initialize(peers).await.map_err(err_str!(ReplicationV2Error::RaftSetup))
    }

    /// Force the leader to change by starting an election and waiting until a
    /// new leader is elected
    pub async fn change_leader(&self) -> Result<(), ReplicationV2Error> {
        // Trigger an election
        let curr_leader = self.leader_info().map(|(id, _)| id).unwrap_or(0 /* invalid id */);
        self.raft().trigger().elect().await.map_err(err_str!(ReplicationV2Error::Raft))?;

        // Await leadership change away from current leader
        let timeout = Duration::from_millis(DEFAULT_LEADER_ELECTION_TIMEOUT_MS);
        self.raft()
            .wait(Some(timeout))
            .metrics(
                |m| m.current_leader.is_some() && m.current_leader.unwrap() != curr_leader,
                "leader-change",
            )
            .await
            .map_err(err_str!(ReplicationV2Error::Raft))
            .map(|_| ())
    }

    /// Add learners to the cluster
    pub async fn add_learners(
        &self,
        learners: Vec<(NodeId, RaftNode)>,
    ) -> Result<ProposalId, ReplicationV2Error> {
        let proposal = Proposal::from(StateTransition::AddRaftLearners { learners });
        let id = proposal.id;
        self.propose_transition(proposal).await.map(|_| id)
    }

    /// Promote learners to voters
    pub async fn promote_learners(
        &self,
        learners: Vec<NodeId>,
    ) -> Result<ProposalId, ReplicationV2Error> {
        let proposal = Proposal::from(StateTransition::AddRaftVoters { peer_ids: learners });
        let id = proposal.id;
        self.propose_transition(proposal).await.map(|_| id)
    }

    /// Remove a peer from the raft
    pub async fn remove_peer(&self, peer: NodeId) -> Result<ProposalId, ReplicationV2Error> {
        let proposal = Proposal::from(StateTransition::RemoveRaftPeer { peer_id: peer });
        let id = proposal.id;
        self.propose_transition(proposal).await.map(|_| id)
    }

    /// Try promoting all learners if the current node is the leader
    pub async fn try_promote_learners(&self) -> Result<(), ReplicationV2Error> {
        let leader = self.leader().await.unwrap_or(0 /* invalid id */);
        if leader != self.node_id() {
            return Ok(());
        }

        // Check all learners replication progress
        let learners = self.learners();
        if self.learners().is_empty() {
            return Ok(());
        }

        let metrics = self.metrics();
        let my_log = metrics.last_applied.map(|l| l.index).unwrap_or(0);
        let replication_info = &match metrics.replication {
            Some(rep) => rep,
            // If there is no replication info the local node may have lost leadership
            None => return Ok(()),
        };

        let learners_to_promote = learners
            .into_iter()
            .filter(|learner| {
                let latest_log = match replication_info.get(&learner).cloned().flatten() {
                    Some(rep) => rep,
                    None => return false,
                };

                let lag = my_log.saturating_sub(latest_log.index);
                lag < self.config.learner_promotion_threshold
            })
            .collect();

        info!("promoting learners: {learners_to_promote:?}");
        self.promote_learners(learners_to_promote).await?;

        Ok(())
    }

    /// Sync the state of the cluster as discovered through gossip with the raft
    /// membership.
    ///
    /// These can fall out of sync in the case that peer additions/removals are
    /// dropped, e.g. if the cluster was simultaneously processing a
    /// configuration change.
    pub async fn sync_membership(
        &self,
        known_peers: Vec<WrappedPeerId>,
    ) -> Result<(), ReplicationV2Error> {
        // Only the leader should update raft membership
        let leader_id = self.leader_info().map(|(id, _)| id).unwrap_or(0 /* invalid id */);
        if self.node_id() != leader_id {
            return Ok(());
        }

        let members = self.membership();

        let known_peers_set: HashSet<_> = known_peers.into_iter().collect();
        let raft_peers_set: HashSet<_> = members.nodes().map(|(_, info)| info.peer_id).collect();

        let new_learner_peer_ids = known_peers_set.difference(&raft_peers_set);
        let to_remove: Vec<_> = raft_peers_set.difference(&known_peers_set).collect();

        // Remove expired peers

        // Add new learners
        let new_learners = new_learner_peer_ids
            .map(|peer_id| (get_raft_id(peer_id), RaftNode::new(*peer_id)))
            .collect();

        self.add_learners(new_learners).await?;

        Ok(())
    }
}
