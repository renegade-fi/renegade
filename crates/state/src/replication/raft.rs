//! Wraps the inner raft in a client interface that handles requests and waiters

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use openraft::{ChangeMembers, Config as RaftConfig, Membership, RaftMetrics, ServerState};
use tokio::sync::Mutex;
use tracing::instrument;
use types_gossip::WrappedPeerId;
use util::log_task;
use util::logging::Outcome;
use util::{err_str, telemetry::helpers::backfill_trace_field};

use crate::{
    logging::Task,
    notifications::ProposalId,
    replication::{error::ReplicationError, get_raft_id},
    state_transition::{Proposal, StateTransition},
    storage::db::DB,
};

use super::{
    Node, NodeId, Raft, RaftNode,
    log_store::LogStore,
    network::{
        P2PNetworkFactory, P2PNetworkFactoryWrapper, P2PRaftNetwork, RaftRequest, RaftResponse,
    },
    state_machine::StateMachine,
};

/// The default cluster name
const DEFAULT_CLUSTER_NAME: &str = "relayer-raft-cluster";
/// The default heartbeat interval for the raft client
const DEFAULT_HEARTBEAT_INTERVAL: u64 = 1_500; // 1.5 second
/// The default election timeout min
const DEFAULT_ELECTION_TIMEOUT_MIN: u64 = 10_000; // 10 seconds
/// The default election timeout max
const DEFAULT_ELECTION_TIMEOUT_MAX: u64 = 15_000; // 15 seconds
/// The default log lag threshold for promoting learners
const DEFAULT_LEARNER_PROMOTION_THRESHOLD: u64 = 20; // 20 log entries
/// The number of consecutive membership-sync checks a peer must be absent from
/// the gossip layer's known-peers set before it is expired from the raft.
///
/// Acts as failure-detector hysteresis: at the 10s membership-sync interval
/// this is a ~30s grace window. Without it, a single missed gossip tick evicts
/// a peer immediately, so a freshly-joined learner can be removed before gossip
/// has even propagated it -- starving promotion and driving membership churn.
const DEFAULT_EXPIRY_GRACE_CHECKS: u32 = 3;
/// The maximum time to wait for an openraft membership change to commit.
///
/// `change_membership` is awaited with no internal timeout while holding the
/// `membership_change_lock` from the leader-only membership-sync tick. If the
/// raft core wedges and the await never returns, the lock is held forever and
/// the (sequentially-scheduled) membership-sync timer hangs on its next tick --
/// silently freezing membership reconciliation so workers can no longer be
/// adopted and the cluster looks leaderless. Bounding the call releases the
/// lock, keeps the timer alive, and surfaces the hang.
const CHANGE_MEMBERSHIP_TIMEOUT_MS: u64 = 5_000;
/// The amount of time to await promotion before timing out
///
/// Set to five minutes; giving enough time to receive snapshots and catch up to
/// logs
const DEFAULT_PROMOTION_TIMEOUT_MS: u64 = 5 * 60 * 1000;
/// The amount of time to await a leader election before timing out
const DEFAULT_LEADER_ELECTION_TIMEOUT_MS: u64 = 30_000; // 30 seconds
/// The default max chunk size for snapshots
const DEFAULT_SNAPSHOT_MAX_CHUNK_SIZE: u64 = 10 * 1024 * 1024; // 10MiB
/// The default max number of logs to keep in a snapshot
const DEFAULT_MAX_IN_SNAPSHOT_LOG_TO_KEEP: u64 = 50;
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
    /// The number of consecutive missed gossip checks before a raft peer is
    /// expired (failure-detector hysteresis)
    pub expiry_grace_checks: u32,
    /// Whether to promote caught-up learners to voters.
    ///
    /// When false (sole-voter mode) the seed remains the only voter and all
    /// workers stay learners. This is the safe mode while workers have
    /// ephemeral p2p identities: promoting a worker to voter is unsafe because
    /// a restart brings it back with a new node-id, leaving a dead voter the
    /// leader cannot remove without quorum -- a permanent quorum deadlock.
    /// Re-enable once workers have stable identities.
    pub enable_voter_promotion: bool,
    /// The directory at which snapshots are stored
    pub snapshot_path: String,
    /// The nodes to initialize the membership with
    pub initial_nodes: Vec<(NodeId, RaftNode)>,
    /// The maximum size of snapshot chunks in bytes
    pub snapshot_max_chunk_size: u64,
    /// The maximum number of logs to keep that are already included in
    /// the snapshot
    pub max_in_snapshot_log_to_keep: u64,
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
            expiry_grace_checks: DEFAULT_EXPIRY_GRACE_CHECKS,
            // Sole-voter mode by default: workers have ephemeral identities, so
            // promoting them to voters risks a quorum deadlock on restart.
            enable_voter_promotion: false,
            snapshot_path: "./raft-snapshots".to_string(),
            initial_nodes: vec![],
            snapshot_max_chunk_size: DEFAULT_SNAPSHOT_MAX_CHUNK_SIZE,
            max_in_snapshot_log_to_keep: DEFAULT_MAX_IN_SNAPSHOT_LOG_TO_KEEP,
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
    /// A lock to prevent simultaneous membership changes
    membership_change_lock: Arc<Mutex<()>>,
    /// Per-peer count of consecutive membership-sync checks during which the
    /// peer was absent from the gossip layer's known-peers set. A peer is only
    /// expired once its count reaches `config.expiry_grace_checks`; seeing the
    /// peer again resets it. Maintained only while this node is the leader.
    expiry_misses: Arc<Mutex<HashMap<NodeId, u32>>>,
}

impl RaftClient {
    /// Create a new raft client
    pub async fn new<N: P2PNetworkFactory>(
        config: RaftClientConfig,
        db: Arc<DB>,
        net_factory: N,
        state_machine: StateMachine,
    ) -> Result<Self, ReplicationError> {
        let raft_config = Arc::new(RaftConfig {
            cluster_name: config.cluster_name.clone(),
            heartbeat_interval: config.heartbeat_interval,
            election_timeout_min: config.election_timeout_min,
            election_timeout_max: config.election_timeout_max,
            snapshot_max_chunk_size: config.snapshot_max_chunk_size,
            max_in_snapshot_log_to_keep: config.max_in_snapshot_log_to_keep,
            install_snapshot_timeout: config.install_snapshot_timeout,
            max_payload_entries: config.max_payload_entries,
            ..Default::default()
        });

        // Create the raft
        let p2p_factory = P2PNetworkFactoryWrapper::new(net_factory);
        let log_store = LogStore::new(db.clone());
        let raft = Raft::new(config.id, raft_config, p2p_factory.clone(), log_store, state_machine)
            .await
            .map_err(err_str!(ReplicationError::RaftSetup))?;

        // Initialize the raft
        if config.init {
            let initial_nodes = config.initial_nodes.clone();
            let members = initial_nodes.into_iter().collect::<BTreeMap<_, _>>();
            raft.initialize(members).await.map_err(err_str!(ReplicationError::RaftSetup))?;
        }

        Ok(Self {
            config,
            raft,
            network_factory: p2p_factory,
            membership_change_lock: Arc::new(Mutex::new(())),
            expiry_misses: Arc::new(Mutex::new(HashMap::new())),
        })
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
    pub async fn is_initialized(&self) -> Result<bool, ReplicationError> {
        self.raft.is_initialized().await.map_err(err_str!(ReplicationError::Raft))
    }

    /// Get a copy of the raft metrics
    pub fn metrics(&self) -> RaftMetrics<NodeId, Node> {
        self.raft.metrics().borrow().clone()
    }

    /// Get the membership of the cluster
    pub(crate) fn membership(&self) -> Membership<NodeId, Node> {
        let metrics = self.metrics();
        metrics.membership_config.membership().clone()
    }

    /// Emit a periodic raft-health gauge (term, role, leader, voter/learner
    /// counts, last-applied index) so cluster degradation -- quorum loss, a
    /// stuck learner, an unexpected role -- is visible as a queryable signal
    /// instead of being inferred from low-level error spam. Called from every
    /// node on the membership-sync tick.
    pub fn log_health(&self) {
        let m = self.metrics();
        let membership = m.membership_config.membership();
        let voters = membership.voter_ids().count();
        let learners = membership.learner_ids().count();
        let last_applied = m.last_applied.map(|l| l.index).unwrap_or(0);
        let leader = m.current_leader.map(|l| l.to_string()).unwrap_or_else(|| "none".to_string());

        log_task!(
            Task::RaftLifecycle,
            Outcome::Ok,
            term = m.current_term,
            state = ?m.state,
            leader = %leader,
            voters = voters,
            learners = learners,
            last_applied = last_applied,
            "raft health"
        );
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

    /// Whether the local node is the leader
    pub(crate) fn is_leader(&self) -> bool {
        match self.leader_info() {
            Some((leader_id, _)) => self.node_id() == leader_id,
            None => false,
        }
    }

    /// Get the ids of the learners in the raft
    fn learners(&self) -> Vec<NodeId> {
        let metrics = self.metrics();
        metrics.membership_config.membership().learner_ids().collect()
    }

    /// Returns the local node's view of the raft cluster size
    pub(crate) fn cluster_size(&self) -> usize {
        self.membership().nodes().count()
    }

    /// Check for a panic in the raft core
    ///
    /// Returns `true` if the raft core panicked
    pub async fn raft_core_panicked(&self) -> bool {
        // The raft state method will return a `Fatal` error iff the core panicked
        self.raft.with_raft_state(|_| ()).await.is_err()
    }

    /// Shutdown the raft
    pub async fn shutdown(&self) -> Result<(), ReplicationError> {
        self.raft.shutdown().await.map_err(err_str!(ReplicationError::RaftTeardown))
    }

    // -------------------
    // | Wait Conditions |
    // -------------------

    /// Await the promotion of the local peer to a voter
    pub async fn await_promotion(&self) -> Result<(), ReplicationError> {
        let timeout = Duration::from_millis(DEFAULT_PROMOTION_TIMEOUT_MS);

        // Sole-voter mode: a worker stays a learner for its whole lifetime, so
        // it must NOT wait to become a voter -- that wait never resolves and
        // would time out into a restart loop (the original churn). Instead wait
        // until it has been adopted into the cluster as a learner: a leader
        // exists and the local node is present in the membership (the seed has
        // added it and it is now replicating).
        if !self.config.enable_voter_promotion {
            let my_id = self.node_id();
            return self
                .raft
                .wait(Some(timeout))
                .metrics(
                    |m| {
                        m.current_leader.is_some()
                            && m.membership_config.membership().get_node(&my_id).is_some()
                    },
                    "local-node-adoption",
                )
                .await
                .map_err(err_str!(ReplicationError::Raft))
                .map(|_| ());
        }

        // Wait until the local node is a VOTER -- any non-learner state (Follower,
        // Candidate, or Leader). Waiting only for `Follower` (as before) breaks the
        // restart-with-persisted-state path: a node that recovers as the sole voter
        // -- notably the SEED on its second boot -- becomes the *Leader*, never a
        // Follower, so the wait hangs until the timeout and crashes the startup task.
        // That is the bug that required manually wiping the seed's raft state
        // (relayer_state.db + raft_snapshots) to recover. A freshly-joining learner
        // still blocks here until it is promoted to a voter.
        self.raft
            .wait(Some(timeout))
            .metrics(|m| m.state != ServerState::Learner, "local-node-promotion")
            .await
            .map_err(err_str!(ReplicationError::Raft))
            .map(|_| ())
    }

    /// Await the election of a leader in the raft
    pub async fn await_leader_election(&self) -> Result<(), ReplicationError> {
        let timeout = Duration::from_millis(DEFAULT_LEADER_ELECTION_TIMEOUT_MS);
        self.raft
            .wait(Some(timeout))
            .metrics(|metrics| metrics.current_leader.is_some(), "leader-election")
            .await
            .map_err(err_str!(ReplicationError::Raft))
            .map(|_| ())
    }

    // -------------
    // | Snapshots |
    // -------------

    /// Trigger a snapshot to be created
    ///
    /// Does not wait for the snapshot to build, returns immediately after
    /// sending the command to the raft core
    pub async fn trigger_snapshot(&self) -> Result<(), ReplicationError> {
        self.raft().trigger().snapshot().await.map_err(err_str!(ReplicationError::Raft))
    }

    // -------------
    // | Proposals |
    // -------------

    /// Propose an update to the raft
    pub async fn propose_transition(&self, update: Proposal) -> Result<(), ReplicationError> {
        // If the current node is not the leader, forward to the leader
        let (mut leader_nid, leader_info) = self
            .leader_info()
            .ok_or_else(|| ReplicationError::Proposal(ERR_NO_LEADER.to_string()))?;

        // If we're expiring the leader, first change leader then propose an expiry
        if let StateTransition::RemoveRaftPeers { peer_ids } = update.transition.as_ref()
            && peer_ids.contains(&leader_nid)
        {
            log_task!(Task::LeaderElection, Outcome::Started, "removing raft leader");
            leader_nid = self.change_leader().await?;
        }

        if leader_nid != self.node_id() {
            // Get a client to the leader's raft
            let net = self.network_factory.new_p2p_client(leader_nid, leader_info);

            // Send a message
            let msg = RaftRequest::ForwardedProposal(update);
            net.send_request(leader_nid, msg)
                .await
                .map_err(err_str!(ReplicationError::Proposal))?;
            return Ok(());
        }

        match *update.transition {
            StateTransition::AddRaftLearners { learners } => {
                self.handle_add_learners(learners).await
            },
            StateTransition::AddRaftVoters { peer_ids } => self.handle_add_voters(peer_ids).await,
            StateTransition::RemoveRaftPeers { peer_ids } => {
                self.handle_remove_peers(peer_ids).await
            },
            _ => self.handle_client_write(update).await,
        }
    }

    /// Handle a proposal for an application level write
    async fn handle_client_write(&self, update: Proposal) -> Result<(), ReplicationError> {
        let rx = self
            .raft()
            .client_write_ff(update)
            .await
            .map_err(err_str!(ReplicationError::Proposal))?;

        // Watch the proposal for errors in a separate thread, return to the client
        tokio::spawn(async move {
            match rx.await {
                Err(e) => {
                    log_task!(
                        Task::Proposal,
                        Outcome::Failed,
                        error = %e,
                        "error watching proposal"
                    );
                },
                Ok(Err(raft_err)) => {
                    log_task!(
                        Task::Proposal,
                        Outcome::Failed,
                        error = %raft_err,
                        "raft error"
                    );
                },
                _ => (),
            }
        });

        Ok(())
    }

    /// Handle a proposal to add learners
    /// Apply an openraft membership change, bounded by a timeout so a wedged
    /// raft core cannot hang the caller (which holds `membership_change_lock`)
    /// forever. See `CHANGE_MEMBERSHIP_TIMEOUT_MS`.
    async fn change_membership_bounded(
        &self,
        change: ChangeMembers<NodeId, Node>,
        retain: bool,
    ) -> Result<(), ReplicationError> {
        let timeout = Duration::from_millis(CHANGE_MEMBERSHIP_TIMEOUT_MS);
        match tokio::time::timeout(timeout, self.raft().change_membership(change, retain)).await {
            Ok(res) => res.map(|_| ()).map_err(err_str!(ReplicationError::Proposal)),
            Err(_) => {
                log_task!(
                    Task::MembershipChange,
                    Outcome::Failed,
                    timeout_ms = CHANGE_MEMBERSHIP_TIMEOUT_MS,
                    "change_membership timed out; raft core may be wedged"
                );
                Err(ReplicationError::Proposal("change_membership timed out".to_string()))
            },
        }
    }

    async fn handle_add_learners(
        &self,
        learners: Vec<(NodeId, RaftNode)>,
    ) -> Result<(), ReplicationError> {
        let _lock = self.membership_change_lock.lock().await;

        // Only add learners that haven't already been added
        let membership = self.membership();
        let mut to_add = Vec::new();
        for (node_id, info) in learners {
            if membership.get_node(&node_id).is_none() {
                to_add.push((node_id, info));
            }
        }

        if !to_add.is_empty() {
            let learners = BTreeMap::from_iter(to_add.into_iter());
            let change = ChangeMembers::AddNodes(learners);

            self.change_membership_bounded(change, true /* retain */).await?;
        }

        Ok(())
    }

    /// Handle a proposal to add voters
    async fn handle_add_voters(&self, peer_ids: Vec<NodeId>) -> Result<(), ReplicationError> {
        let _lock = self.membership_change_lock.lock().await;

        // Only add voters that haven't already been added
        let existing_voters: Vec<_> = self.membership().voter_ids().collect();
        let mut to_add = Vec::new();
        for peer_id in peer_ids {
            if !existing_voters.contains(&peer_id) {
                to_add.push(peer_id);
            }
        }

        if !to_add.is_empty() {
            let voters = BTreeSet::from_iter(to_add.into_iter());
            let change = ChangeMembers::AddVoterIds(voters);
            self.change_membership_bounded(change, false /* retain */).await?;
        }

        Ok(())
    }

    /// Handle a proposal to remove a peer
    async fn handle_remove_peers(&self, peer_ids: Vec<NodeId>) -> Result<(), ReplicationError> {
        let _lock = self.membership_change_lock.lock().await;

        let peers: HashSet<_> = peer_ids.into_iter().collect();
        let members = self.membership();

        let existing_voters: HashSet<_> = members.voter_ids().collect();
        let existing_learners: HashSet<_> = members.learner_ids().collect();

        let mut voters_to_remove: Vec<_> = existing_voters.intersection(&peers).copied().collect();
        let learners_to_remove: Vec<_> = existing_learners.intersection(&peers).copied().collect();

        // Never remove the entire voter set. openraft computes its commit/quorum
        // index over the voters; an empty voter set underflows (index `usize::MAX`
        // into a length-0 slice) and panics the raft core, tearing down the node.
        // Retain at least one voter, preferring the local node.
        if !voters_to_remove.is_empty() && voters_to_remove.len() == existing_voters.len() {
            let keep = if existing_voters.contains(&self.node_id()) {
                self.node_id()
            } else {
                // Deterministic fallback so all nodes agree on the retained voter
                voters_to_remove.iter().copied().min().expect("voters_to_remove is non-empty")
            };
            voters_to_remove.retain(|id| *id != keep);
            log_task!(
                Task::MembershipChange,
                Outcome::Started,
                subject = %keep,
                "refusing to remove the last raft voter; retaining it"
            );
        }

        // Remove voters
        if !voters_to_remove.is_empty() {
            let voter_removal_change =
                ChangeMembers::RemoveVoters(BTreeSet::from_iter(voters_to_remove.into_iter()));
            self.change_membership_bounded(voter_removal_change, false /* retain */).await?;
        }

        // Remove learners
        if !learners_to_remove.is_empty() {
            let learner_removal_change =
                ChangeMembers::RemoveNodes(BTreeSet::from_iter(learners_to_remove.into_iter()));
            self.change_membership_bounded(learner_removal_change, false /* retain */).await?;
        }

        Ok(())
    }

    // ---------------------
    // | External Messages |
    // ---------------------

    /// Handle a raft request from a peer
    #[instrument(name = "handle_raft_request", skip_all, err, fields(req_type))]
    pub(crate) async fn handle_raft_request(
        &self,
        req: RaftRequest,
    ) -> Result<RaftResponse, ReplicationError> {
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
    ) -> Result<(), ReplicationError> {
        self.raft().initialize(peers).await.map_err(err_str!(ReplicationError::RaftSetup))
    }

    /// Force the leader to change by starting an election and waiting until a
    /// new leader is elected
    ///
    /// Returns the new leader
    pub async fn change_leader(&self) -> Result<NodeId, ReplicationError> {
        // Trigger an election
        let curr_leader = self.leader_info().map(|(id, _)| id).unwrap_or(0 /* invalid id */);
        self.raft().trigger().elect().await.map_err(err_str!(ReplicationError::Raft))?;

        // Await leadership change away from current leader
        let timeout = Duration::from_millis(DEFAULT_LEADER_ELECTION_TIMEOUT_MS);
        let metrics = self
            .raft()
            .wait(Some(timeout))
            .metrics(
                |m| m.current_leader.is_some() && m.current_leader.unwrap() != curr_leader,
                "leader-change",
            )
            .await
            .map_err(err_str!(ReplicationError::Raft))?;

        Ok(metrics.current_leader.expect("wait condition ensures leader exists"))
    }

    /// Add a single learner to the cluster
    pub async fn add_learner(
        &self,
        nid: NodeId,
        info: RaftNode,
    ) -> Result<ProposalId, ReplicationError> {
        self.add_learners(vec![(nid, info)]).await
    }

    /// Add learners to the cluster
    pub async fn add_learners(
        &self,
        learners: Vec<(NodeId, RaftNode)>,
    ) -> Result<ProposalId, ReplicationError> {
        let proposal = Proposal::from(StateTransition::AddRaftLearners { learners });
        let id = proposal.id;
        self.propose_transition(proposal).await.map(|_| id)
    }

    /// Promote a single learner to a voter
    pub async fn promote_learner(&self, learner: NodeId) -> Result<ProposalId, ReplicationError> {
        self.promote_learners(vec![learner]).await
    }

    /// Promote the given learners to voters
    pub async fn promote_learners(
        &self,
        learners: Vec<NodeId>,
    ) -> Result<ProposalId, ReplicationError> {
        let proposal = Proposal::from(StateTransition::AddRaftVoters { peer_ids: learners });
        let id = proposal.id;
        self.propose_transition(proposal).await.map(|_| id)
    }

    /// Remove a peer from the raft
    pub async fn remove_peer(&self, peer: NodeId) -> Result<ProposalId, ReplicationError> {
        self.remove_peers(vec![peer]).await
    }

    /// Remove the given peers from the raft
    pub async fn remove_peers(&self, peers: Vec<NodeId>) -> Result<ProposalId, ReplicationError> {
        let proposal = Proposal::from(StateTransition::RemoveRaftPeers { peer_ids: peers });
        let id = proposal.id;
        self.propose_transition(proposal).await.map(|_| id)
    }

    /// Sync the state of the cluster as discovered through gossip with the raft
    /// membership
    ///
    /// This method is called periodically by a timer and performs three sync
    /// functions:
    ///     - Add new learners that were missed
    ///     - Promote any learners that are eligible to be voters
    ///     - Expire any raft peers that are not in the list of known peers
    pub async fn sync_membership(
        &self,
        known_peers: Vec<WrappedPeerId>,
    ) -> Result<(), ReplicationError> {
        // Only the leader should update raft membership
        let leader = self.leader().await.unwrap_or(0 /* invalid id */);
        if leader != self.node_id() {
            // Not the leader: drop expiry bookkeeping so a future leadership
            // term starts its hysteresis counters fresh.
            self.expiry_misses.lock().await.clear();
            return Ok(());
        }

        // Update per-peer liveness counters once per tick and collect the peers
        // that have been absent long enough to expire (hysteresis applied).
        let expirable = self.update_expiry_misses(&known_peers).await;

        // openraft permits only one membership change at a time, so we make at
        // most one change per tick and return after it. The ORDER matters:
        //
        //   1. Expire dead VOTERS first -- a dead voter counts against quorum,
        //      so reclaiming it protects liveness.
        //   2. Promote caught-up learners -- this must come BEFORE expiring
        //      dead learners. If expiry runs first and there is always a peer
        //      to expire (e.g. stale ids left by restarts with ephemeral p2p
        //      identities), promotion is never reached: joining workers sit as
        //      learners until the await_promotion timeout, then restart, which
        //      creates another stale id to expire -- a self-sustaining churn
        //      loop. Promotion only promotes learners caught up within
        //      `learner_promotion_threshold`, so dead/lagging ids are never
        //      wrongly promoted; they fall through to step 4.
        //   3. Add newly-discovered learners from gossip.
        //   4. Expire dead learners last (no quorum impact).
        if self.expire_peers(&expirable, ExpireScope::VotersOnly).await? > 0 {
            return Ok(());
        }

        // Promote caught-up learners -- only in voter-promotion mode. In
        // sole-voter mode (default) the seed stays the only voter and workers
        // remain learners, which avoids the dead-voter quorum deadlock that
        // ephemeral worker identities create on restart.
        if self.config.enable_voter_promotion && self.try_promote_learners().await? > 0 {
            return Ok(());
        }

        if self.add_missed_learners(&known_peers).await? > 0 {
            return Ok(());
        }

        self.expire_peers(&expirable, ExpireScope::LearnersOnly).await.map(|_| ())
    }

    /// Add any nodes missed by gossip
    ///
    /// Returns the number of learners added
    pub async fn add_missed_learners(
        &self,
        known_peers: &[WrappedPeerId],
    ) -> Result<usize, ReplicationError> {
        let membership = self.membership();
        let mut learners_to_add = Vec::new();

        for peer in known_peers {
            let raft_id = get_raft_id(peer);
            if membership.get_node(&raft_id).is_none() {
                log_task!(
                    Task::MembershipChange,
                    Outcome::Started,
                    subject = %peer,
                    "found missed learner, adding..."
                );
                learners_to_add.push((raft_id, RaftNode::new(*peer)));
            }
        }

        let num_learners = learners_to_add.len();
        if num_learners > 0 {
            self.add_learners(learners_to_add).await?;
        }

        Ok(num_learners)
    }

    /// Try promoting all learners if the current node is the leader
    ///
    /// Returns the number of learners promoted
    pub async fn try_promote_learners(&self) -> Result<usize, ReplicationError> {
        // Check all learners replication progress
        let learners = self.learners();
        if self.learners().is_empty() {
            return Ok(0);
        }

        let metrics = self.metrics();
        let my_log = metrics.last_applied.map(|l| l.index).unwrap_or(0);
        let replication_info = &match metrics.replication {
            Some(rep) => rep,
            // If there is no replication info the local node may have lost leadership
            None => return Ok(0),
        };

        let mut learners_to_promote = Vec::new();
        for learner in learners {
            let latest_log = match replication_info.get(&learner).cloned().flatten() {
                Some(rep) => rep,
                None => continue,
            };

            let lag = my_log.saturating_sub(latest_log.index);
            if lag < self.config.learner_promotion_threshold {
                log_task!(
                    Task::MembershipChange,
                    Outcome::Started,
                    subject = %learner,
                    "promoting learner to voter"
                );
                learners_to_promote.push(learner);
            }
        }

        let num_learners = learners_to_promote.len();
        if num_learners > 0 {
            self.promote_learners(learners_to_promote).await?;
        }

        Ok(num_learners)
    }

    /// Update the per-peer consecutive-miss counters against the latest gossip
    /// view and return the raft node-ids that have been absent for at least
    /// `config.expiry_grace_checks` consecutive checks (eligible for expiry).
    ///
    /// This applies failure-detector hysteresis so that a transient gossip
    /// absence -- including a freshly-joined learner that gossip has not yet
    /// propagated -- does not immediately evict a peer. The local (leader) node
    /// is never tracked or expired: removing the node that drives the
    /// membership change can empty the voter set and panic the raft core.
    ///
    /// Called once per membership-sync tick, before any membership change, so
    /// the counters advance consistently regardless of which change is made.
    async fn update_expiry_misses(&self, known_peers: &[WrappedPeerId]) -> Vec<NodeId> {
        let known_peers_set: HashSet<_> = known_peers.iter().collect();
        let members = self.membership();
        let local_id = self.node_id();

        let member_ids: HashSet<NodeId> = members.nodes().map(|(id, _)| *id).collect();
        let mut misses = self.expiry_misses.lock().await;

        // Forget counters for nodes no longer in the membership
        misses.retain(|id, _| member_ids.contains(id));

        let mut expirable = Vec::new();
        for (id, info) in members.nodes() {
            if *id == local_id {
                continue;
            }

            if known_peers_set.contains(&info.peer_id) {
                // Seen this tick -- reset the miss counter
                misses.remove(id);
            } else {
                let count = misses.entry(*id).or_insert(0);
                *count += 1;
                if *count >= self.config.expiry_grace_checks {
                    expirable.push(*id);
                }
            }
        }

        expirable
    }

    /// Expire the eligible peers that fall within the given scope (voters or
    /// learners). Splitting expiry by scope lets the membership-sync loop
    /// reclaim dead voters with priority (quorum safety) while deferring dead
    /// learner cleanup below promotion, so promotion is never starved.
    ///
    /// Returns the number of peers expired.
    async fn expire_peers(
        &self,
        expirable: &[NodeId],
        scope: ExpireScope,
    ) -> Result<usize, ReplicationError> {
        if expirable.is_empty() {
            return Ok(0);
        }

        let members = self.membership();
        let voters: HashSet<_> = members.voter_ids().collect();
        let to_expire: Vec<NodeId> = expirable
            .iter()
            .copied()
            .filter(|id| match scope {
                ExpireScope::VotersOnly => voters.contains(id),
                ExpireScope::LearnersOnly => !voters.contains(id),
            })
            .collect();

        if to_expire.is_empty() {
            return Ok(0);
        }

        for id in &to_expire {
            log_task!(
                Task::MembershipChange,
                Outcome::Started,
                subject = %id,
                "found missed expiry, removing raft peer"
            );
        }

        let num = to_expire.len();
        self.remove_peers(to_expire).await?;
        Ok(num)
    }
}

/// The set of peers a single expiry pass should consider, used to prioritize
/// reclaiming dead voters over dead learners within a membership-sync tick.
#[derive(Clone, Copy)]
enum ExpireScope {
    /// Only expire peers that are currently voters
    VotersOnly,
    /// Only expire peers that are currently learners (non-voters)
    LearnersOnly,
}
