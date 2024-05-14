//! Wraps the inner raft in a client interface that handles requests and waiters

use std::{collections::BTreeSet, sync::Arc};

use openraft::{ChangeMembers, Config as RaftConfig, RaftNetworkFactory};
use util::err_str;

use crate::{notifications::ProposalId, storage::db::DB, Proposal, StateTransition};

use super::{
    error::ReplicationV2Error,
    log_store::LogStore,
    network::{P2PRaftNetwork, RaftRequest, RaftResponse},
    state_machine::StateMachine,
    NodeId, Raft, RaftNode, TypeConfig,
};

/// The default cluster name
const DEFAULT_CLUSTER_NAME: &str = "relayer-raft-cluster";
/// The default heartbeat interval for the raft client
const DEFAULT_HEARTBEAT_INTERVAL: u64 = 1000; // 1 second
/// The default election timeout min
const DEFAULT_ELECTION_TIMEOUT_MIN: u64 = 10000; // 10 seconds
/// The default election timeout max
const DEFAULT_ELECTION_TIMEOUT_MAX: u64 = 15000; // 15 seconds

/// Error message emitted when there is no known leader
const ERR_NO_LEADER: &str = "no leader";

/// Marker trait to simplify raft client trait bounds
#[rustfmt::skip]
pub trait NetworkEssential: RaftNetworkFactory<TypeConfig> + P2PRaftNetwork + Clone {}
impl<T: RaftNetworkFactory<TypeConfig> + P2PRaftNetwork + Clone> NetworkEssential for T {}

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
    /// The nodes to initialize the membership with
    pub initial_nodes: Vec<NodeId>,
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
            initial_nodes: vec![],
        }
    }
}

/// A client interface to the raft
#[derive(Clone)]
pub struct RaftClient<N: NetworkEssential> {
    /// The client's config
    config: RaftClientConfig,
    /// The inner raft
    raft: Raft,
    /// The network to use for the raft client
    net: N,
}

impl<N: NetworkEssential> RaftClient<N> {
    /// Create a new raft client
    pub async fn new(
        config: RaftClientConfig,
        db: Arc<DB>,
        net: N,
        state_machine: StateMachine,
    ) -> Result<Self, ReplicationV2Error> {
        let raft_config = Arc::new(RaftConfig {
            cluster_name: config.cluster_name.clone(),
            heartbeat_interval: config.heartbeat_interval,
            election_timeout_min: config.election_timeout_min,
            election_timeout_max: config.election_timeout_max,
            ..Default::default()
        });

        // Create the raft
        let log_store = LogStore::new(db.clone());
        let raft = Raft::new(config.id, raft_config, net.clone(), log_store, state_machine)
            .await
            .map_err(err_str!(ReplicationV2Error::RaftSetup))?;

        // Initialize the raft
        if config.init {
            let mut initial_nodes = config.initial_nodes.clone();
            if !initial_nodes.contains(&config.id) {
                initial_nodes.push(config.id);
            }

            let members = initial_nodes.iter().copied().collect::<BTreeSet<_>>();
            raft.initialize(members).await.map_err(err_str!(ReplicationV2Error::RaftSetup))?;
        }

        Ok(Self { config, raft, net })
    }

    /// Get the inner raft
    pub fn raft(&self) -> &Raft {
        &self.raft
    }

    /// Get a handle to the network implementation
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn network(&self) -> N {
        self.net.clone()
    }

    /// Get the node ID of the local raft
    pub fn node_id(&self) -> NodeId {
        self.config.id
    }

    /// Get the current leader
    pub async fn leader(&self) -> Option<NodeId> {
        self.raft.current_leader().await
    }

    /// Shutdown the raft
    pub async fn shutdown(&self) -> Result<(), ReplicationV2Error> {
        self.raft.shutdown().await.map_err(err_str!(ReplicationV2Error::RaftTeardown))
    }

    // -------------
    // | Proposals |
    // -------------

    /// Propose an update to the raft
    pub async fn propose_transition(&self, update: Proposal) -> Result<(), ReplicationV2Error> {
        // If the current node is not the leader, forward to the leader
        let leader = self
            .leader()
            .await
            .ok_or_else(|| ReplicationV2Error::Proposal(ERR_NO_LEADER.to_string()))?;
        if leader != self.node_id() {
            let msg = RaftRequest::ForwardedProposal(update);
            self.net
                .send_request(leader, msg)
                .await
                .map_err(err_str!(ReplicationV2Error::Proposal))?;

            return Ok(());
        }

        match update.transition.as_ref() {
            StateTransition::AddRaftLearner { peer_id, info } => {
                self.handle_add_learner(*peer_id, *info).await
            },
            StateTransition::AddRaftVoter { peer_id } => self.handle_add_voter(*peer_id).await,
            StateTransition::RemoveRaftPeer { peer_id } => self.handle_remove_peer(*peer_id).await,
            _ => self
                .raft()
                .client_write(update)
                .await
                .map_err(err_str!(ReplicationV2Error::Proposal))
                .map(|_| ()),
        }
    }

    /// Handle a proposal to add a learner
    async fn handle_add_learner(
        &self,
        peer_id: NodeId,
        info: RaftNode,
    ) -> Result<(), ReplicationV2Error> {
        self.raft()
            .add_learner(peer_id, info, false /* blocking */)
            .await
            .map_err(err_str!(ReplicationV2Error::Proposal))
            .map(|_| ())
    }

    /// Handle a proposal to add a voter
    async fn handle_add_voter(&self, peer_id: NodeId) -> Result<(), ReplicationV2Error> {
        let change = ChangeMembers::AddVoterIds(BTreeSet::from([peer_id]));
        self.raft()
            .change_membership(change, false /* retain */)
            .await
            .map_err(err_str!(ReplicationV2Error::Proposal))
            .map(|_| ())
    }

    /// Handle a proposal to remove a peer
    async fn handle_remove_peer(&self, peer_id: NodeId) -> Result<(), ReplicationV2Error> {
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
    pub(crate) async fn handle_raft_request(
        &self,
        req: RaftRequest,
    ) -> Result<RaftResponse, ReplicationV2Error> {
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

    /// Add a learner to the cluster
    pub async fn add_learner(
        &self,
        learner: NodeId,
        info: RaftNode,
    ) -> Result<ProposalId, ReplicationV2Error> {
        let proposal = Proposal::from(StateTransition::AddRaftLearner { peer_id: learner, info });
        let id = proposal.id;
        self.propose_transition(proposal).await.map(|_| id)
    }

    /// Promote a learner to a voter
    pub async fn promote_learner(&self, learner: NodeId) -> Result<ProposalId, ReplicationV2Error> {
        let proposal = Proposal::from(StateTransition::AddRaftVoter { peer_id: learner });
        let id = proposal.id;
        self.propose_transition(proposal).await.map(|_| id)
    }

    /// Remove a peer from the raft
    pub async fn remove_peer(&self, peer: NodeId) -> Result<ProposalId, ReplicationV2Error> {
        let proposal = Proposal::from(StateTransition::RemoveRaftPeer { peer_id: peer });
        let id = proposal.id;
        self.propose_transition(proposal).await.map(|_| id)
    }
}
