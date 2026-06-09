//! Handlers for incoming raft commands and messages

use std::collections::BTreeMap;

use tracing::instrument;
use types_gossip::WrappedPeerId;

use crate::{
    StateInner, ciborium_deserialize,
    error::StateError,
    replication::{
        Node, NodeId, RaftNode, get_raft_id,
        network::{RaftRequest, RaftResponse},
    },
};

impl StateInner {
    // --- Raft State --- //

    /// Whether the state machine was recovered from a snapshot
    pub fn was_recovered_from_snapshot(&self) -> bool {
        self.config.recovered_from_snapshot
    }

    /// Whether the raft is initialized (has non-empty voters)
    pub async fn is_raft_initialized(&self) -> Result<bool, StateError> {
        self.raft.is_initialized().await.map_err(StateError::Replication)
    }

    /// Whether the local node-id appears in the current (persisted) raft
    /// membership, as a voter or a learner.
    ///
    /// Used at startup to detect a stale/foreign persisted raft state: if this
    /// node recovered raft state but its own node-id is absent from the
    /// membership (e.g. its p2p key regenerated to a new node-id), rejoining
    /// would wedge it as a Learner the leader can never see. The caller should
    /// re-bootstrap / wipe instead of rejoining.
    pub fn local_node_in_membership(&self) -> bool {
        let id = self.raft.node_id();
        let metrics = self.raft.metrics();
        let membership = metrics.membership_config.membership();
        membership.voter_ids().any(|v| v == id) || membership.learner_ids().any(|l| l == id)
    }

    /// Whether the local node is ready to serve API requests: a raft leader is
    /// known AND the local node is present in the current membership.
    ///
    /// This mirrors the sole-voter adoption condition awaited in
    /// `await_promotion` (replication/raft.rs), so the ELB `/v2/ping` health
    /// check can reflect "this node is an adopted, replicating cluster member"
    /// rather than merely "the process is up". A node that has not yet been
    /// adopted (still joining), or that has dropped out of membership / lost the
    /// leader, returns false so the load balancer drains it instead of routing
    /// requests it cannot serve -- which otherwise surface to clients as 504
    /// Gateway Timeouts. Reads only the non-blocking raft metrics watch channel,
    /// so it is safe to call from the dedicated (near-idle) health runtime.
    pub fn is_raft_ready(&self) -> bool {
        let id = self.raft.node_id();
        let metrics = self.raft.metrics();
        metrics.current_leader.is_some()
            && metrics.membership_config.membership().get_node(&id).is_some()
    }

    /// Whether the local node is the leader
    pub fn is_leader(&self) -> bool {
        self.raft.is_leader()
    }

    /// Get the size of the raft cluster
    pub fn cluster_size(&self) -> usize {
        self.raft.cluster_size()
    }

    /// Get the leader of the raft
    pub fn get_leader(&self) -> Option<WrappedPeerId> {
        let (_raft_id, info) = self.raft.leader_info()?;
        Some(info.peer_id)
    }

    // --- Raft Control --- //

    /// Initialize a new raft with the given set of peers
    pub async fn initialize_raft(&self, peers: Vec<WrappedPeerId>) -> Result<(), StateError> {
        let mut node_info: BTreeMap<NodeId, Node> = BTreeMap::new();
        for peer in peers.into_iter() {
            let nid = get_raft_id(&peer);
            let info = RaftNode::new(peer);
            node_info.insert(nid, info);
        }

        self.raft.initialize(node_info).await.map_err(StateError::Replication)
    }

    /// Await promotion of the local node to a voter
    pub async fn await_promotion(&self) -> Result<(), StateError> {
        self.raft.await_promotion().await.map_err(StateError::Replication)
    }

    /// Await a leader to be elected
    pub async fn await_leader(&self) -> Result<(), StateError> {
        self.raft.await_leader_election().await.map_err(StateError::Replication)
    }

    /// Trigger a snapshot
    pub async fn trigger_snapshot(&self) -> Result<(), StateError> {
        self.raft.trigger_snapshot().await.map_err(StateError::Replication)
    }

    // --- Networking --- //

    /// Handle a raft request from a peer
    ///
    /// We (de)serialize at the raft layer to avoid dependency leak
    #[instrument(name = "handle_raft_request", skip_all, err)]
    pub async fn handle_raft_req(&self, msg_bytes: Vec<u8>) -> Result<RaftResponse, StateError> {
        let msg = Self::deserialize_raft_request(&msg_bytes)?;
        self.raft.handle_raft_request(msg).await.map_err(StateError::Replication)
    }

    /// Deserialize a raft request from bytes
    #[instrument(name = "deserialize_raft_request", skip_all, fields(msg_size = msg_bytes.len()), err)]
    pub fn deserialize_raft_request(msg_bytes: &[u8]) -> Result<RaftRequest, StateError> {
        ciborium_deserialize(msg_bytes).map_err(StateError::serde)
    }
}
