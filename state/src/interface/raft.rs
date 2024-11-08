//! Handlers for incoming raft commands and messages

use std::collections::BTreeMap;

use common::types::gossip::WrappedPeerId;
use tracing::instrument;
use util::err_str;

use crate::{
    error::StateError,
    replication::{
        get_raft_id,
        network::{RaftRequest, RaftResponse},
        Node, NodeId, RaftNode,
    },
    StateInner,
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
        ciborium::de::from_reader(msg_bytes).map_err(err_str!(StateError::Serde))
    }
}
