//! Handlers for incoming raft commands and messages

use std::collections::BTreeMap;

use common::types::gossip::WrappedPeerId;
use util::err_str;

use crate::{
    error::StateError,
    replication::{
        get_raft_id,
        network::{RaftRequest, RaftResponse},
        Node, NodeId, RaftNode,
    },
    State,
};

impl State {
    // --- Raft State --- //

    /// Whether the raft is initialized (has non-empty voters)
    pub fn is_raft_initialized(&self) -> bool {
        self.raft.is_initialized()
    }

    /// Whether the local node is the leader
    pub fn is_leader(&self) -> bool {
        match self.raft.leader_info() {
            Some((leader_id, _)) => self.raft.node_id() == leader_id,
            None => false,
        }
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

    // --- Networking --- //

    /// Handle a raft request from a peer
    ///
    /// We (de)serialize at the raft layer to avoid dependency leak
    pub async fn handle_raft_req(&self, msg_bytes: Vec<u8>) -> Result<RaftResponse, StateError> {
        let msg: RaftRequest =
            bincode::deserialize(&msg_bytes).map_err(err_str!(StateError::Serde))?;
        self.raft.handle_raft_request(msg).await.map_err(StateError::Replication)
    }
}
