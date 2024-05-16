//! Handlers for incoming raft commands and messages

use std::collections::BTreeMap;

use common::types::gossip::WrappedPeerId;
use util::err_str;

use crate::{
    error::StateError,
    replicationv2::{
        get_raft_id,
        network::{RaftRequest, RaftResponse},
        Node, NodeId, RaftNode,
    },
    State,
};

impl State {
    // --- Raft Control --- //

    /// Whether the raft is initialized (has non-empty voters)
    pub fn is_raft_initialized(&self) -> bool {
        self.raft.is_initialized()
    }

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
