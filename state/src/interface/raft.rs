//! Handlers for incoming raft commands and messages

use util::err_str;

use crate::{
    error::StateError,
    replicationv2::network::{RaftRequest, RaftResponse},
    State,
};

impl State {
    /// Handle a raft request from a peer
    ///
    /// We (de)serialize at the raft layer to avoid dependency leak
    pub async fn handle_raft_req(&self, msg_bytes: Vec<u8>) -> Result<RaftResponse, StateError> {
        let msg: RaftRequest =
            bincode::deserialize(&msg_bytes).map_err(err_str!(StateError::Serde))?;
        self.raft.handle_raft_request(msg).await.map_err(StateError::Replication)
    }
}
